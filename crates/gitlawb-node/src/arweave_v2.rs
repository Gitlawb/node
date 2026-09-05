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

use anyhow::{anyhow, Result};
use ed25519_dalek::PUBLIC_KEY_LENGTH;

use crate::ans104::{self, DataItem};

/// Outcome of a gateway probe for a persisted `item_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// 2xx, body parses as ANS-104, signature verifies against the
    /// expected owner, and the derived id matches the requested
    /// `item_id`. No re-upload allowed.
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
    /// The node's public key, for signature verification. `Present`
    /// requires proof, so a `None` here can never report `Present`:
    /// it still enforces 2xx/404/indeterminate classification and the
    /// 2xx body shape, but a 2xx match stays `Indeterminate`.
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
///
/// Returns `(outcome, body)`: on `Present`, the body is the
/// capped, validated bytes the probe already consumed (so
/// `verify_anchor` does not need a second GET to extract the
/// payload); on `DefinitivelyAbsent` and `Indeterminate`, the
/// body is `None`. Splitting validation and consumption across
/// two independent network reads would let a second-read
/// transport / cap failure become a 500, contradicting the
/// endpoint's three-outcome model.
pub async fn probe_anchor_item(
    client: &reqwest::Client,
    req: &ProbeRequest,
) -> (ProbeOutcome, Option<Vec<u8>>) {
    let url = format!("{}/{}", req.gateway_url.trim_end_matches('/'), req.item_id);

    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return (ProbeOutcome::Indeterminate, None),
    };

    let status = resp.status();

    if status.as_u16() == 404 {
        let outcome = classify_404(resp).await;
        return (outcome, None);
    }

    if !status.is_success() {
        return (ProbeOutcome::Indeterminate, None);
    }

    let bytes = match read_capped_body(resp, PROBE_MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => return (ProbeOutcome::Indeterminate, None),
    };

    // Legacy v1 shape (`schema: "gitlawb/ref-update/v1"`) carries no
    // signature and no item/content binding: anyone can mint matching
    // JSON. It must never report `verified`, so classify it as
    // `Indeterminate` here rather than routing it into a verifying
    // path.
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
        if v.get("schema").and_then(|s| s.as_str()) == Some("gitlawb/ref-update/v1") {
            return (ProbeOutcome::Indeterminate, None);
        }
    }

    // v2: accept the binary ANS-104 frame first (what a gateway
    // serving a verifiable envelope returns), then the JSON DataItem
    // projection used by the tests. Raw content alone (neither frame)
    // is `Indeterminate`: without the envelope there is no signature
    // to verify.
    if let Ok(item) = DataItem::from_binary(&bytes) {
        return probe_item(item, req);
    }

    let item: DataItem = match serde_json::from_slice(&bytes) {
        Ok(i) => i,
        Err(_) => return (ProbeOutcome::Indeterminate, None),
    };

    probe_item(item, req)
}

/// Shared v2 classification for a parsed `DataItem`: owner binding,
/// Ed25519 verification against the expected key, and artifact-identity
/// binding to the requested `item_id`. Any failure is `Indeterminate`,
/// never a proof of absence. The id check must live here, not only in
/// `verify_v2`: direct `probe_anchor_item` consumers (the split-1
/// recovery drain) never reach `verify_v2`, and without it a gateway
/// answering `GET /wrong-id` with any other valid same-owner item
/// would report `Present`. Likewise `Present` requires an expected
/// owner: with `None` there is no signature to check, so an anonymous
/// probe stays `Indeterminate` even on id match rather than attesting
/// presence with no cryptographic proof.
fn probe_item(item: DataItem, req: &ProbeRequest) -> (ProbeOutcome, Option<Vec<u8>>) {
    let Some(expected) = req.expected_owner_pk else {
        return (ProbeOutcome::Indeterminate, None);
    };
    let owner_pk = match item.owner_pubkey() {
        Ok(p) => p,
        Err(_) => return (ProbeOutcome::Indeterminate, None),
    };

    if owner_pk != expected {
        return (ProbeOutcome::Indeterminate, None);
    }
    if ans104::verify_data_item(&item, &expected).is_err() {
        return (ProbeOutcome::Indeterminate, None);
    }

    // Artifact-identity check: the derived protocol id must equal the
    // requested `item_id`. A valid signature only proves who signed
    // the response, not that it is the item the caller asked about.
    match item.id() {
        Ok(derived) if derived == req.item_id => {}
        _ => return (ProbeOutcome::Indeterminate, None),
    }

    // Re-encode the verified item for the `Present` consumer so
    // `verify_anchor` does not need a second GET. The bytes handed
    // back are the canonical binary frame (the original Avro tag
    // payload included).
    let bytes = item.to_binary().unwrap_or_default();
    if bytes.is_empty() {
        return (ProbeOutcome::Indeterminate, None);
    }
    (ProbeOutcome::Present, Some(bytes))
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

/// Persisted anchor fields used by the verify path. The HTTP handler
/// fetches the row from `arweave_anchors` and passes the persisted
/// `node_did` in; the v2 path compares it against the DID derived
/// from the verified envelope's owner. Legacy v1 fields are not
/// carried: v1 has no cryptographic proof either way.
#[derive(Debug, Clone)]
pub struct PersistedAnchorFields<'a> {
    pub node_did: &'a str,
}

/// Fetch a persisted anchor from the gateway and verify the
/// envelope. The full path the public verify endpoint takes.
///
/// `expected_owner_pk` is the persisted `node_did` of the anchor,
/// decoded as a 32-byte Ed25519 public key.
///
/// `persisted` carries the row's `node_did` for the v2
/// artifact-identity check and for the legacy-v1 indeterminate reason.
///
/// The verify path accepts the v2 ANS-104 envelope only:
/// parse as `DataItem` (binary frame first, then the JSON
/// projection), verify the Ed25519 signature against
/// `expected_owner_pk`, derive the protocol id via `DataItem::id()`
/// and require equality with `item_id`. A stale or malicious mirror
/// serving a different valid same-owner item is the attack the
/// artifact-id check closes.
///
/// The legacy v1 raw-JSON shape (`schema ==
/// "gitlawb/ref-update/v1"`) has no signature and no item/content
/// binding, so it is `Indeterminate` by construction — never
/// `verified`. A copied set of row fields is forgeable by any
/// gateway.
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
    let (outcome, bytes) = probe_anchor_item(
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
            // Round-3 P2 (reviewer): the probe already consumed
            // the body once. Re-fetching it here is what produced
            // the 500-on-second-failure contract the reviewer
            // called out. Consume the bytes the probe handed back
            // instead of issuing a second GET.
            let bytes = match bytes {
                Some(b) => b,
                None => {
                    return Ok(AnchorVerifyResult {
                        item_id: item_id.to_string(),
                        verified: false,
                        data_payload: None,
                        owner_did: None,
                        error: Some(
                            "the probe returned Present without a buffered body — \
                             this is an internal contract violation"
                                .to_string(),
                        ),
                        outcome: ProbeOutcome::Indeterminate,
                    });
                }
            };

            // The probe hands back the canonical binary frame (or the
            // JSON projection when the gateway served JSON). Prefer the
            // binary envelope: a real signed v2 anchor's payload alone
            // has no signature to verify. A v1 JSON body reaching here
            // is legacy without cryptographic proof — indeterminate.
            if let Ok(item) = DataItem::from_binary(&bytes) {
                return verify_v2(item, item_id, expected_owner_pk, persisted);
            }
            let v: serde_json::Value = match serde_json::from_slice(&bytes) {
                Ok(v) => v,
                Err(_) => {
                    return Ok(AnchorVerifyResult {
                        item_id: item_id.to_string(),
                        verified: false,
                        data_payload: None,
                        owner_did: None,
                        error: Some(
                            "the gateway response is not a verifiable ANS-104 envelope".to_string(),
                        ),
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
            // No second fetch: the probe already spent one outbound
            // request, and a second GET per indeterminate verify is
            // anonymous amplification. Return the classification.
            Ok(AnchorVerifyResult {
                item_id: item_id.to_string(),
                verified: false,
                data_payload: None,
                owner_did: None,
                error: Some(
                    "verification is indeterminate: the gateway response is ambiguous".to_string(),
                ),
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

    // Derive the owner DID from the ITEM's actual owner — not from
    // the expected key — so the comparison below contrasts two
    // different sources (gateway envelope vs persisted row). The
    // signature check above already bound the item's owner to
    // `expected_owner_pk`; this names that signer for the response
    // and refuses a stale row.
    let owner_did = {
        let owner_pk = item
            .owner_pubkey_ed25519()
            .map_err(|e| anyhow!("decoding item owner as Ed25519 for DID derivation: {e}"))?;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&owner_pk)
            .map_err(|e| anyhow!("decoding verifying key: {e}"))?;
        gitlawb_core::did::Did::from_verifying_key(&vk).to_string()
    };

    // Compare the persisted row's `node_did` with the DID derived
    // from the verified item. A mismatch means someone re-keyed and
    // the row is stale; refuse.
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

    Ok(AnchorVerifyResult {
        item_id: item_id.to_string(),
        verified: true,
        data_payload: Some(data_payload),
        owner_did: Some(owner_did),
        error: None,
        outcome: ProbeOutcome::Present,
    })
}

/// v1 verify path. The v1 raw-JSON shape has no signature and no
/// item/content binding: five copied row fields never prove the
/// persisted artifact. Every v1 response is `Indeterminate` — never
/// `verified` — so a stale or hostile gateway cannot make the
/// endpoint attest a ref update that was not proven.
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

    // Even when every copied field matches, v1 has no signature and
    // no binding to the requested `item_id`: a stale or hostile
    // gateway can serve different JSON with the same five public
    // values at the requested URL. Report `Indeterminate`, never
    // `verified`.
    let _ = persisted;
    Ok(AnchorVerifyResult {
        item_id: item_id.to_string(),
        verified: false,
        data_payload: None,
        owner_did: None,
        error: Some(
            "v1 legacy anchor has no cryptographic proof: the gateway served \
             unsigned JSON without an item/content binding, so verification is \
             indeterminate"
                .to_string(),
        ),
        outcome: ProbeOutcome::Indeterminate,
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

        let (outcome, _) = probe_anchor_item(&reqwest::Client::new(), &req_for(server.url())).await;
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

        let (outcome, _) = probe_anchor_item(&reqwest::Client::new(), &req_for(server.url())).await;
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

        let (outcome, _) = probe_anchor_item(&reqwest::Client::new(), &req_for(server.url())).await;
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
        // Bind the request to the served item's real derived id: the
        // probe enforces artifact identity, so a placeholder id would
        // (correctly) classify as `Indeterminate`.
        req.item_id = item.id().unwrap();
        let (outcome, _) = probe_anchor_item(&reqwest::Client::new(), &req).await;
        assert_eq!(outcome, ProbeOutcome::Present);
    }

    /// A valid signed item served under the WRONG requested id is
    /// `Indeterminate`: the signature proves the signer, not that the
    /// gateway served the item the caller asked about. This is the
    /// probe-level artifact-identity check direct `probe_anchor_item`
    /// consumers (the split-1 recovery drain) rely on.
    #[tokio::test]
    async fn probe_2xx_with_valid_signed_item_under_wrong_id_is_indeterminate() {
        let kp = Keypair::generate();
        let pk = kp.verifying_key().to_bytes();
        let mut item =
            DataItem::new_unsigned(&pk, "", "", vec![(b"App-Name", b"gitlawb")], b"{}".to_vec());
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

        // Deliberately request an id that is NOT the served item's
        // derived id. The signature is valid and the owner matches,
        // but the artifact identity does not.
        let mut req = req_for(server.url());
        req.item_id = "this-is-not-the-items-actual-id".to_string();
        req.expected_owner_pk = Some(pk);
        let (outcome, bytes) = probe_anchor_item(&reqwest::Client::new(), &req).await;
        assert_eq!(outcome, ProbeOutcome::Indeterminate);
        assert!(bytes.is_none(), "no bytes on Indeterminate");
    }

    /// Without an expected owner there is no signature to check: even
    /// an id-matching envelope must be `Indeterminate`, never
    /// `Present`. The item below carries a random 64-byte signature
    /// (no valid signature over its content) whose derived id equals
    /// the requested id — before the proof requirement this reported
    /// confirmed presence with no cryptographic proof.
    #[tokio::test]
    async fn probe_2xx_without_expected_owner_is_indeterminate_on_id_match() {
        let kp = Keypair::generate();
        let pk = kp.verifying_key().to_bytes();
        let mut item =
            DataItem::new_unsigned(&pk, "", "", vec![(b"App-Name", b"gitlawb")], b"{}".to_vec());
        item.signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xABu8; 64]);
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

        let req = ProbeRequest {
            item_id,
            expected_owner_pk: None,
            gateway_url: server.url(),
        };
        let (outcome, bytes) = probe_anchor_item(&reqwest::Client::new(), &req).await;
        assert_eq!(outcome, ProbeOutcome::Indeterminate);
        assert!(bytes.is_none(), "no bytes on Indeterminate");
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
        let (outcome, _) = probe_anchor_item(&reqwest::Client::new(), &req).await;
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

        let (outcome, _) = probe_anchor_item(&reqwest::Client::new(), &req_for(server.url())).await;
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

        let (outcome, _) = probe_anchor_item(&reqwest::Client::new(), &req_for(server.url())).await;
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
        let (outcome, _) = probe_anchor_item(&reqwest::Client::new(), &req).await;
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

        let (outcome, _) = probe_anchor_item(&reqwest::Client::new(), &req_for(server.url())).await;
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

        let (outcome, _) = probe_anchor_item(&reqwest::Client::new(), &req_for(server.url())).await;
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

        let (outcome, _) = probe_anchor_item(&reqwest::Client::new(), &req_for(server.url())).await;
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
            // The persisted `node_did` must match the DID derived
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
    /// The probe enforces this before `verify_v2` (whose own check
    /// remains as defense-in-depth), so the reason here is the
    /// probe-level indeterminate classification.
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
            err.contains("indeterminate"),
            "expected indeterminate error on id mismatch, got: {err}"
        );
    }

    /// v1 raw-JSON anchor — even with all five persisted fields
    /// matching — is `Indeterminate`, never `verified`. The v1 shape
    /// has no signature and no item/content binding, so copied fields
    /// never prove the persisted artifact.
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
        assert!(
            !r.verified,
            "v1 is never verified: no signature, no binding"
        );
        assert_eq!(r.outcome, ProbeOutcome::Indeterminate);
        assert!(r.data_payload.is_none(), "no payload on Indeterminate");
        let err = r.error.unwrap();
        assert!(
            err.contains("indeterminate"),
            "expected indeterminate error for legacy v1, got: {err}"
        );
    }

    /// A v1 payload with a single field mismatch is also
    /// `Indeterminate` — for the same reason as a matching one: the
    /// shape carries no proof either way.
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
            err.contains("indeterminate"),
            "expected indeterminate error for legacy v1, got: {err}"
        );
    }

    /// Direct unit pin: `verify_v1` never reports `verified`, even
    /// when every copied field matches. A forged gateway response
    /// with the same five public values must not attest.
    #[test]
    fn verify_v1_never_reports_verified() {
        let node_did = "did:key:z6node";
        let persisted = PersistedAnchorFields { node_did };
        let v = serde_json::json!({
            "schema": "gitlawb/ref-update/v1",
            "repo": "alice/r",
            "ref_name": "refs/heads/main",
            "old_sha": "0000",
            "new_sha": "1111",
            "node_did": node_did,
        });
        let r = verify_v1(v, "v1-item-id", &persisted).unwrap();
        assert!(!r.verified);
        assert_eq!(r.outcome, ProbeOutcome::Indeterminate);
        assert!(r.error.unwrap().contains("no cryptographic proof"));
    }
}
