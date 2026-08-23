//! Arweave permanent anchoring via Bundler (Irys).
//!
//! Every ref-update event (push) is anchored to Arweave through the Bundler
//! network. The anchor payload is a small JSON object containing:
//!
//!   { repo, owner_did, ref_name, old_sha, new_sha, cid, timestamp, node_did }
//!
//! Uploads are signed ANS-104 data items (see [`crate::ans104`]): the node
//! signs the item with its own keypair and embeds the metadata as item tags, so
//! the item is verifiably authored by this node. That signature is NOT payment:
//! the bundler only serves items backed by a funded account, and refuses
//! under-funded uploads with "Not enough balance" — which the push path degrades
//! to a warning, so an unfunded node silently loses every anchor. Funding is
//! therefore mandatory configuration, not optional. Irys bills each upload
//! against a payment token at `/tx/{token}` and reads the funded address from
//! the `x-irys-paid-by` header (see the `@irys/upload` js-sdk,
//! `UploadHeaders.PAID_BY`), so the node sends:
//!   - `GITLAWB_BUNDLER_ACCOUNT` — the funded address/identity, as `x-irys-paid-by`
//!   - `GITLAWB_BUNDLER_TOKEN` — the payment-token slug (e.g. "matic")
//!   - `GITLAWB_BUNDLER_URL` — the node base URL; uploads go to `{url}/tx/{token}`
//!   - `Config::validate()` refuses to start with a bundler URL but no funded
//!     account or payment token.
//!
//! Set `GITLAWB_BUNDLER_URL` (deprecated name: `GITLAWB_IRYS_URL`) to override the default endpoint:
//!   - devnet (faucet-funded):  https://devnet.irys.xyz
//!   - mainnet:                 https://node2.irys.xyz
//!
//! `GITLAWB_ARWEAVE_GATEWAY` has NO default. An anchoring node MUST set it to a
//! gateway on the SAME network as the bundler (devnet → the devnet gateway,
//! mainnet → https://arweave.net): the old implicit arweave.net default paired
//! the gateway to the bundler URL and made /verify fail for devnet
//! transactions, which arweave.net cannot resolve. `Config::validate()` refuses
//! to start with a bundler configured but no explicit gateway; a node that
//! does not anchor may leave the gateway unset (existing recorded anchors stay
//! durable and listable, but carry no presentation URL).
//!
//! Each anchor returns a transaction ID (43-char base64url) that is the
//! content-derived id of the signed data item. The permanent Arweave URL is:
//! <gateway>/<tx_id>
//!
//! Anchors are stored in the `arweave_anchors` table for auditability.
use anyhow::Result;
use base64::Engine as _;
use futures::StreamExt;
use serde::Serialize;
use serde_json::json;
use sha2::Digest;
use std::collections::HashMap;
use std::str::FromStr;
/// Data describing a ref-update event to be anchored.
#[derive(Debug, Clone)]
pub struct RefAnchor {
    pub repo: String,
    pub repo_id: String,
    pub owner_did: String,
    pub ref_name: String,
    pub old_sha: String,
    pub new_sha: String,
    /// IPFS CIDv1 of the commit object, if available
    pub cid: Option<String>,
    pub timestamp: String,
    pub node_did: String,
    /// The full signed [`crate::db::RefCertificate`] for this ref update,
    /// serialized and embedded so a verifier can validate the chain.
    pub certificate: Option<crate::db::RefCertificate>,
}
/// Validate an Arweave transaction / data-item ID: 43-character base64url.
/// This is the expected wire format for both a bundler's `{"id": ...}` response
/// and the id under which a gateway resolves a data item. The durable job and
/// the public `/verify` endpoint share this boundary so a malformed id is
/// rejected the same way everywhere.
pub(crate) fn is_valid_tx_id(tx_id: &str) -> bool {
    if tx_id.len() != 43 {
        return false;
    }
    tx_id
        .bytes()
        .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
}

/// Classified outcome of a bundler upload, so the durable job can decide
/// whether a retry may safely pay for another upload (#224 review):
///
/// - [`UploadOutcome::Accepted`] — the provider returned a well-formed
///   transaction id; the item is permanently accepted.
/// - [`UploadOutcome::Rejected`] — the provider returned a definitive
///   non-acceptance (HTTP error body). The item was NOT accepted, so a retry
///   may re-upload safely.
/// - [`UploadOutcome::Uncertain`] — the request failed before a verdict
///   (connection drop, or a success response that did not carry a valid id).
///   The item MAY have been accepted; a retry must reconcile via the gateway
///   probe before issuing another paid request, never re-upload blindly.
#[derive(Debug)]
pub enum UploadOutcome {
    Accepted { tx_id: String },
    Rejected { message: String },
    Uncertain { message: String },
}

/// Build the signed ANS-104 data item for a ref-update anchor. The metadata is
/// embedded as tags inside the item (where the bundler verifies them against
/// the signature); nothing is passed out-of-band.
pub(crate) fn build_ref_anchor_item(
    anchor: &RefAnchor,
    node_keypair: &gitlawb_core::identity::Keypair,
) -> Result<Vec<u8>> {
    let mut payload = json!({
        "schema": "gitlawb/ref-update/v1",
        "repo": anchor.repo,
        "repo_id": anchor.repo_id,
        "owner_did": anchor.owner_did,
        "ref_name": anchor.ref_name,
        "old_sha": anchor.old_sha,
        "new_sha": anchor.new_sha,
        "cid": anchor.cid,
        "timestamp": anchor.timestamp,
        "node_did": anchor.node_did,
        "network": "alpha",
    });
    // Embed the signed certificate so verifiers can validate the chain.
    if let Some(cert) = &anchor.certificate {
        payload["certificate"] = serde_json::to_value(cert)?;
    }
    let body = serde_json::to_vec(&payload)?;
    let tags: Vec<(String, String)> = [
        "App-Name:gitlawb".to_string(),
        "Schema:gitlawb/ref-update/v1".to_string(),
        format!("Repo:{}", sanitize_tag(&anchor.repo)),
        format!("Ref:{}", sanitize_tag(&anchor.ref_name)),
        format!("SHA:{}", &anchor.new_sha[..anchor.new_sha.len().min(16)]),
        format!("Node-DID:{}", sanitize_tag(&anchor.node_did)),
    ]
    .iter()
    .map(|pair| {
        let (name, value) = pair.split_once(':').unwrap_or((pair.as_str(), ""));
        (name.to_string(), value.to_string())
    })
    .collect();
    crate::ans104::build_signed_data_item(node_keypair, &tag_refs(&tags), &body)
}

/// Upload a signed ANS-104 data item to the bundler and classify the outcome.
/// The caller supplies the already-signed item so it can persist the item's
/// deterministic id ([`crate::ans104::data_item_id`]) BEFORE the request is
/// sent — that is the durable request identity a crash-recovery probes.
///
/// `expected_id` binds the provider acknowledgement to the exact request
/// identity: a success response whose `id` differs from the id the node
/// derived locally (a misrouted, faulty, or compromised bundler substituting
/// a different well-formed item) is classified `Uncertain`, never `Accepted`.
/// The recorded identity must be the item the node signed and would re-upload
/// and recover by identity (R2 #224 review).
pub async fn upload_ref_anchor_item(
    client: &reqwest::Client,
    bundler_url: &str,
    bundler_account: &str,
    bundler_token: &str,
    item: &[u8],
    expected_id: &str,
) -> Result<UploadOutcome> {
    // Irys upload target: {bundler_url}/tx/{token}. Built structurally so a
    // query on the base URL is preserved and a fragment is rejected outright.
    let url = bundler_upload_url(bundler_url, bundler_token)?;
    let display_url = crate::server::mask_credential_url(&url);
    let resp = match client
        .post(&url)
        .header("Content-Type", "application/octet-stream")
        .header("x-irys-paid-by", bundler_account)
        .body(item.to_vec())
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            // The request did not reach a verdict: the item MAY have been
            // accepted. The message is already redacted/masked.
            return Ok(UploadOutcome::Uncertain {
                message: remote_send_error("Bundler upload failed", &e, &url, &display_url)
                    .to_string(),
            });
        }
    };
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let message = remote_response_error(
            "Bundler upload",
            &status,
            &body,
            &url,
            &display_url,
            &[bundler_account, bundler_token],
        )
        .to_string();
        return Ok(UploadOutcome::Rejected { message });
    }
    let json: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            // Success status but no parseable body: outcome unknown. Treating a
            // malformed success as `Accepted` would let a misbehaving bundler
            // turn a required anchor into a silent no-op; treating it as
            // `Rejected` would risk a second paid artifact if the item landed.
            return Ok(UploadOutcome::Uncertain {
                message: format!("failed to parse Bundler response: {e}"),
            });
        }
    };
    // Bundler response: {"id": "<data_item_id>", "timestamp": ..., "version": ...}
    // The id must be a well-formed non-empty Arweave id; an empty/malformed
    // success response is an Uncertain outcome, not success (#224 review).
    let tx_id = match json["id"].as_str() {
        Some(id) if is_valid_tx_id(id) => id.to_string(),
        _ => {
            return Ok(UploadOutcome::Uncertain {
                message: format!(
                    "Bundler returned a malformed transaction id in its success response: {}",
                    truncate_for_error(&json.to_string(), 512)
                ),
            });
        }
    };
    // Bind the provider acknowledgement to the exact request identity. A
    // well-formed id that is NOT the id the node signed and persisted means
    // the bundler returned a different item than the one sent (misrouted,
    // faulty, or compromised): accepting it would record an anchor whose
    // signature/identity the node cannot reproduce, verify, or recover.
    // Classify as Uncertain (nonterminal) so recovery probes the item the node
    // actually sent and re-uploads it if absent, rather than recording a
    // foreign id as the durable anchor (R2 #224 review).
    if tx_id != expected_id {
        return Ok(UploadOutcome::Uncertain {
            message: format!(
                "Bundler reported success for a transaction id that does not match the \
                 item sent: expected {expected_id}, got {tx_id} — treating as unknown \
                 outcome so the durable identity of the anchor is not replaced"
            ),
        });
    }
    Ok(UploadOutcome::Accepted { tx_id })
}

/// Anchor a ref-update to Arweave via Irys.
///
/// The payload is uploaded as a signed ANS-104 data item: `node_keypair` signs
/// the item and the indexing metadata (App-Name, Schema, Repo, Ref, SHA,
/// Node-DID) is embedded as data-item tags inside the signed item — never in a
/// request header. Returns the Irys/Arweave transaction ID on success.
/// Returns `Ok("")` if `bundler_url` is empty (anchoring disabled).
///
/// The durable post-receive job does not call this directly: it drives
/// [`build_ref_anchor_item`] + [`upload_ref_anchor_item`] so it can persist the
/// item id before the request and classify the outcome. This thin wrapper keeps
/// the manifest/tail call sites and tests on a `Result<String>` contract.
#[cfg(test)]
pub async fn anchor_ref_update(
    client: &reqwest::Client,
    bundler_url: &str,
    bundler_account: &str,
    bundler_token: &str,
    anchor: &RefAnchor,
    node_keypair: &gitlawb_core::identity::Keypair,
) -> Result<String> {
    if bundler_url.is_empty() {
        return Ok(String::new());
    }
    let item = build_ref_anchor_item(anchor, node_keypair)?;
    let expected_id = crate::ans104::data_item_id(&item);
    match upload_ref_anchor_item(
        client,
        bundler_url,
        bundler_account,
        bundler_token,
        &item,
        &expected_id,
    )
    .await?
    {
        UploadOutcome::Accepted { tx_id } => {
            tracing::info!(
                repo = %anchor.repo,
                ref_name = %anchor.ref_name,
                new_sha = %anchor.new_sha,
                tx_id = %tx_id,
                bundler_account = %bundler_account,
                bundler_token = %bundler_token,
                "anchored ref update to Arweave via bundler"
            );
            Ok(tx_id)
        }
        UploadOutcome::Rejected { message } => Err(anyhow::anyhow!(message)),
        UploadOutcome::Uncertain { message } => Err(anyhow::anyhow!(message)),
    }
}
/// A per-push manifest of the blobs encrypted this push (Option B3). The
/// `blobs` slice is `(oid, cid)` tuples. Anchored directly to Arweave as its JSON
/// body so the discovery index survives total node loss. Recipient identities are
/// never part of the manifest.
pub struct EncryptedManifest<'a> {
    pub repo: &'a str,
    pub owner_did: &'a str,
    pub node_did: &'a str,
    pub timestamp: &'a str,
    pub blobs: &'a [(String, String)],
}
/// Anchor a per-push encrypted-blob manifest to Arweave via Irys. The manifest
/// JSON body is the payload (not a CID pointer to IPFS), so the index is
/// permanent and self-contained. Recipient identities are deliberately omitted:
/// the anchor is permanent and public, and the v2 envelopes no longer expose
/// recipients, so the reader set must not be written to Arweave either.
///
/// The manifest is uploaded as a signed ANS-104 data item (same scheme as
/// `anchor_ref_update`); the discovery tags are embedded inside the item.
///
/// Returns the Arweave transaction ID, or `Ok("")` when `bundler_url` is empty
/// (anchoring disabled) or there are no blobs to anchor.
pub async fn anchor_encrypted_manifest(
    client: &reqwest::Client,
    bundler_url: &str,
    bundler_account: &str,
    bundler_token: &str,
    manifest: &EncryptedManifest<'_>,
    node_keypair: &gitlawb_core::identity::Keypair,
) -> Result<String> {
    if bundler_url.is_empty() || manifest.blobs.is_empty() {
        return Ok(String::new());
    }
    let blobs_json: Vec<serde_json::Value> = manifest
        .blobs
        .iter()
        .map(|(oid, cid)| manifest_blob_json(oid, cid))
        .collect();
    let payload = json!({
        "schema": "gitlawb/encrypted-manifest/v1",
        "repo": manifest.repo,
        "owner_did": manifest.owner_did,
        "node_did": manifest.node_did,
        "timestamp": manifest.timestamp,
        "blobs": blobs_json,
    });
    let body = serde_json::to_vec(&payload)?;
    let tags: Vec<(String, String)> = [
        "App-Name:gitlawb".to_string(),
        "Schema:gitlawb/encrypted-manifest/v1".to_string(),
        format!("Repo:{}", sanitize_tag(manifest.repo)),
        format!("Owner-DID:{}", sanitize_tag(manifest.owner_did)),
        format!("Node-DID:{}", sanitize_tag(manifest.node_did)),
    ]
    .iter()
    .map(|pair| {
        let (name, value) = pair.split_once(':').unwrap_or((pair.as_str(), ""));
        (name.to_string(), value.to_string())
    })
    .collect();
    let data_item = crate::ans104::build_signed_data_item(node_keypair, &tag_refs(&tags), &body)?;
    // Irys upload target: {bundler_url}/tx/{token}. Built structurally so a
    // query on the base URL is preserved and a fragment is rejected outright.
    let url = bundler_upload_url(bundler_url, bundler_token)?;
    let display_url = crate::server::mask_credential_url(&url);
    let resp = client
        .post(&url)
        .header("Content-Type", "application/octet-stream")
        .header("x-irys-paid-by", bundler_account)
        .body(data_item)
        .send()
        .await
        .map_err(|e| remote_send_error("Bundler upload failed", &e, &url, &display_url))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(remote_response_error(
            "Bundler manifest upload",
            &status,
            &body,
            &url,
            &display_url,
            &[bundler_account, bundler_token],
        ));
    }
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("failed to parse Bundler response: {e}"))?;
    // Bundler response: {"id": "<data_item_id>", "timestamp": ..., "version": ...}
    // A success without a well-formed, non-empty id must be an error (never a
    // silent no-op), so a malformed success cannot fake an anchor (#224 review).
    let tx_id = match json["id"].as_str() {
        Some(id) if is_valid_tx_id(id) => id.to_string(),
        _ => {
            return Err(anyhow::anyhow!(
                "Bundler returned a malformed transaction id in its success response: {}",
                truncate_for_error(&json.to_string(), 512)
            ));
        }
    };
    tracing::info!(
        repo = %manifest.repo,
        tx_id = %tx_id,
        blobs = manifest.blobs.len(),
        bundler_account = %bundler_account,
        bundler_token = %bundler_token,
        "anchored encrypted manifest to Arweave via bundler"
    );
    Ok(tx_id)
}
/// Serialize one blob for the Arweave manifest. Recipient identities are
/// intentionally absent so the permanent public anchor never records who can
/// read a blob.
fn manifest_blob_json(oid: &str, cid: &str) -> serde_json::Value {
    json!({ "oid": oid, "cid": cid })
}
/// Borrow `(name, value)` string slices from owned tag pairs for
/// [`crate::ans104::build_signed_data_item`].
fn tag_refs(tags: &[(String, String)]) -> Vec<(&str, &str)> {
    tags.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect()
}
/// Strip characters that are invalid in bundler/Arweave tag values.
fn sanitize_tag(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':'))
        .take(128)
        .collect()
}
/// Arweave URL for a given transaction ID, resolved through a configurable gateway.
#[allow(dead_code)]
pub fn arweave_url(gateway: &str, tx_id: &str) -> String {
    format!("{}/{}", gateway.trim_end_matches('/'), tx_id)
}
/// Structurally join a base URL onto a path (`/tx/{token}` for uploads, a tx_id
/// for gateway reads), preserving the base's query string and rejecting
/// fragments. String concatenation would silently drop or garble a
/// query/fragment form and could smuggle credentials into the request target;
/// joining through `Url` keeps every part where it belongs. The returned string
/// is also the exact request target, so tests can assert it verbatim.
fn join_url_path(base: &str, segments: &[&str], what: &str) -> Result<String> {
    let mut url = reqwest::Url::parse(base).map_err(|e| anyhow::anyhow!("invalid {what}: {e}"))?;
    if url.fragment().is_some() {
        return Err(anyhow::anyhow!(
            "{what} must not contain a URL fragment (a fragment is never sent to the \
             bundler/gateway and would silently change the request)"
        ));
    }
    let query = url.query().map(str::to_string);
    {
        let mut segments_mut = url
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("{what} must be a hierarchical URL"))?;
        segments_mut.pop_if_empty();
        for seg in segments {
            segments_mut.push(seg);
        }
    }
    if let Some(q) = query {
        url.set_query(Some(&q));
    }
    Ok(url.to_string())
}
/// Irys upload request target: `{bundler_url}/tx/{token}`, structurally joined.
fn bundler_upload_url(bundler_url: &str, token: &str) -> Result<String> {
    join_url_path(bundler_url, &["tx", token], "bundler URL")
}
/// Gateway request target for a transaction ID: `{gateway_url}/{tx_id}`.
fn gateway_tx_url(gateway_url: &str, tx_id: &str) -> Result<String> {
    join_url_path(gateway_url, &[tx_id], "gateway URL")
}
/// Whether a data item with the given id is resolvable at the configured
/// gateway (`GET {gateway}/{id}`). This is the reconciliation probe a durable
/// job uses to decide whether a crashed upload actually landed before issuing
/// a second paid request (#224 review): present → record the item id and skip
/// the upload; absent → the earlier upload did not land, re-upload is safe;
/// any other failure to reach a verdict → the caller must fail closed (no
/// upload). A 404/400/410 means the item is absent; a missing gateway means
/// the probe cannot run at all and is an error, never a silent "absent".
pub(crate) async fn anchor_item_present(
    client: &reqwest::Client,
    gateway_url: &str,
    item_id: &str,
) -> Result<bool> {
    if gateway_url.trim().is_empty() {
        return Err(anyhow::anyhow!(
            "no GITLAWB_ARWEAVE_GATEWAY configured to reconcile a possibly-uploaded anchor"
        ));
    }
    let url = gateway_tx_url(gateway_url, item_id)?;
    let display_url = crate::server::mask_credential_url(&url);
    let resp =
        client.get(&url).send().await.map_err(|e| {
            remote_send_error("Arweave gateway probe failed", &e, &url, &display_url)
        })?;
    if resp.status().is_success() {
        // A 2xx means the gateway found *something*, but it might be an error
        // page or a different item. Verify the returned item's id matches what
        // we asked for — a misconfigured gateway/proxy returning 200 for any
        // id would cause us to record a phantom anchor. Fail closed by treating
        // a non-matching 2xx as "cannot determine" rather than "present".
        let body = resp
            .bytes()
            .await
            .map_err(|e| anyhow::anyhow!("failed to read gateway probe response: {e}"))?;
        // The response is an ANS-104 data item. Verify its id by deriving it
        // from the signature region (bytes 2..66) per ANS-104 spec.
        let body_id = crate::ans104::data_item_id(&body);
        if body_id == item_id {
            return Ok(true);
        }
        // 2xx but id mismatch: the gateway resolved a DIFFERENT item (or an
        // error page). We cannot conclude the requested item landed, and the
        // caller must fail closed rather than record a phantom anchor — the
        // durable recovery path re-probes / fails the job instead.
        return Err(anyhow::anyhow!(
            "gateway probe returned 2xx but item id mismatch: expected {}, got {}",
            item_id,
            body_id
        ));
    }
    match resp.status() {
        reqwest::StatusCode::NOT_FOUND
        | reqwest::StatusCode::BAD_REQUEST
        | reqwest::StatusCode::GONE => Ok(false),
        other => Err(anyhow::anyhow!(
            "Arweave gateway probe returned {other} for {display_url}"
        )),
    }
}
/// Cap a value for error messages/logs so a hostile or misbehaving endpoint
/// cannot drive unbounded allocations or output through an error string.
fn truncate_for_error(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut out = s.chars().take(max).collect::<String>();
    out.push_str("…(truncated)");
    out
}
/// Central redaction boundary for every error that comes from a remote
/// endpoint the node talked to. reqwest embeds the request URL verbatim in its
/// error text, and a remote server can reflect anything the node sent — the
/// funded-account identity (`x-irys-paid-by`), the payment token riding in the
/// URL path, and any credentials in the base URL — back through an error or a
/// response body. Routing every such error through this module guarantees a raw
/// URL or a credential-bearing remote body never reaches a log (`err = %e`) or
/// a caller.
///
/// `detail` is any string that may contain the raw URL or the secrets; the raw
/// URL is swapped for `display_url` (its credential-masked form) and each
/// non-empty secret is replaced with `<redacted>`.
fn redact_remote_detail(detail: &str, url: &str, display_url: &str, secrets: &[&str]) -> String {
    let mut out = detail.replace(url, display_url);
    for secret in secrets {
        if !secret.is_empty() {
            out = out.replace(secret, "<redacted>");
        }
    }
    out
}
/// Build the error for a remote request that failed before a response body was
/// available (connection refused, TLS failure, dropped stream). The reqwest
/// error text may embed the raw request URL, so it is masked and any secrets
/// scrubbed before the error is constructed.
fn remote_send_error(
    prefix: &str,
    err: &reqwest::Error,
    url: &str,
    display_url: &str,
) -> anyhow::Error {
    let detail = redact_remote_detail(&err.to_string(), url, display_url, &[]);
    anyhow::anyhow!("{prefix}: {detail}")
}
/// Build the error for a non-success response whose body the remote may have
/// populated by reflecting the request (including credential-bearing pieces).
/// The body is truncated, its raw URL swapped for the masked form, and the
/// secrets the node actually sent scrubbed — so a hostile bundler/gateway
/// cannot echo the operator's funded-account identity or payment token into
/// logs or an error surfaced to a caller.
fn remote_response_error(
    prefix: &str,
    status: &reqwest::StatusCode,
    body: &str,
    url: &str,
    display_url: &str,
    secrets: &[&str],
) -> anyhow::Error {
    let body = truncate_for_error(&redact_remote_detail(body, url, display_url, secrets), 512);
    anyhow::anyhow!("{prefix} returned {status}: {body}")
}
/// Result of verifying an Arweave anchor against the stored certificate chain.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyResult {
    pub valid: bool,
    pub anchor: serde_json::Value,
    pub certificate: Option<crate::db::RefCertificate>,
    pub errors: Vec<String>,
}
/// Fetch an anchor from Arweave, extract the embedded certificate, and verify
/// the full chain: certificate signature, prev hash linkage, and pusher signature.
pub async fn verify_anchor(
    client: &reqwest::Client,
    gateway_url: &str,
    tx_id: &str,
    db: &crate::db::Db,
    node_did: &str,
) -> Result<VerifyResult> {
    // Fetch the data item from the Arweave gateway's data path.
    // Gateways serve data at /{tx_id}, not /v1/tx/{id} (which is the bundler API).
    // Built structurally: a query on the gateway config is preserved, and a
    // fragment is rejected (it would never be sent to the gateway).
    let url = match gateway_tx_url(gateway_url, tx_id) {
        Ok(u) => u,
        Err(e) => {
            return Ok(VerifyResult {
                valid: false,
                anchor: serde_json::Value::Null,
                certificate: None,
                errors: vec![e.to_string()],
            });
        }
    };
    // Public-facing display form of the same URL: reqwest's connection error
    // embeds the request URL verbatim, so if the gateway config carries
    // credentials the error text would otherwise leak them into VerifyResult.
    let display_url = crate::server::mask_credential_url(&url);
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            let safe_err =
                remote_send_error("Arweave gateway connection failed", &e, &url, &display_url)
                    .to_string();
            tracing::warn!("{safe_err}");
            return Ok(VerifyResult {
                valid: false,
                anchor: serde_json::Value::Null,
                certificate: None,
                errors: vec![safe_err],
            });
        }
    };
    if !resp.status().is_success() {
        return Ok(VerifyResult {
            valid: false,
            anchor: serde_json::Value::Null,
            certificate: None,
            errors: vec![format!("Arweave gateway returned {}", resp.status())],
        });
    }
    // Stream the response body with a running 1 MiB cap so a chunked or
    // header-omitting gateway cannot drive multi-hundred-MB allocations.
    let mut body_bytes = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let data = match chunk {
            Ok(d) => d,
            Err(e) => {
                // Mid-stream transport errors carry the same risk as connection
                // errors: reqwest can embed the raw request URL in the error
                // text, so it is masked through the same boundary as above.
                let safe_err =
                    remote_send_error("failed to read response body", &e, &url, &display_url)
                        .to_string();
                tracing::warn!("{safe_err}");
                return Ok(VerifyResult {
                    valid: false,
                    anchor: serde_json::Value::Null,
                    certificate: None,
                    errors: vec![safe_err],
                });
            }
        };
        if body_bytes.len() + data.len() > 1_048_576 {
            return Ok(VerifyResult {
                valid: false,
                anchor: serde_json::Value::Null,
                certificate: None,
                errors: vec!["response body exceeds 1 MiB limit".to_string()],
            });
        }
        body_bytes.extend_from_slice(&data);
    }
    // Parse the payload — could be JSON or raw bytes depending on gateway.
    // Non-JSON responses are handled as an invalid result rather than an error.
    let anchor: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            return Ok(VerifyResult {
                valid: false,
                anchor: serde_json::Value::Null,
                certificate: None,
                errors: vec![format!("anchor payload is not valid JSON: {e}")],
            });
        }
    };
    let cert_value = anchor.get("certificate");
    let cert: Option<crate::db::RefCertificate> = match cert_value {
        Some(v) => serde_json::from_value(v.clone()).ok(),
        None => None,
    };
    let mut errors = Vec::new();
    if let Some(ref c) = cert {
        // 0a. Verify the certificate was issued by this node.
        if c.node_did != node_did {
            errors.push(format!(
                "certificate node_did ({}) does not match this node ({})",
                c.node_did, node_did
            ));
        }
        // 0b. Cross-check the outer anchor fields against the embedded certificate.
        //    A valid anchor must commit to the same identities and ref state.
        //    The outer repo_id (UUID) is compared against the cert's repo_id (UUID)
        //    to avoid comparing a human-readable slug against a UUID.
        let outer_repo_id = anchor.get("repo_id").and_then(|v| v.as_str());
        let outer_ref = anchor.get("ref_name").and_then(|v| v.as_str());
        let outer_old = anchor.get("old_sha").and_then(|v| v.as_str());
        let outer_new = anchor.get("new_sha").and_then(|v| v.as_str());
        let outer_node = anchor.get("node_did").and_then(|v| v.as_str());
        if outer_repo_id.is_none() {
            errors.push("anchor payload is missing top-level 'repo_id'".to_string());
        } else if outer_repo_id != Some(&c.repo_id) {
            errors.push(format!(
                "anchor outer repo_id ({}) does not match certificate repo_id ({})",
                outer_repo_id.unwrap_or(""),
                c.repo_id
            ));
        }
        if outer_ref.is_none() {
            errors.push("anchor payload is missing top-level 'ref_name'".to_string());
        } else if outer_ref != Some(&c.ref_name) {
            errors.push(format!(
                "anchor outer ref_name ({}) does not match certificate ref_name ({})",
                outer_ref.unwrap_or(""),
                c.ref_name
            ));
        }
        // Fail closed: old_sha, new_sha, and node_did are mandatory in the
        // outer anchor when a certificate is embedded.  A forger who omits
        // them must not pass verification.
        if outer_old.is_none() {
            errors.push("anchor payload is missing top-level 'old_sha'".to_string());
        } else if outer_old != Some(&c.old_sha) {
            errors.push(format!(
                "anchor outer old_sha ({}) does not match certificate old_sha ({})",
                outer_old.unwrap_or(""),
                c.old_sha
            ));
        }
        if outer_new.is_none() {
            errors.push("anchor payload is missing top-level 'new_sha'".to_string());
        } else if outer_new != Some(&c.new_sha) {
            errors.push(format!(
                "anchor outer new_sha ({}) does not match certificate new_sha ({})",
                outer_new.unwrap_or(""),
                c.new_sha
            ));
        }
        if outer_node.is_none() {
            errors.push("anchor payload is missing top-level 'node_did'".to_string());
        } else if outer_node != Some(&c.node_did) {
            errors.push(format!(
                "anchor outer node_did ({}) does not match certificate node_did ({})",
                outer_node.unwrap_or(""),
                c.node_did
            ));
        }
        // 0c. Corroborate outer repo slug and owner_did against the node's own
        //    record for the certificate's repo_id.  The certificate signs the
        //    repo_id UUID but not the human-readable slug or owner DID, so a
        //    forger could otherwise echo attacker-chosen identities next to a
        //    valid:true verdict.  When the node hosts the repo, the outer
        //    identity fields must agree with what it recorded.
        let outer_repo = anchor.get("repo").and_then(|v| v.as_str());
        let outer_owner = anchor.get("owner_did").and_then(|v| v.as_str());
        // Fail closed: when the outer identity fields are present, a lookup
        // that cannot complete (repo missing or DB error) must not silently
        // skip corroboration. Otherwise a forger could echo attacker-chosen
        // identities next to a valid:true verdict simply because the node has
        // no record — or the DB is down — to check them against.
        let outer_identity_present = outer_repo.is_some() || outer_owner.is_some();
        match db.get_repo_by_id(&c.repo_id).await {
            Ok(Some(record)) => {
                let expected_repo = format!(
                    "{}/{}",
                    crate::db::normalize_owner_key(&record.owner_did),
                    record.name
                );
                if let Some(outer_repo) = outer_repo {
                    if outer_repo != expected_repo {
                        errors.push(format!(
                            "anchor outer repo ({outer_repo}) does not match recorded repo ({expected_repo})"
                        ));
                    }
                }
                if let Some(outer_owner) = outer_owner {
                    if outer_owner != record.owner_did {
                        errors.push(format!(
                            "anchor outer owner_did ({outer_owner}) does not match recorded owner_did ({})",
                            record.owner_did
                        ));
                    }
                }
            }
            Ok(None) => {
                if outer_identity_present {
                    errors.push(format!(
                        "anchor outer repo/owner_did present but repo_id {} not found in node database — outer identity cannot be corroborated",
                        c.repo_id
                    ));
                } else {
                    tracing::warn!(
                        repo_id = %c.repo_id,
                        "cannot corroborate anchor repo/owner_did — repo_id not found in node database"
                    );
                }
            }
            Err(e) => {
                // The raw DB error never reaches the caller (it can embed
                // connection details); it is logged server-side only, and the
                // deny is stated without it, like the not-found branch above.
                tracing::warn!("repo lookup failed for {}: {e}", c.repo_id);
                if outer_identity_present {
                    errors.push(format!(
                        "repo lookup failed for {} — outer repo/owner_did cannot be corroborated",
                        c.repo_id
                    ));
                }
            }
        }
        // 1. Verify node signature on the certificate payload.
        //    Version 2 certificates use a 14-field payload that includes an
        //    explicit `version` field.  Post-PR but pre-version-2 certificates
        //    use a 13-field payload (no version).  Pre-PR certificates used a
        //    7-field payload (repo_id, ref, old, new, pusher, node, ts) with
        //    NULL proof fields.  Try each in order; the version field is the
        //    authoritative discriminator — nullable-field inference is not.
        let proof_fields_null = c.pusher_sig.is_none()
            && c.signature_input.is_none()
            && c.content_digest.is_none()
            && c.request_path.is_none();
        // Resolve node DID to public key
        let node_did = match gitlawb_core::did::Did::from_str(&c.node_did) {
            Ok(did) => did,
            Err(e) => {
                errors.push(format!("invalid node DID: {e}"));
                return Ok(VerifyResult {
                    valid: false,
                    anchor,
                    certificate: cert,
                    errors,
                });
            }
        };
        let verifying_key = match node_did.to_verifying_key() {
            Ok(vk) => vk,
            Err(e) => {
                errors.push(format!("unresolvable node DID: {e}"));
                return Ok(VerifyResult {
                    valid: false,
                    anchor,
                    certificate: cert,
                    errors,
                });
            }
        };
        let sig_array: [u8; 64] =
            match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&c.signature) {
                Ok(bytes) => match bytes.as_slice().try_into() {
                    Ok(a) => a,
                    Err(_) => {
                        errors.push("certificate signature is not 64 bytes".to_string());
                        return Ok(VerifyResult {
                            valid: false,
                            anchor,
                            certificate: cert,
                            errors,
                        });
                    }
                },
                Err(_) => {
                    errors.push("certificate signature is not valid base64".to_string());
                    return Ok(VerifyResult {
                        valid: false,
                        anchor,
                        certificate: cert,
                        errors,
                    });
                }
            };
        // Try 14-field payload first (version 2 — includes `version` field).
        let payload_14 = serde_json::json!({
            "repo_id":    c.repo_id,
            "ref":        c.ref_name,
            "old":        c.old_sha,
            "new":        c.new_sha,
            "pusher":     c.pusher_did,
            "node":       c.node_did,
            "ts":         c.issued_at,
            "version":    crate::cert::CERT_PAYLOAD_VERSION,
            "seq":              c.seq,
            "prev":             c.prev,
            "pusher_sig":       c.pusher_sig,
            "signature_input":  c.signature_input,
            "content_digest":   c.content_digest,
            "request_path":     c.request_path,
        });
        let payload_bytes_14 = serde_json::to_vec(&payload_14)?;
        let sig_valid_14 =
            gitlawb_core::identity::verify(&verifying_key, &payload_bytes_14, &sig_array);
        let mut legacy_7_field_verified = false;
        if sig_valid_14.is_ok() {
            // Version-2 signature verified — nothing more to try.
        } else {
            // Fall back to 13-field payload (post-PR, pre-version-2).
            let payload_13 = serde_json::json!({
                "repo_id":    c.repo_id,
                "ref":        c.ref_name,
                "old":        c.old_sha,
                "new":        c.new_sha,
                "pusher":     c.pusher_did,
                "node":       c.node_did,
                "ts":         c.issued_at,
                "seq":              c.seq,
                "prev":             c.prev,
                "pusher_sig":       c.pusher_sig,
                "signature_input":  c.signature_input,
                "content_digest":   c.content_digest,
                "request_path":     c.request_path,
            });
            let payload_bytes_13 = serde_json::to_vec(&payload_13)?;
            let sig_valid_13 =
                gitlawb_core::identity::verify(&verifying_key, &payload_bytes_13, &sig_array);
            if sig_valid_13.is_ok() {
                // 13-field signature verified.
            } else if proof_fields_null {
                // Fall back to 7-field payload for pre-PR certificates.
                let payload_7 = serde_json::json!({
                    "repo_id":    c.repo_id,
                    "ref":        c.ref_name,
                    "old":        c.old_sha,
                    "new":        c.new_sha,
                    "pusher":     c.pusher_did,
                    "node":       c.node_did,
                    "ts":         c.issued_at,
                });
                let payload_bytes_7 = serde_json::to_vec(&payload_7)?;
                if gitlawb_core::identity::verify(&verifying_key, &payload_bytes_7, &sig_array)
                    .is_ok()
                {
                    legacy_7_field_verified = true;
                } else {
                    errors.push("certificate signature verification failed (7-field)".to_string());
                }
            } else {
                errors.push(
                    "certificate signature verification failed: no recognized payload version matched"
                        .to_string(),
                );
            }
        }
        // 1b. Corroborate chain position for legacy certificates.
        //    The 7-field fallback covers only repo_id, ref, old, new, pusher,
        //    node, ts.  seq and prev are NOT covered on that path, so a tampered
        //    legacy cert could otherwise pass with a blanket valid: true.  Look
        //    up the node's own stored row by the FIELDS THE SIGNATURE COVERS
        //    (repo_id, ref_name, old_sha, new_sha, issued_at) — never by `id`,
        //    which appears in no signed payload and would let a forger choose
        //    which stored row their seq/prev claims are measured against — and
        //    require seq/prev agreement.
        if legacy_7_field_verified {
            match db
                .get_cert_by_signed_tuple(
                    &c.repo_id,
                    &c.ref_name,
                    &c.old_sha,
                    &c.new_sha,
                    &c.issued_at,
                )
                .await
            {
                Ok(Some(stored)) => {
                    if stored.seq != c.seq {
                        errors.push(format!(
                            "certificate seq {} disagrees with stored seq {}",
                            c.seq, stored.seq
                        ));
                    }
                    if stored.prev != c.prev {
                        errors.push(format!(
                            "certificate prev {} disagrees with stored prev {}",
                            c.prev, stored.prev
                        ));
                    }
                }
                Ok(None) => {
                    errors.push(
                        "no stored certificate matches the signed (repo_id, ref_name, old_sha, new_sha, ts) — cannot corroborate legacy chain position"
                            .to_string(),
                    );
                }
                Err(e) => {
                    tracing::warn!("certificate lookup failed for {}: {e}", c.id);
                    errors.push(format!(
                        "error looking up certificate {} in node database",
                        c.id
                    ));
                }
            }
        }
        // 2. Verify prev hash linkage against the predecessor at seq - 1.
        //    The prev hash covers the 7-field payload (repo_id, ref, old, new,
        //    pusher, node, ts) — seq, prev, and proof fields are excluded so
        //    that the hash chain is stable across certificate versions.
        //    Fail closed: a missing declared predecessor is treated as invalid.
        //
        //    Legacy certificates backfilled by the v13 migration have the
        //    default all-zeros prev even when seq > 1 because the migration
        //    only assigns sequence numbers without computing prev hashes.
        //    For these rows the chain link is unknown — skip the check and
        //    warn rather than reporting a valid signature as invalid.
        if c.seq > 1 {
            if c.prev == "0000000000000000000000000000000000000000000000000000000000000000" {
                // Prevent legacy false-positives: the migration that assigned
                // seq never backfilled prev, so every pre-upgrade cert after
                // the first in a repo has default all-zeros.
                tracing::warn!(
                    "legacy certificate seq {} has default prev — chain continuity not verifiable, skipping prev check",
                    c.seq
                );
            } else {
                match db.get_cert_by_seq(&c.repo_id, c.seq - 1).await {
                    Ok(Some(pred)) => {
                        let prev_payload = serde_json::json!({
                            "repo_id":    pred.repo_id,
                            "ref":        pred.ref_name,
                            "old":        pred.old_sha,
                            "new":        pred.new_sha,
                            "pusher":     pred.pusher_did,
                            "node":       pred.node_did,
                            "ts":         pred.issued_at,
                        });
                        let prev_bytes = serde_json::to_vec(&prev_payload)?;
                        let expected_prev = hex::encode(sha2::Sha256::digest(&prev_bytes));
                        if c.prev != expected_prev {
                            errors.push(format!(
                                "prev hash mismatch: claimed {} expected {}",
                                c.prev, expected_prev
                            ));
                        }
                    }
                    Ok(None) => {
                        errors.push(format!(
                            "predecessor cert seq {} not found for repo {}",
                            c.seq - 1,
                            c.repo_id
                        ));
                    }
                    Err(e) => {
                        tracing::warn!("predecessor lookup failed for seq {}: {e}", c.seq - 1);
                        errors.push(format!("error looking up predecessor seq {}", c.seq - 1));
                    }
                }
            }
        }
        // 3. Verify the pusher authorization proof (RFC 9421 HTTP Signature).
        //    The context fields (signature_input, content_digest, request_path)
        //    are bound into the node signing payload, so a certificate whose
        //    node signature verified already commits to them.
        //
        //    The ref transition is NOT directly signed by the pusher — the
        //    shipped pusher signs only @method, @path, and content-digest.
        //    Instead the binding works through the node certificate: the node
        //    verifies the pusher proof during push, then issues a certificate
        //    whose 13-field signed payload includes ref_name, old_sha, new_sha.
        //    A captured pusher proof for one ref transition cannot be reused
        //    to authorize a different transition because the node signature on
        //    the mismatch would fail verification in step 1 above.
        //
        //    When proof fields are present, pusher_sig is REQUIRED; a missing
        //    pusher_sig is treated as invalid rather than silently skipped.
        if !proof_fields_null && c.pusher_sig.is_none() {
            errors.push("pusher signature is required when proof fields are present".to_string());
        }
        if let Some(pusher_sig) = &c.pusher_sig {
            match (&c.signature_input, &c.content_digest, &c.request_path) {
                (Some(sig_input), Some(content_digest), Some(request_path)) => {
                    match gitlawb_core::http_sig::HttpSignature::parse(
                        sig_input,
                        &format!("sig1=:{pusher_sig}:"),
                    ) {
                        Ok(http_sig) => {
                            let mut request_values: HashMap<String, String> = HashMap::new();
                            request_values.insert("@method".to_string(), "POST".to_string());
                            request_values.insert("@path".to_string(), request_path.clone());
                            request_values
                                .insert("content-digest".to_string(), content_digest.clone());
                            let sig_params_value =
                                sig_input.strip_prefix("sig1=").unwrap_or(sig_input);
                            let components_ref: Vec<&str> =
                                http_sig.components.iter().map(String::as_str).collect();
                            match gitlawb_core::http_sig::build_signing_string(
                                &components_ref,
                                sig_params_value,
                                &request_values,
                            ) {
                                Ok(signing_string) => {
                                    let pusher_did =
                                        gitlawb_core::did::Did::from_str(&c.pusher_did);
                                    let pusher_vk = pusher_did.and_then(|d| d.to_verifying_key());
                                    match pusher_vk {
                                        Ok(vk) => {
                                            let sig_bytes: [u8; 64] =
                                                match base64::engine::general_purpose::STANDARD
                                                    .decode(pusher_sig)
                                                {
                                                    Ok(bytes) => {
                                                        match bytes.as_slice().try_into() {
                                                            Ok(a) => a,
                                                            Err(_) => {
                                                                errors.push(
                                                        "pusher signature is not 64 bytes"
                                                            .to_string(),
                                                    );
                                                                return Ok(VerifyResult {
                                                                    valid: false,
                                                                    anchor,
                                                                    certificate: cert,
                                                                    errors,
                                                                });
                                                            }
                                                        }
                                                    }
                                                    Err(_) => {
                                                        errors.push(
                                                            "pusher signature is not valid base64"
                                                                .to_string(),
                                                        );
                                                        return Ok(VerifyResult {
                                                            valid: false,
                                                            anchor,
                                                            certificate: cert,
                                                            errors,
                                                        });
                                                    }
                                                };
                                            if let Err(e) = gitlawb_core::identity::verify(
                                                &vk,
                                                signing_string.as_bytes(),
                                                &sig_bytes,
                                            ) {
                                                errors.push(format!(
                                                    "pusher signature verification failed: {e}"
                                                ));
                                            }
                                        }
                                        Err(e) => {
                                            errors.push(format!("unresolvable pusher DID: {e}"));
                                        }
                                    }
                                }
                                Err(e) => {
                                    errors.push(format!("failed to build signing string: {e}"));
                                }
                            }
                        }
                        Err(e) => {
                            errors.push(format!("failed to parse pusher Signature-Input: {e}"));
                        }
                    } // inner match
                }
                (sig_input, content_digest, request_path) => {
                    errors.push(format!(
                        "pusher signature present but context fields incomplete \
                         (signature_input={}, content_digest={}, request_path={})",
                        sig_input.is_some(),
                        content_digest.is_some(),
                        request_path.is_some(),
                    ));
                }
            }
        }
    } else {
        errors.push("no embedded certificate found in anchor".to_string());
    }
    Ok(VerifyResult {
        valid: errors.is_empty(),
        anchor,
        certificate: cert,
        errors,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use gitlawb_core::identity::Keypair;
    /// Spin up an in-process bundler that *enforces* the signed data item
    /// contract: it parses the posted bytes as an ANS-104 item, verifies the
    /// Ed25519 signature against `kp`, checks that every `expected_tag` is
    /// present inside the item, and requires the embedded JSON payload to pass
    /// `validate`. It also asserts the Irys wire contract verbatim: the request
    /// target must equal `expected_request_target` (i.e. `/tx/{token}`, possibly
    /// with a path prefix or query) and the `x-irys-paid-by` header must carry
    /// `expected_bundler_account`. Any failure returns 400 (surfacing as `Err`
    /// from the anchor functions); success returns `{"id": <item_id>}` where
    /// `item_id` is the ANS-104 id derived from the received item's signature
    /// region — exactly what a real bundler echoes back (#224).
    async fn spawn_enforcing_bundler(
        kp: &Keypair,
        expected_bundler_account: &'static str,
        expected_request_target: &'static str,
        expected_tags: &[(&str, &str)],
        validate: impl Fn(&serde_json::Value) -> bool + Send + Sync + Clone + 'static,
    ) -> String {
        let vk = kp.verifying_key();
        let expected: Vec<(String, String)> = expected_tags
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Serve the exact path the client must request (path portion of the
        // expected request target), so prefixed or query-carrying bases are
        // exercised structurally rather than special-cased.
        let route_path = expected_request_target
            .split('?')
            .next()
            .unwrap_or(expected_request_target);
        let router = axum::Router::new().route(
            route_path,
            axum::routing::post(
                move |uri: axum::http::Uri,
                      headers: axum::http::HeaderMap,
                      body: axum::body::Bytes| {
                    let vk = vk;
                    let expected = expected.clone();
                    async move {
                        // The request target is the Irys contract: /tx/{token}
                        // with the base's query preserved. Assert it verbatim so
                        // the structural URL join cannot regress.
                        let target = uri.path_and_query().map(|q| q.as_str()).unwrap_or("");
                        if target != expected_request_target {
                            return (
                                StatusCode::BAD_REQUEST,
                                format!(
                                    "wrong request target: got {target:?}, want \
                                     {expected_request_target:?}"
                                ),
                            );
                        }
                        // The funded-account identity must be part of the request,
                        // not just the config: the item signature is authorship.
                        if !expected_bundler_account.is_empty() {
                            let got = headers
                                .get("x-irys-paid-by")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or_default();
                            if got != expected_bundler_account {
                                return (
                                    StatusCode::BAD_REQUEST,
                                    format!(
                                        "missing/wrong x-irys-paid-by: got {got:?}, want \
                                     {expected_bundler_account:?}"
                                    ),
                                );
                            }
                        }
                        let parsed = match crate::ans104::verify_data_item(&vk, &body) {
                            Ok(p) => p,
                            Err(e) => {
                                return (
                                    StatusCode::BAD_REQUEST,
                                    format!("unsigned/invalid item: {e}"),
                                );
                            }
                        };
                        for (name, value) in &expected {
                            if !parsed.tags.iter().any(|(tn, tv)| tn == name && tv == value) {
                                return (
                                    StatusCode::BAD_REQUEST,
                                    format!("missing signed tag {name}:{value}"),
                                );
                            }
                        }
                        let json: serde_json::Value = match serde_json::from_slice(&parsed.data) {
                            Ok(j) => j,
                            Err(e) => {
                                return (
                                    StatusCode::BAD_REQUEST,
                                    format!("item data is not JSON: {e}"),
                                );
                            }
                        };
                        if !validate(&json) {
                            return (
                                StatusCode::BAD_REQUEST,
                                "payload validation failed".to_string(),
                            );
                        }
                        // A real bundler echoes the ANS-104 data-item id of the
                        // exact item it received (base64url(sha256(signature))),
                        // not an arbitrary constant. Derive it from the request
                        // body so the response-binding contract in
                        // upload_ref_anchor_item is exercised end to end (#224).
                        let item_id = crate::ans104::data_item_id(&body);
                        (StatusCode::OK, format!(r#"{{"id":"{item_id}"}}"#))
                    }
                },
            ),
        );
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        format!("http://{addr}")
    }
    #[tokio::test]
    async fn test_anchor_noop_when_url_empty() {
        let kp = Keypair::generate();
        let client = reqwest::Client::new();
        let anchor = RefAnchor {
            repo: "alice/myrepo".into(),
            repo_id: "repo-uuid".into(),
            owner_did: "did:key:z6Mk...".into(),
            ref_name: "refs/heads/main".into(),
            old_sha: "0000000000000000000000000000000000000000".into(),
            new_sha: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".into(),
            cid: Some("bafyreib5...".into()),
            timestamp: "2026-03-14T00:00:00Z".into(),
            node_did: "did:key:z6MknndwexV9...".into(),
            certificate: None,
        };
        let result = anchor_ref_update(&client, "", "", "", &anchor, &kp).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }
    #[tokio::test]
    async fn test_anchor_success() {
        let kp = Keypair::generate();
        let server = spawn_enforcing_bundler(
            &kp,
            "zBundlerAccount",
            "/tx/matic",
            &[
                ("App-Name", "gitlawb"),
                ("Schema", "gitlawb/ref-update/v1"),
                ("Repo", "alice/myrepo"),
            ],
            |j| j["repo"] == "alice/myrepo",
        )
        .await;
        let client = reqwest::Client::new();
        let anchor = RefAnchor {
            repo: "alice/myrepo".into(),
            repo_id: "repo-uuid".into(),
            owner_did: "did:key:z6Mk...".into(),
            ref_name: "refs/heads/main".into(),
            old_sha: "0".repeat(40),
            new_sha: "a1b2c3d4".repeat(8),
            cid: None,
            timestamp: "2026-03-14T00:00:00Z".into(),
            node_did: "did:key:z6Mknnd...".into(),
            certificate: None,
        };
        let result =
            anchor_ref_update(&client, &server, "zBundlerAccount", "matic", &anchor, &kp).await;
        assert!(result.is_ok(), "anchor should succeed: {result:?}");
        assert!(
            is_valid_tx_id(&result.unwrap()),
            "anchor must return the well-formed data-item id the bundler echoed"
        );
    }
    /// #224 review, P2 + R2 BIND: the client validates the bundler's success id
    /// at the boundary AND binds it to the item actually sent. An empty,
    /// missing, or malformed transaction id in a 200 response must NOT read as
    /// success — it is Uncertain (the item may or may not have been accepted),
    /// so the durable job probes the gateway instead of recording a fabricated
    /// anchor. And a well-formed id that does NOT match the id of the item the
    /// node sent (a misrouted/faulty/compromised bundler substituting a
    /// different item) must also be Uncertain, never Accepted — recording a
    /// foreign id would destroy the durable identity the node can recover.
    #[tokio::test]
    async fn test_upload_rejects_empty_missing_and_malformed_success_ids() {
        use axum::response::IntoResponse;
        use std::sync::atomic::Ordering;

        async fn mock_bundler(
            body: String,
        ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
            let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let app = {
                let calls_srv = calls.clone();
                axum::Router::new().route(
                    "/tx/matic",
                    axum::routing::post(move || {
                        let calls = calls_srv.clone();
                        let body = body.clone();
                        async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            (axum::http::StatusCode::OK, body).into_response()
                        }
                    }),
                )
            };
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            (format!("http://{addr}"), calls)
        }

        let client = reqwest::Client::new();
        // Must be long enough (>= 2 + 64 bytes) for data_item_id to derive a
        // real id from the signature region rather than the short-item sentinel.
        let mut item = vec![0u8; 70];
        item[0] = 0x02;
        item[1] = 0x00;
        item[2..66].copy_from_slice(&[0xAA; 64]);
        let expected_id = crate::ans104::data_item_id(&item);
        assert_eq!(expected_id.len(), 43, "derived id must be a valid tx id");

        for (label, body) in [
            ("empty id", r#"{"id":""}"#),
            ("missing id", r#"{"foo":"bar"}"#),
            ("malformed id", r#"{"id":"WAY_TOO_SHORT"}"#),
        ] {
            let (server, calls) = mock_bundler(body.to_string()).await;
            let outcome = upload_ref_anchor_item(
                &client,
                &server,
                "zBundlerAccount",
                "matic",
                &item,
                &expected_id,
            )
            .await
            .unwrap();
            assert!(
                matches!(outcome, UploadOutcome::Uncertain { .. }),
                "{label} must classify as Uncertain: {outcome:?}"
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }

        // A well-formed id that MATCHES the item the node sent is Accepted.
        let (server, _calls) = mock_bundler(format!(r#"{{"id":"{expected_id}"}}"#)).await;
        let outcome = upload_ref_anchor_item(
            &client,
            &server,
            "zBundlerAccount",
            "matic",
            &item,
            &expected_id,
        )
        .await
        .unwrap();
        assert!(
            matches!(&outcome, UploadOutcome::Accepted { tx_id } if tx_id == &expected_id),
            "a matching well-formed id must be Accepted: {outcome:?}"
        );

        // A well-formed id that does NOT match the item sent is Uncertain, never
        // Accepted (R2 #224): a bundler that returns a different well-formed id
        // must not be able to replace the durable anchor identity.
        let (server, _calls) =
            mock_bundler(r#"{"id":"7xGpIoHUQ8j9GhD3Y2mKzP1NsVtXwRcFe4bEaLnMuO9"}"#.to_string())
                .await;
        let outcome = upload_ref_anchor_item(
            &client,
            &server,
            "zBundlerAccount",
            "matic",
            &item,
            &expected_id,
        )
        .await
        .unwrap();
        assert!(
            matches!(outcome, UploadOutcome::Uncertain { .. }),
            "a mismatched well-formed id must classify as Uncertain: {outcome:?}"
        );
    }
    /// The funded bundler account must ride on the upload request: the item
    /// signature is authorship, not payment, so an upload that omits the
    /// account must be refused — it would otherwise be billed to nobody.
    #[tokio::test]
    async fn test_anchor_ref_update_rejects_missing_bundler_account() {
        let kp = Keypair::generate();
        let client = reqwest::Client::new();
        let anchor = RefAnchor {
            repo: "alice/myrepo".into(),
            repo_id: "repo-uuid".into(),
            owner_did: "did:key:z6Mk...".into(),
            ref_name: "refs/heads/main".into(),
            old_sha: "0".repeat(40),
            new_sha: "a1b2c3d4".repeat(8),
            cid: None,
            timestamp: "2026-03-14T00:00:00Z".into(),
            node_did: "did:key:z6Mknnd...".into(),
            certificate: None,
        };
        let server = spawn_enforcing_bundler(
            &kp,
            "zBundlerAccount",
            "/tx/matic",
            &[("App-Name", "gitlawb"), ("Schema", "gitlawb/ref-update/v1")],
            |_| true,
        )
        .await;
        let result = anchor_ref_update(&client, &server, "", "matic", &anchor, &kp).await;
        let err = result.expect_err("missing bundler account must fail the upload");
        assert!(
            err.to_string().contains("x-irys-paid-by"),
            "error should name the missing account header: {err}"
        );
    }
    #[tokio::test]
    async fn test_anchor_body_carries_real_old_sha() {
        // The anchored body must serialize the real old→new transition the
        // node was handed, never a zero placeholder. Regression guard for the
        // push handler that used to hardcode `old_sha` to 64 zeros (#26).
        // The enforcing bundler rejects the upload unless the signed item's
        // JSON data carries both real SHAs.
        let real_old = "1111111111111111111111111111111111111111";
        let real_new = "2222222222222222222222222222222222222222";
        let kp = Keypair::generate();
        let server = spawn_enforcing_bundler(
            &kp,
            "zBundlerAccount",
            "/tx/matic",
            &[("App-Name", "gitlawb")],
            move |j| j["old_sha"] == real_old && j["new_sha"] == real_new,
        )
        .await;
        let client = reqwest::Client::new();
        let anchor = RefAnchor {
            repo: "alice/myrepo".into(),
            repo_id: "repo-uuid".into(),
            owner_did: "did:key:z6Mk...".into(),
            ref_name: "refs/heads/main".into(),
            old_sha: real_old.into(),
            new_sha: real_new.into(),
            cid: None,
            timestamp: "2026-03-14T00:00:00Z".into(),
            node_did: "did:key:z6Mknnd...".into(),
            certificate: None,
        };
        let result =
            anchor_ref_update(&client, &server, "zBundlerAccount", "matic", &anchor, &kp).await;
        // The bundler now echoes the item's own ANS-104 id; compare it against
        // the id derived from the very item this call would sign.
        let item = build_ref_anchor_item(&anchor, &kp).unwrap();
        assert_eq!(result.unwrap(), crate::ans104::data_item_id(&item));
    }
    #[tokio::test]
    async fn test_anchor_rejected_when_signed_by_other_key() {
        // The bundler enforces the node's public key; an item signed by a
        // different credential must be denied end-to-end, not silently accepted.
        let node_kp = Keypair::generate();
        let impostor_kp = Keypair::generate();
        let server = spawn_enforcing_bundler(
            &node_kp,
            "zBundlerAccount",
            "/tx/matic",
            &[("App-Name", "gitlawb")],
            |_| true,
        )
        .await;
        let client = reqwest::Client::new();
        let anchor = RefAnchor {
            repo: "alice/myrepo".into(),
            repo_id: "repo-uuid".into(),
            owner_did: "did:key:z6Mk...".into(),
            ref_name: "refs/heads/main".into(),
            old_sha: "0".repeat(40),
            new_sha: "a1b2c3d4".repeat(8),
            cid: None,
            timestamp: "2026-03-14T00:00:00Z".into(),
            node_did: "did:key:z6Mknnd...".into(),
            certificate: None,
        };
        let result = anchor_ref_update(
            &client,
            &server,
            "zBundlerAccount",
            "matic",
            &anchor,
            &impostor_kp,
        )
        .await;
        assert!(
            result.is_err(),
            "upload signed by the wrong key must be denied by the bundler"
        );
    }
    #[test]
    fn test_arweave_url() {
        let url = arweave_url(
            "https://arweave.net",
            "7xGpIoHUQ8j9GhD3Y2mKzP1NsVtXwRcFe4bEaLnMuOk",
        );
        assert_eq!(
            url,
            "https://arweave.net/7xGpIoHUQ8j9GhD3Y2mKzP1NsVtXwRcFe4bEaLnMuOk"
        );
    }
    #[tokio::test]
    async fn test_manifest_anchor_noop_when_url_empty() {
        let client = reqwest::Client::new();
        let kp = Keypair::generate();
        let blobs = vec![("oid1".to_string(), "cid1".to_string())];
        let m = EncryptedManifest {
            repo: "alice/r",
            owner_did: "did:key:zO",
            node_did: "did:key:zN",
            timestamp: "2026-06-11T00:00:00Z",
            blobs: &blobs,
        };
        assert_eq!(
            anchor_encrypted_manifest(&client, "", "", "", &m, &kp)
                .await
                .unwrap(),
            ""
        );
    }
    #[tokio::test]
    async fn test_manifest_anchor_noop_when_no_blobs() {
        let client = reqwest::Client::new();
        let kp = Keypair::generate();
        let blobs: Vec<(String, String)> = vec![];
        let m = EncryptedManifest {
            repo: "alice/r",
            owner_did: "did:key:zO",
            node_did: "did:key:zN",
            timestamp: "2026-06-11T00:00:00Z",
            blobs: &blobs,
        };
        // Non-empty URL, but no blobs: still a no-op.
        assert_eq!(
            anchor_encrypted_manifest(&client, "https://example.invalid", "", "", &m, &kp)
                .await
                .unwrap(),
            ""
        );
    }
    #[tokio::test]
    async fn test_manifest_anchor_success() {
        let kp = Keypair::generate();
        let server = spawn_enforcing_bundler(
            &kp,
            "zBundlerAccount",
            "/tx/matic",
            &[
                ("App-Name", "gitlawb"),
                ("Schema", "gitlawb/encrypted-manifest/v1"),
                ("Repo", "alice/r"),
                ("Owner-DID", "did:key:zO"),
                ("Node-DID", "did:key:zN"),
            ],
            |j| j["repo"] == "alice/r" && j["blobs"].as_array().is_some_and(|b| b.len() == 1),
        )
        .await;
        let client = reqwest::Client::new();
        let blobs = vec![("oid1".to_string(), "cid1".to_string())];
        let m = EncryptedManifest {
            repo: "alice/r",
            owner_did: "did:key:zO",
            node_did: "did:key:zN",
            timestamp: "2026-06-11T00:00:00Z",
            blobs: &blobs,
        };
        let r =
            anchor_encrypted_manifest(&client, &server, "zBundlerAccount", "matic", &m, &kp).await;
        assert!(
            is_valid_tx_id(&r.unwrap()),
            "manifest anchor must return the well-formed data-item id the bundler echoed"
        );
    }
    /// A minimal ref-update anchor for the URL-join tests.
    fn test_anchor(repo: &str, new_sha: &str) -> RefAnchor {
        RefAnchor {
            repo: repo.into(),
            repo_id: "repo-uuid".into(),
            owner_did: "did:key:z6Mk...".into(),
            ref_name: "refs/heads/main".into(),
            old_sha: "0".repeat(40),
            new_sha: new_sha.into(),
            cid: None,
            timestamp: "2026-03-14T00:00:00Z".into(),
            node_did: "did:key:z6Mknnd...".into(),
            certificate: None,
        }
    }
    /// The upload target must survive a path-prefixed bundler base: joining
    /// `{url}/prefix` must produce `/prefix/tx/matic`, never a dropped prefix.
    #[tokio::test]
    async fn test_anchor_preserves_bundler_path_prefix() {
        let kp = Keypair::generate();
        let server = spawn_enforcing_bundler(
            &kp,
            "zBundlerAccount",
            "/prefix/tx/matic",
            &[("App-Name", "gitlawb")],
            |_| true,
        )
        .await;
        let client = reqwest::Client::new();
        let base = format!("{server}/prefix");
        let result = anchor_ref_update(
            &client,
            &base,
            "zBundlerAccount",
            "matic",
            &test_anchor(
                "alice/myrepo",
                "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4",
            ),
            &kp,
        )
        .await;
        // The bundler echoes the item's own ANS-104 id; compare against the id
        // derived from the item this exact anchor + keypair signs.
        let item = build_ref_anchor_item(
            &test_anchor(
                "alice/myrepo",
                "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4",
            ),
            &kp,
        )
        .unwrap();
        assert_eq!(result.unwrap(), crate::ans104::data_item_id(&item));
    }
    /// A query on the bundler base must ride along on the upload request target
    /// (`/tx/matic?token=secret`) rather than being dropped by string concat.
    #[tokio::test]
    async fn test_anchor_preserves_bundler_query() {
        let kp = Keypair::generate();
        let server = spawn_enforcing_bundler(
            &kp,
            "zBundlerAccount",
            "/tx/matic?token=secret",
            &[("App-Name", "gitlawb")],
            |_| true,
        )
        .await;
        let client = reqwest::Client::new();
        let base = format!("{server}?token=secret");
        let result = anchor_ref_update(
            &client,
            &base,
            "zBundlerAccount",
            "matic",
            &test_anchor(
                "alice/myrepo",
                "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4",
            ),
            &kp,
        )
        .await;
        let item = build_ref_anchor_item(
            &test_anchor(
                "alice/myrepo",
                "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4",
            ),
            &kp,
        )
        .unwrap();
        assert_eq!(result.unwrap(), crate::ans104::data_item_id(&item));
    }
    /// A fragment in the bundler URL must be rejected outright for both upload
    /// paths: it is never sent to the bundler, so sending it silently would
    /// change the request target in a way the operator cannot see.
    #[tokio::test]
    async fn test_anchor_rejects_fragment_in_bundler_url() {
        let kp = Keypair::generate();
        let client = reqwest::Client::new();
        let bad = "https://example.invalid/#fragment";
        let anchor = test_anchor(
            "alice/myrepo",
            "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4",
        );
        let err = anchor_ref_update(&client, bad, "acct", "matic", &anchor, &kp)
            .await
            .expect_err("a fragment in the bundler URL must fail the upload");
        assert!(
            err.to_string().contains("fragment"),
            "error should name the fragment: {err}"
        );
        let blobs = vec![("oid1".to_string(), "cid1".to_string())];
        let m = EncryptedManifest {
            repo: "alice/r",
            owner_did: "did:key:zO",
            node_did: "did:key:zN",
            timestamp: "2026-06-11T00:00:00Z",
            blobs: &blobs,
        };
        let err = anchor_encrypted_manifest(&client, bad, "acct", "matic", &m, &kp)
            .await
            .expect_err("a fragment in the bundler URL must fail the manifest upload");
        assert!(
            err.to_string().contains("fragment"),
            "error should name the fragment: {err}"
        );
    }
    /// The gateway read must preserve a query on the gateway config (structural
    /// join), so the mock only answers a request whose target carries it.
    #[tokio::test]
    async fn test_verify_anchor_preserves_gateway_query() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/some-tx-id?token=secret")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"valid":false}"#)
            .create_async()
            .await;
        let client = reqwest::Client::new();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/gitlawb_test_placeholder")
            .expect("lazy pool creation should not fail");
        let db = crate::db::Db::for_testing(pool);
        let gateway = format!("{}?token=secret", server.url());
        let r = verify_anchor(&client, &gateway, "some-tx-id", &db, "did:key:zNODE")
            .await
            .expect("verify_anchor should return Ok");
        assert!(!r.valid, "non-certificate JSON should be invalid");
        mock.assert_async().await;
    }
    /// A fragment in the gateway URL must be rejected without ever issuing an
    /// HTTP request: a fragment is never sent to the gateway, so a config that
    /// carries one is a configuration error, surfaced as an invalid result.
    #[tokio::test]
    async fn test_verify_anchor_rejects_fragment_in_gateway_url() {
        let client = reqwest::Client::new();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/gitlawb_test_placeholder")
            .expect("lazy pool creation should not fail");
        let db = crate::db::Db::for_testing(pool);
        let r = verify_anchor(
            &client,
            "https://gateway.example/#fragment",
            "some-tx-id",
            &db,
            "did:key:zNODE",
        )
        .await
        .expect("verify_anchor should return Ok");
        assert!(!r.valid, "fragment in gateway URL must be invalid");
        assert!(
            r.errors.iter().any(|e| e.contains("fragment")),
            "errors should name the fragment: {:?}",
            r.errors
        );
    }
    #[test]
    fn manifest_blob_json_omits_recipients() {
        let v = manifest_blob_json("oid1", "cidA");
        assert_eq!(v["oid"], "oid1");
        assert_eq!(v["cid"], "cidA");
        assert!(
            v.get("recipients").is_none(),
            "Arweave manifest must not anchor recipient identities"
        );
    }
    #[test]
    fn test_sanitize_tag() {
        assert_eq!(sanitize_tag("alice/myrepo"), "alice/myrepo");
        assert_eq!(sanitize_tag("hello world!"), "helloworld");
    }
    #[tokio::test]
    async fn test_verify_anchor_uses_correct_gateway_url() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/does-not-exist")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"valid":false}"#)
            .create_async()
            .await;
        let client = reqwest::Client::new();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/gitlawb_test_placeholder")
            .expect("lazy pool creation should not fail");
        let db = crate::db::Db::for_testing(pool);
        let result = verify_anchor(
            &client,
            &server.url(),
            "does-not-exist",
            &db,
            "did:key:zNODE",
        )
        .await;
        let r = result.expect("verify_anchor should return Ok for gateway errors");
        assert!(!r.valid, "non-certificate JSON should be invalid");
        mock.assert_async().await;
    }
    /// A gateway URL carrying a query token must never surface that token in
    /// the public VerifyResult error text: reqwest embeds the request URL in
    /// its connection error, so the error must be rebuilt from the masked URL.
    #[tokio::test]
    async fn test_verify_anchor_error_does_not_leak_gateway_query_credentials() {
        let client = reqwest::Client::new();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/gitlawb_test_placeholder")
            .expect("lazy pool creation should not fail");
        let db = crate::db::Db::for_testing(pool);
        // Port 1 on loopback refuses connections deterministically.
        let result = verify_anchor(
            &client,
            "http://127.0.0.1:1/?token=SECRET",
            "txid",
            &db,
            "did:key:zNODE",
        )
        .await;
        let r = result.expect("verify_anchor should return Ok for gateway connection errors");
        assert!(!r.valid);
        let err_text = r.errors.join(" ");
        assert!(
            !err_text.contains("SECRET"),
            "gateway query token leaked into VerifyResult: {err_text}"
        );
    }
    #[tokio::test]
    async fn test_verify_anchor_malformed_node_did() {
        let mut server = mockito::Server::new_async().await;
        let bad_cert_json = serde_json::json!({
            "certificate": {
                "id": "cert-1",
                "repo_id": "repo-uuid",
                "ref_name": "refs/heads/main",
                "old_sha": "0000000000000000000000000000000000000000",
                "new_sha": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "pusher_did": "did:key:zPusher",
                "node_did": "malformed-node-did",
                "signature": "c2lnbmF0dXJl",
                "issued_at": "2026-06-11T00:00:00Z",
                "seq": 1,
                "prev": "0000000000000000000000000000000000000000000000000000000000000000",
            },
            "repo_id": "repo-uuid",
            "ref_name": "refs/heads/main",
            "old_sha": "0000000000000000000000000000000000000000",
            "new_sha": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            "node_did": "malformed-node-did",
        });
        let _mock = server
            .mock("GET", "/test-tx")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&bad_cert_json).unwrap())
            .create_async()
            .await;
        let client = reqwest::Client::new();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/gitlawb_test_placeholder")
            .expect("lazy pool creation should not fail");
        let db = crate::db::Db::for_testing(pool);
        // Verify as "malformed-node-did" itself so the issuer check passes and
        // the DID-parse guard is what must fire. This pins the `invalid node
        // DID` error push: with the anchor claiming the node IS the malformed
        // DID, only parsing the certificate's node_did can reject it.
        let result =
            verify_anchor(&client, &server.url(), "test-tx", &db, "malformed-node-did").await;
        assert!(
            result.is_ok(),
            "Expected Ok response, got Err: {:?}",
            result
        );
        let verify_result = result.unwrap();
        assert!(!verify_result.valid, "VerifyResult should be invalid");
        assert!(
            verify_result
                .errors
                .iter()
                .any(|e| e.contains("invalid node DID")),
            "Expected the DID-parse error, got: {:?}",
            verify_result.errors
        );
    }
    /// Pins the issuer guard (`c.node_did != node_did`): a cert that is fully
    /// authentic — real node signature over the real 13-field payload, real
    /// pusher proof — but names a DIFFERENT node as its issuer must fail with
    /// exactly the issuer-mismatch error. If the guard were removed, the cert
    /// would verify clean (the signature resolves against its own node_did),
    /// so this test turns that regression red.
    #[tokio::test]
    async fn test_verify_anchor_rejects_cert_issued_by_different_node() {
        let node_kp = gitlawb_core::identity::Keypair::generate();
        let node_did = node_kp.did().as_str().to_string();
        let other_kp = gitlawb_core::identity::Keypair::generate();
        let other_did = other_kp.did().as_str().to_string();
        let pusher_kp = gitlawb_core::identity::Keypair::generate();
        let pusher_did = pusher_kp.did().as_str().to_string();
        let repo_id = "repo-uuid";
        let ref_name = "refs/heads/main";
        let old_sha = "0".repeat(40);
        let new_sha = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let issued_at = "2026-07-22T00:00:00+00:00";
        let seq = 1i64;
        let prev = "0".repeat(64);
        let request_path = "/repo-uuid.git/git-receive-pack";
        let signed =
            gitlawb_core::http_sig::sign_request(&pusher_kp, "POST", request_path, b"push-body");
        let pusher_sig = signed
            .signature
            .strip_prefix("sig1=:")
            .and_then(|s| s.strip_suffix(':'))
            .unwrap()
            .to_string();
        // Signed by `other_kp`, which the payload names as node_did — so the
        // cert is internally self-consistent and its signature verifies.
        let payload = serde_json::json!({
            "repo_id": repo_id,
            "ref": ref_name,
            "old": old_sha,
            "new": new_sha,
            "pusher": pusher_did,
            "node": other_did,
            "ts": issued_at,
            "seq": seq,
            "prev": prev,
            "pusher_sig": pusher_sig,
            "signature_input": signed.signature_input,
            "content_digest": signed.content_digest,
            "request_path": request_path,
        });
        let signature = other_kp.sign_b64(&serde_json::to_vec(&payload).unwrap());
        let cert = crate::db::RefCertificate {
            id: "cert-other-node".to_string(),
            repo_id: repo_id.to_string(),
            ref_name: ref_name.to_string(),
            old_sha: old_sha.clone(),
            new_sha: new_sha.to_string(),
            pusher_did,
            node_did: other_did.clone(),
            signature,
            issued_at: issued_at.to_string(),
            seq,
            prev,
            pusher_sig: Some(pusher_sig),
            signature_input: Some(signed.signature_input),
            content_digest: Some(signed.content_digest),
            request_path: Some(request_path.to_string()),
        };
        let anchor_json = serde_json::json!({
            "repo_id": repo_id,
            "ref_name": ref_name,
            "old_sha": old_sha,
            "new_sha": new_sha,
            "node_did": other_did,
            "certificate": cert,
        });
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/other-node-tx")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&anchor_json).unwrap())
            .create_async()
            .await;
        let client = reqwest::Client::new();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/gitlawb_test_placeholder")
            .expect("lazy pool creation should not fail");
        let db = crate::db::Db::for_testing(pool);
        let result = verify_anchor(&client, &server.url(), "other-node-tx", &db, &node_did).await;
        let verify_result = result.expect("verify_anchor should return Ok for a served anchor");
        assert!(
            !verify_result.valid,
            "cert issued by a different node must not verify as valid"
        );
        assert!(
            verify_result
                .errors
                .iter()
                .any(|e| e.contains("does not match this node")),
            "expected the issuer-mismatch error, got: {:?}",
            verify_result.errors
        );
        _mock.assert_async().await;
    }
    /// Pins the 13-field signature-failure error push: an authentic cert whose
    /// node signature was tampered must fail with the 13-field signature error.
    /// If the push were removed, no other guard would catch it (the proof
    /// fields are present, so no 7-field fallback runs and the tamper would be
    /// silent).
    #[tokio::test]
    async fn test_verify_anchor_rejects_tampered_13_field_signature() {
        let node_kp = gitlawb_core::identity::Keypair::generate();
        let node_did = node_kp.did().as_str().to_string();
        let pusher_kp = gitlawb_core::identity::Keypair::generate();
        let pusher_did = pusher_kp.did().as_str().to_string();
        let repo_id = "repo-uuid";
        let ref_name = "refs/heads/main";
        let old_sha = "0".repeat(40);
        let new_sha = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let issued_at = "2026-07-22T00:00:00+00:00";
        let seq = 1i64;
        let prev = "0".repeat(64);
        let request_path = "/repo-uuid.git/git-receive-pack";
        let signed =
            gitlawb_core::http_sig::sign_request(&pusher_kp, "POST", request_path, b"push-body");
        let pusher_sig = signed
            .signature
            .strip_prefix("sig1=:")
            .and_then(|s| s.strip_suffix(':'))
            .unwrap()
            .to_string();
        let payload = serde_json::json!({
            "repo_id": repo_id,
            "ref": ref_name,
            "old": old_sha,
            "new": new_sha,
            "pusher": pusher_did,
            "node": node_did,
            "ts": issued_at,
            "seq": seq,
            "prev": prev,
            "pusher_sig": pusher_sig,
            "signature_input": signed.signature_input,
            "content_digest": signed.content_digest,
            "request_path": request_path,
        });
        let signature = node_kp.sign_b64(&serde_json::to_vec(&payload).unwrap());
        // Tamper: decode the b64url signature, flip one byte (guaranteed to
        // change the value — unlike prefix replacement, which is a 1-in-64
        // no-op), and re-encode.
        let tampered_signature = {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let mut bytes = URL_SAFE_NO_PAD
                .decode(&signature)
                .expect("signature should decode");
            bytes[0] ^= 0x01;
            let tampered = URL_SAFE_NO_PAD.encode(&bytes);
            assert_ne!(tampered, signature, "tamper must change the signature");
            tampered
        };
        let cert = crate::db::RefCertificate {
            id: "cert-tampered-13".to_string(),
            repo_id: repo_id.to_string(),
            ref_name: ref_name.to_string(),
            old_sha: old_sha.clone(),
            new_sha: new_sha.to_string(),
            pusher_did,
            node_did: node_did.clone(),
            signature: tampered_signature,
            issued_at: issued_at.to_string(),
            seq,
            prev,
            pusher_sig: Some(pusher_sig),
            signature_input: Some(signed.signature_input),
            content_digest: Some(signed.content_digest),
            request_path: Some(request_path.to_string()),
        };
        let anchor_json = serde_json::json!({
            "repo_id": repo_id,
            "ref_name": ref_name,
            "old_sha": old_sha,
            "new_sha": new_sha,
            "node_did": node_did,
            "certificate": cert,
        });
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/tampered-13-tx")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&anchor_json).unwrap())
            .create_async()
            .await;
        let client = reqwest::Client::new();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/gitlawb_test_placeholder")
            .expect("lazy pool creation should not fail");
        let db = crate::db::Db::for_testing(pool);
        let result = verify_anchor(&client, &server.url(), "tampered-13-tx", &db, &node_did).await;
        let verify_result = result.expect("verify_anchor should return Ok for a served anchor");
        assert!(
            !verify_result.valid,
            "tampered 13-field cert must not verify as valid"
        );
        assert!(
            verify_result
                .errors
                .iter()
                .any(|e| e.contains("certificate signature verification failed")),
            "expected the 13-field signature error, got: {:?}",
            verify_result.errors
        );
        _mock.assert_async().await;
    }
    /// Pins the 7-field signature-failure error push: a legacy cert (proof
    /// fields NULL) whose node signature was tampered must fail with the
    /// 7-field signature error.
    #[tokio::test]
    async fn test_verify_anchor_rejects_tampered_7_field_signature() {
        let node_kp = gitlawb_core::identity::Keypair::generate();
        let node_did = node_kp.did().as_str().to_string();
        let repo_id = "repo-uuid";
        let ref_name = "refs/heads/main";
        let old_sha = "0".repeat(40);
        let new_sha = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let issued_at = "2026-07-22T00:00:00+00:00";
        let payload = serde_json::json!({
            "repo_id": repo_id,
            "ref": ref_name,
            "old": old_sha,
            "new": new_sha,
            "pusher": "did:key:z6MkPusher",
            "node": node_did,
            "ts": issued_at,
        });
        let signature = node_kp.sign_b64(&serde_json::to_vec(&payload).unwrap());
        // Tamper: decode the b64url signature, flip one byte (guaranteed to
        // change the value — unlike prefix replacement, which is a 1-in-64
        // no-op), and re-encode.
        let tampered_signature = {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let mut bytes = URL_SAFE_NO_PAD
                .decode(&signature)
                .expect("signature should decode");
            bytes[0] ^= 0x01;
            let tampered = URL_SAFE_NO_PAD.encode(&bytes);
            assert_ne!(tampered, signature, "tamper must change the signature");
            tampered
        };
        let cert = crate::db::RefCertificate {
            id: "cert-tampered-7".to_string(),
            repo_id: repo_id.to_string(),
            ref_name: ref_name.to_string(),
            old_sha: old_sha.clone(),
            new_sha: new_sha.to_string(),
            pusher_did: "did:key:z6MkPusher".to_string(),
            node_did: node_did.clone(),
            signature: tampered_signature,
            issued_at: issued_at.to_string(),
            seq: 1,
            prev: "0".repeat(64),
            pusher_sig: None,
            signature_input: None,
            content_digest: None,
            request_path: None,
        };
        let anchor_json = serde_json::json!({
            "repo_id": repo_id,
            "ref_name": ref_name,
            "old_sha": old_sha,
            "new_sha": new_sha,
            "node_did": node_did,
            "certificate": cert,
        });
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/tampered-7-tx")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&anchor_json).unwrap())
            .create_async()
            .await;
        let client = reqwest::Client::new();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/gitlawb_test_placeholder")
            .expect("lazy pool creation should not fail");
        let db = crate::db::Db::for_testing(pool);
        let result = verify_anchor(&client, &server.url(), "tampered-7-tx", &db, &node_did).await;
        let verify_result = result.expect("verify_anchor should return Ok for a served anchor");
        assert!(
            !verify_result.valid,
            "tampered 7-field cert must not verify as valid"
        );
        assert!(
            verify_result.errors.iter().any(|e| e.contains("(7-field)")),
            "expected the 7-field signature error, got: {:?}",
            verify_result.errors
        );
        _mock.assert_async().await;
    }
    /// A true end-to-end accept: a cert signed by a real node keypair over a
    /// real 13-field payload, with a real RFC 9421 pusher proof, served through
    /// a mock gateway, must verify to `valid: true` with empty errors.
    /// Build an authentic 13-field certificate signed by `node_kp` with a real
    /// RFC 9421 pusher proof from `pusher_kp` — the exact shape a live node
    /// issues. Shared by the accept and fail-closed corroboration tests.
    #[allow(clippy::too_many_arguments)]
    fn authentic_13_field_cert(
        node_kp: &Keypair,
        pusher_kp: &Keypair,
        repo_id: &str,
        ref_name: &str,
        old_sha: &str,
        new_sha: &str,
        node_did: &str,
        issued_at: &str,
        seq: i64,
        prev: &str,
    ) -> crate::db::RefCertificate {
        let request_path = "/repo-uuid.git/git-receive-pack";
        let signed =
            gitlawb_core::http_sig::sign_request(pusher_kp, "POST", request_path, b"push-body");
        let pusher_sig = signed
            .signature
            .strip_prefix("sig1=:")
            .and_then(|s| s.strip_suffix(':'))
            .unwrap()
            .to_string();
        let payload = serde_json::json!({
            "repo_id": repo_id,
            "ref": ref_name,
            "old": old_sha,
            "new": new_sha,
            "pusher": pusher_kp.did().as_str().to_string(),
            "node": node_did,
            "ts": issued_at,
            "seq": seq,
            "prev": prev,
            "pusher_sig": pusher_sig,
            "signature_input": signed.signature_input,
            "content_digest": signed.content_digest,
            "request_path": request_path,
        });
        let signature = node_kp.sign_b64(&serde_json::to_vec(&payload).unwrap());
        crate::db::RefCertificate {
            id: "cert-accept-1".to_string(),
            repo_id: repo_id.to_string(),
            ref_name: ref_name.to_string(),
            old_sha: old_sha.to_string(),
            new_sha: new_sha.to_string(),
            pusher_did: pusher_kp.did().as_str().to_string(),
            node_did: node_did.to_string(),
            signature,
            issued_at: issued_at.to_string(),
            seq,
            prev: prev.to_string(),
            pusher_sig: Some(pusher_sig),
            signature_input: Some(signed.signature_input),
            content_digest: Some(signed.content_digest),
            request_path: Some(request_path.to_string()),
        }
    }
    /// Run the current schema on a fresh `#[sqlx::test]` pool so DB-backed
    /// anchor tests share one seeding path.
    async fn migrated_db(pool: sqlx::PgPool) -> crate::db::Db {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations should apply");
        db
    }
    #[sqlx::test]
    async fn test_verify_anchor_accepts_authentic_13_field_certificate(pool: sqlx::PgPool) {
        let node_kp = gitlawb_core::identity::Keypair::generate();
        let node_did = node_kp.did().as_str().to_string();
        let pusher_kp = gitlawb_core::identity::Keypair::generate();
        let owner_did = "did:key:z6MkOwner";
        let repo_id = "repo-uuid";
        let ref_name = "refs/heads/main";
        let old_sha = "0".repeat(40);
        let new_sha = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let issued_at = "2026-07-22T00:00:00+00:00";
        let seq = 1i64;
        let prev = "0".repeat(64);
        let db = migrated_db(pool).await;
        // Seed the repo so the outer identity corroboration actually runs
        // against a real row instead of being skipped by a lazy pool.
        db.create_repo(&crate::db::RepoRecord {
            id: repo_id.to_string(),
            name: "myrepo".into(),
            owner_did: owner_did.to_string(),
            description: None,
            is_public: true,
            default_branch: "main".into(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            disk_path: "/tmp/anchor-test".into(),
            forked_from: None,
            machine_id: None,
        })
        .await
        .unwrap();
        let cert = authentic_13_field_cert(
            &node_kp, &pusher_kp, repo_id, ref_name, &old_sha, new_sha, &node_did, issued_at, seq,
            &prev,
        );
        // The outer identity fields are present and must corroborate against
        // the seeded repo row: expected_repo = normalize_owner_key(owner) / name.
        let anchor_json = serde_json::json!({
            "repo": format!("{}/myrepo", crate::db::normalize_owner_key(owner_did)),
            "owner_did": owner_did,
            "repo_id": repo_id,
            "ref_name": ref_name,
            "old_sha": old_sha,
            "new_sha": new_sha,
            "node_did": node_did,
            "certificate": cert,
        });
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/accept-tx")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&anchor_json).unwrap())
            .create_async()
            .await;
        let client = reqwest::Client::new();
        let result = verify_anchor(&client, &server.url(), "accept-tx", &db, &node_did).await;
        let r = result.expect("verify_anchor should return Ok for a served anchor");
        assert!(
            r.valid,
            "authentic 13-field cert must verify, errors: {:?}",
            r.errors
        );
        assert!(
            r.errors.is_empty(),
            "expected no errors, got: {:?}",
            r.errors
        );
        _mock.assert_async().await;
    }
    /// Version 2 certificate: the `version` field is included in the signed
    /// payload.  Verification must succeed on the 14-field first pass.
    #[sqlx::test]
    async fn test_verify_anchor_accepts_authentic_14_field_version2_certificate(
        pool: sqlx::PgPool,
    ) {
        let node_kp = gitlawb_core::identity::Keypair::generate();
        let node_did = node_kp.did().as_str().to_string();
        let pusher_kp = gitlawb_core::identity::Keypair::generate();
        let owner_did = "did:key:z6MkOwner";
        let repo_id = "repo-uuid";
        let ref_name = "refs/heads/main";
        let old_sha = "0".repeat(40);
        let new_sha = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let issued_at = "2026-07-22T00:00:00+00:00";
        let seq = 1i64;
        let prev = "0".repeat(64);
        let db = migrated_db(pool).await;
        db.create_repo(&crate::db::RepoRecord {
            id: repo_id.to_string(),
            name: "myrepo".into(),
            owner_did: owner_did.to_string(),
            description: None,
            is_public: true,
            default_branch: "main".into(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            disk_path: "/tmp/anchor-test".into(),
            forked_from: None,
            machine_id: None,
        })
        .await
        .unwrap();
        // Build a version-2 (14-field) certificate.
        let request_path = "/repo-uuid.git/git-receive-pack";
        let signed =
            gitlawb_core::http_sig::sign_request(&pusher_kp, "POST", request_path, b"push-body");
        let pusher_sig = signed
            .signature
            .strip_prefix("sig1=:")
            .and_then(|s| s.strip_suffix(':'))
            .unwrap()
            .to_string();
        let payload = serde_json::json!({
            "repo_id": repo_id,
            "ref": ref_name,
            "old": old_sha,
            "new": new_sha,
            "pusher": pusher_kp.did().as_str().to_string(),
            "node": node_did,
            "ts": issued_at,
            "version": crate::cert::CERT_PAYLOAD_VERSION,
            "seq": seq,
            "prev": prev,
            "pusher_sig": pusher_sig,
            "signature_input": signed.signature_input,
            "content_digest": signed.content_digest,
            "request_path": request_path,
        });
        let signature = node_kp.sign_b64(&serde_json::to_vec(&payload).unwrap());
        let cert = crate::db::RefCertificate {
            id: "cert-accept-v2-1".to_string(),
            repo_id: repo_id.to_string(),
            ref_name: ref_name.to_string(),
            old_sha: old_sha.to_string(),
            new_sha: new_sha.to_string(),
            pusher_did: pusher_kp.did().as_str().to_string(),
            node_did: node_did.to_string(),
            signature,
            issued_at: issued_at.to_string(),
            seq,
            prev: prev.to_string(),
            pusher_sig: Some(pusher_sig),
            signature_input: Some(signed.signature_input),
            content_digest: Some(signed.content_digest),
            request_path: Some(request_path.to_string()),
        };
        let anchor_json = serde_json::json!({
            "repo": format!("{}/myrepo", crate::db::normalize_owner_key(owner_did)),
            "owner_did": owner_did,
            "repo_id": repo_id,
            "ref_name": ref_name,
            "old_sha": old_sha,
            "new_sha": new_sha,
            "node_did": node_did,
            "certificate": cert,
        });
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/accept-v2-tx")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&anchor_json).unwrap())
            .create_async()
            .await;
        let client = reqwest::Client::new();
        let result = verify_anchor(&client, &server.url(), "accept-v2-tx", &db, &node_did).await;
        let r = result.expect("verify_anchor should return Ok for a served anchor");
        assert!(
            r.valid,
            "authentic version-2 (14-field) cert must verify, errors: {:?}",
            r.errors
        );
        assert!(
            r.errors.is_empty(),
            "expected no errors, got: {:?}",
            r.errors
        );
        _mock.assert_async().await;
    }
    /// Fail closed: when the anchor carries outer `repo`/`owner_did` claims but
    /// the node has no record of the repo, corroboration cannot run — and the
    /// verdict must not rest on the certificate signature alone.
    #[sqlx::test]
    async fn test_verify_anchor_fails_closed_when_outer_identity_cannot_be_corroborated(
        pool: sqlx::PgPool,
    ) {
        let node_kp = gitlawb_core::identity::Keypair::generate();
        let node_did = node_kp.did().as_str().to_string();
        let pusher_kp = gitlawb_core::identity::Keypair::generate();
        let owner_did = "did:key:zVictim";
        let repo_id = "repo-uuid";
        let ref_name = "refs/heads/main";
        let old_sha = "0".repeat(40);
        let new_sha = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let issued_at = "2026-07-22T00:00:00+00:00";
        let db = migrated_db(pool).await;
        // Deliberately do NOT seed the repo row: the lookup must come up empty.
        let cert = authentic_13_field_cert(
            &node_kp,
            &pusher_kp,
            repo_id,
            ref_name,
            &old_sha,
            new_sha,
            &node_did,
            issued_at,
            1,
            &"0".repeat(64),
        );
        // Forged outer identity fields, no way to corroborate them.
        let anchor_json = serde_json::json!({
            "repo": "victim-owner/victim-repo",
            "owner_did": owner_did,
            "repo_id": repo_id,
            "ref_name": ref_name,
            "old_sha": old_sha,
            "new_sha": new_sha,
            "node_did": node_did,
            "certificate": cert,
        });
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/uncorroborated-tx")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&anchor_json).unwrap())
            .create_async()
            .await;
        let client = reqwest::Client::new();
        let result =
            verify_anchor(&client, &server.url(), "uncorroborated-tx", &db, &node_did).await;
        let r = result.expect("verify_anchor should return Ok for a served anchor");
        assert!(
            !r.valid,
            "uncorroborated outer identity must not verify as valid"
        );
        assert!(
            r.errors
                .iter()
                .any(|e| e.contains("cannot be corroborated")),
            "expected the uncorroborated-identity error, got: {:?}",
            r.errors
        );
        _mock.assert_async().await;
    }
    /// A tampered seq on an authentic legacy 7-field cert must fail: the
    /// 7-field signature does not cover seq/prev, so the node's stored row
    /// must be corroborated rather than accepting a blanket valid: true.
    #[tokio::test]
    async fn test_verify_anchor_legacy_seq_tamper_fails_closed() {
        let node_kp = gitlawb_core::identity::Keypair::generate();
        let node_did = node_kp.did().as_str().to_string();
        let repo_id = "repo-uuid";
        let ref_name = "refs/heads/main";
        let old_sha = "0".repeat(40);
        let new_sha = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let issued_at = "2026-07-22T00:00:00+00:00";
        // Sign the 7-field payload exactly as pre-PR nodes did.
        let payload_7 = serde_json::json!({
            "repo_id": repo_id,
            "ref": ref_name,
            "old": old_sha,
            "new": new_sha,
            "pusher": "did:key:z6MkPusher",
            "node": node_did,
            "ts": issued_at,
        });
        let signature = node_kp.sign_b64(&serde_json::to_vec(&payload_7).unwrap());
        let cert = crate::db::RefCertificate {
            id: "cert-legacy-tamper".to_string(),
            repo_id: repo_id.to_string(),
            ref_name: ref_name.to_string(),
            old_sha: old_sha.clone(),
            new_sha: new_sha.to_string(),
            pusher_did: "did:key:z6MkPusher".to_string(),
            node_did: node_did.clone(),
            signature,
            issued_at: issued_at.to_string(),
            seq: 1,
            prev: "0".repeat(64),
            pusher_sig: None,
            signature_input: None,
            content_digest: None,
            request_path: None,
        };
        let anchor_json = serde_json::json!({
            "repo_id": repo_id,
            "ref_name": ref_name,
            "old_sha": old_sha,
            "new_sha": new_sha,
            "node_did": node_did,
            "certificate": cert,
        });
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/legacy-tamper-tx")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&anchor_json).unwrap())
            .create_async()
            .await;
        let client = reqwest::Client::new();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/gitlawb_test_placeholder")
            .expect("lazy pool creation should not fail");
        let db = crate::db::Db::for_testing(pool);
        // The cert is not present in the (lazy) node database — no stored row
        // matches its signed (repo_id, ref_name, old_sha, new_sha, ts), so the
        // legacy corroboration must fail closed instead of returning valid.
        let result =
            verify_anchor(&client, &server.url(), "legacy-tamper-tx", &db, &node_did).await;
        let r = result.expect("verify_anchor should return Ok for a served anchor");
        assert!(
            !r.valid,
            "legacy cert not present in node DB must not verify as valid"
        );
        assert!(
            r.errors
                .iter()
                .any(|e| e.contains("no stored certificate matches the signed")
                    || e.contains("error looking up certificate")),
            "expected a corroboration error, got: {:?}",
            r.errors
        );
        _mock.assert_async().await;
    }
    /// The legacy corroboration must key on the fields the 7-field signature
    /// actually covers — never on `id`, which appears in no signed payload.
    /// A forged cert that copies `id`/`seq`/`prev` from a stored row at seq 7
    /// while its signed tuple describes a DIFFERENT transition must fail: the
    /// old `get_ref_certificate(id)` lookup measured the forger against the row
    /// they chose, returning valid:true.
    #[sqlx::test]
    async fn test_verify_anchor_forged_legacy_cert_cannot_borrow_stored_chain_position(
        pool: sqlx::PgPool,
    ) {
        let node_kp = gitlawb_core::identity::Keypair::generate();
        let node_did = node_kp.did().as_str().to_string();
        let db = crate::db::Db::for_testing(pool.clone());
        db.run_migrations().await.expect("migrations should apply");
        // Build a full stored chain seq 1..7 for the repo so every chain check
        // the forged cert must survive (prev-linkage against seq-1, predecessor
        // lookups) has a real row to pass against. Each cert's `prev` is the
        // sha256 of its predecessor's 7-field payload, as production issuance
        // computes it.
        let repo_id = "repo-uuid";
        let ref_name = "refs/heads/main";
        let mut prev = "0".repeat(64);
        let mut stored_at_seq_7: Option<crate::db::RefCertificate> = None;
        for seq in 1..=7 {
            let old = format!("{:040}", seq);
            let new = format!("{:040}", seq + 1);
            let ts = format!("2026-01-{:02}T00:00:00+00:00", seq);
            let payload = serde_json::json!({
                "repo_id": repo_id,
                "ref": ref_name,
                "old": old,
                "new": new,
                "pusher": "did:key:z6MkStored",
                "node": node_did,
                "ts": ts,
            });
            let signature = node_kp.sign_b64(&serde_json::to_vec(&payload).unwrap());
            let cert = crate::db::RefCertificate {
                id: format!("stored-cert-{seq}"),
                repo_id: repo_id.to_string(),
                ref_name: ref_name.to_string(),
                old_sha: old.clone(),
                new_sha: new.clone(),
                pusher_did: "did:key:z6MkStored".to_string(),
                node_did: node_did.clone(),
                signature,
                issued_at: ts.clone(),
                seq,
                prev: prev.clone(),
                pusher_sig: None,
                signature_input: None,
                content_digest: None,
                request_path: None,
            };
            db.insert_ref_certificate(&cert)
                .await
                .expect("stored cert insert should succeed");
            prev = hex::encode(sha2::Sha256::digest(serde_json::to_vec(&payload).unwrap()));
            if seq == 7 {
                stored_at_seq_7 = Some(cert);
            }
        }
        let stored_seq_7 = stored_at_seq_7.expect("seq-7 cert was inserted");
        // The forged anchor: signed tuple says the transition (repo, ref,
        // forged_old, forged_new, forged_ts) — a DIFFERENT, never-recorded
        // transition — but id/seq/prev are copied verbatim from the seq-7
        // stored row. The forger mints their own keypair (permissionless
        // identities) and signs that payload as node_did.
        let forged_kp = gitlawb_core::identity::Keypair::generate();
        let forged_did = forged_kp.did().as_str().to_string();
        let forged_old = "2222222222222222222222222222222222222222";
        let forged_new = "3333333333333333333333333333333333333333";
        let forged_ts = "2026-02-02T00:00:00+00:00";
        let forged_payload = serde_json::json!({
            "repo_id": repo_id,
            "ref": ref_name,
            "old": forged_old,
            "new": forged_new,
            "pusher": "did:key:z6MkForged",
            "node": forged_did,
            "ts": forged_ts,
        });
        let forged_signature = forged_kp.sign_b64(&serde_json::to_vec(&forged_payload).unwrap());
        let forged_cert = crate::db::RefCertificate {
            id: stored_seq_7.id.clone(),
            repo_id: repo_id.to_string(),
            ref_name: ref_name.to_string(),
            old_sha: forged_old.to_string(),
            new_sha: forged_new.to_string(),
            pusher_did: "did:key:z6MkForged".to_string(),
            node_did: forged_did.clone(),
            signature: forged_signature,
            issued_at: forged_ts.to_string(),
            seq: stored_seq_7.seq,
            prev: stored_seq_7.prev.clone(),
            pusher_sig: None,
            signature_input: None,
            content_digest: None,
            request_path: None,
        };
        let anchor_json = serde_json::json!({
            "repo_id": repo_id,
            "ref_name": ref_name,
            "old_sha": forged_old,
            "new_sha": forged_new,
            "node_did": forged_did,
            "certificate": forged_cert,
        });
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/forged-borrowed-position-tx")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&anchor_json).unwrap())
            .create_async()
            .await;
        let client = reqwest::Client::new();
        // Verify as the forger's own node: node_did, the issuer check, the
        // outer-field cross-check, the signature, and the chain-position
        // checks all line up. ONLY the signed-tuple corroboration can catch
        // that this cert claims a chain position it never earned.
        let result = verify_anchor(
            &client,
            &server.url(),
            "forged-borrowed-position-tx",
            &db,
            &forged_did,
        )
        .await;
        let r = result.expect("verify_anchor should return Ok for a served anchor");
        assert!(
            !r.valid,
            "forged cert borrowing a stored chain position must not verify as valid: {:?}",
            r.errors
        );
        assert!(
            r.errors
                .iter()
                .any(|e| e.contains("no stored certificate matches the signed")),
            "expected the signed-tuple corroboration to reject the forged cert, got: {:?}",
            r.errors
        );
        _mock.assert_async().await;
    }
    /// A bundler that returns 500 with a body reflecting the request back — the
    /// scenario a hostile or buggy endpoint uses to leak the credential-bearing
    /// pieces (the `x-irys-paid-by` funded account and the payment token riding
    /// in the path) through the error path. The error path must redact them.
    async fn spawn_echoing_error_bundler() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = axum::Router::new().route(
            "/tx/matic",
            axum::routing::post(
                move |uri: axum::http::Uri, headers: axum::http::HeaderMap| async move {
                    let paid_by = headers
                        .get("x-irys-paid-by")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default();
                    let target = uri.path_and_query().map(|q| q.as_str()).unwrap_or("");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!(r#"{{"error":"rejected for {paid_by} at {target}"}}"#),
                    )
                },
            ),
        );
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        format!("http://{addr}")
    }
    /// A non-success bundler response must not let the remote reflect the
    /// credential-bearing request back into the error text: the funded-account
    /// identity and the payment token are sent by the node, so a bundler that
    /// echoes them (hostile or buggy) must be defeated by the redaction
    /// boundary, not surfaced verbatim in logs or a caller-visible error.
    #[tokio::test]
    async fn test_anchor_ref_update_redacts_credentials_in_error_body() {
        let kp = Keypair::generate();
        let client = reqwest::Client::new();
        let server = spawn_echoing_error_bundler().await;
        let account = "zSecretFundedAccount";
        let result = anchor_ref_update(
            &client,
            &server,
            account,
            "matic",
            &test_anchor(
                "alice/myrepo",
                "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4",
            ),
            &kp,
        )
        .await;
        let err = result.expect_err("a 500 bundler response must fail the upload");
        let text = err.to_string();
        assert!(
            text.contains("500"),
            "error should carry the status: {text}"
        );
        assert!(
            !text.contains(account),
            "funded account echoed by the bundler must be redacted: {text}"
        );
        assert!(
            !text.contains("matic"),
            "payment token echoed by the bundler must be redacted: {text}"
        );
        assert!(
            text.contains("<redacted>"),
            "expected a redaction marker: {text}"
        );
    }
    /// The manifest upload path shares the same redaction boundary: a 500 body
    /// that echoes the funded account and token must not reach the error text.
    #[tokio::test]
    async fn test_manifest_anchor_redacts_credentials_in_error_body() {
        let kp = Keypair::generate();
        let client = reqwest::Client::new();
        let server = spawn_echoing_error_bundler().await;
        let account = "zSecretFundedAccount";
        let blobs = vec![("oid1".to_string(), "cid1".to_string())];
        let m = EncryptedManifest {
            repo: "alice/r",
            owner_did: "did:key:zO",
            node_did: "did:key:zN",
            timestamp: "2026-06-11T00:00:00Z",
            blobs: &blobs,
        };
        let err = anchor_encrypted_manifest(&client, &server, account, "matic", &m, &kp)
            .await
            .expect_err("a 500 bundler response must fail the manifest upload");
        let text = err.to_string();
        assert!(
            !text.contains(account),
            "funded account must be redacted: {text}"
        );
        assert!(
            !text.contains("matic"),
            "payment token must be redacted: {text}"
        );
        assert!(
            text.contains("<redacted>"),
            "expected a redaction marker: {text}"
        );
    }
    /// A gateway that announces a body it never delivers (headers promise
    /// Content-Length, connection dropped mid-body) surfaces a mid-stream error.
    /// That error must be rebuilt through the redaction boundary so a
    /// credential-bearing gateway URL never leaks into the public VerifyResult.
    #[tokio::test]
    async fn test_verify_anchor_interrupted_stream_error_is_masked() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = socket.read(&mut buf).await;
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                              content-length: 1000\r\n\r\n{\"certificate\":",
                        )
                        .await;
                    // Drop the connection mid-body: the promised length is never
                    // delivered, forcing a stream error on the client.
                    drop(socket);
                });
            }
        });
        let gateway = format!("http://{addr}/?token=SECRET");
        let client = reqwest::Client::new();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/gitlawb_test_placeholder")
            .expect("lazy pool creation should not fail");
        let db = crate::db::Db::for_testing(pool);
        let r = verify_anchor(&client, &gateway, "txid", &db, "did:key:zNODE")
            .await
            .expect("verify_anchor should return Ok for a stream error");
        assert!(!r.valid);
        let err_text = r.errors.join(" ");
        assert!(
            err_text.contains("failed to read response body"),
            "expected a masked stream error, got: {err_text}"
        );
        assert!(
            !err_text.contains("SECRET"),
            "gateway query token leaked through the stream error: {err_text}"
        );
    }
    /// The redaction helpers must scrub a raw URL (userinfo, token in the path)
    /// and every secret the node sent out of an error string, and the scrub
    /// must apply to remote bodies that reflect the request.
    #[test]
    fn redaction_helpers_scrub_urls_and_secrets() {
        let url = "https://user:pw@example.invalid/tx/matic";
        let display = "https://***@example.invalid/tx/matic";
        let body = format!(r#"{{"error":"rejected for zFundedAccount at {url}"}}"#);
        let err = remote_response_error(
            "Bundler upload",
            &StatusCode::INTERNAL_SERVER_ERROR,
            &body,
            url,
            display,
            &["zFundedAccount", "matic"],
        );
        let text = err.to_string();
        assert!(
            text.contains("Bundler upload returned 500"),
            "error should carry prefix and status: {text}"
        );
        assert!(
            !text.contains("zFundedAccount"),
            "funded account leaked: {text}"
        );
        assert!(!text.contains("matic"), "payment token leaked: {text}");
        assert!(!text.contains("user:pw"), "URL userinfo leaked: {text}");
        assert!(
            !text.contains("example.invalid/tx/matic"),
            "raw URL leaked: {text}"
        );
        assert!(
            text.contains("<redacted>"),
            "expected a redaction marker: {text}"
        );

        // A reqwest-style detail that embeds the raw URL is masked through the
        // same boundary (used for connection and mid-stream errors).
        let detail = format!("error sending request for url ({url})");
        let detail = redact_remote_detail(&detail, url, display, &["matic"]);
        assert!(!detail.contains("user:pw"), "URL userinfo leaked: {detail}");
        assert!(!detail.contains("matic"), "payment token leaked: {detail}");
        assert!(
            detail.contains("<redacted>"),
            "expected a redaction marker: {detail}"
        );
    }
}
