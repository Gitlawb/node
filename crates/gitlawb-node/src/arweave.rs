//! Arweave permanent anchoring via Bundler (Irys).
//!
//! Every ref-update event (push) is anchored to Arweave through the Bundler
//! network. The anchor payload is a small JSON object containing:
//!
//!   { repo, owner_did, ref_name, old_sha, new_sha, cid, timestamp, node_did }
//!
//! Irys allows free uploads for data < 100 KiB on both devnet and mainnet
//! (via Turbo). No wallet is required for payloads under the free threshold.
//!
//! Set `GITLAWB_BUNDLER_URL` (deprecated name: `GITLAWB_IRYS_URL`) to override the default endpoint:
//!   - devnet (free, no cost): https://devnet.irys.xyz
//!   - mainnet:                https://node2.irys.xyz
//!
//! Configure `GITLAWB_ARWEAVE_GATEWAY` to override the gateway used for resolving anchors
//! (defaults to https://arweave.net).
//!
//! Each anchor returns a transaction ID (43-char base58 string).
//! The permanent Arweave URL is: <gateway>/<tx_id>
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

/// Anchor a ref-update to Arweave via Irys.
///
/// Returns the Irys/Arweave transaction ID on success.
/// Returns `Ok("")` if `bundler_url` is empty (anchoring disabled).
pub async fn anchor_ref_update(
    client: &reqwest::Client,
    bundler_url: &str,
    anchor: &RefAnchor,
) -> Result<String> {
    if bundler_url.is_empty() {
        return Ok(String::new());
    }

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

    // Irys upload endpoint
    let url = format!("{}/v1/tx", bundler_url.trim_end_matches('/'));

    let resp = client
        .post(&url)
        .header("Content-Type", "application/octet-stream")
        .header("x-bundler-tags", build_tags_header(anchor))
        .body(body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Bundler upload failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Bundler returned {status}: {body}"));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("failed to parse Bundler response: {e}"))?;

    // Bundler response: {"id": "<data_item_id>", "timestamp": ..., "version": ...}
    let tx_id = json["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no 'id' in Bundler response: {json}"))?
        .to_string();

    tracing::info!(
        repo = %anchor.repo,
        ref_name = %anchor.ref_name,
        new_sha = %anchor.new_sha,
        tx_id = %tx_id,
        "anchored ref update to Arweave via bundler"
    );

    Ok(tx_id)
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
/// Returns the Arweave transaction ID, or `Ok("")` when `bundler_url` is empty
/// (anchoring disabled) or there are no blobs to anchor.
pub async fn anchor_encrypted_manifest(
    client: &reqwest::Client,
    bundler_url: &str,
    manifest: &EncryptedManifest<'_>,
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
    let url = format!("{}/v1/tx", bundler_url.trim_end_matches('/'));

    let resp = client
        .post(&url)
        .header("Content-Type", "application/octet-stream")
        .header("x-bundler-tags", build_manifest_tags_header(manifest))
        .body(body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Bundler upload failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Bundler returned {status}: {body}"));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("failed to parse Bundler response: {e}"))?;

    let tx_id = json["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no 'id' in Bundler response: {json}"))?
        .to_string();

    tracing::info!(
        repo = %manifest.repo,
        tx_id = %tx_id,
        blobs = manifest.blobs.len(),
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

/// Build the bundler tag header for an encrypted-blob manifest. `Repo` and `Schema`
/// are the tags the `gl` recovery query filters on.
fn build_manifest_tags_header(manifest: &EncryptedManifest<'_>) -> String {
    [
        "App-Name:gitlawb".to_string(),
        "Schema:gitlawb/encrypted-manifest/v1".to_string(),
        format!("Repo:{}", sanitize_tag(manifest.repo)),
        format!("Owner-DID:{}", sanitize_tag(manifest.owner_did)),
        format!("Node-DID:{}", sanitize_tag(manifest.node_did)),
    ]
    .join(",")
}

/// Build the bundler tag header value for Arweave indexing.
/// Format: comma-separated "name:value" pairs.
fn build_tags_header(anchor: &RefAnchor) -> String {
    [
        "App-Name:gitlawb".to_string(),
        "Schema:gitlawb/ref-update/v1".to_string(),
        format!("Repo:{}", sanitize_tag(&anchor.repo)),
        format!("Ref:{}", sanitize_tag(&anchor.ref_name)),
        format!("SHA:{}", &anchor.new_sha[..anchor.new_sha.len().min(16)]),
        format!("Node-DID:{}", sanitize_tag(&anchor.node_did)),
    ]
    .join(",")
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
    let url = format!("{}/{}", gateway_url.trim_end_matches('/'), tx_id);
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Arweave gateway connection failed: {e}");
            return Ok(VerifyResult {
                valid: false,
                anchor: serde_json::Value::Null,
                certificate: None,
                errors: vec![format!("Arweave gateway connection failed: {e}")],
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
                return Ok(VerifyResult {
                    valid: false,
                    anchor: serde_json::Value::Null,
                    certificate: None,
                    errors: vec![format!("failed to read response body: {e}")],
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
                tracing::warn!(
                    repo_id = %c.repo_id,
                    "cannot corroborate anchor repo/owner_did — repo_id not found in node database"
                );
            }
            Err(e) => {
                tracing::warn!("repo lookup failed for {}: {e}", c.repo_id);
            }
        }

        // 1. Verify node signature on the certificate payload.
        //    Certificates produced after this PR use a 13-field payload
        //    that includes seq, prev, and proof fields.  Pre-PR certificates
        //    used a 7-field payload (repo_id, ref, old, new, pusher, node, ts)
        //    with NULL proof fields.  Try the 13-field check first; if it
        //    fails and all proof fields are NULL, fall back to 7-field.
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

        // Try 13-field payload first.
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

        let mut legacy_7_field_verified = false;
        if proof_fields_null && sig_valid_13.is_err() {
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
            if gitlawb_core::identity::verify(&verifying_key, &payload_bytes_7, &sig_array).is_ok()
            {
                legacy_7_field_verified = true;
            } else {
                errors.push("certificate signature verification failed (7-field)".to_string());
            }
        } else if let Err(e) = sig_valid_13 {
            errors.push(format!("certificate signature verification failed: {e}"));
        }

        // 1b. Corroborate chain position for legacy certificates.
        //    The 7-field fallback covers only repo_id, ref, old, new, pusher,
        //    node, ts.  seq and prev are NOT covered on that path, so a tampered
        //    legacy cert could otherwise pass with a blanket valid: true.  Look
        //    up the node's own stored row and require seq/prev agreement.
        if legacy_7_field_verified {
            match db.get_ref_certificate(&c.id).await {
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
                    errors.push(format!(
                        "certificate {} not found in node database — cannot corroborate legacy chain position",
                        c.id
                    ));
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

    #[tokio::test]
    async fn test_anchor_noop_when_url_empty() {
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
        let result = anchor_ref_update(&client, "", &anchor).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }

    #[tokio::test]
    async fn test_anchor_success() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/v1/tx")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"7xGpIoHUQ8j9GhD3Y2mKzP1NsVtXwRcFe4bEaLnMuOk","timestamp":1710000000000,"version":"1.0.0"}"#)
            .create_async()
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

        let result = anchor_ref_update(&client, &server.url(), &anchor).await;
        assert!(result.is_ok(), "anchor should succeed: {result:?}");
        assert_eq!(
            result.unwrap(),
            "7xGpIoHUQ8j9GhD3Y2mKzP1NsVtXwRcFe4bEaLnMuOk"
        );
        _mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_anchor_body_carries_real_old_sha() {
        // The anchored body must serialize the real old→new transition the
        // node was handed, never a zero placeholder. Regression guard for the
        // push handler that used to hardcode `old_sha` to 64 zeros (#26).
        let mut server = mockito::Server::new_async().await;
        let real_old = "1111111111111111111111111111111111111111";
        let real_new = "2222222222222222222222222222222222222222";
        let _mock = server
            .mock("POST", "/v1/tx")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::PartialJsonString(format!(r#"{{"old_sha":"{real_old}"}}"#)),
                mockito::Matcher::PartialJsonString(format!(r#"{{"new_sha":"{real_new}"}}"#)),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"TX_REAL_OLD_SHA","timestamp":1710000000000,"version":"1.0.0"}"#)
            .create_async()
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

        let result = anchor_ref_update(&client, &server.url(), &anchor).await;
        assert_eq!(result.unwrap(), "TX_REAL_OLD_SHA");
        // The mock only matches when the posted JSON carries both real SHAs.
        _mock.assert_async().await;
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
        let blobs = vec![("oid1".to_string(), "cid1".to_string())];
        let m = EncryptedManifest {
            repo: "alice/r",
            owner_did: "did:key:zO",
            node_did: "did:key:zN",
            timestamp: "2026-06-11T00:00:00Z",
            blobs: &blobs,
        };
        assert_eq!(
            anchor_encrypted_manifest(&client, "", &m).await.unwrap(),
            ""
        );
    }

    #[tokio::test]
    async fn test_manifest_anchor_noop_when_no_blobs() {
        let client = reqwest::Client::new();
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
            anchor_encrypted_manifest(&client, "https://example.invalid", &m)
                .await
                .unwrap(),
            ""
        );
    }

    #[tokio::test]
    async fn test_manifest_anchor_success() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/v1/tx")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"MANIFESTTX123","timestamp":1710000000000,"version":"1.0.0"}"#)
            .create_async()
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
        let r = anchor_encrypted_manifest(&client, &server.url(), &m).await;
        assert_eq!(r.unwrap(), "MANIFESTTX123");
        _mock.assert_async().await;
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

        let result = verify_anchor(&client, &server.url(), "test-tx", &db, "did:key:zNODE").await;
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
                .any(|e| e.contains("does not match this node") || e.contains("invalid node DID")),
            "Expected issuer or DID error in: {:?}",
            verify_result.errors
        );
    }

    /// A true end-to-end accept: a cert signed by a real node keypair over a
    /// real 13-field payload, with a real RFC 9421 pusher proof, served through
    /// a mock gateway, must verify to `valid: true` with empty errors.
    #[tokio::test]
    async fn test_verify_anchor_accepts_authentic_13_field_certificate() {
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

        // Build a real RFC 9421 pusher proof over an arbitrary push body.
        let request_path = "/repo-uuid.git/git-receive-pack";
        let signed =
            gitlawb_core::http_sig::sign_request(&pusher_kp, "POST", request_path, b"push-body");
        // The stored pusher_sig is the raw STANDARD base64 of the 64-byte
        // signature, unwrapped from the `sig1=:...:` header form.
        let pusher_sig = signed
            .signature
            .strip_prefix("sig1=:")
            .and_then(|s| s.strip_suffix(':'))
            .unwrap()
            .to_string();

        // Sign the 13-field payload exactly as the node does.
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

        let cert = crate::db::RefCertificate {
            id: "cert-accept-1".to_string(),
            repo_id: repo_id.to_string(),
            ref_name: ref_name.to_string(),
            old_sha: old_sha.clone(),
            new_sha: new_sha.to_string(),
            pusher_did,
            node_did: node_did.clone(),
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
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/gitlawb_test_placeholder")
            .expect("lazy pool creation should not fail");
        let db = crate::db::Db::for_testing(pool);

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

        // The cert id is not present in the (lazy) node database, so the
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
                .any(|e| e.contains("not found in node database")
                    || e.contains("error looking up certificate")),
            "expected a corroboration error, got: {:?}",
            r.errors
        );
        _mock.assert_async().await;
    }
}
