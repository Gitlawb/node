//! Certificate issuance for ref updates.
//!
//! When a push lands, the node signs a receipt proving the commit was
//! accepted. This receipt is a `RefCertificate` stored in the DB and
//! accessible via the API.

use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;

use crate::db::RefCertificate;
use crate::state::AppState;

/// Issue a signed ref-update certificate for a successful push.
///
/// Builds a canonical JSON payload, signs it with the node's Ed25519 key,
/// persists the certificate, and returns it.
///
/// #26 Split PR 1: the live handler now uses
/// [`issue_ref_certificate_idempotent`] so the cert id is deterministic
/// and recovery re-derives the same primary key. This legacy entry
/// point remains for callers that prefer a fresh UUID per cert (it
/// keeps the older `insert_ref_certificate` upsert semantics); Split
/// PR 3 owns the cert/CLI compatibility decision of whether to keep
/// it or remove it.
#[allow(dead_code)] // kept for the PR 3 cert/CLI compat pass
pub async fn issue_ref_certificate(
    state: &AppState,
    repo_id: &str,
    ref_name: &str,
    old_sha: &str,
    new_sha: &str,
    pusher_did: &str,
) -> Result<RefCertificate> {
    let cert =
        build_ref_certificate(state, repo_id, ref_name, old_sha, new_sha, pusher_did, None).await?;
    state.db.insert_ref_certificate(&cert).await
}

/// #26 Split PR 1 — idempotent variant used by the recovery drain.
///
/// `cert_id` is the deterministic id derived from
/// `(request_id, ref_name)` so a recovery re-pass against the same
/// transition produces the same primary key. The insert uses
/// `ON CONFLICT (repo_id, ref_name) DO NOTHING` (the existing
/// `insert_ref_certificate_idempotent` helper), so the function
/// returns `None` if a live-path cert already exists for the
/// `(repo_id, ref_name)` pair, and `Some(cert)` if it wrote a new
/// one. Either way, exactly one cert row exists for the transition.
pub async fn issue_ref_certificate_idempotent(
    state: &AppState,
    repo_id: &str,
    ref_name: &str,
    old_sha: &str,
    new_sha: &str,
    pusher_did: &str,
    cert_id: &str,
) -> Result<Option<RefCertificate>> {
    let cert = build_ref_certificate(
        state,
        repo_id,
        ref_name,
        old_sha,
        new_sha,
        pusher_did,
        Some(cert_id.to_string()),
    )
    .await?;
    state.db.insert_ref_certificate_idempotent(&cert).await
}

/// Shared cert construction: build the JSON payload, sign it with the
/// node key, and assemble the `RefCertificate` row. `cert_id_override`
/// lets the recovery path plug in a deterministic id; the live path
/// passes `None` and gets a fresh UUID.
async fn build_ref_certificate(
    state: &AppState,
    repo_id: &str,
    ref_name: &str,
    old_sha: &str,
    new_sha: &str,
    pusher_did: &str,
    cert_id_override: Option<String>,
) -> Result<RefCertificate> {
    let node_did = state.node_did.to_string();
    let issued_at = Utc::now().to_rfc3339();

    // Build the canonical signing payload.
    let payload = serde_json::json!({
        "repo_id": repo_id,
        "ref":     ref_name,
        "old":     old_sha,
        "new":     new_sha,
        "pusher":  pusher_did,
        "node":    node_did,
        "ts":      issued_at,
    });
    let payload_bytes = serde_json::to_vec(&payload)?;

    let signature = state.node_keypair.sign_b64(&payload_bytes);

    let id = cert_id_override.unwrap_or_else(|| Uuid::new_v4().to_string());
    Ok(RefCertificate {
        id,
        repo_id: repo_id.to_string(),
        ref_name: ref_name.to_string(),
        old_sha: old_sha.to_string(),
        new_sha: new_sha.to_string(),
        pusher_did: pusher_did.to_string(),
        node_did,
        signature,
        issued_at,
    })
}
