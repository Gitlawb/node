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

/// Issue a signed ref-update certificate for a successful push. The
/// live receive-pack handler calls this on every successful push.
///
/// `cert_id` is the deterministic id derived from `(request_id,
/// ref_name)` (see [`crate::db::ref_cert_id_for`]). It is required so
/// the recovery drain and the live handler produce the same primary
/// key: a live push followed by a recovery pass collapses to a
/// single cert row, and a re-push to the same `(repo, ref)` updates
/// the existing row's `old_sha` / `new_sha` / `pusher_did` /
/// `issued_at` / `signature` to the new transition while preserving
/// the original `id` (the `insert_ref_certificate` upsert is
/// keyed on `(repo_id, ref_name)` and only updates fields when the
/// new `issued_at` is strictly greater).
///
/// #26 Split PR 1 P1-B: the live handler routes through this
/// function (the upsert), NOT through
/// [`issue_ref_certificate_idempotent`] (DO NOTHING). The
/// idempotent variant is reserved for the recovery drain. Both
/// paths use the same deterministic `cert_id` so a re-pass is
/// always safe:
///
/// - Live handler → live upsert: re-push updates the row, preserves
///   the original `id`. The contract pinned by
///   `insert_ref_certificate_upserts_on_repo_ref` is restored.
/// - Live handler → recovery: live's `ON CONFLICT (id) DO UPDATE`
///   preserves the original `id`; the recovery's
///   `ON CONFLICT (repo_id, ref_name) DO NOTHING` is a no-op.
/// - Recovery → live handler: the recovery wrote a row with the
///   deterministic `id`; the live upsert (which preserves `id` and
///   only updates other fields when `issued_at` is strictly newer)
///   is a no-op for an equal-`issued_at` re-run and a refresh for
///   a strictly-newer one.
pub async fn issue_ref_certificate(
    state: &AppState,
    repo_id: &str,
    ref_name: &str,
    old_sha: &str,
    new_sha: &str,
    pusher_did: &str,
    cert_id: &str,
) -> Result<RefCertificate> {
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
