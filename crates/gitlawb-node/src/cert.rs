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
/// [`issue_ref_certificate_idempotent`] (DO NOTHING). After the
/// reviewer-1 round-2 fix, the recovery drain also routes through
/// this function (P1: refresh a stale cert), so both paths use the
/// same deterministic `cert_id` and the same upsert. A re-pass is
/// always safe:
///
/// - Live handler → live upsert: re-push updates the row, preserves
///   the original `id`. The contract pinned by
///   `insert_ref_certificate_upserts_on_repo_ref` is restored.
/// - Live handler → recovery: live's `ON CONFLICT (id) DO UPDATE`
///   preserves the original `id`; the recovery's same upsert is
///   a no-op for an equal-`issued_at` re-run and a refresh for a
///   strictly-newer one.
/// - Recovery → live handler: the recovery wrote a row with the
///   deterministic `id`; the live upsert (which preserves `id` and
///   only updates other fields when `issued_at` is strictly newer)
///   is a no-op for an equal-`issued_at` re-run and a refresh for
///   a strictly-newer one.
#[allow(dead_code)] // round-trip test in db/mod.rs pins the upsert contract; the live path and the drain use issue_ref_certificate_with_issued_at
pub async fn issue_ref_certificate(
    state: &AppState,
    repo_id: &str,
    ref_name: &str,
    old_sha: &str,
    new_sha: &str,
    pusher_did: &str,
    cert_id: &str,
) -> Result<RefCertificate> {
    issue_ref_certificate_with_issued_at(
        state, repo_id, ref_name, old_sha, new_sha, pusher_did, cert_id, None,
    )
    .await
}

/// #26 Split PR 1 round 4 — variant that lets the caller stamp the
/// cert's `issued_at` with a transition-time timestamp instead of
/// `Utc::now()`. The recovery drain passes the persisted
/// `row.created_at` so a replay after a later live cert does not
/// outrank the live cert in the `EXCLUDED.issued_at >
/// ref_certificates.issued_at` upsert guard.
///
/// The live handler uses the default `issue_ref_certificate` (no
/// override), which keeps `Utc::now()` — the reviewer's invariant
/// is that `issued_at` reflects the transition time, and for a
/// live push the transition time and the wall-clock are the same.
///
/// `issued_at_override` is honored verbatim; passing a value not in
/// RFC 3339 form is a logic bug (the upsert will mis-order), so
/// callers must use the row's persisted `created_at`.
///
/// # Clippy allow — too many arguments
/// This is the explicit "stamp a transition-time `issued_at`"
/// variant of `issue_ref_certificate`. The drain
/// (`durable_outbox::derive_one`) is the in-crate caller; the
/// test `replay_of_stale_row_does_not_overwrite_live_cert_b` pins
/// the contract that a recovery replay's `issued_at` does NOT
/// outrank a later live cert. Adding a struct-arg would be a
/// larger refactor for two callers (live + drain) and obscure the
/// parallel to `issue_ref_certificate` (which is `#[allow]`'d for
/// the same reason historically).
#[allow(clippy::too_many_arguments)]
pub async fn issue_ref_certificate_with_issued_at(
    state: &AppState,
    repo_id: &str,
    ref_name: &str,
    old_sha: &str,
    new_sha: &str,
    pusher_did: &str,
    cert_id: &str,
    issued_at_override: Option<String>,
) -> Result<RefCertificate> {
    let cert = build_ref_certificate(
        state,
        repo_id,
        ref_name,
        old_sha,
        new_sha,
        pusher_did,
        Some(cert_id.to_string()),
        issued_at_override,
    )
    .await?;
    state.db.insert_ref_certificate(&cert).await
}

/// #26 Split PR 1 — idempotent variant.
///
/// `cert_id` is the deterministic id derived from
/// `(request_id, ref_name)` so a recovery re-pass against the same
/// transition produces the same primary key. The insert uses
/// `ON CONFLICT (repo_id, ref_name) DO NOTHING` (the existing
/// `insert_ref_certificate_idempotent` helper), so the function
/// returns `None` if a live-path cert already exists for the
/// `(repo_id, ref_name)` pair, and `Some(cert)` if it wrote a new
/// one.
///
/// Retained for any future caller that wants DO-NOTHING semantics
/// (e.g. an explicit "never overwrite" handler); the live and
/// recovery paths both use [`issue_ref_certificate`] (the upsert)
/// after the P1 fix in #26 Split 1 round 2.
#[allow(dead_code)]
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
        None,
    )
    .await?;
    state.db.insert_ref_certificate_idempotent(&cert).await
}

/// Shared cert construction: build the JSON payload, sign it with the
/// node key, and assemble the `RefCertificate` row. `cert_id_override`
/// lets the recovery path plug in a deterministic id; the live path
/// passes `None` and gets a fresh UUID. `issued_at_override` lets
/// the recovery path stamp the cert with the original transition
/// time so the upsert's `issued_at > issued_at` guard correctly
/// orders transitions regardless of write order.
#[allow(clippy::too_many_arguments)]
async fn build_ref_certificate(
    state: &AppState,
    repo_id: &str,
    ref_name: &str,
    old_sha: &str,
    new_sha: &str,
    pusher_did: &str,
    cert_id_override: Option<String>,
    issued_at_override: Option<String>,
) -> Result<RefCertificate> {
    let node_did = state.node_did.to_string();
    // P1 (reviewer-1 round 4): when the caller passes a transition-
    // time `issued_at` (the recovery drain passes `row.created_at`),
    // use it verbatim so the upsert's per-column guard
    // `EXCLUDED.issued_at > ref_certificates.issued_at` correctly
    // orders transitions regardless of write order. The live handler
    // passes `None` and gets `Utc::now()` — for a live push the
    // transition time and the wall-clock are the same.
    let issued_at = issued_at_override.unwrap_or_else(|| Utc::now().to_rfc3339());

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
