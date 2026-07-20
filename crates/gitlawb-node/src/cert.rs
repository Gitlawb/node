//! Certificate issuance for ref updates.
//!
//! When a push lands, the node signs a receipt proving the commit was
//! accepted. This receipt is a `RefCertificate` stored in the DB and
//! accessible via the API.

use anyhow::Result;
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::db::RefCertificate;
use crate::state::AppState;

/// Issue a signed ref-update certificate for a successful push.
///
/// Builds a canonical JSON payload, signs it with the node's Ed25519 key,
/// persists the certificate, and returns it.
pub async fn issue_ref_certificate(
    state: &AppState,
    repo_id: &str,
    ref_name: &str,
    old_sha: &str,
    new_sha: &str,
    pusher_did: &str,
    pusher_sig: Option<String>,
) -> Result<RefCertificate> {
    let node_did = state.node_did.to_string();
    let issued_at = Utc::now().to_rfc3339();

    // Look up the previous certificate to chain from it.
    let prev_cert = state.db.get_most_recent_cert(repo_id).await?;
    let seq = match &prev_cert {
        Some(c) => c.seq + 1,
        None => 1,
    };
    let prev = match &prev_cert {
        Some(c) => {
            let prev_payload = serde_json::json!({
                "repo_id": c.repo_id,
                "ref":     c.ref_name,
                "old":     c.old_sha,
                "new":     c.new_sha,
                "pusher":  c.pusher_did,
                "node":    c.node_did,
                "ts":      c.issued_at,
            });
            let prev_bytes = serde_json::to_vec(&prev_payload)?;
            hex::encode(Sha256::digest(&prev_bytes))
        }
        None => "0".repeat(64),
    };

    // Build the canonical signing payload with chain info.
    let payload = serde_json::json!({
        "repo_id":    repo_id,
        "ref":        ref_name,
        "old":        old_sha,
        "new":        new_sha,
        "pusher":     pusher_did,
        "node":       node_did,
        "ts":         issued_at,
        "seq":        seq,
        "prev":       prev,
        "pusher_sig": pusher_sig,
    });
    let payload_bytes = serde_json::to_vec(&payload)?;

    let signature = state.node_keypair.sign_b64(&payload_bytes);

    let cert = RefCertificate {
        id: Uuid::new_v4().to_string(),
        repo_id: repo_id.to_string(),
        ref_name: ref_name.to_string(),
        old_sha: old_sha.to_string(),
        new_sha: new_sha.to_string(),
        pusher_did: pusher_did.to_string(),
        node_did,
        signature,
        issued_at,
        seq,
        prev,
        pusher_sig,
    };

    // Persist and return the row as it exists in the database (on a
    // conflict the existing row survives when it is newer).
    state.db.insert_ref_certificate(&cert).await
}
