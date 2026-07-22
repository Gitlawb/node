use anyhow::Result;
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::db::RefCertificate;
use crate::state::AppState;

/// Issue a signed ref-update certificate for a successful push.
///
/// Acquires a per-repo advisory lock to atomically allocate the chain
/// sequence number. Retries once on unique-constraint violation (safety
/// net for the rare case the advisory lock yields a false collision).
pub async fn issue_ref_certificate(
    state: &AppState,
    repo_id: &str,
    ref_name: &str,
    old_sha: &str,
    new_sha: &str,
    pusher_did: &str,
    pusher_sig: Option<String>,
    signature_input: Option<String>,
    content_digest: Option<String>,
    request_path: Option<String>,
) -> Result<RefCertificate> {
    // Serialize cert issuance per repo to avoid seq collisions
    state.db.lock_repo_cert_issuance(repo_id).await?;

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
        node_did: node_did.clone(),
        signature,
        issued_at: issued_at.clone(),
        seq,
        prev,
        pusher_sig,
        signature_input,
        content_digest,
        request_path,
    };

    // Persist and return the row as it exists in the database.
    // Under the advisory lock the INSERT should succeed; if a unique
    // violation nevertheless occurs, retry once.
    match state.db.insert_ref_certificate(&cert).await {
        Ok(c) => Ok(c),
        Err(e) => {
            // Check for PostgreSQL unique violation (code 23505)
            let err_str = e.to_string();
            if err_str.contains("23505") || err_str.contains("unique") {
                // Re-read the predecessor and retry with a fresh seq
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
                    "pusher_sig": cert.pusher_sig,
                });
                let payload_bytes = serde_json::to_vec(&payload)?;
                let signature = state.node_keypair.sign_b64(&payload_bytes);
                let retry_cert = RefCertificate {
                    seq,
                    prev,
                    signature,
                    ..cert
                };
                state.db.insert_ref_certificate(&retry_cert).await
            } else {
                Err(e)
            }
        }
    }
}
