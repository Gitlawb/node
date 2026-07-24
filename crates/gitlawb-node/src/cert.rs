use std::ops::DerefMut;

use anyhow::Result;
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::db::RefCertificate;
use crate::state::AppState;

/// Build the canonical signing payload for a certificate.
#[allow(clippy::too_many_arguments)]
fn cert_payload(
    repo_id: &str,
    ref_name: &str,
    old_sha: &str,
    new_sha: &str,
    pusher_did: &str,
    node_did: &str,
    issued_at: &str,
    seq: i64,
    prev: &str,
    pusher_sig: Option<String>,
    signature_input: Option<String>,
    content_digest: Option<String>,
    request_path: Option<String>,
) -> serde_json::Value {
    serde_json::json!({
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
        "signature_input": signature_input,
        "content_digest": content_digest,
        "request_path": request_path,
    })
}

/// Compute the SHA-256 prev hash from a predecessor certificate.
fn prev_hash(c: &RefCertificate) -> Result<String> {
    let prev_payload = serde_json::json!({
        "repo_id": c.repo_id,
        "ref": c.ref_name,
        "old": c.old_sha,
        "new": c.new_sha,
        "pusher": c.pusher_did,
        "node": c.node_did,
        "ts": c.issued_at,
    });
    let prev_bytes = serde_json::to_vec(&prev_payload)?;
    Ok(hex::encode(Sha256::digest(&prev_bytes)))
}

/// Attempt a single cert-issuance within an active transaction.
#[allow(clippy::too_many_arguments)]
async fn issue_once(
    state: &AppState,
    repo_id: &str,
    ref_name: &str,
    old_sha: &str,
    new_sha: &str,
    pusher_did: &str,
    pusher_sig: &Option<String>,
    signature_input: &Option<String>,
    content_digest: &Option<String>,
    request_path: &Option<String>,
    conn: &mut sqlx::postgres::PgConnection,
) -> Result<RefCertificate> {
    // Look up the previous certificate to chain from it.
    let prev_cert = state.db.get_most_recent_cert_tx(repo_id, conn).await?;
    let seq = prev_cert.as_ref().map_or(1, |c| c.seq + 1);
    let prev = match prev_cert.as_ref() {
        Some(c) => prev_hash(c)?,
        None => "0".repeat(64),
    };

    let node_did = state.node_did.to_string();
    let issued_at = Utc::now().to_rfc3339();

    let payload = cert_payload(
        repo_id,
        ref_name,
        old_sha,
        new_sha,
        pusher_did,
        &node_did,
        &issued_at,
        seq,
        &prev,
        pusher_sig.clone(),
        signature_input.clone(),
        content_digest.clone(),
        request_path.clone(),
    );
    let payload_bytes = serde_json::to_vec(&payload)?;
    let signature = state.node_keypair.sign_b64(&payload_bytes);

    let cert = RefCertificate {
        id: Uuid::new_v4().to_string(),
        repo_id: repo_id.to_string(),
        ref_name: ref_name.to_string(),
        old_sha: old_sha.to_string(),
        new_sha: new_sha.to_string(),
        pusher_did: pusher_did.to_string(),
        node_did: node_did.to_string(),
        signature,
        issued_at: issued_at.to_string(),
        seq,
        prev,
        pusher_sig: pusher_sig.clone(),
        signature_input: signature_input.clone(),
        content_digest: content_digest.clone(),
        request_path: request_path.clone(),
    };

    state.db.insert_ref_certificate_tx(&cert, conn).await
}

/// Issue a signed ref-update certificate for a successful push.
///
/// Acquires a per-repo advisory lock to atomically allocate the chain
/// sequence number within a single database transaction, preventing race
/// conditions with concurrent pushes to the same repository.
#[allow(clippy::too_many_arguments)]
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
    let mut tx = state.db.pool().begin().await?;

    // Serialize cert issuance per repo within the transaction so the
    // advisory lock is held for the entire lock → lookup → insert sequence.
    state
        .db
        .lock_repo_cert_issuance_tx(repo_id, tx.deref_mut())
        .await?;

    let result = issue_once(
        state,
        repo_id,
        ref_name,
        old_sha,
        new_sha,
        pusher_did,
        &pusher_sig,
        &signature_input,
        &content_digest,
        &request_path,
        &mut tx,
    )
    .await;

    match result {
        Ok(cert) => {
            tx.commit().await?;
            Ok(cert)
        }
        Err(e) => {
            // Rollback the failed attempt before retrying
            tx.rollback().await?;
            let err_str = e.to_string();
            if err_str.contains("23505") || err_str.contains("unique") {
                // Retry once with a fresh transaction
                let mut tx = state.db.pool().begin().await?;
                state
                    .db
                    .lock_repo_cert_issuance_tx(repo_id, tx.deref_mut())
                    .await?;
                let cert = issue_once(
                    state,
                    repo_id,
                    ref_name,
                    old_sha,
                    new_sha,
                    pusher_did,
                    &pusher_sig,
                    &signature_input,
                    &content_digest,
                    &request_path,
                    &mut tx,
                )
                .await?;
                tx.commit().await?;
                Ok(cert)
            } else {
                Err(e)
            }
        }
    }
}
