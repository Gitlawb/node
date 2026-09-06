//! Outbound webhook delivery.
//!
//! Events fired:
//!   pull_request.opened   — PR created
//!   pull_request.reviewed — review submitted
//!   pull_request.merged   — PR merged
//!   pull_request.closed   — PR closed without merging
//!   push                  — branch pushed
//!
//! Payload headers:
//!   Content-Type: application/json
//!   X-Gitlawb-Event: <event>
//!   X-Gitlawb-Delivery: <uuid>
//!   X-Gitlawb-Signature-256: sha256=<hmac-sha256-hex>  (only if secret set)

use std::sync::Arc;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::db::Db;

type HmacSha256 = Hmac<Sha256>;

/// Compute `sha256=<hex>` HMAC signature for a webhook payload.
fn sign_payload(secret: &str, payload: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(payload);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

/// Fire webhooks for `event` on `repo_id`. Spawns background tasks — never blocks.
pub fn fire_event(
    db: Arc<Db>,
    http_client: Arc<reqwest::Client>,
    repo_id: &str,
    event: &str,
    payload: serde_json::Value,
) {
    fire_event_occurrence(db, http_client, repo_id, event, payload, None, None);
}

/// Occurrence-keyed variant: at most one delivery per
/// `(request_id, ref_name, hook)` is spawned; concurrent executors
/// collapse via the `webhook_deliveries` ledger. Best-effort on crash
/// (ledger is claimed before spawn), which the PR scope allows.
pub fn fire_event_occurrence(
    db: Arc<Db>,
    http_client: Arc<reqwest::Client>,
    repo_id: &str,
    event: &str,
    payload: serde_json::Value,
    request_id: Option<&str>,
    ref_name: Option<&str>,
) {
    let repo_id = repo_id.to_string();
    let event = event.to_string();
    let request_id = request_id.map(|s| s.to_string());
    let ref_name = ref_name.map(|s| s.to_string());
    tokio::spawn(async move {
        fire_event_async_occurrence(
            db,
            http_client,
            &repo_id,
            &event,
            payload,
            request_id.as_deref(),
            ref_name.as_deref(),
        )
        .await;
    });
}

async fn fire_event_async_occurrence(
    db: Arc<Db>,
    http_client: Arc<reqwest::Client>,
    repo_id: &str,
    event: &str,
    payload: serde_json::Value,
    request_id: Option<&str>,
    ref_name: Option<&str>,
) {
    let hooks = match db.list_webhooks_for_event(repo_id, event).await {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(err = %e, "failed to list webhooks for event {event}");
            return;
        }
    };

    if hooks.is_empty() {
        return;
    }

    let payload_bytes = match serde_json::to_vec(&payload) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(err = %e, "failed to serialize webhook payload");
            return;
        }
    };

    for hook in hooks {
        let client = Arc::clone(&http_client);
        let event_name = event.to_string();
        let bytes = payload_bytes.clone();
        // Stable occurrence delivery key when request context exists;
        // random UUID otherwise (legacy callers without occurrence).
        let delivery_id = match (request_id, ref_name) {
            (Some(req), Some(r)) => crate::db::deterministic_id(&["webhook", req, r, &hook.id]),
            _ => uuid::Uuid::new_v4().to_string(),
        };
        // Claim before spawn so concurrent executors collapse to one
        // delivery per occurrence. Failures to record fall back to
        // sending (legacy best-effort) rather than dropping.
        if request_id.is_some() {
            match db
                .clone()
                .claim_webhook_delivery(&delivery_id, request_id.unwrap_or(""), repo_id, event)
                .await
            {
                Ok(true) => {}
                Ok(false) => continue,
                Err(_) => {}
            }
        }

        let db_for_mark = db.clone();
        tokio::spawn(async move {
            let delivery_for_mark = delivery_id.clone();
            let signature = hook.secret.as_deref().map(|s| sign_payload(s, &bytes));

            let mut req = client
                .post(&hook.url)
                .header("Content-Type", "application/json")
                .header("X-Gitlawb-Event", &event_name)
                .header("X-Gitlawb-Delivery", &delivery_id)
                .body(bytes);

            if let Some(sig) = signature {
                req = req.header("X-Gitlawb-Signature-256", sig);
            }

            match req.send().await {
                Ok(resp) => {
                    let result_label = if resp.status().is_success() {
                        "ok"
                    } else {
                        "http_error"
                    };
                    crate::metrics::record_webhook_delivery(result_label);
                    // Any HTTP response proves the delivery fired; mark
                    // sent so the ledger never claims an unsent delivery.
                    // Network errors stay pending for stale-reclaim.
                    let _ = db_for_mark.mark_webhook_sent(&delivery_for_mark).await;
                    tracing::info!(
                        url = %hook.url,
                        event = %event_name,
                        status = %resp.status(),
                        "webhook delivered"
                    )
                }
                Err(e) => {
                    crate::metrics::record_webhook_delivery("network_error");
                    tracing::warn!(
                        url = %hook.url,
                        event = %event_name,
                        err = %e,
                        "webhook delivery failed"
                    )
                }
            }
        });
    }
}
