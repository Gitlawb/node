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
///
/// For durable outbox usage, call `claim_webhook_delivery_before_spawn` first
/// to claim deliveries synchronously, then call this with `skip_claim=true` and
/// the claimed hook IDs to only spawn HTTP POST for claimed hooks.
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
            false,
            None,
        )
        .await;
    });
}

/// Variant for durable outbox: only spawn HTTP POST for previously claimed hooks.
#[allow(clippy::too_many_arguments)]
pub fn fire_event_occurrence_with_claimed_hooks(
    db: Arc<Db>,
    http_client: Arc<reqwest::Client>,
    repo_id: &str,
    event: &str,
    payload: serde_json::Value,
    request_id: Option<&str>,
    ref_name: Option<&str>,
    claimed_hook_ids: Vec<String>,
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
            true,
            Some(claimed_hook_ids),
        )
        .await;
    });
}

/// Claim webhook delivery before spawning HTTP POST.
/// Returns the list of hook IDs that were successfully claimed.
/// This synchronous claim phase must be awaited before child deletion to prevent
/// permanent webhook loss on crash between deletion and claim.
pub async fn claim_webhook_delivery_before_spawn(
    db: Arc<Db>,
    repo_id: &str,
    event: &str,
    request_id: Option<&str>,
    ref_name: Option<&str>,
) -> Vec<String> {
    let mut claimed_hooks = Vec::new();

    // Only claim when we have occurrence context (request_id + ref_name)
    if let (Some(req), Some(r)) = (request_id, ref_name) {
        let hooks = match db.list_webhooks_for_event(repo_id, event).await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(err = %e, "failed to list webhooks for event {event}");
                return claimed_hooks;
            }
        };

        for hook in hooks {
            let delivery_id = crate::db::deterministic_id(&["webhook", req, r, &hook.id]);
            match db
                .claim_webhook_delivery(&delivery_id, req, repo_id, event)
                .await
            {
                Ok(true) => claimed_hooks.push(hook.id),
                Ok(false) => continue, // Already claimed
                Err(_) => continue,
            }
        }
    }

    claimed_hooks
}

#[allow(clippy::too_many_arguments)]
async fn fire_event_async_occurrence(
    db: Arc<Db>,
    http_client: Arc<reqwest::Client>,
    repo_id: &str,
    event: &str,
    payload: serde_json::Value,
    request_id: Option<&str>,
    ref_name: Option<&str>,
    skip_claim: bool,
    claimed_hook_ids: Option<Vec<String>>,
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
        // Skip claim if already done by caller (durable_outbox path).
        if !skip_claim && request_id.is_some() {
            match db
                .clone()
                .claim_webhook_delivery(&delivery_id, request_id.unwrap_or(""), repo_id, event)
                .await
            {
                Ok(true) => {}
                Ok(false) => continue,
                Err(_) => {}
            }
        } else if skip_claim {
            // Skip hooks that weren't claimed by the caller
            if let Some(ref claimed) = claimed_hook_ids {
                if !claimed.contains(&hook.id) {
                    continue;
                }
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
