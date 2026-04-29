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
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
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
    let repo_id = repo_id.to_string();
    let event = event.to_string();
    tokio::spawn(async move {
        fire_event_async(db, http_client, &repo_id, &event, payload).await;
    });
}

async fn fire_event_async(
    db: Arc<Db>,
    http_client: Arc<reqwest::Client>,
    repo_id: &str,
    event: &str,
    payload: serde_json::Value,
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
        let delivery_id = uuid::Uuid::new_v4().to_string();

        tokio::spawn(async move {
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
                Ok(resp) => tracing::info!(
                    url = %hook.url,
                    event = %event_name,
                    status = %resp.status(),
                    "webhook delivered"
                ),
                Err(e) => tracing::warn!(
                    url = %hook.url,
                    event = %event_name,
                    err = %e,
                    "webhook delivery failed"
                ),
            }
        });
    }
}
