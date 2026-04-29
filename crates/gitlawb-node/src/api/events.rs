//! API handlers for ref-update event feeds.

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::Json;

use crate::error::Result;
use crate::state::AppState;

/// GET /api/v1/events/ref-updates?limit=50
pub async fn list_ref_updates(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>> {
    let limit = params.get("limit")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(50)
        .min(200);

    let updates = state.db.list_ref_updates(limit).await?;
    let events: Vec<serde_json::Value> = updates.iter().map(|u| serde_json::json!({
        "id":          u.id,
        "node_did":    u.node_did,
        "pusher_did":  u.pusher_did,
        "repo":        u.repo,
        "ref_name":    u.ref_name,
        "old_sha":     u.old_sha,
        "new_sha":     u.new_sha,
        "timestamp":   u.timestamp,
        "cert_id":     u.cert_id,
        "received_at": u.received_at,
        "from_peer":   u.from_peer,
    })).collect();

    let count = events.len();
    Ok(Json(serde_json::json!({ "events": events, "count": count })))
}

/// GET /api/v1/repos/{owner}/{repo}/events
pub async fn list_repo_events(
    State(state): State<AppState>,
    Path((owner, repo_name)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>> {
    let limit = params.get("limit")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(50)
        .min(200);

    // Look up the repo record once so we can use the full owner DID
    let repo_record = state.db.get_repo(&owner, &repo_name).await.ok().flatten();

    // Build the repo identifier using the FULL DID key part (not the 8-char URL truncation).
    // Gossip events are stored as "{full_key_part}/{repo_name}" (e.g. "z6MksXZDfullkeyhere/myrepo"),
    // but the URL only carries the first 8 chars of the key.  Without the full slug the
    // WHERE repo = '...' query never matches and the events tab appears empty.
    let repo_id_str = if let Some(ref record) = repo_record {
        format!(
            "{}/{}",
            record.owner_did.split(':').last().unwrap_or(&record.owner_did),
            repo_name
        )
    } else {
        format!("{owner}/{repo_name}")
    };

    // Fetch local ref certificates for this repo (if the repo exists on this node)
    let cert_events: Vec<serde_json::Value> = if let Some(ref record) = repo_record {
        state.db.list_ref_certificates(&record.id).await
            .unwrap_or_default()
            .iter()
            .map(|c| serde_json::json!({
                "type":       "local_cert",
                "id":         c.id,
                "repo":       repo_id_str,
                "ref_name":   c.ref_name,
                "old_sha":    c.old_sha,
                "new_sha":    c.new_sha,
                "pusher_did": c.pusher_did,
                "node_did":   c.node_did,
                "timestamp":  c.issued_at,
                "source":     "local",
            }))
            .collect()
    } else {
        vec![]
    };

    // Fetch gossipsub received ref updates for this repo (uses full slug built above)
    let gossip_events: Vec<serde_json::Value> = state.db
        .list_repo_ref_updates(&repo_id_str, limit).await
        .unwrap_or_default()
        .iter()
        .map(|u| serde_json::json!({
            "type":        "gossipsub",
            "id":          u.id,
            "repo":        u.repo,
            "ref_name":    u.ref_name,
            "old_sha":     u.old_sha,
            "new_sha":     u.new_sha,
            "pusher_did":  u.pusher_did,
            "node_did":    u.node_did,
            "timestamp":   u.timestamp,
            "cert_id":     u.cert_id,
            "received_at": u.received_at,
            "from_peer":   u.from_peer,
            "source":      "gossipsub",
        }))
        .collect();

    // Merge both lists
    let mut all_events: Vec<serde_json::Value> = cert_events;
    all_events.extend(gossip_events);

    // Sort by timestamp descending
    all_events.sort_by(|a, b| {
        let ts_a = a.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        let ts_b = b.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        ts_b.cmp(ts_a)
    });

    // Apply limit
    all_events.truncate(limit as usize);

    let count = all_events.len();
    Ok(Json(serde_json::json!({ "events": all_events, "count": count })))
}
