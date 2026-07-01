//! API handlers for ref-update event feeds.

use std::collections::HashMap;

use axum::extract::{Extension, Path, Query, State};
use axum::Json;

use crate::auth::AuthenticatedDid;
use crate::error::Result;
use crate::state::AppState;

/// GET /api/v1/events/ref-updates?limit=50
pub async fn list_ref_updates(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(50)
        .min(200);

    let mut updates = state.db.list_ref_updates(limit).await?;

    // Fail-closed visibility gate (#114): drop any row matching a local repo the
    // caller cannot read at root. DB errors `?`-propagate (500) rather than
    // serving unfiltered rows. Rows matching no local repo pass through
    // (remote/gossip-only). Mirrors the GraphQL feed gate (#112).
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let deduped = state.db.list_all_repos_deduped().await?;
    let ids: Vec<String> = deduped.iter().map(|r| r.id.clone()).collect();
    let rules = state.db.list_visibility_rules_for_repos(&ids).await?;
    updates
        .retain(|u| crate::visibility::ref_update_row_visible(&deduped, &rules, caller, &u.repo));

    let events: Vec<serde_json::Value> = updates
        .iter()
        .map(|u| {
            serde_json::json!({
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
            })
        })
        .collect();

    let count = events.len();
    Ok(Json(
        serde_json::json!({ "events": events, "count": count }),
    ))
}

/// GET /api/v1/repos/{owner}/{repo}/events
pub async fn list_repo_events(
    State(state): State<AppState>,
    Path((owner, repo_name)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>> {
    let limit = params
        .get("limit")
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
            crate::db::normalize_owner_key(&record.owner_did),
            repo_name
        )
    } else {
        format!("{owner}/{repo_name}")
    };

    // Fetch local ref certificates for this repo (if the repo exists on this node)
    let cert_events: Vec<serde_json::Value> = if let Some(ref record) = repo_record {
        state
            .db
            .list_ref_certificates(&record.id)
            .await
            .unwrap_or_default()
            .iter()
            .map(|c| {
                serde_json::json!({
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
                })
            })
            .collect()
    } else {
        vec![]
    };

    // Fetch gossipsub received ref updates for this repo (uses full slug built above)
    let gossip_events: Vec<serde_json::Value> = state
        .db
        .list_repo_ref_updates(&repo_id_str, limit)
        .await
        .unwrap_or_default()
        .iter()
        .map(|u| {
            serde_json::json!({
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
            })
        })
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
    Ok(Json(
        serde_json::json!({ "events": all_events, "count": count }),
    ))
}

#[cfg(test)]
mod ref_updates_feed_tests {
    use crate::db::{ReceivedRefUpdate, RepoRecord};
    use crate::test_support::{signed_request_as, test_state};
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::Router;
    use chrono::Utc;
    use sqlx::PgPool;
    use tower::ServiceExt;

    const OWNER: &str = "did:key:z6MkOwner";

    fn repo(id: &str, owner_did: &str, name: &str, is_public: bool) -> RepoRecord {
        let now = Utc::now();
        RepoRecord {
            id: id.into(),
            name: name.into(),
            owner_did: owner_did.into(),
            description: None,
            is_public,
            default_branch: "main".into(),
            created_at: now,
            updated_at: now,
            disk_path: format!("/tmp/{id}"),
            forked_from: None,
            machine_id: None,
        }
    }

    fn ref_row(id: &str, slug: &str) -> ReceivedRefUpdate {
        ReceivedRefUpdate {
            id: id.into(),
            node_did: "did:key:z6MkNode".into(),
            pusher_did: "did:key:z6MkPusher".into(),
            repo: slug.into(),
            ref_name: "refs/heads/main".into(),
            old_sha: "0".repeat(40),
            new_sha: "a".repeat(40),
            timestamp: Utc::now().to_rfc3339(),
            cert_id: None,
            received_at: Utc::now().to_rfc3339(),
            from_peer: "peer1".into(),
        }
    }

    fn router(state: crate::state::AppState) -> Router {
        Router::new()
            .route(
                "/api/v1/events/ref-updates",
                axum::routing::get(super::list_ref_updates),
            )
            .with_state(state)
    }

    fn anon_get() -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri("/api/v1/events/ref-updates")
            .body(Body::empty())
            .expect("request builder")
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        serde_json::from_slice(&bytes).expect("json body")
    }

    /// Repo slugs present in the `events` array of the feed response.
    fn slugs(v: &serde_json::Value) -> Vec<String> {
        v["events"]
            .as_array()
            .expect("events array")
            .iter()
            .filter_map(|e| e["repo"].as_str().map(str::to_string))
            .collect()
    }

    fn count(v: &serde_json::Value) -> u64 {
        v["count"].as_u64().expect("count number")
    }

    // Scenario 1 — load-bearing RED→GREEN: anon must not get a private local
    // repo's row, and `count` must reflect the filtered set.
    #[sqlx::test]
    async fn feed_private_repo_dropped_for_anon(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("r1", OWNER, "widget", false))
            .await
            .unwrap();
        state
            .db
            .insert_ref_update(&ref_row("u1", "z6MkOwner/widget"))
            .await
            .unwrap();

        let resp = router(state).oneshot(anon_get()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert!(
            slugs(&body).is_empty(),
            "anon must not see a private local repo's ref update, got {:?}",
            slugs(&body)
        );
        assert_eq!(count(&body), 0, "count must reflect the filtered set");
    }

    // Scenario 2 — owner still sees their own private repo's row.
    #[sqlx::test]
    async fn feed_private_repo_kept_for_owner(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("r1", OWNER, "widget", false))
            .await
            .unwrap();
        state
            .db
            .insert_ref_update(&ref_row("u1", "z6MkOwner/widget"))
            .await
            .unwrap();

        let resp = router(state)
            .oneshot(signed_request_as(
                OWNER,
                Method::GET,
                "/api/v1/events/ref-updates",
                Body::empty(),
            ))
            .await
            .unwrap();
        let body = body_json(resp).await;
        assert_eq!(slugs(&body), vec!["z6MkOwner/widget".to_string()]);
        assert_eq!(count(&body), 1);
    }

    // Scenario 3 — mixed feed: anon sees only the public row; count == 1.
    #[sqlx::test]
    async fn feed_mixed_anon_gets_only_public(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("pub", OWNER, "openrepo", true))
            .await
            .unwrap();
        state
            .db
            .create_repo(&repo("priv", OWNER, "secret", false))
            .await
            .unwrap();
        state
            .db
            .insert_ref_update(&ref_row("u_pub", "z6MkOwner/openrepo"))
            .await
            .unwrap();
        state
            .db
            .insert_ref_update(&ref_row("u_priv", "z6MkOwner/secret"))
            .await
            .unwrap();

        let resp = router(state).oneshot(anon_get()).await.unwrap();
        let body = body_json(resp).await;
        assert_eq!(slugs(&body), vec!["z6MkOwner/openrepo".to_string()]);
        assert_eq!(count(&body), 1);
    }

    // Scenario 4 — alias fail-closed: private repo's row stored full-DID form.
    #[sqlx::test]
    async fn feed_full_did_slug_dropped_for_anon(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("r1", "did:key:zABC", "widget", false))
            .await
            .unwrap();
        state
            .db
            .insert_ref_update(&ref_row("u1", "did:key:zABC/widget"))
            .await
            .unwrap();

        let resp = router(state).oneshot(anon_get()).await.unwrap();
        let body = body_json(resp).await;
        assert!(slugs(&body).is_empty(), "full-DID alias must be dropped");
        assert_eq!(count(&body), 0);
    }

    // Scenario 5 — truncated-key fail-closed: 8-char-prefix owner form.
    #[sqlx::test]
    async fn feed_truncated_key_slug_dropped_for_anon(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("r1", "did:key:zABCDEFGH", "widget", false))
            .await
            .unwrap();
        state
            .db
            .insert_ref_update(&ref_row("u1", "zABCDEF/widget"))
            .await
            .unwrap();

        let resp = router(state).oneshot(anon_get()).await.unwrap();
        let body = body_json(resp).await;
        assert!(
            slugs(&body).is_empty(),
            "truncated-key alias must be dropped"
        );
        assert_eq!(count(&body), 0);
    }

    // Scenario 6 — remote slug (no local match) is returned to anon.
    #[sqlx::test]
    async fn feed_remote_slug_kept_for_anon(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("r1", OWNER, "widget", false))
            .await
            .unwrap();
        state
            .db
            .insert_ref_update(&ref_row("u1", "zZZZOTHER/gadget"))
            .await
            .unwrap();

        let resp = router(state).oneshot(anon_get()).await.unwrap();
        let body = body_json(resp).await;
        assert_eq!(slugs(&body), vec!["zZZZOTHER/gadget".to_string()]);
        assert_eq!(count(&body), 1);
    }
}
