//! API handlers for ref-update event feeds.

use std::collections::HashMap;

use axum::extract::{Extension, Path, Query, State};
use axum::Json;

use crate::auth::AuthenticatedDid;
use crate::error::Result;
use crate::state::AppState;

/// Collect up to `limit` ref-update rows visible to `caller`, newest first,
/// paging past rows the feed gate drops. Filtering after a plain SQL `LIMIT`
/// under-serves an anonymous caller whenever the newest rows name private local
/// repos (#114): the older, visible rows are never fetched, so a small limit can
/// return zero. Over-fetch in bounded pages until `limit` visible rows are
/// collected or the scan window is spent. Fail-closed: any DB error propagates
/// rather than serving ungated rows, and the scan cap only ever returns fewer
/// rows. Rows matching no local repo pass through (remote/gossip-only). Shared by
/// the REST global feed (#114) and the GraphQL `ref_updates` resolver (#112) so
/// the one gate cannot drift between the two surfaces.
pub(crate) async fn collect_visible_ref_updates(
    db: &crate::db::Db,
    repo: Option<&str>,
    limit: i64,
    caller: Option<&str>,
) -> Result<Vec<crate::db::ReceivedRefUpdate>> {
    // 128 rows per DB round-trip. The page size is a parameter on the inner fn
    // only so tests can force multi-page offset paging over a small dataset.
    collect_visible_ref_updates_inner(db, repo, limit, caller, 128).await
}

async fn collect_visible_ref_updates_inner(
    db: &crate::db::Db,
    repo: Option<&str>,
    limit: i64,
    caller: Option<&str>,
    page: i64,
) -> Result<Vec<crate::db::ReceivedRefUpdate>> {
    let want = limit.max(0) as usize;
    let mut visible = Vec::with_capacity(want.min(200));
    if want == 0 {
        return Ok(visible);
    }

    // Gate inputs loaded once; DB errors abort (fail closed, never serve).
    let deduped = db.list_all_repos_deduped().await?;
    let ids: Vec<String> = deduped.iter().map(|r| r.id.clone()).collect();
    let rules = db.list_visibility_rules_for_repos(&ids).await?;

    // Never scan fewer rows than the caller asked for (no regression vs the old
    // single LIMIT), but cap the walk so a feed of newest-private rows can't
    // force an unbounded scan. The cap only fails safe (may return fewer).
    let max_scan = limit.max(2_048);
    let mut offset: i64 = 0;
    while offset < max_scan {
        let rows = db.list_ref_updates_page(repo, page, offset).await?;
        let fetched = rows.len() as i64;
        for u in rows {
            if crate::visibility::ref_update_row_visible(&deduped, &rules, caller, &u.repo) {
                visible.push(u);
                if visible.len() == want {
                    return Ok(visible);
                }
            }
        }
        offset += fetched;
        if fetched < page {
            break; // page under-filled → table exhausted
        }
    }
    Ok(visible)
}

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

    // Fail-closed visibility gate (#114), applied before the limit via paging so
    // an anon caller still gets the latest visible events, not a short page.
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let updates = collect_visible_ref_updates(&state.db, None, limit, caller).await?;

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
            record
                .owner_did
                .split(':')
                .next_back()
                .unwrap_or(&record.owner_did),
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

    // Scenario 7 (#114 P2) — a small limit must page past the newest rows when
    // they are private, so the older public rows are still returned instead of a
    // short/empty page. Before the gate moved ahead of the limit this returned 0.
    // RED→GREEN.
    #[sqlx::test]
    async fn feed_small_limit_pages_past_newest_private(pool: PgPool) {
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
        // 3 older PUBLIC rows …
        for i in 0..3 {
            let mut r = ref_row(&format!("pub{i}"), "z6MkOwner/openrepo");
            r.timestamp = format!("2026-07-01T10:00:0{i}+00:00");
            state.db.insert_ref_update(&r).await.unwrap();
        }
        // … then 5 NEWER PRIVATE rows (the newest in the feed).
        for i in 0..5 {
            let mut r = ref_row(&format!("priv{i}"), "z6MkOwner/secret");
            r.timestamp = format!("2026-07-01T10:00:1{i}+00:00");
            state.db.insert_ref_update(&r).await.unwrap();
        }

        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/events/ref-updates?limit=3")
            .body(Body::empty())
            .expect("request builder");
        let resp = router(state).oneshot(req).await.unwrap();
        let body = body_json(resp).await;
        // The 3-row limit is filled from the older public rows, not left short.
        assert_eq!(
            count(&body),
            3,
            "limit must be filled from older public rows"
        );
        assert!(
            slugs(&body).iter().all(|s| s == "z6MkOwner/openrepo"),
            "returned rows must all be the public repo's, got {:?}",
            slugs(&body)
        );
    }

    // Scenario 8 (#114 P2) — multi-page paging: a page smaller than the dataset
    // must still collect the requested visible rows from older pages, advancing
    // the offset without skipping or duplicating. page=2 over 5 newest-private +
    // 3 older-public rows spans four fetches (offset 0→2→4→6). Guards the offset
    // paging that the single-page feed tests above can't reach.
    #[sqlx::test]
    async fn collect_visible_pages_across_page_boundary(pool: PgPool) {
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
        for i in 0..3 {
            let mut r = ref_row(&format!("pub{i}"), "z6MkOwner/openrepo");
            r.timestamp = format!("2026-07-01T10:00:0{i}+00:00");
            state.db.insert_ref_update(&r).await.unwrap();
        }
        for i in 0..5 {
            let mut r = ref_row(&format!("priv{i}"), "z6MkOwner/secret");
            r.timestamp = format!("2026-07-01T10:00:1{i}+00:00");
            state.db.insert_ref_update(&r).await.unwrap();
        }

        let got = super::collect_visible_ref_updates_inner(&state.db, None, 3, None, 2)
            .await
            .unwrap();
        // All 3 older public rows, collected across four pages …
        let got_slugs: Vec<&str> = got.iter().map(|u| u.repo.as_str()).collect();
        assert_eq!(got_slugs, vec!["z6MkOwner/openrepo"; 3]);
        // … each exactly once (no duplicate rows across page boundaries).
        let unique: std::collections::HashSet<&str> = got.iter().map(|u| u.id.as_str()).collect();
        assert_eq!(unique.len(), 3, "no row returned twice across pages");
    }
}
