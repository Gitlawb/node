//! API handlers for ref-update event feeds.

use std::collections::HashMap;

use axum::extract::{Extension, Path, Query, State};
use axum::Json;

use crate::auth::AuthenticatedDid;
use crate::error::Result;
use crate::state::AppState;

/// Hard ceiling on rows any ref-update feed returns in one request. Shared by the
/// shared collector's clamp and the per-handler request caps so they can't drift.
const MAX_VISIBLE_REF_UPDATES: i64 = 200;

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
    // Clamp the effective limit inside the shared collector so both callers are
    // bounded: REST already caps at MAX_VISIBLE_REF_UPDATES, but the GraphQL
    // resolver passes its caller-provided limit straight through, which would
    // otherwise let a large request return unbounded rows and scan unbounded DB
    // rows.
    let bounded_limit = limit.clamp(0, MAX_VISIBLE_REF_UPDATES);
    let want = bounded_limit as usize;
    let mut visible = Vec::with_capacity(want);
    if want == 0 {
        return Ok(visible);
    }

    // Gate inputs loaded once; DB errors abort (fail closed, never serve).
    let deduped = db.list_all_repos_deduped().await?;
    // Quarantined mirrors are excluded from the deduped set, and quarantine must
    // be withheld from every surface INCLUDING the owner: it's a status decided
    // at admission, checked separately from the mirror's (untrustworthy)
    // visibility fields. A folded is_public=false cannot enforce that here —
    // visibility_check short-circuits to Allow for the owner before is_public is
    // read, so an owner-matched row would leak. Instead, drop any row that names a
    // quarantined repo in the loop below, before the visibility gate runs, so the
    // drop bypasses that owner short-circuit entirely.
    let quarantined = db.list_quarantined_repos().await?;
    let ids: Vec<String> = deduped.iter().map(|r| r.id.clone()).collect();
    let rules = db.list_visibility_rules_for_repos(&ids).await?;

    // Never scan fewer rows than the caller asked for (no regression vs the old
    // single LIMIT), but cap the walk so a feed of newest-private rows can't
    // force an unbounded scan. The cap only fails safe (may return fewer).
    let max_scan = bounded_limit.max(2_048);
    let mut scanned: i64 = 0;
    // Keyset cursor: the (timestamp, id) of the last row fetched so far. Paging
    // by this instead of OFFSET keeps one multi-page scan stable when
    // received_ref_updates is written concurrently (a newer row sorts above the
    // window and cannot shift it, so no page duplicates or skips a row). It is
    // the last FETCHED row (pre-filter), because the scan pages past withheld
    // rows too; there is no client-facing cursor here, so INV-13 does not apply.
    let mut after: Option<(String, String)> = None;
    while scanned < max_scan {
        let rows = db
            .list_ref_updates_keyset(
                repo,
                page,
                after.as_ref().map(|(ts, id)| (ts.as_str(), id.as_str())),
            )
            .await?;
        let fetched = rows.len() as i64;
        if fetched == 0 {
            break; // table exhausted
        }
        // Advance the cursor to the last row of this page BEFORE the filter loop
        // consumes `rows`.
        if let Some(last) = rows.last() {
            after = Some((last.timestamp.clone(), last.id.clone()));
        }
        for u in rows {
            // Quarantine denies unconditionally, before the visibility gate, so
            // even a caller matching the mirror's owner_did cannot read the row.
            if quarantined
                .iter()
                .any(|q| crate::visibility::ref_update_row_names_repo(q, &u.repo))
            {
                continue;
            }
            if crate::visibility::ref_update_row_visible(&deduped, &rules, caller, &u.repo) {
                visible.push(u);
                if visible.len() == want {
                    return Ok(visible);
                }
            }
        }
        scanned += fetched;
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
        .clamp(0, MAX_VISIBLE_REF_UPDATES);

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
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    // The lower bound of this clamp is load-bearing, not just an upper cap: the
    // local ref-cert half below is bounded only by `all_events.truncate(limit as
    // usize)`, which bypasses the shared collector. A negative limit would wrap to
    // usize::MAX and leave that truncate a no-op. Do not relax to `.min` here (the
    // global feed can, since its limit is re-clamped inside the collector).
    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(50)
        .clamp(0, MAX_VISIBLE_REF_UPDATES);

    // Gate this handler in two layers (#112/#114). First, a repo-root read gate on
    // THIS repo: authorize_repo_read returns RepoNotFound (→ 404) when the repo is
    // quarantined, visibility-denied, or not hosted here, so the local ref
    // certificates (keyed by the unique repo record id) are served only to a caller
    // who may read this repo. A repo this node does not host returns 404: it holds no
    // visibility record for it, so it fails closed (remote gossip is read via the
    // global /api/v1/events/ref-updates feed). Second, the gossip half below is
    // filtered per row: received_ref_updates rows are keyed by a lossy, non-unique
    // wire slug, so the repo-root gate alone would leak a colliding private repo's
    // rows — the shared collector's row gate closes that.
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &repo_name, caller, "/").await?;

    // Build the repo identifier using the FULL DID key part (not the 8-char URL truncation).
    // Gossip events are stored as "{full_key_part}/{repo_name}" (e.g. "z6MksXZDfullkeyhere/myrepo"),
    // but the URL only carries the first 8 chars of the key.  Without the full slug the
    // WHERE repo = '...' query never matches and the events tab appears empty.
    let repo_id_str = format!(
        "{}/{}",
        crate::db::normalize_owner_key(&record.owner_did),
        repo_name
    );

    // Fetch this repo's local ref certificates (keyed by the unique record id, so no
    // slug-collision concern). DB errors propagate as 500 rather than being swallowed
    // into an empty 200, matching the gossip half below.
    let cert_events: Vec<serde_json::Value> = state
        .db
        .list_ref_certificates(&record.id)
        .await?
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
        .collect();

    // Fetch gossipsub received ref updates for this repo (uses the normalize_owner_key
    // slug built above), filtered per row by the SAME shared gate the cross-repo feeds
    // use. The stored slug is an UNTRUSTED, non-unique wire form: the exact-match
    // `WHERE repo = slug` narrows to this repo's canonical slug, but a peer can plant a
    // row under a colliding owner form, and a did:key canonical owner and its bare
    // short-key mirror normalize to the SAME slug, so the query alone could serve a
    // colliding PRIVATE repo's rows to anyone allowed to read this one.
    // collect_visible_ref_updates drops any row whose slug matches a local repo the
    // caller cannot read (fail-closed), and propagates DB errors instead of swallowing
    // them.
    let gossip_events: Vec<serde_json::Value> =
        collect_visible_ref_updates(&state.db, Some(&repo_id_str), limit, caller)
            .await?
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
    use crate::db::{ReceivedRefUpdate, RefCertificate, RepoRecord};
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

    // --- repo-scoped events endpoint (list_repo_events) gate tests ---
    // The handler serves one repo's ref certificates + received gossip ref-updates.
    // authorize_repo_read gates the whole handler on repo-root read visibility:
    // allow → serve both datasets; deny / quarantine / not-hosted → opaque 404.

    fn repo_events_router(state: crate::state::AppState) -> Router {
        Router::new()
            .route(
                "/api/v1/repos/{owner}/{repo}/events",
                axum::routing::get(super::list_repo_events),
            )
            .with_state(state)
    }

    fn ref_cert(id: &str, repo_id: &str) -> RefCertificate {
        RefCertificate {
            id: id.into(),
            repo_id: repo_id.into(),
            ref_name: "refs/heads/main".into(),
            old_sha: "0".repeat(40),
            new_sha: "b".repeat(40),
            pusher_did: "did:key:z6MkPusher".into(),
            node_did: "did:key:z6MkNode".into(),
            signature: "sig".into(),
            issued_at: Utc::now().to_rfc3339(),
        }
    }

    fn anon_repo_events(owner: &str, name: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(format!("/api/v1/repos/{owner}/{name}/events"))
            .body(Body::empty())
            .expect("request builder")
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

    // Scenario 5b — two-repo owner-key collision, load-bearing RED->GREEN. A public
    // bare-key mirror (`z6MkX`) and a private did:key canonical repo (`did:key:z6MkX`)
    // normalize to the SAME owner key, so their gossip rows share the `z6MkX/...` slug
    // space. The gate keys on the FULL slug (owner + name), so the public mirror's own
    // row still reaches anon while the private repo's row is dropped: a readable public
    // repo under an owner key must not unlock that owner's OTHER private repos' rows.
    // (post-#141 normalize_owner_key collapses did:key canonical and bare mirror to the
    // same key; the removed repo-scoped did:web collision test never covered this pair.)
    // Disabling the per-row gate serves `z6MkX/secret` to anon, so this pins the drop.
    #[sqlx::test]
    async fn feed_public_mirror_does_not_unlock_private_canonical_sibling(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("mirror", "z6MkX", "widget", true))
            .await
            .unwrap();
        state
            .db
            .create_repo(&repo("canon", "did:key:z6MkX", "secret", false))
            .await
            .unwrap();
        // The public mirror's legit row and the private canonical's row, both keyed
        // under the shared `z6MkX` owner-key slug space.
        state
            .db
            .insert_ref_update(&ref_row("u_pub", "z6MkX/widget"))
            .await
            .unwrap();
        state
            .db
            .insert_ref_update(&ref_row("u_priv", "z6MkX/secret"))
            .await
            .unwrap();

        let resp = router(state).oneshot(anon_get()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(
            slugs(&body),
            vec!["z6MkX/widget".to_string()],
            "anon must see the public mirror's row but NOT the private canonical sibling's; got {:?}",
            slugs(&body)
        );
        assert_eq!(count(&body), 1);
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

    // A negative limit on the GLOBAL feed must return zero, not the whole visible
    // set. Unlike the repo feed, this handler has no local `truncate`; its guard is
    // the shared collector's `clamp(0, MAX)` (want==0 short-circuits before any
    // scan), so the handler-level clamp here is a consistency measure, not the
    // load-bearing one. Seeded with 5 visible public rows so an unbounded return
    // would be 5; asserting 0 proves the clamp chain holds.
    #[sqlx::test]
    async fn feed_negative_limit_returns_empty(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("pub", OWNER, "openrepo", true))
            .await
            .unwrap();
        for i in 0..5 {
            let mut r = ref_row(&format!("pub{i}"), "z6MkOwner/openrepo");
            r.timestamp = format!("2026-07-01T10:00:0{i}+00:00");
            state.db.insert_ref_update(&r).await.unwrap();
        }

        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/events/ref-updates?limit=-1")
            .body(Body::empty())
            .expect("request builder");
        let resp = router(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            count(&body_json(resp).await),
            0,
            "negative limit must clamp to 0, not return the full visible set"
        );
    }

    // Scenario 8 (#114 P2) — multi-page paging: a page smaller than the dataset
    // must still collect the requested visible rows from older pages, advancing
    // the keyset cursor without skipping or duplicating. page=2 over 5
    // newest-private + 3 older-public rows spans four keyset pages. Guards the
    // multi-page collection the single-page feed tests above can't reach.
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

    // Scenario 8b — the collector's repo-filtered path across a page boundary:
    // repo=Some AND a keyset continuation (after=Some) in one collect, exercising
    // the four-bind `WHERE repo=$1 AND (timestamp,id)<($2,$3)` query end to end
    // through the collector, not just the DB primitive.
    #[sqlx::test]
    async fn collect_visible_repo_filtered_pages_across_boundary(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("pub", OWNER, "openrepo", true))
            .await
            .unwrap();
        // 3 visible rows for the target repo …
        for i in 0..3 {
            let mut r = ref_row(&format!("t{i}"), "z6MkOwner/openrepo");
            r.timestamp = format!("2026-07-01T10:00:0{i}+00:00");
            state.db.insert_ref_update(&r).await.unwrap();
        }
        // … plus newer noise rows for a different repo that the SQL repo filter
        // must exclude on every page.
        for i in 0..2 {
            let mut r = ref_row(&format!("n{i}"), "z6MkOther/elsewhere");
            r.timestamp = format!("2026-07-01T10:00:1{i}+00:00");
            state.db.insert_ref_update(&r).await.unwrap();
        }

        let got = super::collect_visible_ref_updates_inner(
            &state.db,
            Some("z6MkOwner/openrepo"),
            3,
            None,
            2,
        )
        .await
        .unwrap();
        assert_eq!(got.len(), 3, "all three target rows collected across pages");
        assert!(
            got.iter().all(|u| u.repo == "z6MkOwner/openrepo"),
            "repo filter holds across the keyset continuation; no noise rows"
        );
        let unique: std::collections::HashSet<&str> = got.iter().map(|u| u.id.as_str()).collect();
        assert_eq!(
            unique.len(),
            3,
            "no duplicate across the repo-filtered page boundary"
        );
    }

    // Scenario 8c — the empty-table termination: want > 0 but no rows, so the
    // first keyset page returns zero and the loop hits the `fetched == 0` break
    // (distinct from the want == 0 short-circuit above the loop).
    #[sqlx::test]
    async fn collect_visible_empty_table_terminates_empty(pool: PgPool) {
        let state = test_state(pool).await;
        let got = super::collect_visible_ref_updates_inner(&state.db, None, 5, None, 2)
            .await
            .unwrap();
        assert!(
            got.is_empty(),
            "empty received_ref_updates returns empty, no hang"
        );
    }

    // Scenario 9 — an oversized limit (the GraphQL resolver passes its
    // caller-provided limit uncapped) must be clamped inside the shared collector
    // so it can't return unbounded rows or scan unbounded DB rows.
    #[sqlx::test]
    async fn collect_visible_clamps_oversized_limit(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("pub", OWNER, "openrepo", true))
            .await
            .unwrap();
        // 201 public rows — one more than the 200 cap.
        for i in 0..201 {
            let mut r = ref_row(&format!("pub{i}"), "z6MkOwner/openrepo");
            r.timestamp = format!("2026-07-01T10:00:00.{i:04}+00:00");
            state.db.insert_ref_update(&r).await.unwrap();
        }

        let got = super::collect_visible_ref_updates_inner(&state.db, None, 100_000, None, 128)
            .await
            .unwrap();
        assert_eq!(got.len(), 200, "oversized limit must clamp to 200");
    }

    // Scenario 10 — a quarantined mirror is withheld from every listing surface.
    // Its rows are excluded from list_all_repos_deduped, so without folding them
    // into the match universe the gate would misclassify the row as remote and
    // serve it to anon.
    #[sqlx::test]
    async fn feed_quarantined_mirror_withheld_from_anon(pool: PgPool) {
        let state = test_state(pool).await;
        // Quarantined mirror: admitted but unvalidated, withheld from listings.
        state
            .db
            .upsert_mirror_repo("z6MkQuar", "secret", "/tmp/q", None, true)
            .await
            .unwrap();
        state
            .db
            .insert_ref_update(&ref_row("u1", "z6MkQuar/secret"))
            .await
            .unwrap();

        let resp = router(state).oneshot(anon_get()).await.unwrap();
        let body = body_json(resp).await;
        assert!(
            slugs(&body).is_empty(),
            "quarantined mirror's ref-update must be withheld from anon, got {:?}",
            slugs(&body)
        );
    }

    // Scenario 10b — a quarantined mirror must be withheld even from a caller who
    // matches its owner_did, not just from anon. is_public=false cannot enforce
    // this: visibility_check short-circuits to Allow for the owner BEFORE is_public
    // is read, so quarantine has to deny before that check runs. The anon test
    // above never exercises that owner short-circuit; this one does (RED before
    // the collector's explicit quarantine drop). upsert_mirror_repo stores the
    // owner as the bare short key, so the matching caller is the bare form.
    #[sqlx::test]
    async fn feed_quarantined_mirror_withheld_from_owner(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .upsert_mirror_repo("z6MkQuar", "secret", "/tmp/q", None, true)
            .await
            .unwrap();
        state
            .db
            .insert_ref_update(&ref_row("u1", "z6MkQuar/secret"))
            .await
            .unwrap();

        let got =
            super::collect_visible_ref_updates_inner(&state.db, None, 50, Some("z6MkQuar"), 128)
                .await
                .unwrap();
        let got_slugs: Vec<&str> = got.iter().map(|u| u.repo.as_str()).collect();
        assert!(
            got_slugs.is_empty(),
            "quarantined mirror must be withheld from its own owner, got {got_slugs:?}"
        );
    }

    // Scenario 10c — a quarantined repo whose owner_did is a full did:key must be
    // withheld from that full-DID owner, the exact identity require_signature
    // injects on the live path. This is the reachable shape once an operator
    // quarantines a canonical repo via set_repo_quarantine. RED before the drop:
    // the owner short-circuit keeps the row for the full-DID caller.
    #[sqlx::test]
    async fn feed_quarantined_full_did_repo_withheld_from_owner(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("q1", "did:key:z6MkQuar", "secret", false))
            .await
            .unwrap();
        let touched = state.db.set_repo_quarantine("q1", true).await.unwrap();
        assert_eq!(touched, 1, "quarantine flag must be set on the repo");
        state
            .db
            .insert_ref_update(&ref_row("u1", "z6MkQuar/secret"))
            .await
            .unwrap();

        let got = super::collect_visible_ref_updates_inner(
            &state.db,
            None,
            50,
            Some("did:key:z6MkQuar"),
            128,
        )
        .await
        .unwrap();
        let got_slugs: Vec<&str> = got.iter().map(|u| u.repo.as_str()).collect();
        assert!(
            got_slugs.is_empty(),
            "quarantined full-DID repo must be withheld from its owner, got {got_slugs:?}"
        );
    }

    // Must-not: the quarantine drop withholds ONLY the rows it names, never an
    // unrelated visible row. A servable public repo alongside two quarantined
    // mirrors — the public row is served, both quarantined rows withheld. This is
    // the drop's `.any() == false → serve` branch over a NON-EMPTY (multi-element)
    // quarantined set, which the single-repo tests above never reach.
    #[sqlx::test]
    async fn feed_quarantine_drop_does_not_suppress_unrelated_rows(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("pub", OWNER, "openrepo", true))
            .await
            .unwrap();
        state
            .db
            .upsert_mirror_repo("z6MkQuar", "secret", "/tmp/q", None, true)
            .await
            .unwrap();
        state
            .db
            .upsert_mirror_repo("z6MkOther", "hidden", "/tmp/o", None, true)
            .await
            .unwrap();
        state
            .db
            .insert_ref_update(&ref_row("pub1", "z6MkOwner/openrepo"))
            .await
            .unwrap();
        state
            .db
            .insert_ref_update(&ref_row("q1", "z6MkQuar/secret"))
            .await
            .unwrap();
        state
            .db
            .insert_ref_update(&ref_row("q2", "z6MkOther/hidden"))
            .await
            .unwrap();

        let got = super::collect_visible_ref_updates_inner(&state.db, None, 50, None, 128)
            .await
            .unwrap();
        let got_slugs: Vec<&str> = got.iter().map(|u| u.repo.as_str()).collect();
        assert_eq!(
            got_slugs,
            vec!["z6MkOwner/openrepo"],
            "quarantine must withhold only its own rows, still serving unrelated visible ones"
        );
    }

    // The live REST handler (not just the collector) must withhold a quarantined
    // repo from an authenticated owner. Drives list_ref_updates through the router
    // with the owner's full DID as caller — the identity require_signature injects.
    #[sqlx::test]
    async fn feed_quarantined_repo_withheld_from_owner_via_router(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("q1", "did:key:z6MkQuar", "secret", false))
            .await
            .unwrap();
        state.db.set_repo_quarantine("q1", true).await.unwrap();
        state
            .db
            .insert_ref_update(&ref_row("u1", "z6MkQuar/secret"))
            .await
            .unwrap();

        let req = signed_request_as(
            "did:key:z6MkQuar",
            Method::GET,
            "/api/v1/events/ref-updates",
            Body::empty(),
        );
        let resp = router(state).oneshot(req).await.unwrap();
        let body = body_json(resp).await;
        assert!(
            slugs(&body).is_empty(),
            "quarantined repo must be withheld from its owner via the REST handler, got {:?}",
            slugs(&body)
        );
    }

    // RED→GREEN: anon must not read a private repo's ref metadata; a denied read is
    // an opaque 404, not a 200 carrying the cert/gossip rows.
    #[sqlx::test]
    async fn repo_events_private_repo_404_for_anon(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("r1", OWNER, "widget", false))
            .await
            .unwrap();
        state
            .db
            .insert_ref_certificate(&ref_cert("c1", "r1"))
            .await
            .unwrap();
        state
            .db
            .insert_ref_update(&ref_row("u1", "z6MkOwner/widget"))
            .await
            .unwrap();

        let resp = repo_events_router(state)
            .oneshot(anon_repo_events("z6MkOwner", "widget"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "anon read of a private repo's events must be an opaque 404"
        );
    }

    // Owner reads their own private repo → 200 with BOTH datasets (cert + gossip),
    // guarding against a one-dataset half-fix.
    #[sqlx::test]
    async fn repo_events_private_repo_served_to_owner(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("r1", OWNER, "widget", false))
            .await
            .unwrap();
        state
            .db
            .insert_ref_certificate(&ref_cert("c1", "r1"))
            .await
            .unwrap();
        state
            .db
            .insert_ref_update(&ref_row("u1", "z6MkOwner/widget"))
            .await
            .unwrap();

        let resp = repo_events_router(state)
            .oneshot(signed_request_as(
                OWNER,
                Method::GET,
                "/api/v1/repos/z6MkOwner/widget/events",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(
            count(&body),
            2,
            "owner sees both the cert and the gossip row"
        );
        let sources: Vec<&str> = body["events"]
            .as_array()
            .expect("events array")
            .iter()
            .filter_map(|e| e["source"].as_str())
            .collect();
        assert!(
            sources.contains(&"local"),
            "cert row must be present, got {sources:?}"
        );
        assert!(
            sources.contains(&"gossipsub"),
            "gossip row must be present, got {sources:?}"
        );
    }

    // Anon reads a PUBLIC repo → 200 with data (positive control: the gate must not
    // over-withhold).
    #[sqlx::test]
    async fn repo_events_public_repo_served_to_anon(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("pub", OWNER, "openrepo", true))
            .await
            .unwrap();
        state
            .db
            .insert_ref_certificate(&ref_cert("c1", "pub"))
            .await
            .unwrap();
        state
            .db
            .insert_ref_update(&ref_row("u1", "z6MkOwner/openrepo"))
            .await
            .unwrap();

        let resp = repo_events_router(state)
            .oneshot(anon_repo_events("z6MkOwner", "openrepo"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(count(&body_json(resp).await), 2);
    }

    // Anon reads a quarantined mirror → 404 (withheld without disclosing existence
    // via authorize_repo_read's quarantine short-circuit).
    #[sqlx::test]
    async fn repo_events_quarantined_mirror_404_for_anon(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .upsert_mirror_repo("z6MkQuar", "secret", "/tmp/q", None, true)
            .await
            .unwrap();
        state
            .db
            .insert_ref_update(&ref_row("u1", "z6MkQuar/secret"))
            .await
            .unwrap();

        let resp = repo_events_router(state)
            .oneshot(anon_repo_events("z6MkQuar", "secret"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // Authenticated non-owner with no visibility grant → 404 (visibility_check deny
    // path, distinct from the anonymous case).
    #[sqlx::test]
    async fn repo_events_private_repo_404_for_non_owner(pool: PgPool) {
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

        let resp = repo_events_router(state)
            .oneshot(signed_request_as(
                "did:key:z6MkStranger",
                Method::GET,
                "/api/v1/repos/z6MkOwner/widget/events",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // RED→GREEN characterization of the deliberate behavior change: a repo NOT
    // hosted here (no repos row) but with a received gossip row under a matching
    // last-segment slug was served a populated 200 pre-gate; the gate closes it to
    // 404 (this node holds no visibility record for a not-hosted repo, so it fails
    // closed). Every other scenario seeds a local row and is blind to this path.
    #[sqlx::test]
    async fn repo_events_not_local_with_gossip_404_for_anon(pool: PgPool) {
        let state = test_state(pool).await;
        // No create_repo → get_repo returns None. A did:web-style short last segment
        // ("alice") makes the stored gossip slug equal the URL owner, so pre-gate the
        // not-local fallback slug matched and served the row.
        state
            .db
            .insert_ref_update(&ref_row("u1", "alice/widget"))
            .await
            .unwrap();

        let resp = repo_events_router(state)
            .oneshot(anon_repo_events("alice", "widget"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "a repo this node does not host must 404, not serve its gossip"
        );
    }

    // A private LOCAL did:web repo denies anon → 404. Complements the not-local test:
    // this proves anon cannot read a private did:web repo; the not-local test is what
    // exercises the truncated-owner resolution path.
    #[sqlx::test]
    async fn repo_events_did_web_private_local_404_for_anon(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("r1", "did:web:example.com:alice", "widget", false))
            .await
            .unwrap();
        state
            .db
            .insert_ref_update(&ref_row("u1", "alice/widget"))
            .await
            .unwrap();

        let resp = repo_events_router(state)
            .oneshot(anon_repo_events("alice", "widget"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // Authenticated non-owner reads a PUBLIC repo → 200 with data. Exercises
    // visibility_check's is_public Allow branch with a Some(caller), which the
    // anon-public and non-owner-private tests do not cover together.
    #[sqlx::test]
    async fn repo_events_public_repo_served_to_authenticated_non_owner(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("pub", OWNER, "openrepo", true))
            .await
            .unwrap();
        state
            .db
            .insert_ref_update(&ref_row("u1", "z6MkOwner/openrepo"))
            .await
            .unwrap();

        let resp = repo_events_router(state)
            .oneshot(signed_request_as(
                "did:key:z6MkStranger",
                Method::GET,
                "/api/v1/repos/z6MkOwner/openrepo/events",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(count(&body_json(resp).await), 1);
    }

    // did:web OWNER reads their own private repo → 200 with both datasets. The gossip
    // row is stored under the slug the emit side writes: normalize_owner_key leaves a
    // non-did:key DID intact, so api/repos publishes "did:web:example.com:alice/widget"
    // (not the last-segment "alice/widget"). This exercises the gossip KEEP branch of
    // the shared collector for a did:web caller, the happy-path complement to the
    // did:web deny test.
    #[sqlx::test]
    async fn repo_events_did_web_owner_reads_own_gossip(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = "did:web:example.com:alice";
        state
            .db
            .create_repo(&repo("r1", owner, "widget", false))
            .await
            .unwrap();
        state
            .db
            .insert_ref_certificate(&ref_cert("c1", "r1"))
            .await
            .unwrap();
        state
            .db
            .insert_ref_update(&ref_row("u1", "did:web:example.com:alice/widget"))
            .await
            .unwrap();

        let resp = repo_events_router(state)
            .oneshot(signed_request_as(
                owner,
                Method::GET,
                "/api/v1/repos/did:web:example.com:alice/widget/events",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(count(&body), 2, "did:web owner sees cert + gossip");
        let sources: Vec<&str> = body["events"]
            .as_array()
            .expect("events array")
            .iter()
            .filter_map(|e| e["source"].as_str())
            .collect();
        assert!(
            sources.contains(&"gossipsub"),
            "did:web owner's own gossip must be served, got {sources:?}"
        );
    }

    // An oversized limit is clamped at this handler (parity with the global feed).
    #[sqlx::test]
    async fn repo_events_oversized_limit_clamped(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("pub", OWNER, "openrepo", true))
            .await
            .unwrap();
        for i in 0..201 {
            let mut r = ref_row(&format!("g{i}"), "z6MkOwner/openrepo");
            r.timestamp = format!("2026-07-01T10:00:00.{i:04}+00:00");
            state.db.insert_ref_update(&r).await.unwrap();
        }

        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/repos/z6MkOwner/openrepo/events?limit=100000")
            .body(Body::empty())
            .expect("request builder");
        let resp = repo_events_router(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            count(&body_json(resp).await),
            200,
            "limit must clamp to MAX_VISIBLE_REF_UPDATES"
        );
    }

    // A negative limit must floor to 0 at this handler, not wrap to usize::MAX and
    // leave the local ref-cert list untruncated. The bug lives in the LOCAL half's
    // `truncate(limit as usize)` (the gossip half is already clamped in the shared
    // collector), so the repo is seeded with local certs and no gossip rows to keep
    // the assertion load-bearing.
    #[sqlx::test]
    async fn repo_events_negative_limit_clamped(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("pub", OWNER, "openrepo", true))
            .await
            .unwrap();
        for i in 0..3 {
            let mut c = ref_cert(&format!("c{i}"), "pub");
            c.ref_name = format!("refs/heads/b{i}");
            state.db.insert_ref_certificate(&c).await.unwrap();
        }

        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/repos/z6MkOwner/openrepo/events?limit=-1")
            .body(Body::empty())
            .expect("request builder");
        let resp = repo_events_router(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            count(&body_json(resp).await),
            0,
            "negative limit must clamp to 0, not leave the local set untruncated"
        );
    }

    // A mirror released from quarantine becomes readable → 200 (complements the
    // quarantined→404 test; guards against the gate staying closed after release).
    #[sqlx::test]
    async fn repo_events_released_mirror_served_to_anon(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .upsert_mirror_repo("z6MkQuar", "secret", "/tmp/q", None, true)
            .await
            .unwrap();
        state
            .db
            .insert_ref_update(&ref_row("u1", "z6MkQuar/secret"))
            .await
            .unwrap();
        // upsert_mirror_repo builds the id as "{owner_short}/{name}".
        state
            .db
            .set_repo_quarantine("z6MkQuar/secret", false)
            .await
            .unwrap();

        let resp = repo_events_router(state)
            .oneshot(anon_repo_events("z6MkQuar", "secret"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a released mirror must be readable again"
        );
    }

    // A DB error in the gate fails closed as 500, not swallowed into an empty 200 (the
    // regression the old get_repo().ok().flatten() allowed). Inject by dropping a
    // column get_repo selects so its query errors.
    #[sqlx::test]
    async fn repo_events_db_error_fails_closed_500(pool: PgPool) {
        let state = test_state(pool.clone()).await;
        state
            .db
            .create_repo(&repo("r1", OWNER, "widget", true))
            .await
            .unwrap();
        sqlx::query("ALTER TABLE repos DROP COLUMN is_public")
            .execute(&pool)
            .await
            .unwrap();

        let resp = repo_events_router(state)
            .oneshot(anon_repo_events("z6MkOwner", "widget"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "a DB error must fail closed (500), never serve an empty 200"
        );
    }

    // Symmetric to the gate DB-error test: a DB error in the CERT fetch (after the gate
    // passes) must also fail closed as 500, not an empty 200. Drop a column
    // list_ref_certificates selects so its query errors. (sqlx::test gives each test its
    // own isolated database, so the schema change cannot bleed into other tests.)
    #[sqlx::test]
    async fn repo_events_cert_db_error_fails_closed_500(pool: PgPool) {
        let state = test_state(pool.clone()).await;
        state
            .db
            .create_repo(&repo("r1", OWNER, "widget", true))
            .await
            .unwrap();
        sqlx::query("ALTER TABLE ref_certificates DROP COLUMN signature")
            .execute(&pool)
            .await
            .unwrap();

        let resp = repo_events_router(state)
            .oneshot(anon_repo_events("z6MkOwner", "widget"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "a DB error in the cert fetch must fail closed (500), never an empty 200"
        );
    }
}
