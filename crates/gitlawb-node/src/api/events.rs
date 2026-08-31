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

/// Documented maximum page size of the repo-scoped push-event poll surface, and
/// the value an over-large `limit` is clamped to. Named separately from the
/// ref-update ceiling above because it bounds a different feed with a different
/// gate; they happen to agree on a number today.
const MAX_PUSH_EVENT_PAGE: i64 = 200;

/// Smallest page the poll surface will serve. Not zero, and that is the point: a
/// zero-row page reads to a cursor-persisting poller exactly like "you have
/// reached the end", so combined with a cursor it could not carry forward it
/// silently sent the poller back to the beginning of history.
const MIN_PUSH_EVENT_PAGE: i64 = 1;

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
        .map(|v| v.max(0))
        .unwrap_or(50)
        .clamp(0, MAX_VISIBLE_REF_UPDATES);

    // Fail-closed visibility gate (#114), applied before the limit via paging so
    // an anon caller still gets the latest visible events, not a short page.
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let updates = collect_visible_ref_updates(&state.db, None, limit, caller).await?;

    // Resolve the trusted display owner_did per row. The stored wire value is
    // untrusted (arrives over gossip / unsigned peer notify), so it is echoed
    // only when it matches the canonical owner of the local repo the slug
    // names (#P1); legacy None rows are attributed via an exact unique local
    // match (#P3). Both surfaces share this resolver so they cannot drift.
    // The batch resolver issues at most one query per distinct local repo
    // rather than one per event row (#P2).
    let raw_dids: Vec<Option<String>> = state
        .db
        .resolve_ref_update_owner_dids(
            &updates
                .iter()
                .map(|u| (u.repo.as_str(), u.owner_did.as_deref()))
                .collect::<Vec<_>>(),
        )
        .await?;

    let owner_dids: Vec<serde_json::Value> = raw_dids
        .into_iter()
        .map(|o| o.map_or(serde_json::Value::Null, |s| serde_json::json!(s)))
        .collect();

    let events: Vec<serde_json::Value> = updates
        .iter()
        .enumerate()
        .map(|(i, u)| {
            let owner_did = owner_dids[i].clone();
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
                "owner_did":   owner_did,
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
        .map(|v| v.max(0))
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
        .list_ref_certificates(&record.id, limit)
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
                "owner_did":  record.owner_did,
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
    let gossip_updates =
        collect_visible_ref_updates(&state.db, Some(&repo_id_str), limit, caller).await?;
    let gossip_raw: Vec<Option<String>> = state
        .db
        .resolve_ref_update_owner_dids(
            &gossip_updates
                .iter()
                .map(|u| (u.repo.as_str(), u.owner_did.as_deref()))
                .collect::<Vec<_>>(),
        )
        .await?;

    let gossip_owner_dids: Vec<serde_json::Value> = gossip_raw
        .into_iter()
        .map(|o| o.map_or(serde_json::Value::Null, |s| serde_json::json!(s)))
        .collect();

    let gossip_events: Vec<serde_json::Value> = gossip_updates
        .iter()
        .enumerate()
        .map(|(i, u)| {
            let owner_did = gossip_owner_dids[i].clone();
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
                "owner_did":   owner_did,
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

/// Version prefix inside the cursor token, so a future change of shape is a
/// refusal a client can read rather than a silent misparse.
const PUSH_CURSOR_VERSION: &str = "1";

/// The value that binds a cursor to one repository ON one node.
///
/// A hash rather than the repository id itself, for two reasons that both
/// matter. It is fixed width, so the token's size does not vary with the id, and
/// it does not put an internal identifier on the wire — a cursor is a value
/// clients log, store and paste into bug reports.
///
/// Not a secret and not a MAC: a caller who knows the node DID and the
/// repository id can compute it. It is not trying to stop forgery, because there
/// is nothing to forge — the position inside the token is a row id that is
/// checked against this repository's own rows anyway. What it buys is that a
/// cursor from ANOTHER repository or another node is refused by shape, with a
/// message that says which mistake was made, instead of being silently applied
/// to a repository it was never issued for.
fn push_cursor_tag(node_did: &str, repo_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"gitlawb-push-cursor:v1:");
    h.update(node_did.as_bytes());
    h.update([0u8]);
    h.update(repo_id.as_bytes());
    hex::encode(&h.finalize()[..8])
}

/// Encode a poll position as the opaque token clients round-trip.
///
/// `after` is the id of the last event the caller has seen, or `None` for the
/// start of history — which is a real, expressible position rather than an
/// absent one, so `next_cursor` never has to be null and a poller that persists
/// it never rewinds.
///
/// What is NOT in here is the point: the table-global `seq`. It used to be the
/// cursor, handed to the client verbatim, and `repo_push_events` is written by
/// every repository on the node. Its gaps are therefore a measurement of how
/// much OTHER repositories pushed between two of this one's events, private ones
/// included. A row id carries no such information; the id is already in every
/// event this surface serves, so it discloses nothing new.
fn encode_push_cursor(tag: &str, after: Option<&str>) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(format!(
        "{PUSH_CURSOR_VERSION}.{tag}.{}",
        after.unwrap_or("")
    ))
}

/// A caller-supplied `cursor` value as a poll position, or a 400.
///
/// `Ok(None)` is the start of history; `Ok(Some(id))` names the last event the
/// caller saw. The id is NOT trusted here — [`Db::push_event_seq`] resolves it
/// against this repository's own rows, and an id that resolves to nothing is
/// refused there.
///
/// Everything else is refused rather than reinterpreted, because both silent
/// readings are wrong in a way the poller cannot see. Reading an unknown cursor
/// as "no cursor" replays the repository's whole history to a client that
/// believed it was up to date; reading it as "the end" hides every event after
/// it — which is exactly what a bare `seq > $1` did with a number issued by some
/// other repository, or retained across a restore: an empty 200, echoed back, and
/// a subscriber permanently past events it never received.
fn decode_push_cursor(raw: &str, tag: &str) -> Result<Option<String>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let refuse = |what: &str| {
        crate::error::AppError::BadRequest(format!(
            "cursor {what}; use the `next_cursor` this endpoint returned for this repository"
        ))
    };
    let unissued = "is not a token this endpoint issued";

    let decoded = URL_SAFE_NO_PAD.decode(raw).map_err(|_| refuse(unissued))?;
    let text = String::from_utf8(decoded).map_err(|_| refuse(unissued))?;
    let mut parts = text.splitn(3, '.');
    let (Some(version), Some(bound_tag), Some(after)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(refuse(unissued));
    };
    if version != PUSH_CURSOR_VERSION {
        return Err(refuse(
            "was issued in a format this endpoint no longer reads",
        ));
    }
    if bound_tag != tag {
        return Err(refuse(
            "was issued for a different repository or a different node",
        ));
    }
    Ok((!after.is_empty()).then(|| after.to_string()))
}

/// GET /api/v1/repos/{owner}/{repo}/push-events?cursor=&limit=
///
/// The catch-up half of push notification. A subscriber whose webhook delivery
/// failed polls this with the cursor it last saw and gets every push since,
/// oldest first, so a missed delivery costs a poll rather than needing retry
/// machinery on the send side.
///
/// The cursor is the `next_cursor` the previous page returned: an OPAQUE token
/// naming the last event the caller saw, scoped to this repository on this node.
/// Rows are read strictly after it. Omitting it starts at the beginning of the
/// repo's history.
///
/// Opaque and scoped, rather than the raw `seq` it used to be, because that
/// number was neither. Every non-negative integer was accepted and passed
/// straight into a per-repo `seq > $1`, so a value issued by a DIFFERENT
/// repository — or by this one before a restore — returned an empty 200 and was
/// echoed back, permanently skipping this repository's history while the
/// subscriber believed it was caught up. And the number was the table-global
/// `BIGSERIAL`, shared by every repository on the node, so its gaps measured how
/// much other repositories pushed, private ones included. The token now carries
/// a repository binding that is checked before the read, and a row id that is
/// resolved against this repository's own rows; an unknown or foreign cursor is
/// a visible 400 instead of a silent skip.
///
/// Rows are still ordered by the database-assigned `seq` internally — the
/// timestamp is stamped by the application before the insert and cannot order
/// them (see [`crate::db::Db::list_repo_push_events_keyset`]) — but that value
/// no longer leaves the node.
///
/// `next_cursor` is always present, never null, and never moves backwards: an
/// empty page hands back the position the caller already had, and the start of
/// history is itself an expressible position rather than an absent one. A poller
/// that persists it therefore stays where it is when there is nothing new,
/// instead of restarting from the beginning.
///
/// `limit` is clamped to [`MIN_PUSH_EVENT_PAGE`]..=[`MAX_PUSH_EVENT_PAGE`]. A
/// value that does not parse falls back to the default page size.
///
/// Rows come from `repo_push_events`, which only this node's own pushes write.
/// The gossip-sourced `received_ref_updates` rows are a different data class on
/// a different surface, and nothing here reads or writes them.
pub async fn list_repo_push_events(
    State(state): State<AppState>,
    Path((owner, repo_name)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(50)
        .clamp(MIN_PUSH_EVENT_PAGE, MAX_PUSH_EVENT_PAGE);

    // Repo-root read gate on the requested path, before any event row is
    // touched: a caller who cannot read the repo gets the repo's own not-found,
    // byte-identical to a repo that does not exist here, so the surface is not an
    // oracle for which private repos are being pushed to. Rows are keyed by the
    // unique repo record id, so unlike the gossip feed there is no lossy wire
    // slug to re-gate per row.
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &repo_name, caller, "/").await?;

    // Cursor validation runs AFTER the gate on purpose: a caller who may not read
    // this repo gets the not-found for every request shape, so a 400 can never
    // become the tell that distinguishes a private repo from a missing one.
    let tag = push_cursor_tag(&state.node_did.to_string(), &record.id);
    let after = match params.get("cursor") {
        Some(raw) => decode_push_cursor(raw, &tag)?,
        None => None,
    };

    // Resolve the named event to its ordering key against THIS repository's
    // rows. A cursor whose event is not here — a token kept across a restore
    // that lost it, or one for a row that never existed — is a visible 400, not
    // an empty page that reads to the poller as "you are up to date". The read
    // itself still walks `seq`, which is what makes the page cheap.
    let cursor = match &after {
        Some(id) => Some(
            state
                .db
                .push_event_seq(&record.id, id)
                .await?
                .ok_or_else(|| {
                    crate::error::AppError::BadRequest(
                        "cursor names an event this repository does not have; poll without a \
                         cursor to restart from the beginning of its history"
                            .into(),
                    )
                })?,
        ),
        None => None,
    };

    let rows = state
        .db
        .list_repo_push_events_keyset(&record.id, cursor, limit)
        .await?;

    let events: Vec<serde_json::Value> = rows
        .iter()
        .map(|e| {
            serde_json::json!({
                "id":         e.id,
                "ref_name":   e.ref_name,
                "after_sha":  e.after_sha,
                "created_at": e.created_at,
            })
        })
        .collect();
    // Never null and never backwards: an empty page returns the cursor the caller
    // arrived with (or the start of history, if it arrived with none), re-encoded
    // to the same bytes it sent.
    let next = encode_push_cursor(&tag, rows.last().map_or(after.as_deref(), |e| Some(&e.id)));
    let count = events.len();
    Ok(Json(serde_json::json!({
        "events": events,
        "count": count,
        "next_cursor": next,
    })))
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
            owner_did: None,
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
        let body = body_json(resp).await;
        assert_eq!(count(&body), 2);
        for event in body["events"].as_array().unwrap() {
            assert_eq!(
                event["owner_did"], OWNER,
                "each event must carry the local owner_did"
            );
        }
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

#[cfg(test)]
mod push_events_tests {
    use crate::db::{RepoPushEvent, RepoRecord};
    use crate::test_support::{signed_request_as, test_state};
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::Router;
    use chrono::Utc;
    use sqlx::PgPool;
    use tower::ServiceExt;

    use super::MAX_PUSH_EVENT_PAGE;

    const OWNER: &str = "did:key:z6MkOwner";
    const SHA_A: &str = "1111111111111111111111111111111111111111";
    const SHA_B: &str = "2222222222222222222222222222222222222222";

    fn repo(id: &str, name: &str, is_public: bool) -> RepoRecord {
        let now = Utc::now();
        RepoRecord {
            id: id.into(),
            name: name.into(),
            owner_did: OWNER.into(),
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

    fn poll_router(state: crate::state::AppState) -> Router {
        Router::new()
            .route(
                "/api/v1/repos/{owner}/{repo}/push-events",
                axum::routing::get(super::list_repo_push_events),
            )
            .with_state(state)
    }

    fn global_feed_router(state: crate::state::AppState) -> Router {
        Router::new()
            .route(
                "/api/v1/events/ref-updates",
                axum::routing::get(super::list_ref_updates),
            )
            .with_state(state)
    }

    fn poll_uri(name: &str, query: &str) -> String {
        let base = format!("/api/v1/repos/{OWNER}/{name}/push-events");
        if query.is_empty() {
            base
        } else {
            format!("{base}?{query}")
        }
    }

    async fn poll(
        state: &crate::state::AppState,
        caller: Option<&str>,
        uri: &str,
    ) -> axum::response::Response {
        let req = match caller {
            Some(did) => signed_request_as(did, Method::GET, uri, Body::empty()),
            None => Request::builder()
                .method(Method::GET)
                .uri(uri)
                .body(Body::empty())
                .expect("request builder"),
        };
        poll_router(state.clone()).oneshot(req).await.unwrap()
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        serde_json::from_slice(&bytes).expect("json body")
    }

    /// Status plus the full response body, for the byte-identical deny comparison.
    async fn status_and_bytes(resp: axum::response::Response) -> (StatusCode, Vec<u8>) {
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        (status, bytes)
    }

    fn event_rows(v: &serde_json::Value) -> Vec<(String, String, String)> {
        v["events"]
            .as_array()
            .expect("events array")
            .iter()
            .map(|e| {
                (
                    e["id"].as_str().expect("id").to_string(),
                    e["ref_name"].as_str().expect("ref_name").to_string(),
                    e["after_sha"].as_str().expect("after_sha").to_string(),
                )
            })
            .collect()
    }

    /// Walk the whole poll surface one row at a time, following the cursor the
    /// surface itself hands back, and return the event ids in the order served.
    /// `max_steps` bounds the walk, so a cursor that fails to advance fails the
    /// test instead of hanging it.
    async fn walk_cursor(
        state: &crate::state::AppState,
        name: &str,
        max_steps: usize,
    ) -> Vec<String> {
        let mut ids: Vec<String> = Vec::new();
        let mut query = "limit=1".to_string();
        for _ in 0..max_steps {
            let body = body_json(poll(state, Some(OWNER), &poll_uri(name, &query)).await).await;
            let rows = event_rows(&body);
            if rows.is_empty() {
                return ids;
            }
            ids.extend(rows.into_iter().map(|r| r.0));
            query = format!(
                "limit=1&cursor={}",
                body["next_cursor"].as_str().expect("next_cursor"),
            );
        }
        panic!("the cursor walk did not terminate within {max_steps} steps: {ids:?}");
    }

    /// Seed one push-event row directly, for the read-side scenarios that are
    /// about paging and gating rather than about the producer.
    async fn seed_event(
        state: &crate::state::AppState,
        id: &str,
        repo_id: &str,
        ref_name: &str,
        sha: &str,
        at: &str,
    ) {
        state
            .db
            .insert_repo_push_event(&RepoPushEvent {
                id: id.into(),
                // Ignored on insert; the database assigns the ordering key.
                seq: 0,
                repo_id: repo_id.into(),
                ref_name: ref_name.into(),
                after_sha: sha.into(),
                created_at: at.into(),
            })
            .await
            .unwrap();
    }

    /// A TCP port with nothing listening on it: bind, read the port, drop the
    /// listener. Used to make "the webhook target is unreachable" a property the
    /// test observes rather than one it assumes.
    fn dead_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = l.local_addr().expect("local addr").port();
        drop(l);
        port
    }

    /// Covers AE6. The repo's webhook points at a port nothing is listening on,
    /// so the push notification cannot be delivered; the test proves that by
    /// firing a request at the same target with the same client and observing the
    /// transport error, rather than assuming it. The push still records its event,
    /// and a poll with a cursor from before the push returns the pushed ref and
    /// SHA. That is the whole point of the unit: delivery reliability becomes a
    /// read-side property, with no retry machinery anywhere.
    #[sqlx::test]
    async fn ae6_poll_catches_up_when_the_webhook_target_is_unreachable(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("r-ae6", "widget", true))
            .await
            .unwrap();

        let url = format!("http://127.0.0.1:{}/hook", dead_port());
        state
            .db
            .create_webhook(&crate::db::Webhook {
                id: "hook-ae6".into(),
                repo_id: "r-ae6".into(),
                url: url.clone(),
                secret: None,
                events: vec!["push".into()],
                created_by_did: OWNER.into(),
                created_at: Utc::now().to_rfc3339(),
                active: true,
            })
            .await
            .unwrap();

        // The cursor a subscriber last polled at. The repo has never been pushed
        // to, so that cursor is the start of history — which the surface hands
        // out as a real token rather than as an absent value.
        let before = body_json(poll(&state, Some(OWNER), &poll_uri("widget", "")).await).await
            ["next_cursor"]
            .as_str()
            .expect("next_cursor")
            .to_string();

        // The push happens. The webhook fires into the void.
        crate::api::repos::record_push_events(
            &state.db,
            "r-ae6",
            &[crate::api::repos::RefUpdate {
                old_sha: "0".repeat(40),
                new_sha: SHA_A.into(),
                ref_name: "refs/heads/main".into(),
            }],
        )
        .await;
        crate::webhooks::fire_event(
            state.db.clone(),
            state.http_client.clone(),
            "r-ae6",
            "push",
            serde_json::json!({ "ref": "refs/heads/main", "after": SHA_A }),
        );

        // The target really is unreachable: same client, same URL, transport error.
        let delivery = state.http_client.post(&url).body("{}").send().await;
        assert!(
            delivery.is_err(),
            "the webhook target must be unreachable for this scenario to prove \
             anything; got {delivery:?}"
        );

        let body = body_json(
            poll(
                &state,
                Some(OWNER),
                &poll_uri("widget", &format!("cursor={before}")),
            )
            .await,
        )
        .await;
        let rows = event_rows(&body);
        assert_eq!(
            rows.len(),
            1,
            "the missed push must be discoverable by polling, got {body}"
        );
        assert_eq!(rows[0].1, "refs/heads/main");
        assert_eq!(rows[0].2, SHA_A);
        assert_eq!(body["count"].as_u64(), Some(1));
    }

    /// Two ref updates in one push share a timestamp by construction, which is
    /// the case a timestamp-based cursor cannot page: it either repeats a row or
    /// drops one at the boundary. The collision is produced deterministically by
    /// pushing two refs at once (the producer stamps one timestamp for the whole
    /// push), not raced for. With a page size of one, the walk must return both
    /// rows exactly once and then terminate.
    ///
    /// The cursor is fed back verbatim into the query string, so this also pins
    /// that the emitted cursor survives that round trip.
    #[sqlx::test]
    async fn colliding_timestamps_page_once_each(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("r-tie", "widget", true))
            .await
            .unwrap();

        crate::api::repos::record_push_events(
            &state.db,
            "r-tie",
            &[
                crate::api::repos::RefUpdate {
                    old_sha: "0".repeat(40),
                    new_sha: SHA_A.into(),
                    ref_name: "refs/heads/main".into(),
                },
                crate::api::repos::RefUpdate {
                    old_sha: "0".repeat(40),
                    new_sha: SHA_B.into(),
                    ref_name: "refs/heads/other".into(),
                },
            ],
        )
        .await;

        let all = body_json(poll(&state, Some(OWNER), &poll_uri("widget", "")).await).await;
        let stamps: Vec<&str> = all["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["created_at"].as_str().unwrap())
            .collect();
        assert_eq!(stamps.len(), 2);
        assert_eq!(
            stamps[0], stamps[1],
            "the scenario needs a real timestamp collision to test, got {stamps:?}"
        );

        let first =
            body_json(poll(&state, Some(OWNER), &poll_uri("widget", "limit=1")).await).await;
        let page1 = event_rows(&first);
        assert_eq!(
            page1.len(),
            1,
            "page size of one must return one row, got {first}"
        );

        let next_cursor = first["next_cursor"].as_str().expect("next_cursor");

        let cursor = format!("cursor={next_cursor}&limit=1");
        let second = body_json(poll(&state, Some(OWNER), &poll_uri("widget", &cursor)).await).await;
        let page2 = event_rows(&second);
        assert_eq!(
            page2.len(),
            1,
            "the second row must survive the page boundary, got {second}"
        );

        assert_ne!(
            page1[0].0, page2[0].0,
            "the cursor must advance past the first row, not repeat it"
        );
        let mut refs = vec![page1[0].1.clone(), page2[0].1.clone()];
        refs.sort();
        assert_eq!(
            refs,
            vec![
                "refs/heads/main".to_string(),
                "refs/heads/other".to_string()
            ],
            "both colliding-timestamp rows must be returned, once each"
        );

        let cursor2 = format!(
            "cursor={}&limit=1",
            second["next_cursor"].as_str().expect("next_cursor"),
        );
        let third = body_json(poll(&state, Some(OWNER), &poll_uri("widget", &cursor2)).await).await;
        assert!(
            event_rows(&third).is_empty(),
            "the walk must terminate rather than repeat a row, got {third}"
        );
    }

    /// The cursor must order on insertion, not on the wall clock. `created_at` is
    /// stamped by the application before the insert, so a row stamped later can
    /// commit earlier, and an NTP step backwards makes that ordinary rather than
    /// a race. A poller that has already advanced past the later stamp then never
    /// sees the earlier-stamped row at all.
    ///
    /// The disagreement is constructed rather than raced for: the first row
    /// written carries the LATER timestamp. A walk must still return both rows
    /// exactly once, in the order they were inserted.
    #[sqlx::test]
    async fn the_cursor_walk_follows_insertion_order_not_the_wall_clock(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("r-clock", "widget", true))
            .await
            .unwrap();

        seed_event(
            &state,
            "evt-first",
            "r-clock",
            "refs/heads/one",
            SHA_A,
            "2026-08-07T13:00:00.000000Z",
        )
        .await;
        seed_event(
            &state,
            "evt-second",
            "r-clock",
            "refs/heads/two",
            SHA_B,
            "2026-08-07T12:00:00.000000Z",
        )
        .await;

        let walked = walk_cursor(&state, "widget", 6).await;
        assert_eq!(
            walked,
            vec!["evt-first".to_string(), "evt-second".to_string()],
            "the walk must return every row exactly once in insertion order; \
             ordering on the application-stamped clock reverses these two and \
             strands the second behind a cursor that has already passed it"
        );
    }

    /// Seed two events and hand back the repo name plus the cursor that sits
    /// between them, for the degenerate-input cases below.
    async fn two_event_repo(state: &crate::state::AppState) -> String {
        state
            .db
            .create_repo(&repo("r-bad", "widget", true))
            .await
            .unwrap();
        seed_event(
            state,
            "evt-1",
            "r-bad",
            "refs/heads/one",
            SHA_A,
            "2026-08-07T12:00:00.000000Z",
        )
        .await;
        seed_event(
            state,
            "evt-2",
            "r-bad",
            "refs/heads/two",
            SHA_B,
            "2026-08-07T12:00:01.000000Z",
        )
        .await;

        let first = body_json(poll(state, Some(OWNER), &poll_uri("widget", "limit=1")).await).await;
        first["next_cursor"]
            .as_str()
            .expect("next_cursor")
            .to_string()
    }

    /// A cursor the surface could not have issued is a client bug, and the only
    /// safe answer is to say so. Silently treating it as "no cursor" replays the
    /// repo's whole history to a poller that believed it was up to date, and
    /// silently treating it as "the end" hides every event after it.
    #[sqlx::test]
    async fn a_malformed_cursor_is_rejected_with_a_400(pool: PgPool) {
        let state = test_state(pool).await;
        let mid = two_event_repo(&state).await;

        for bad in [
            "notacursor",
            "",
            "-1",
            "1.5",
            "99999999999999999999999999",
            // Percent-encoded leading space: a valid URI that decodes to " 1".
            "%201",
            // What the surface used to issue and accept: a bare sequence
            // number. It is no longer a cursor at all, and the poller that
            // kept one across the change is told so rather than being served an
            // empty page it would read as "caught up".
            "42",
        ] {
            let resp = poll(
                &state,
                Some(OWNER),
                &poll_uri("widget", &format!("cursor={bad}")),
            )
            .await;
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "cursor={bad:?} must be refused, not reinterpreted"
            );
            let body = body_json(resp).await;
            assert_eq!(
                body["error"], "bad_request",
                "the refusal needs a stable code a client can branch on, got {body}"
            );
        }

        // The control: a cursor the surface actually issued still works, so the
        // rejection above is validation and not a blanket refusal.
        let ok = poll(
            &state,
            Some(OWNER),
            &poll_uri("widget", &format!("cursor={mid}")),
        )
        .await;
        assert_eq!(ok.status(), StatusCode::OK);
        assert_eq!(event_rows(&body_json(ok).await).len(), 1);
    }

    /// `limit=0` used to return an empty page carrying no cursor, which reads to
    /// a cursor-persisting poller exactly like "you are at the end" while also
    /// wiping the position it had, so the next poll started from the beginning
    /// of history. A limit below one is clamped up instead: the page makes
    /// progress, and the cursor it returns moves forward.
    #[sqlx::test]
    async fn a_zero_limit_makes_progress_instead_of_rewinding(pool: PgPool) {
        let state = test_state(pool).await;
        let mid = two_event_repo(&state).await;

        let body = body_json(
            poll(
                &state,
                Some(OWNER),
                &poll_uri("widget", &format!("cursor={mid}&limit=0")),
            )
            .await,
        )
        .await;
        let next = body["next_cursor"].as_str().expect("next_cursor");
        assert!(
            !next.is_empty(),
            "a cursor must never come back empty; asked from {mid}, got {body}"
        );
        assert_eq!(
            event_rows(&body).len(),
            1,
            "a limit below one is clamped to one row, not to an empty page, got {body}"
        );
    }

    /// The upper clamp, from the other side: a caller asking for more than the
    /// surface serves gets the documented maximum rather than an unbounded scan.
    #[sqlx::test]
    async fn an_oversized_limit_is_clamped_to_the_documented_maximum(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("r-big", "widget", true))
            .await
            .unwrap();
        for i in 0..(MAX_PUSH_EVENT_PAGE + 5) {
            seed_event(
                &state,
                &format!("evt-{i}"),
                "r-big",
                "refs/heads/main",
                SHA_A,
                "2026-08-07T12:00:00.000000Z",
            )
            .await;
        }

        let body =
            body_json(poll(&state, Some(OWNER), &poll_uri("widget", "limit=100000")).await).await;
        assert_eq!(
            event_rows(&body).len() as i64,
            MAX_PUSH_EVENT_PAGE,
            "an oversized limit must be clamped, got {}",
            event_rows(&body).len()
        );
    }

    /// A caller already up to date polls with the cursor it got last time. That is
    /// the steady state of this surface, and it is a 200 with an empty page, not
    /// an error and not a repeat of the last row.
    #[sqlx::test]
    async fn cursor_past_the_last_event_returns_an_empty_page(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("r-tail", "widget", true))
            .await
            .unwrap();
        seed_event(
            &state,
            "evt-1",
            "r-tail",
            "refs/heads/main",
            SHA_A,
            "2026-08-07T12:00:00.000000Z",
        )
        .await;

        // The steady state: poll with the cursor the last page returned.
        let caught_up = body_json(poll(&state, Some(OWNER), &poll_uri("widget", "")).await).await;
        let tail = caught_up["next_cursor"]
            .as_str()
            .expect("next_cursor")
            .to_string();

        let resp = poll(
            &state,
            Some(OWNER),
            &poll_uri("widget", &format!("cursor={tail}")),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "an exhausted cursor is not an error"
        );
        let body = body_json(resp).await;
        assert!(
            event_rows(&body).is_empty(),
            "expected an empty page, got {body}"
        );
        assert_eq!(body["count"].as_u64(), Some(0));
        assert_eq!(
            body["next_cursor"].as_str(),
            Some(tail.as_str()),
            "an empty page must hand back the cursor it was given; a null (or an \
             earlier position) tells a poller that persists it to start over from \
             the beginning of history, got {body}"
        );

        // And the same on a repo with no events at all, where there is no row to
        // derive a cursor from: the start of history is an expressible position,
        // not an absent one, so the answer is a usable token rather than null.
        state
            .db
            .create_repo(&repo("r-empty", "quiet", true))
            .await
            .unwrap();
        let empty = body_json(poll(&state, Some(OWNER), &poll_uri("quiet", "")).await).await;
        let start = empty["next_cursor"]
            .as_str()
            .expect("a first poll must still carry a cursor")
            .to_string();
        let again = poll(
            &state,
            Some(OWNER),
            &poll_uri("quiet", &format!("cursor={start}")),
        )
        .await;
        assert_eq!(
            again.status(),
            StatusCode::OK,
            "the start-of-history token must be a cursor this endpoint accepts back"
        );
    }

    /// A cursor issued for ANOTHER repository is refused, not applied.
    ///
    /// This is the failure the bare sequence number could not see. `seq` is a
    /// table-global bigserial shared by every repository on the node, so a
    /// number issued for a busy repository is an ordinary, larger number here:
    /// `seq > $1` matched nothing, the surface answered 200 with an empty page
    /// and echoed the value back, and the subscriber sat permanently past
    /// history it had never received — with nothing anywhere reading as an
    /// error. Both repositories are readable by this caller, so the refusal is
    /// about scope and not about access.
    ///
    /// The control matters as much as the refusal: the same position, expressed
    /// as this repository's own cursor, still serves its second event.
    #[sqlx::test]
    async fn a_cursor_issued_for_another_repository_is_refused(pool: PgPool) {
        let state = test_state(pool).await;
        for (id, name) in [("r-mine", "mine"), ("r-theirs", "theirs")] {
            state.db.create_repo(&repo(id, name, true)).await.unwrap();
        }
        // Interleaved, so the two repositories' rows do not occupy contiguous
        // ranges of the shared sequence: a cursor from one really does land in
        // the middle of the other's history.
        for n in 0..2 {
            for repo_id in ["r-theirs", "r-mine"] {
                seed_event(
                    &state,
                    &format!("evt-{repo_id}-{n}"),
                    repo_id,
                    "refs/heads/main",
                    SHA_A,
                    "2026-08-07T12:00:00.000000Z",
                )
                .await;
            }
        }

        let theirs = body_json(poll(&state, Some(OWNER), &poll_uri("theirs", "limit=1")).await)
            .await["next_cursor"]
            .as_str()
            .expect("next_cursor")
            .to_string();

        let resp = poll(
            &state,
            Some(OWNER),
            &poll_uri("mine", &format!("cursor={theirs}")),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "another repository's cursor must be refused visibly, not silently \
             skip this repository's history"
        );
        let body = body_json(resp).await;
        assert!(
            body["message"]
                .as_str()
                .is_some_and(|m| m.contains("different repository")),
            "the refusal must say WHICH mistake was made, got {body}"
        );

        // The control: this repository's own cursor, at the same position,
        // serves the next row.
        let mine = body_json(poll(&state, Some(OWNER), &poll_uri("mine", "limit=1")).await).await
            ["next_cursor"]
            .as_str()
            .expect("next_cursor")
            .to_string();
        let ok = body_json(
            poll(
                &state,
                Some(OWNER),
                &poll_uri("mine", &format!("cursor={mine}")),
            )
            .await,
        )
        .await;
        assert_eq!(
            event_rows(&ok).len(),
            1,
            "the repository's own cursor must still page it, got {ok}"
        );
    }

    /// A cursor whose event this repository no longer has is refused, which is
    /// the "retained across a restore" case.
    ///
    /// The token is well formed and correctly scoped; the row behind it is
    /// simply gone. Answering an empty 200 would tell a poller it is up to date
    /// about a history it has not read, and would keep telling it that forever.
    /// The refusal names the recovery — poll without a cursor — so the client
    /// can act on it.
    #[sqlx::test]
    async fn a_cursor_naming_an_event_this_repo_no_longer_has_is_refused(pool: PgPool) {
        let state = test_state(pool.clone()).await;
        state
            .db
            .create_repo(&repo("r-gone", "widget", true))
            .await
            .unwrap();
        for n in 0..2 {
            seed_event(
                &state,
                &format!("evt-{n}"),
                "r-gone",
                "refs/heads/main",
                SHA_A,
                "2026-08-07T12:00:00.000000Z",
            )
            .await;
        }

        let cursor = body_json(poll(&state, Some(OWNER), &poll_uri("widget", "limit=1")).await)
            .await["next_cursor"]
            .as_str()
            .expect("next_cursor")
            .to_string();

        // The row the cursor names disappears — a restore from a backup taken
        // before it, in production.
        sqlx::query("DELETE FROM repo_push_events WHERE id = 'evt-0'")
            .execute(&pool)
            .await
            .unwrap();

        let resp = poll(
            &state,
            Some(OWNER),
            &poll_uri("widget", &format!("cursor={cursor}")),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "a cursor whose event is gone must be refused, not answered with an \
             empty page the poller reads as being up to date"
        );
        let body = body_json(resp).await;
        assert!(
            body["message"]
                .as_str()
                .is_some_and(|m| m.contains("does not have")),
            "the refusal must name the recovery, got {body}"
        );
    }

    /// The cursor discloses no table-global counter.
    ///
    /// `repo_push_events.seq` is one bigserial shared by every repository on the
    /// node. Handing it to clients turned the gaps between one repository's
    /// cursors into a measurement of how much OTHER repositories pushed in
    /// between — private ones included. The token that replaced it carries a
    /// repository binding and a row id the surface already publishes, and it
    /// must not carry that number in any form a reader can lift back out.
    #[sqlx::test]
    async fn the_cursor_does_not_carry_the_table_global_sequence(pool: PgPool) {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let state = test_state(pool.clone()).await;
        for (id, name) in [("r-noisy", "noisy"), ("r-leak", "widget")] {
            state.db.create_repo(&repo(id, name, true)).await.unwrap();
        }
        // The other repository's pushes come first, so the sequence value this
        // repository's single row lands on is a multi-digit number that could
        // not be confused with the token's version prefix — and is itself the
        // measurement the old cursor handed out.
        for n in 0..20 {
            seed_event(
                &state,
                &format!("noise-{n}"),
                "r-noisy",
                "refs/heads/main",
                SHA_A,
                "2026-08-07T12:00:00.000000Z",
            )
            .await;
        }
        seed_event(
            &state,
            "evt-1",
            "r-leak",
            "refs/heads/main",
            SHA_A,
            "2026-08-07T12:00:00.000000Z",
        )
        .await;

        let seq: i64 = sqlx::query_scalar("SELECT seq FROM repo_push_events WHERE id = 'evt-1'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(
            seq > 9,
            "the scenario needs a multi-digit sequence to be meaningful, got {seq}"
        );

        let cursor = body_json(poll(&state, Some(OWNER), &poll_uri("widget", "")).await).await
            ["next_cursor"]
            .as_str()
            .expect("next_cursor")
            .to_string();

        assert!(
            !cursor.contains(&seq.to_string()),
            "the encoded cursor must not spell the global sequence, got {cursor}"
        );
        let decoded = String::from_utf8(URL_SAFE_NO_PAD.decode(&cursor).expect("base64url"))
            .expect("utf-8 token");
        assert!(
            !decoded.contains(&seq.to_string()),
            "decoding the cursor must not reveal the global sequence either, got \
             {decoded}"
        );
        assert_eq!(
            decoded.splitn(3, '.').nth(2),
            Some("evt-1"),
            "the position must be the row id this surface already publishes, got \
             {decoded}"
        );
    }

    /// An anonymous poll of a PRIVATE repo answers byte for byte what the same
    /// caller gets for a repo that does not exist. Events are seeded first, so the
    /// deny cannot pass vacuously on an empty projection.
    #[sqlx::test]
    async fn anon_poll_on_a_private_repo_is_indistinguishable_from_missing(pool: PgPool) {
        let state = test_state(pool).await;
        let target = poll_uri("secret", "");

        let missing = status_and_bytes(poll(&state, None, &target).await).await;

        state
            .db
            .create_repo(&repo("r-priv", "secret", false))
            .await
            .unwrap();
        seed_event(
            &state,
            "evt-priv",
            "r-priv",
            "refs/heads/main",
            SHA_A,
            "2026-08-07T12:00:00.000000Z",
        )
        .await;

        let denied = status_and_bytes(poll(&state, None, &target).await).await;

        assert_eq!(missing.0, StatusCode::NOT_FOUND);
        assert_eq!(
            denied, missing,
            "a private-repo deny must be byte-identical to the missing-repo response"
        );
        assert!(
            !String::from_utf8_lossy(&denied.1).contains(SHA_A),
            "the deny must carry no trace of the seeded event"
        );
    }

    /// The other half of the gate: a public repo's push events are served to an
    /// anonymous caller, so the deny above is a gate and not a blanket refusal.
    #[sqlx::test]
    async fn public_repo_push_events_served_to_anon(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("r-pub", "openrepo", true))
            .await
            .unwrap();
        seed_event(
            &state,
            "evt-pub",
            "r-pub",
            "refs/heads/main",
            SHA_A,
            "2026-08-07T12:00:00.000000Z",
        )
        .await;

        let body = body_json(poll(&state, None, &poll_uri("openrepo", "")).await).await;
        assert_eq!(
            event_rows(&body).len(),
            1,
            "a public repo's events are anonymous-readable"
        );
    }

    /// Containment. A push to a PRIVATE repo must not surface on the
    /// unauthenticated global feed at `/api/v1/events/ref-updates`, which reads
    /// `received_ref_updates`. If the producer ever wrote there instead of into
    /// the repo-scoped table, this unit would be introducing an anonymous leak of
    /// private-repo push metadata.
    #[sqlx::test]
    async fn a_private_push_never_reaches_the_anonymous_global_feed(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("r-contain", "secret", false))
            .await
            .unwrap();

        crate::api::repos::record_push_events(
            &state.db,
            "r-contain",
            &[crate::api::repos::RefUpdate {
                old_sha: "0".repeat(40),
                new_sha: SHA_A.into(),
                ref_name: "refs/heads/main".into(),
            }],
        )
        .await;

        let anon = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/events/ref-updates")
            .body(Body::empty())
            .expect("request builder");
        let resp = global_feed_router(state.clone())
            .oneshot(anon)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(
            !raw.contains(SHA_A) && !raw.contains("refs/heads/main"),
            "a local push must not appear on the anonymous global feed, got {raw}"
        );

        // And the row really was written somewhere: the owner's poll finds it, so
        // the assertion above is not passing because nothing was recorded at all.
        let body = body_json(poll(&state, Some(OWNER), &poll_uri("secret", "")).await).await;
        assert_eq!(
            event_rows(&body).len(),
            1,
            "the push event must exist on the repo-scoped surface, got {body}"
        );
    }

    /// A branch deletion carries an all-zero new SHA. Recording it would hand a
    /// poller a target that resolves to no commit, so the producer skips it, the
    /// same way the stored-head update does.
    #[sqlx::test]
    async fn a_branch_deletion_records_no_push_event(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("r-del", "widget", true))
            .await
            .unwrap();

        crate::api::repos::record_push_events(
            &state.db,
            "r-del",
            &[crate::api::repos::RefUpdate {
                old_sha: SHA_A.into(),
                new_sha: "0".repeat(40),
                ref_name: "refs/heads/gone".into(),
            }],
        )
        .await;

        let body = body_json(poll(&state, Some(OWNER), &poll_uri("widget", "")).await).await;
        assert!(
            event_rows(&body).is_empty(),
            "a deletion must not record a push event, got {body}"
        );
    }
}
