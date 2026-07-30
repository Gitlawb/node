use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Json;
use bytes::Bytes;
use std::sync::Arc;

use crate::auth::{caller_authorized_to_push, AuthenticatedDid};
use crate::db::RepoRecord;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cert;
use crate::error::{AppError, Result};
use crate::git::{smart_http, store, visibility_pack};
use crate::state::AppState;
use crate::visibility::{visibility_check, withheld_globs, Decision};
use crate::webhooks;

/// The git all-zeros object id — the create/delete sentinel in a ref update.
const ZERO_SHA: &str = "0000000000000000000000000000000000000000";

/// The set of blob OIDs withheld from **anonymous** replication for a repo, or
/// `None` when the repo must not replicate at all (private / mode A /
/// undetermined — fail closed). This is the anonymous replication gate:
/// `caller` is hard-coded to `None` and there is intentionally no caller
/// parameter, which distinguishes it from the per-caller read-serve projection
/// in `git_upload_pack` (which passes the real caller). Both the push pin path
/// and the reconciliation sweep call this helper so the two cannot drift on
/// what is withheld. `rules` is the already-fetched visibility-rule snapshot
/// (callers fetch once and may reuse it, e.g. for encrypt-then-pin).
///
/// Returns `(announce, withheld)`: `announce` is whether the repo may be
/// announced/replicated to the anonymous public at all (also gates gossip and
/// Arweave anchoring downstream), and `withheld` is the anonymous withheld blob
/// set when announceable (`None` when not announceable). A failed/panicked
/// withheld walk fails closed on both axes: `announce` is forced false and
/// `withheld` is `None`, so an unvetted push neither replicates blobs nor
/// announces. Returning both keeps the gate's announce decision a single
/// source rather than recomputing it at each call site.
async fn replication_withheld_set(
    rules: Option<Vec<crate::db::VisibilityRule>>,
    owner_did: &str,
    is_public: bool,
    disk_path: std::path::PathBuf,
) -> (bool, Option<std::collections::HashSet<String>>) {
    let announce = match &rules {
        Some(rules) => crate::visibility::listable_at_root(rules, is_public, owner_did, None),
        None => false,
    };
    if !announce {
        return (false, None);
    }
    let withheld = match rules {
        // No path-scoped rule can withhold anything (covers the empty-rules and
        // root-only-rules cases), so skip the full withheld_blob_oids walk and
        // withhold nothing. The predicate's safety-invariant test guards that
        // this short-circuit matches what the walk would have returned.
        Some(rules) if !visibility_pack::has_path_scoped_rule(&rules) => {
            Some(std::collections::HashSet::new())
        }
        // withheld_blob_oids walks every ref with blocking `git ls-tree`; keep
        // that off the async worker thread.
        Some(rules) => {
            let owner_did = owner_did.to_string();
            tokio::task::spawn_blocking(move || {
                crate::git::visibility_pack::withheld_blob_oids(
                    &disk_path, &rules, is_public, &owner_did, None,
                )
            })
            .await
            .map_err(|e| {
                tracing::warn!(err = %e, "withheld_blob_oids task panicked; skipping replication")
            })
            .ok()
            .and_then(|r| {
                r.map_err(|e| {
                    tracing::warn!(err = %e, "withheld_blob_oids failed; skipping replication")
                })
                .ok()
            })
        }
        None => None,
    };
    // Fail closed on a failed/panicked withheld walk: with `announce` already
    // true here, a `None` withheld can only mean the walk errored (rules are
    // necessarily `Some`, else we returned above). Suppress the announce too so
    // a push we couldn't vet does not gossip, notify peers, or anchor to Arweave.
    match withheld {
        Some(withheld) => (announce, Some(withheld)),
        None => (false, None),
    }
}

/// The replicable object set for a full-scan pin fallback, failing closed (#99).
/// The full-scan candidate set includes dangling objects the reachable-only
/// withheld set never classified, so compute the reachable visibility-allowed
/// blob set and the all-blob universe off the async worker and keep only
/// non-blobs plus allowed blobs. Any error in either walk (or a task panic)
/// pins nothing this push, mirroring the degraded-path shape of
/// `replication_withheld_set`.
async fn fail_closed_full_scan_objects(
    disk_path: std::path::PathBuf,
    rules: Vec<crate::db::VisibilityRule>,
    is_public: bool,
    owner_did: String,
    candidates: Vec<String>,
) -> Vec<String> {
    tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<String>> {
        let allowed = crate::git::visibility_pack::replicable_blob_set(
            &disk_path, &rules, is_public, &owner_did,
        )?;
        let all_blobs = crate::git::push_delta::all_blob_oids(&disk_path)?;
        Ok(crate::git::visibility_pack::replicable_objects_fail_closed(
            candidates, &allowed, &all_blobs,
        ))
    })
    .await
    .map_err(|e| {
        tracing::warn!(err = %e, "fail-closed blob walk task panicked; pinning nothing this push")
    })
    .ok()
    .and_then(|r| {
        r.map_err(|e| {
            tracing::warn!(err = %e, "fail-closed blob walk failed; pinning nothing this push")
        })
        .ok()
    })
    .unwrap_or_default()
}

// ── Request / Response types ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateRepoRequest {
    pub name: String,
    pub description: Option<String>,
    #[serde(default = "default_true")]
    pub is_public: bool,
    #[serde(default = "default_main")]
    pub default_branch: String,
}

fn default_true() -> bool {
    true
}
fn default_main() -> String {
    "main".to_string()
}

#[derive(Debug, Serialize)]
pub struct RepoResponse {
    pub id: String,
    pub name: String,
    pub owner_did: String,
    pub description: Option<String>,
    pub is_public: bool,
    pub default_branch: String,
    pub clone_url: String,
    pub star_count: i64,
    pub created_at: String,
    pub updated_at: String,
    pub forked_from: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct InfoRefsQuery {
    pub service: Option<String>,
}

// ── Handlers ──────────────────────────────────────────────────────────────

/// POST /api/v1/repos
/// Create a new repository. Requires HTTP Signature auth.
pub async fn create_repo(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateRepoRequest>,
) -> Result<(StatusCode, Json<RepoResponse>)> {
    // iCaptcha gate (inert unless ICAPTCHA_MODE is set). Verify the proof up
    // front so an invalid/missing proof is rejected early; the proof is only
    // spent once the request is admissible, just before the first write — so a
    // rejected request (bad name, already exists) never burns a valid proof.
    let proof = crate::icaptcha::verify_request(&headers, &auth.0)?;

    // Sanitize name: alphanumeric, hyphens, underscores only
    if !req
        .name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AppError::BadRequest(
            "repo name must contain only alphanumeric characters, hyphens, and underscores".into(),
        ));
    }

    // Owner is the authenticated agent's DID
    let owner_did = auth.0;

    // Serialize against a concurrent purge of the SAME owner/name. The purge holds
    // this per-repo advisory lock across its delete-row + remove-dir, so without
    // taking the same lock here a create could slip into the row-deleted-but-dir-
    // not-yet-removed window and land a repos row pointing at a directory the purge
    // then removes (a dangling row). Held across the existence-check -> init ->
    // create_repo sequence so the two operations cannot interleave; released
    // explicitly on the success path, and its guard's Drop frees the lock on every
    // error path below. Bounded-wait (no object-store I/O), so the uncontended hot
    // path returns on the first attempt. (KTD6, R6.)
    //
    // Lock on the write lock_pool (via `lock_repo_blocking`), NOT the app pool. The
    // create's own work (get_repo, proof.consume, db.create_repo) runs on the app
    // pool via state.db, so drawing the lock guard from a SEPARATE pool keeps it from
    // pinning an app connection that work then needs. At GITLAWB_DB_MAX_CONNECTIONS=1
    // an app-pool lock self-deadlocks (get_repo waits for the one connection the
    // guard holds -> PoolTimedOut -> 500). The advisory lock is DB-global, so it
    // still serializes against a same-key purge holding it from lock_pool. Accepted
    // residual: a sustained 32-writer burst that pins lock_pool can make this acquire
    // wait -> a retryable 503, far less bad than breaking create at MAX_CONNECTIONS=1.
    let repo_lock = state
        .repo_store
        .lock_repo_blocking(&owner_did, &req.name)
        .await
        // Both arms are a transient resource condition, not a create failure: the
        // lock pool is pinned (Err from acquiring the lock connection) or the key
        // stayed held through the bounded retry (None: a live writer or a purge).
        // Return a retryable 503 so the client backs off and retries, as the
        // call-site comment promises, rather than a misleading 500 git_error.
        .map_err(|e| AppError::Unavailable(e.to_string()))?
        .ok_or_else(|| {
            AppError::Unavailable(format!(
                "could not acquire repo lock for {owner_did}/{} — held by a live writer or purge",
                req.name
            ))
        })?;

    // Check it doesn't already exist
    if state.db.get_repo(&owner_did, &req.name).await?.is_some() {
        return Err(AppError::RepoExists(req.name));
    }

    // Request is admissible — spend the proof now, immediately before the write.
    let verified_proof = proof.consume(&state.db).await?;

    let disk_path = state
        .repo_store
        .init(&owner_did, &req.name)
        .await
        .map_err(|e| {
            // `{:#}` walks the anyhow chain to the leaf cause; the other git
            // handlers log their failures, this one didn't.
            tracing::error!(owner = %owner_did, repo = %req.name, err = %format!("{e:#}"), "repo create failed");
            AppError::Git(e.to_string())
        })?;

    let now = Utc::now();
    let record = crate::db::RepoRecord {
        id: Uuid::new_v4().to_string(),
        name: req.name.clone(),
        owner_did: owner_did.clone(),
        description: req.description.clone(),
        is_public: req.is_public,
        default_branch: req.default_branch.clone(),
        created_at: now,
        updated_at: now,
        disk_path: disk_path.to_string_lossy().to_string(),
        forked_from: None,
        machine_id: state.machine_id.clone(),
    };

    state.db.create_repo(&record).await?;

    // Row + on-disk dir now both exist consistently; the race window is closed, so
    // release the per-repo lock before the (best-effort) proof recording below.
    repo_lock.release().await;

    // Persist the proof so it can travel with the repo and a mirroring peer can
    // re-verify it (enforce-mode origins only; off/shadow yield no proof here).
    if let Some(p) = verified_proof {
        if let Err(e) = p.record_for_repo(&state.db, &record.id).await {
            tracing::warn!(repo = %req.name, err = %e, "failed to record iCaptcha proof for repo");
        }
    }

    tracing::info!(repo = %req.name, owner = %owner_did, "created repository");

    let resp = to_response(&record, &state, 0);
    Ok((StatusCode::CREATED, Json(resp)))
}

#[derive(Debug, Deserialize)]
pub struct ListReposQuery {
    /// Filter by owner DID key segment (short form after last colon) or full DID.
    pub owner: Option<String>,
    /// Page size. If omitted, the legacy "return all rows" path is used so existing
    /// peer/CLI callers stay backwards-compatible. Capped at 200 when provided.
    pub limit: Option<i64>,
    /// Row offset. Ignored unless `limit` is also provided.
    #[serde(default)]
    pub offset: Option<i64>,
}

/// GET /api/v1/repos[?owner=<short>][&limit=&offset=]
///
/// Lists repositories on this node, optionally filtered by owner. When `limit` is
/// present, returns one page and the `X-Total-Count` response header carries the
/// total matching row count. Without `limit`, falls back to returning every row
/// (kept for backwards compat with peer sync and existing CLI tooling).
///
/// Every returned row passes the per-caller `"/"` visibility gate
/// (`crate::visibility::listable_at_root`), the same decision the per-repo
/// content endpoints make, so neither the page nor `X-Total-Count` leaks a repo
/// (or its mere count) the caller may not read (#97).
pub async fn list_repos(
    State(state): State<AppState>,
    Query(query): Query<ListReposQuery>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Response> {
    use axum::http::HeaderValue;
    use axum::response::IntoResponse;

    let caller = auth.as_ref().map(|e| e.0 .0.as_str());

    // Over-fetch the deduped set (did:key-aware DEDUP_CTE collapses mirror rows),
    // then apply the per-repo "/" visibility gate in Rust BEFORE pagination so
    // neither the page nor X-Total-Count leaks a repo the caller may not read —
    // including its mere count. The "/" decision depends on owner short/full-DID
    // matching and JSON reader-DID membership, so it cannot be a clean SQL
    // predicate without drifting from visibility_check; the count is derived from
    // the visible set (#97).
    let owner_filtered = state
        .db
        .list_all_repos_deduped_with_stars(query.owner.as_deref())
        .await?;

    let ids: Vec<String> = owner_filtered.iter().map(|(r, _)| r.id.clone()).collect();
    let rules_by_repo = state.db.list_visibility_rules_for_repos(&ids).await?;
    let visible: Vec<(crate::db::RepoRecord, i64)> = owner_filtered
        .into_iter()
        .filter(|(r, _)| {
            let rules = rules_by_repo.get(&r.id).map(Vec::as_slice).unwrap_or(&[]);
            crate::visibility::listable_at_root(rules, r.is_public, &r.owner_did, caller)
        })
        .collect();

    let total = visible.len() as i64;

    // Paginate in Rust when a limit is set: SQL LIMIT/OFFSET cannot run before
    // the visibility filter without returning short pages and a leaked count.
    let page: Vec<(crate::db::RepoRecord, i64)> = match query.limit {
        Some(raw_limit) => {
            let limit = raw_limit.clamp(1, 200) as usize;
            let offset = query.offset.unwrap_or(0).max(0) as usize;
            visible.into_iter().skip(offset).take(limit).collect()
        }
        None => visible,
    };

    let body: Vec<RepoResponse> = page
        .into_iter()
        .map(|(r, stars)| to_response(&r, &state, stars))
        .collect();
    let mut response = Json(body).into_response();
    response.headers_mut().insert(
        "X-Total-Count",
        HeaderValue::from_str(&total.to_string()).unwrap_or(HeaderValue::from_static("0")),
    );
    Ok(response)
}

/// GET /api/v1/repos/:owner/:repo
pub async fn get_repo(
    State(state): State<AppState>,
    Path((owner, name)): Path<(String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<RepoResponse>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, caller, "/").await?;
    let count = state.db.count_stars(&record.id).await.unwrap_or(0);
    Ok(Json(to_response(&record, &state, count)))
}

/// GET /api/v1/repos/:owner/:repo/commits
pub async fn list_commits(
    State(state): State<AppState>,
    Path((owner, name)): Path<(String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, caller, "/").await?;

    let disk_path = state
        .repo_store
        .acquire(&record.owner_did, &record.name)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;
    let head_ref = store::resolve_head(&disk_path, &record.default_branch);
    let commits = store::log(&disk_path, &head_ref, 30).unwrap_or_default();

    Ok(Json(serde_json::json!({ "commits": commits })))
}

/// GET /api/v1/repos/:owner/:repo/blob/*path
pub async fn get_blob(
    State(state): State<AppState>,
    Path((owner, name, file_path)): Path<(String, String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Response> {
    use axum::http::header;
    use axum::response::IntoResponse;

    // Unnormalized paths ("../..", "./", "//") can't resolve in `git show`
    // and crawlers combinatorially explode them from relative links — that's
    // a client error, not a 500.
    let file_path = file_path.trim_matches('/');
    if file_path.is_empty()
        || file_path
            .split('/')
            .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return Err(AppError::BadRequest("invalid file path".into()));
    }

    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let gate_path = format!("/{file_path}");
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, caller, &gate_path).await?;

    let disk_path = state
        .repo_store
        .acquire(&record.owner_did, &record.name)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;
    let head_ref = store::resolve_head(&disk_path, &record.default_branch);
    let content = store::read_file(&disk_path, &head_ref, file_path).map_err(|e| {
        let msg = e.to_string();
        // `git show ref:path` on a path absent from the tree is a 404,
        // not a server error
        if msg.contains("does not exist in")
            || msg.contains("invalid object name")
            || msg.contains("exists on disk, but not in")
        {
            AppError::NotFound(format!("file not found: {file_path}"))
        } else {
            AppError::Git(msg)
        }
    })?;

    // Guess content type
    let mime = match file_path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("md") => "text/markdown; charset=utf-8",
        Some("rs") | Some("py") | Some("ts") | Some("sh") | Some("txt") | Some("toml")
        | Some("yaml") | Some("yml") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    };

    Ok(([(header::CONTENT_TYPE, mime)], content).into_response())
}

/// GET /api/v1/repos/:owner/:repo/tree  (root listing)
pub async fn get_tree_root(
    State(state): State<AppState>,
    Path((owner, name)): Path<(String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, caller, "/").await?;

    let disk_path = state
        .repo_store
        .acquire(&record.owner_did, &record.name)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;
    let head_ref = store::resolve_head(&disk_path, &record.default_branch);
    let entries = store::ls_tree(&disk_path, &head_ref, "").unwrap_or_default();

    Ok(Json(serde_json::json!({ "entries": entries, "path": "" })))
}

/// GET /api/v1/repos/:owner/:repo/tree/*path
pub async fn get_tree(
    State(state): State<AppState>,
    Path((owner, name, tree_path)): Path<(String, String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    // Gate on the REQUESTED subtree, not the repo root (N3) — otherwise a caller
    // denied a withheld subtree can still enumerate its names/SHAs. Reject
    // traversal and empty interior segments as get_blob does, so the gate path and
    // the path git resolves cannot diverge; an empty path here is the root listing.
    let normalized = tree_path.trim_matches('/');
    if !normalized.is_empty()
        && normalized
            .split('/')
            .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return Err(AppError::BadRequest("invalid tree path".into()));
    }
    let gate_path = if normalized.is_empty() {
        "/".to_string()
    } else {
        format!("/{normalized}")
    };
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, caller, &gate_path).await?;

    let disk_path = state
        .repo_store
        .acquire(&record.owner_did, &record.name)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;
    let head_ref = store::resolve_head(&disk_path, &record.default_branch);
    let entries = store::ls_tree(&disk_path, &head_ref, &tree_path).unwrap_or_default();

    Ok(Json(
        serde_json::json!({ "entries": entries, "path": tree_path }),
    ))
}

// ── Git smart HTTP endpoints ──────────────────────────────────────────────

fn smart_http_repo_name(repo: &str) -> Result<&str> {
    // Strip at most one ".git" suffix: trim_end_matches strips repeatedly,
    // which would misdirect a repo literally named "foo.git" (creatable via
    // the peer mirror path, which skips API name validation) to repo "foo".
    let name = repo.strip_suffix(".git").unwrap_or(repo);
    if name.is_empty() {
        return Err(AppError::BadRequest("missing repository name".into()));
    }
    Ok(name)
}

/// GET /:owner/:repo.git/info/refs?service=git-upload-pack|git-receive-pack
pub async fn git_info_refs(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<InfoRefsQuery>,
    crate::rate_limit::PeerAddr(peer): crate::rate_limit::PeerAddr,
    headers: axum::http::HeaderMap,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Response> {
    let name = smart_http_repo_name(&repo)?;
    tracing::info!(owner = %owner, repo = %name, "info/refs request");
    let record = state
        .db
        .get_repo(&owner, name)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;

    // A quarantined mirror is served to no one (clone or push advertisement) —
    // hidden as repo-not-found until an operator releases it.
    if state.db.is_repo_quarantined(&record.id).await? {
        return Err(AppError::RepoNotFound(format!("{owner}/{name}")));
    }

    let service = query
        .service
        .ok_or_else(|| AppError::BadRequest("missing ?service= parameter".into()))?;
    tracing::debug!(service = %service, repo = %name, "info/refs service");

    // Enforce read visibility on the ref advertisement, for BOTH services. The
    // upload-pack (clone/fetch) and receive-pack (push) advertisements expose the
    // same ref metadata (branch/tag names and commit tips), so a private repo's
    // advertisement must be withheld from a non-reader regardless of which service
    // is requested. The push itself stays separately owner-gated on the
    // git-receive-pack POST; push access implies read access here, so a
    // legitimate pusher (the owner) always clears this gate.
    {
        let rules = state.db.list_visibility_rules(&record.id).await?;
        let caller = auth.as_ref().map(|e| e.0 .0.as_str());
        // Subtree (mode B) rules do not gate the advertisement: refs expose commit
        // tips only, and blob withholding happens in the upload-pack pack build.
        if visibility_check(&rules, record.is_public, &record.owner_did, caller, "/")
            == Decision::Deny
        {
            tracing::debug!(repo = %name, caller = ?caller, service = %service, "info/refs read denied by visibility");
            return Err(AppError::RepoNotFound(format!("{owner}/{name}")));
        }
    }

    // Push flood brake on the advertisement phase. A push always hits this
    // GET first, and for receive-pack it forces a fresh Tigris download below;
    // throttling only the receive-pack POST would leave the expensive
    // fresh-acquire reachable unauthenticated and unlimited. Applied before the
    // acquire so a rejected request does no Tigris work. Same per-IP limiter and
    // trusted-proxy policy as the POST middleware (shared buckets).
    if service == "git-receive-pack" {
        if let Some(key) = crate::rate_limit::client_key(&headers, peer, state.push_limiter_trust) {
            // Use check_retry (like U5's other 429 sites) so the rejection carries a
            // window-derived Retry-After, built via the shared 429 response helper
            // that the per-IP middleware also uses.
            if let Some(retry_after) = state.push_rate_limiter.check_retry(&key).await {
                tracing::warn!(repo = %name, key = %key, "receive-pack advertisement rate limited");
                return Ok(crate::rate_limit::too_many_requests(retry_after));
            }
        }
    }

    // For receive-pack (push), download the latest from Tigris so the client
    // sees the same refs that acquire_write() will operate on.
    let disk_path = if service == "git-receive-pack" {
        state
            .repo_store
            .acquire_fresh(&record.owner_did, &record.name)
            .await
    } else {
        state
            .repo_store
            .acquire(&record.owner_did, &record.name)
            .await
    }
    .map_err(|e| {
        tracing::error!(repo = %name, service = %service, err = %e, "repo acquire failed");
        AppError::Git(e.to_string())
    })?;

    smart_http::info_refs(&disk_path, &service)
        .await
        .map_err(|e| {
            tracing::error!(repo = %name, service = %service, err = %e, "info_refs git failed");
            AppError::Git(e.to_string())
        })
}

/// Map an error from a `smart_http` git service call to the right `AppError`:
/// [`smart_http::GitServiceTimeout`] to 504, a malformed client request to 400,
/// anything else to a 500 git error. Pure (no logging) so it is unit-testable;
/// callers add their own tracing.
fn git_service_app_error(err: &anyhow::Error) -> AppError {
    if err
        .downcast_ref::<smart_http::GitServiceTimeout>()
        .is_some()
    {
        AppError::Timeout("git service timed out".into())
    } else {
        let msg = err.to_string();
        if msg.contains("bad line length") || msg.contains("protocol error") {
            AppError::BadRequest(msg)
        } else {
            AppError::Git(msg)
        }
    }
}

/// POST /:owner/:repo.git/git-upload-pack
pub async fn git_upload_pack(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
    body: Bytes,
) -> Result<Response> {
    let name = smart_http_repo_name(&repo)?;
    let record = state
        .db
        .get_repo(&owner, name)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;

    // A quarantined mirror is never served for clone/fetch.
    if state.db.is_repo_quarantined(&record.id).await? {
        return Err(AppError::RepoNotFound(format!("{owner}/{name}")));
    }

    let rules = state.db.list_visibility_rules(&record.id).await?;
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    if visibility_check(&rules, record.is_public, &record.owner_did, caller, "/") == Decision::Deny
    {
        tracing::debug!(repo = %name, caller = ?caller, "upload-pack read denied by visibility");
        return Err(AppError::RepoNotFound(format!("{owner}/{name}")));
    }

    let disk_path = state
        .repo_store
        .acquire(&record.owner_did, &record.name)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;
    let body_len = body.len();

    // No path-scoped rule can withhold an individual blob, and the whole-repo
    // "/" gate above already enforced repo-level access. Skip the per-blob
    // withheld walk and serve the pack directly.
    let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);
    let resp = if !visibility_pack::has_path_scoped_rule(&rules) {
        smart_http::upload_pack(&disk_path, body, git_timeout).await
    } else {
        // withheld_blob_oids walks every ref with blocking `git ls-tree`; keep
        // that off the async worker thread.
        let withheld = {
            let path = disk_path.clone();
            let rules = rules.clone();
            let owner_did = record.owner_did.clone();
            let caller_owned = caller.map(str::to_string);
            let is_public = record.is_public;
            tokio::task::spawn_blocking(move || {
                visibility_pack::withheld_blob_oids(
                    &path,
                    &rules,
                    is_public,
                    &owner_did,
                    caller_owned.as_deref(),
                )
            })
            .await
            .map_err(|e| AppError::Git(e.to_string()))?
            .map_err(|e| AppError::Git(e.to_string()))?
        };

        if withheld.is_empty() {
            smart_http::upload_pack(&disk_path, body, git_timeout).await
        } else {
            tracing::info!(repo = %name, caller = ?caller, withheld = withheld.len(), "serving filtered pack");
            smart_http::upload_pack_excluding(&disk_path, body, &withheld).await
        }
    }
    .map_err(|e| {
        let app = git_service_app_error(&e);
        match &app {
            AppError::Timeout(_) => tracing::warn!(repo = %name, "git-upload-pack timed out"),
            AppError::BadRequest(msg) => {
                tracing::warn!(repo = %name, err = %msg, "git-upload-pack: bad client request")
            }
            _ => tracing::error!(repo = %name, err = %e, "git-upload-pack failed"),
        }
        app
    })?;
    crate::metrics::record_fetch(&format!("{owner}/{name}"));
    crate::metrics::observe_pack_size(body_len as f64);
    Ok(resp)
}

/// Decide whether the owner-push gate rejects a `git-receive-pack` request.
///
/// Returns `Some(error)` when the push must be rejected, `None` when it may
/// proceed. Pure function so the policy is unit-testable without a database or a
/// live git backend.
///
/// Fails closed: when `enforce` is on, an absent identity (`None`) or a caller
/// that is not authorized to push is rejected. When `enforce` is off it always
/// allows, preserving the legacy (authentication-only) behavior.
fn owner_push_rejection(
    enforce: bool,
    record: &crate::db::RepoRecord,
    caller: Option<&str>,
) -> Option<AppError> {
    if !enforce {
        return None;
    }
    match caller {
        Some(did) if caller_authorized_to_push(record, did) => None,
        _ => Some(AppError::Forbidden(
            "push rejected — only the repo owner may push to this repository \
             (GITLAWB_ENFORCE_OWNER_PUSH is enabled)"
                .into(),
        )),
    }
}

/// Decide whether the fork gate refuses a `fork_repo` request (#98).
///
/// Returns `true` when the fork must be refused: the source carries at least one
/// path-scoped subtree that `caller` may not read, so a full `git clone --mirror`
/// would copy out content the filtered read path (`git_upload_pack`) withholds.
/// Pure function so the policy is unit-testable without a database or git backend.
///
/// Delegates the per-caller decision to [`withheld_globs`](crate::visibility::withheld_globs)
/// / `visibility_check`, so the owner bypass (full and short DID) and `reader_dids`
/// grants are inherited from the read path and the two cannot drift on who may read
/// what. The predicate is a conservative (fail-closed) over-approximation of the
/// read path's object-level withholding: never weaker (so the fork cannot leak
/// content the read path withholds), and stricter only in the narrow
/// duplicate/co-located-blob case. Only called after `authorize_repo_read("/")`
/// has already granted the caller root read.
///
/// The gate evaluates rules at each glob's representative prefix while the serve
/// path withholds per blob path; their "is anything withheld" results agree only
/// because `validate_path_glob` keeps `/` the lone whole-repo scope (no glob can
/// collapse a non-`/` rule's prefix to `/`). If the glob grammar is ever extended,
/// revisit this equivalence — same caveat as `visibility_pack::has_path_scoped_rule`.
fn fork_withheld_blocks(
    rules: &[crate::db::VisibilityRule],
    is_public: bool,
    owner_did: &str,
    caller: &str,
) -> bool {
    !withheld_globs(rules, is_public, owner_did, Some(caller)).is_empty()
}

/// Path of the peer sync-notify endpoint. Used both to build the target URL
/// and as the signing path, so they can never drift apart.
const SYNC_NOTIFY_PATH: &str = "/api/v1/sync/notify";

/// Send one signed `/sync/notify` request for a single ref update.
///
/// The receiver is single-ref, so a multi-ref push fans out one request per
/// ref — each signed over its own body — carrying that ref's real `old_sha`.
#[allow(clippy::too_many_arguments)]
async fn notify_peer_of_ref(
    http_client: &reqwest::Client,
    node_keypair: &gitlawb_core::identity::Keypair,
    peer_did: &str,
    notify_url: &str,
    repo_slug: &str,
    ref_name: &str,
    old_sha: &str,
    new_sha: &str,
    node_did: &str,
    pusher_did: &str,
    owner_did: &str,
) {
    let body = serde_json::json!({
        "repo": repo_slug,
        "ref_name": ref_name,
        "new_sha": new_sha,
        "node_did": node_did,
        "pusher_did": pusher_did,
        "old_sha": old_sha,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "owner_did": owner_did,
    });
    let body_bytes = match serde_json::to_vec(&body) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(peer = %peer_did, ref_name = %ref_name, err = %e, "failed to serialize peer sync notify");
            return;
        }
    };
    let signed =
        gitlawb_core::http_sig::sign_request(node_keypair, "POST", SYNC_NOTIFY_PATH, &body_bytes);
    match http_client
        .post(notify_url)
        .header("Content-Type", "application/json")
        .header("Content-Digest", signed.content_digest)
        .header("Signature-Input", signed.signature_input)
        .header("Signature", signed.signature)
        .body(body_bytes)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => {
            tracing::info!(peer = %peer_did, repo = %repo_slug, ref_name = %ref_name, "notified peer to sync")
        }
        Ok(r) => {
            tracing::warn!(peer = %peer_did, ref_name = %ref_name, status = %r.status(), "peer sync notify returned error")
        }
        Err(e) => {
            tracing::warn!(peer = %peer_did, ref_name = %ref_name, err = %e, "failed to notify peer")
        }
    }
}

/// Notify a single peer of every ref in a push — one request per ref.
///
/// Looping here (rather than sending one flattened request) is what keeps a
/// multi-ref push from collapsing to its first ref; each ref carries its real
/// `old_sha`.
#[allow(clippy::too_many_arguments)]
async fn notify_peer_of_refs(
    http_client: &reqwest::Client,
    node_keypair: &gitlawb_core::identity::Keypair,
    peer_did: &str,
    notify_url: &str,
    repo_slug: &str,
    ref_updates: &[(String, String, String)],
    node_did: &str,
    pusher_did: &str,
    owner_did: &str,
) {
    for (ref_name, old_sha, new_sha) in ref_updates {
        notify_peer_of_ref(
            http_client,
            node_keypair,
            peer_did,
            notify_url,
            repo_slug,
            ref_name,
            old_sha,
            new_sha,
            node_did,
            pusher_did,
            owner_did,
        )
        .await;
    }
}

/// Roll a push whose durable upload failed back to the pre-push ref snapshot.
/// `None` means the pre-push listing itself failed: rolling back to an empty
/// snapshot would delete EVERY ref in the repo, so the rollback is skipped
/// instead. A genuinely empty repo snapshots as `Some(vec![])` and still rolls
/// back (deleting the refs the failed push created).
fn rollback_push_refs(
    path: &std::path::Path,
    repo_name: &str,
    pre_push_refs: &Option<Vec<(String, String)>>,
) {
    match pre_push_refs {
        Some(refs) => {
            if let Err(e) = store::restore_refs(path, refs) {
                tracing::warn!(repo = %repo_name, err = %e,
                    "failed to roll back receive-pack refs after failed durable upload; \
                     a local-fast-path read may serve un-uploaded refs");
            }
        }
        None => {
            tracing::warn!(repo = %repo_name,
                "skipping ref rollback after failed durable upload: pre-push snapshot \
                 unavailable; a local-fast-path read may serve un-uploaded refs");
        }
    }
}

/// POST /:owner/:repo.git/git-receive-pack  (AUTH REQUIRED — enforced by middleware)
pub async fn git_receive_pack(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    Extension(auth): Extension<AuthenticatedDid>,
    body: Bytes,
) -> Result<Response> {
    let name = smart_http_repo_name(&repo)?;
    tracing::info!(owner = %owner, repo = %name, "receive-pack request");
    let record = state
        .db
        .get_repo(&owner, name)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;

    // A quarantined mirror is hidden from every git endpoint, push included —
    // it must not accept writes while withheld from clone/fetch.
    if state.db.is_repo_quarantined(&record.id).await? {
        return Err(AppError::RepoNotFound(format!("{owner}/{name}")));
    }

    // Parse ref updates from pkt-line body before handing to git
    let ref_updates = parse_ref_updates(&body);
    tracing::debug!(
        ref_count = ref_updates.len(),
        "parsed ref updates from pack"
    );

    // ── Owner-only push enforcement (opt-in: GITLAWB_ENFORCE_OWNER_PUSH) ──
    // Runs before branch protection on purpose: when enabled, a non-owner is
    // rejected here regardless of whether the target branch is protected, so a
    // single rejection never yields two different error bodies. The identity is
    // the canonical DID injected by `require_signature`, not a re-parse of the
    // request headers. Fails closed (see `owner_push_rejection`).
    if let Some(err) = owner_push_rejection(
        state.config.enforce_owner_push,
        &record,
        Some(auth.0.as_str()),
    ) {
        tracing::warn!(
            repo = %name,
            pusher = %auth.0,
            owner_did = %record.owner_did,
            "owner-push enforcement: rejecting push from non-owner"
        );
        return Err(err);
    }

    // ── Branch protection check ──────────────────────────────────────────
    // Uses the same verified identity as the owner-push gate above. (When that
    // gate is enabled a non-owner never reaches here; this still applies when it
    // is off, gating only the branches an owner has explicitly protected.)
    for update in &ref_updates {
        // Strip refs/heads/ prefix to get plain branch name
        let branch = update
            .ref_name
            .strip_prefix("refs/heads/")
            .unwrap_or(&update.ref_name);
        if state
            .db
            .is_branch_protected(&record.id, branch)
            .await
            .unwrap_or(false)
            && !crate::api::did_matches(&auth.0, &record.owner_did)
        {
            tracing::warn!(
                branch = %branch,
                pusher = %auth.0,
                owner_did = %record.owner_did,
                "branch protection: rejecting push from non-owner"
            );
            return Err(AppError::Forbidden(format!(
                "branch '{branch}' is protected — only the repo owner can push to it"
            )));
        }
    }

    tracing::debug!(repo = %name, "acquiring write lock");
    let body_len = body.len();
    let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);

    // Detach the WHOLE push — acquire → receive-pack → release AND the success
    // tail (metadata + fan-out) — from THIS handler future. The pack `body` is
    // already fully buffered, so the spawned task is self-contained: a client
    // disconnect drops the handler future but does NOT cancel the task, so a
    // fully-received push still applies the pack, releases the lock, AND runs its
    // full metadata/fan-out tail server-side. Folding the tail INTO the task (vs
    // leaving it in the cancellable request future) is what prevents a split-brain
    // on disconnect: committed git with no push record / certs / broadcast. (KTD1,
    // R1.)
    //
    // report-status is handed to the (possibly still-connected) client over a
    // oneshot the request future awaits — NOT by awaiting the JoinHandle, which
    // would re-couple the client response to the full tail completing (a latency
    // regression). The task sends the receive-pack result, then continues the tail
    // independently; if the client has disconnected the receiver is dropped and the
    // send fails, which the task ignores and runs the tail regardless.
    let (report_tx, report_rx) = tokio::sync::oneshot::channel::<Result<Response>>();
    tokio::spawn(async move {
        let guard = match state
            .repo_store
            .acquire_write(&record.owner_did, &record.name)
            .await
        {
            Ok(g) => g,
            Err(e) => {
                tracing::error!(repo = %record.name, err = %e, "acquire_write failed");
                let _ = report_tx.send(Err(AppError::Git(e.to_string())));
                return;
            }
        };
        let disk_path = guard.path().to_path_buf();

        // Snapshot the pre-push refs so a failed durable upload can roll the
        // applied pack back on local disk (mirrors create_issue). Without this
        // the local fast path in RepoStore::acquire serves the pushed refs until
        // a later write refreshes the archive, even though the client got a 5xx.
        // `.ok()`, not `.unwrap_or_default()`: a listing error must read as
        // "snapshot unavailable", never as an empty snapshot, or the rollback
        // below would delete every ref in the repo. Fail closed on a snapshot
        // failure: without a restore plan, a failed durable upload would leave
        // the pushed refs on the local fast path with no way back (the class
        // this rollback exists to close), so refuse the push before mutating.
        let pre_push_refs = match store::list_refs(&disk_path) {
            Ok(refs) => Some(refs),
            Err(e) => {
                tracing::error!(repo = %record.name, err = %e, "pre-push ref snapshot failed");
                // release(false): no upload attempted, so the bool is always true.
                let _ = guard.release(false).await;
                let _ = report_tx.send(Err(AppError::Internal(anyhow::anyhow!(
                    "cannot snapshot pre-push refs; refusing push: {e}"
                ))));
                return;
            }
        };

        tracing::debug!(repo = %record.name, path = %disk_path.display(), "running git receive-pack");
        let result = smart_http::receive_pack(&disk_path, body, git_timeout).await;
        // Always release the advisory lock — even on error, and BEFORE the tail —
        // to prevent stale locks and to avoid holding the write lock across the
        // fan-out. Only upload to Tigris when the push succeeded; uploading a
        // half-applied repo would propagate corruption. On a failed durable
        // upload, restore the pre-push refs BEFORE the lock releases so a
        // local-fast-path read does not serve refs that never landed durably.
        let upload_ok = guard
            .release_with_failure_cleanup(result.is_ok(), |path| {
                rollback_push_refs(path, &record.name, &pre_push_refs)
            })
            .await;

        // On receive-pack error, deliver the classified error to the client and run
        // NO tail. On success, hand report-status to the client now, then continue
        // the tail regardless of whether the client is still listening.
        let response = match result {
            Ok(resp) => resp,
            Err(e) => {
                let app = git_service_app_error(&e);
                match &app {
                    AppError::Timeout(_) => {
                        tracing::warn!(repo = %record.name, "git receive-pack timed out")
                    }
                    AppError::BadRequest(msg) => {
                        tracing::warn!(repo = %record.name, err = %msg, "git receive-pack: bad client request")
                    }
                    _ => tracing::error!(repo = %record.name, err = %e, "git receive-pack failed"),
                }
                let _ = report_tx.send(Err(app));
                return;
            }
        };

        // The refs applied locally, but the durable upload to object storage
        // FAILED or timed out. Report the push as failed (5xx) instead of 200 so
        // the idempotent client re-pushes and re-uploads: otherwise the next
        // acquire_write downloads the STALE pre-push archive over local disk and
        // reverts these refs, silently losing the commit the client believes it
        // landed. Skip the whole success tail — a push whose durable copy never
        // landed must not be recorded/broadcast as accepted. (P1 data-loss fix.)
        if !upload_ok {
            tracing::error!(repo = %record.name,
                "durable upload failed after receive-pack — reporting push failure so the client retries");
            let _ = report_tx.send(Err(AppError::Git(format!(
                "durable storage upload failed for {}",
                record.name
            ))));
            return;
        }

        let _ = report_tx.send(Ok(response));

        // Update the repo's updated_at timestamp after a successful push
        let _ = state.db.touch_repo(&record.id).await;

        // Record the successful push for metrics. The body has already been
        // consumed by smart_http::receive_pack so we observe size up front.
        crate::metrics::record_push(&record.id);
        crate::metrics::observe_pack_size(body_len as f64);

        // Record push event for trust score and issue a signed ref certificate.
        // The route is behind `require_signature`, so the verified pusher identity is
        // always present; use it directly rather than re-parsing the headers.
        let did = auth.0.as_str();
        {
            // Use the first new commit hash we parsed, fall back to timestamp
            let commit_hash = ref_updates
                .first()
                .map(|u| u.new_sha.clone())
                .unwrap_or_else(|| Utc::now().timestamp().to_string());

            let _ = state.db.record_push(did, &record.id, &commit_hash, 0).await;
            if let Ok(push_count) = state.db.get_push_count(did).await {
                // 0.05 base (from registration) + 0.05 per push, capped at 1.0
                // 1 push → 0.10, 5 pushes → 0.30, 19 pushes → 1.0
                let new_score = (push_count as f64 * 0.05 + 0.05).min(1.0);
                let _ = state.db.update_trust_score(did, new_score).await;
            }

            // Issue a signed certificate for every ref this push advanced, each
            // carrying that ref's real old→new transition. A multi-ref push must
            // not collapse to a single cert covering only the first ref.
            for update in &ref_updates {
                match cert::issue_ref_certificate(
                    &state,
                    &record.id,
                    &update.ref_name,
                    &update.old_sha,
                    &update.new_sha,
                    did,
                )
                .await
                {
                    Ok(c) => {
                        tracing::info!(cert_id = %c.id, repo = %record.name, ref_name = %update.ref_name, pusher = %did, "issued ref certificate")
                    }
                    Err(e) => {
                        tracing::warn!(err = %e, ref_name = %update.ref_name, "failed to issue ref certificate")
                    }
                }
            }
        }

        // Fire push webhooks — one per ref update
        if !ref_updates.is_empty() {
            let base_url = state
                .config
                .public_url
                .as_deref()
                .unwrap_or("http://127.0.0.1:7545")
                .trim_end_matches('/');
            let owner_short = crate::db::normalize_owner_key(&record.owner_did);
            let clone_url = format!("{}/{}/{}.git", base_url, owner_short, record.name);

            for update in &ref_updates {
                let payload = serde_json::json!({
                    "ref": update.ref_name,
                    "before": update.old_sha,
                    "after": update.new_sha,
                    "created": update.old_sha == ZERO_SHA,
                    "forced": false,
                    "pusher": {
                        "did": did,
                    },
                    "repository": {
                        "id": record.id,
                        "name": record.name,
                        "owner_did": record.owner_did,
                        "clone_url": clone_url,
                    },
                });
                webhooks::fire_event(
                    state.db.clone(),
                    state.http_client.clone(),
                    &record.id,
                    "push",
                    payload,
                );
            }
        }

        // Replication enforcement (Phase 2): decide once per push whether the public
        // may read this repo at all and, if so, which blob OIDs must not leave the
        // node. `withheld == None` means replicate nothing (private / mode A /
        // undetermined): skip every pin so even commit and tree objects (which
        // withheld_blob_oids never lists) stay local. `announce` gates the
        // network-facing announcements. Fail closed: a private or undetermined repo
        // never leaks.
        let rules_opt = state.db.list_visibility_rules(&record.id).await.ok();
        let (announce, withheld) = replication_withheld_set(
            rules_opt.clone(),
            &record.owner_did,
            record.is_public,
            disk_path.clone(),
        )
        .await;

        // Resolve the per-push pin candidate set once, off the async worker, then
        // filter to what may actually replicate. Delta path: the reachable-only
        // `withheld` set suffices (delta objects are reachable). Full-scan path: the
        // candidate set can include dangling blobs the withheld set never classified,
        // so fail closed — replicate a blob only if it is reachable AND
        // visibility-allowed (#99). Only computed when something will actually
        // replicate; every degraded path logs rather than failing silently.
        let object_list: Vec<String> = if let Some(withheld_set) = withheld.clone() {
            let new_tips: Vec<String> = ref_updates
                .iter()
                .map(|u| u.new_sha.clone())
                .filter(|s| s != ZERO_SHA)
                .collect();
            let old_tips: Vec<String> = ref_updates
                .iter()
                .map(|u| u.old_sha.clone())
                .filter(|s| s != ZERO_SHA)
                .collect();
            let pin_set = crate::git::push_delta::resolve_candidates_for_push(
                disk_path.clone(),
                new_tips,
                old_tips,
            )
            .await;
            if pin_set.full_scan {
                fail_closed_full_scan_objects(
                    disk_path.clone(),
                    rules_opt.clone().unwrap_or_default(),
                    record.is_public,
                    record.owner_did.clone(),
                    pin_set.candidates,
                )
                .await
            } else {
                crate::git::visibility_pack::replicable_objects(pin_set.candidates, &withheld_set)
            }
        } else {
            Vec::new()
        };

        // Pin new git objects to the local IPFS node (no-op if ipfs_api is empty).
        // Skipped entirely when the public cannot read the repo (withheld == None).
        if withheld.is_some() {
            let object_list_ipfs = object_list.clone();
            let ipfs_api = state.config.ipfs_api.clone();
            let repo_path_clone = disk_path.clone();
            let db_clone = state.db.clone();
            let rules_for_enc = rules_opt.clone();
            let repo_id = record.id.clone();
            let owner_did = record.owner_did.clone();
            let is_public = record.is_public;
            let irys_url = state.config.irys_url.clone();
            let http_client = std::sync::Arc::clone(&state.http_client);
            let node_did_str = state.node_did.to_string();
            let node_seed = state.node_keypair.to_seed();
            let repo_name = record.name.clone();
            tokio::spawn(async move {
                let pinned = crate::ipfs_pin::pin_new_objects(
                    &ipfs_api,
                    &repo_path_clone,
                    object_list_ipfs,
                    &db_clone,
                )
                .await;
                if !pinned.is_empty() {
                    tracing::info!(count = pinned.len(), "pinned git objects to IPFS");
                    for (sha, cid) in &pinned {
                        tracing::info!(sha = %sha, %cid, "pinned");
                    }
                }

                // Option B1: encrypt-then-pin the withheld blobs so authorized
                // readers can recover them when the origin cannot serve them.
                // No path-scoped rule can withhold a blob, so withheld_blob_recipients
                // would return an empty map after a full per-ref walk; skip it. Mirrors
                // the has_path_scoped_rule gate on the other two withheld-walk sites.
                if let Some(rules) =
                    rules_for_enc.filter(|r| visibility_pack::has_path_scoped_rule(r))
                {
                    let p = repo_path_clone.clone();
                    let owner = owner_did.clone();
                    let recip = tokio::task::spawn_blocking(move || {
                        crate::git::visibility_pack::withheld_blob_recipients(
                            &p, &rules, is_public, &owner,
                        )
                    })
                    .await;
                    if let Ok(Ok(recipients)) = recip {
                        let delta = crate::encrypted_pin::encrypt_and_pin(
                            &ipfs_api,
                            &repo_path_clone,
                            &db_clone,
                            &repo_id,
                            &node_seed,
                            &recipients,
                        )
                        .await;

                        // Option B3: anchor a per-push manifest of the blobs sealed
                        // this push to Arweave, so the oid->cid index survives total
                        // node loss. Best-effort; never fails the push.
                        if !delta.is_empty() && !irys_url.is_empty() {
                            let owner_short = crate::db::normalize_owner_key(&owner_did);
                            let repo_slug = format!("{owner_short}/{repo_name}");
                            let ts = chrono::Utc::now().to_rfc3339();
                            let manifest = crate::arweave::EncryptedManifest {
                                repo: &repo_slug,
                                owner_did: &owner_did,
                                node_did: &node_did_str,
                                timestamp: &ts,
                                blobs: &delta,
                            };
                            match crate::arweave::anchor_encrypted_manifest(
                                &http_client,
                                &irys_url,
                                &manifest,
                            )
                            .await
                            {
                                Ok(tx) if !tx.is_empty() => tracing::info!(
                                    repo = %repo_slug,
                                    tx_id = %tx,
                                    "anchored encrypted manifest to Arweave"
                                ),
                                Ok(_) => {}
                                Err(e) => tracing::warn!(
                                    repo = %repo_slug,
                                    err = %e,
                                    "encrypted manifest anchor failed"
                                ),
                            }
                        }
                    }
                }
            });
        }

        // Pin new git objects to Pinata, then record branch→CID and gossip
        {
            let pinata_jwt = state.config.pinata_jwt.clone();
            let pinata_upload_url = state.config.pinata_upload_url.clone();
            let repo_path_clone = disk_path.clone();
            let db_clone = state.db.clone();
            let http_client = Arc::clone(&state.http_client);
            let node_did_str = state.node_did.to_string();
            let repo_slug = format!(
                "{}/{}",
                crate::db::normalize_owner_key(&record.owner_did),
                record.name
            );
            let ref_updates_clone = ref_updates
                .iter()
                .map(|u| (u.ref_name.clone(), u.old_sha.clone(), u.new_sha.clone()))
                .collect::<Vec<_>>();
            let p2p_handle = state.p2p.clone();
            let pusher_did_clone = did.to_string();
            let db_for_peers = state.db.clone();
            let ref_update_tx = state.ref_update_tx.clone();
            let irys_url = state.config.irys_url.clone();
            let owner_did_for_arweave = record.owner_did.clone();
            let self_public_url = state.config.public_url.clone();
            let node_keypair = Arc::clone(&state.node_keypair);
            let object_list_pinata = object_list;
            let do_pinata_replication = withheld.is_some();
            tokio::spawn(async move {
                let pinned = if do_pinata_replication {
                    crate::pinata::pin_new_objects(
                        &http_client,
                        &pinata_upload_url,
                        &pinata_jwt,
                        &repo_path_clone,
                        object_list_pinata,
                        &db_clone,
                    )
                    .await
                } else {
                    Vec::new()
                };

                if !pinned.is_empty() {
                    tracing::info!(count = pinned.len(), "pinned git objects to Pinata");
                }

                // Build sha→cid map from pinned objects
                let cid_map: std::collections::HashMap<String, String> =
                    pinned.into_iter().collect();

                // Record branch→CID for each ref update and publish gossip
                for (ref_name, old_sha, new_sha) in &ref_updates_clone {
                    let cid = cid_map.get(new_sha).map(|s| s.as_str());

                    if let Some(cid_str) = cid {
                        let _ = db_clone
                            .upsert_branch_cid(
                                &repo_slug,
                                ref_name,
                                new_sha,
                                cid_str,
                                &node_did_str,
                            )
                            .await;
                    }

                    if announce {
                        if let Some(p2p) = &p2p_handle {
                            p2p.publish_ref_update(crate::p2p::RefUpdateEvent {
                                node_did: node_did_str.clone(),
                                pusher_did: pusher_did_clone.clone(),
                                owner_did: Some(record.owner_did.clone()),
                                repo: repo_slug.clone(),
                                ref_name: ref_name.clone(),
                                old_sha: old_sha.clone(),
                                new_sha: new_sha.clone(),
                                timestamp: chrono::Utc::now().to_rfc3339(),
                                cert_id: None,
                                cid: cid.map(|s| s.to_string()),
                            })
                            .await;
                        }
                    }
                }

                // Broadcast ref update to GraphQL subscription listeners — one per ref.
                // Gated on `announce`: /graphql/ws is unauthenticated (mounted after
                // the optional_signature layer), and the subscription resolver has no
                // caller to gate against, so only publicly-readable ref updates may
                // reach anonymous subscribers. Mirrors the gossip (above) and Arweave
                // (below) sends, which are already `announce`-gated. Without this a
                // private-repo push would leak live ref metadata over the socket —
                // the subscription analog of #112/#114.
                let now_ts = chrono::Utc::now().to_rfc3339();
                if announce {
                    for (ref_name, old_sha, new_sha) in &ref_updates_clone {
                        let _ = ref_update_tx.send(crate::state::RefUpdateBroadcast {
                            repo: repo_slug.clone(),
                            owner_did: record.owner_did.clone(),
                            ref_name: ref_name.clone(),
                            old_sha: old_sha.clone(),
                            new_sha: new_sha.clone(),
                            pusher_did: pusher_did_clone.clone(),
                            node_did: node_did_str.clone(),
                            timestamp: now_ts.clone(),
                        });
                    }
                }

                // Arweave permanent anchoring — fire for each ref update.
                // Suppressed for repos the public cannot read (public permanent ledger).
                if announce && !irys_url.is_empty() {
                    for (ref_name, old_sha, new_sha) in &ref_updates_clone {
                        let cid = cid_map.get(new_sha).cloned();
                        let anchor = crate::arweave::RefAnchor {
                            repo: repo_slug.clone(),
                            owner_did: owner_did_for_arweave.clone(),
                            ref_name: ref_name.clone(),
                            old_sha: old_sha.clone(),
                            new_sha: new_sha.clone(),
                            cid: cid.clone(),
                            timestamp: now_ts.clone(),
                            node_did: node_did_str.clone(),
                        };
                        match crate::arweave::anchor_ref_update(&http_client, &irys_url, &anchor)
                            .await
                        {
                            Ok(tx_id) if !tx_id.is_empty() => {
                                let arweave_url = crate::arweave::arweave_url(&tx_id);
                                let _ = db_clone
                                    .record_arweave_anchor(&crate::db::RecordAnchorInput {
                                        repo: &repo_slug,
                                        owner_did: &owner_did_for_arweave,
                                        ref_name,
                                        old_sha,
                                        new_sha,
                                        cid: cid.as_deref(),
                                        irys_tx_id: &tx_id,
                                        arweave_url: &arweave_url,
                                        node_did: &node_did_str,
                                    })
                                    .await;
                            }
                            Ok(_) => {}
                            Err(e) => {
                                tracing::warn!(repo=%repo_slug, err=%e, "Arweave anchor failed")
                            }
                        }
                    }
                }

                // HTTP peer notification — notify all known peers to pull from us.
                // This is the reliable fallback when Gossipsub p2p is not yet connected.
                // Suppressed for repos the public cannot read. Runs last so a slow or
                // unreachable peer cannot delay the local GraphQL broadcast or Arweave
                // anchoring above; this is the lowest-priority best-effort step.
                if announce {
                    if let Ok(peers) = db_for_peers.list_peers().await {
                        for peer in peers {
                            if peer.http_url.is_empty() {
                                continue;
                            }
                            let peer_url = peer.http_url.trim_end_matches('/');
                            if let Some(self_url) = self_public_url.as_deref() {
                                if peer_url == self_url.trim_end_matches('/') {
                                    continue;
                                }
                            }
                            let notify_url = format!("{peer_url}{SYNC_NOTIFY_PATH}");
                            notify_peer_of_refs(
                                &http_client,
                                node_keypair.as_ref(),
                                &peer.did,
                                &notify_url,
                                &repo_slug,
                                &ref_updates_clone,
                                &node_did_str,
                                &pusher_did_clone,
                                &record.owner_did,
                            )
                            .await;
                        }
                    }
                }
            });
        }
    });

    // Await report-status from the detached task WITHOUT blocking on the tail. If
    // the client disconnected, this future is already dropped and `report_rx` with
    // it — the task then runs the tail regardless. A send-before-report task panic
    // drops the sender, surfaced here as an internal error (matching the prior
    // JoinError → 500 mapping).
    let result = report_rx.await.map_err(|_| {
        AppError::Internal(anyhow::anyhow!(
            "receive-pack task failed before reporting report-status"
        ))
    })??;

    Ok(result)
}

/// GET /api/v1/repos/{owner}/{repo}/refs
///
/// Returns all branches with their latest git SHA and IPFS CID (if pinned).
/// This is the IPNS-style branch tracking endpoint — content-addressed branch heads.
pub async fn list_refs(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (_record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &repo, caller, "/").await?;

    let repo_slug = format!("{owner}/{repo}");
    let refs = state.db.list_branch_cids(&repo_slug).await?;

    Ok(Json(
        serde_json::json!({ "refs": refs, "count": refs.len() }),
    ))
}

/// GET /api/v1/repos/federated
///
/// Query all known peers for their public repos and return a merged view of
/// the network. Each repo includes a `node_url` and `node_did` indicating
/// which node hosts it. Results from unreachable peers are silently omitted.
pub async fn list_federated_repos(
    State(state): State<AppState>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let local_repos = dedupe_canonical_repos(state.db.list_all_repos_with_stars().await?);

    // Hide local repos the caller may not read at "/" before federating them, so
    // the federated surface does not enumerate private repos (#97). Peer repos
    // arrive already filtered by each peer's own /api/v1/repos (anonymous view).
    let ids: Vec<String> = local_repos.iter().map(|(r, _)| r.id.clone()).collect();
    let rules_by_repo = state.db.list_visibility_rules_for_repos(&ids).await?;
    let local_repos: Vec<(crate::db::RepoRecord, i64)> = local_repos
        .into_iter()
        .filter(|(r, _)| {
            let rules = rules_by_repo.get(&r.id).map(Vec::as_slice).unwrap_or(&[]);
            crate::visibility::listable_at_root(rules, r.is_public, &r.owner_did, caller)
        })
        .collect();

    let local_node_url = state
        .config
        .public_url
        .clone()
        .unwrap_or_else(|| "http://127.0.0.1:7545".to_string());
    let local_node_did = state.node_did.to_string();

    let mut all_repos: Vec<serde_json::Value> = Vec::with_capacity(local_repos.len());
    for (r, count) in &local_repos {
        let mut v = serde_json::to_value(to_response(r, &state, *count)).unwrap_or_default();
        v["node_url"] = serde_json::Value::String(local_node_url.clone());
        v["node_did"] = serde_json::Value::String(local_node_did.clone());
        v["local"] = serde_json::Value::Bool(true);
        all_repos.push(v);
    }

    // Query peers in parallel
    let peers = state.db.list_peers().await.unwrap_or_default();
    let client = &state.http_client;

    let fetch_tasks: Vec<_> = peers
        .into_iter()
        .filter(|p| p.last_ping_ok && !p.http_url.is_empty())
        .map(|peer| {
            let client = Arc::clone(client);
            let url = format!("{}/api/v1/repos", peer.http_url.trim_end_matches('/'));
            let peer_did = peer.did.clone();
            let peer_url = peer.http_url.clone();
            tokio::spawn(async move {
                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    client.get(&url).send(),
                )
                .await;
                match result {
                    Ok(Ok(resp)) if resp.status().is_success() => {
                        if let Ok(repos) = resp.json::<Vec<serde_json::Value>>().await {
                            let enriched: Vec<serde_json::Value> = repos
                                .into_iter()
                                .map(|mut r| {
                                    r["node_url"] = serde_json::Value::String(peer_url.clone());
                                    r["node_did"] = serde_json::Value::String(peer_did.clone());
                                    r["local"] = serde_json::Value::Bool(false);
                                    r
                                })
                                .collect();
                            return enriched;
                        }
                    }
                    _ => {}
                }
                vec![]
            })
        })
        .collect();

    for task in fetch_tasks {
        if let Ok(repos) = task.await {
            all_repos.extend(repos);
        }
    }

    let count = all_repos.len();
    Ok(Json(serde_json::json!({
        "repos": all_repos,
        "count": count,
        "nodes_queried": 1, // local + peers that responded
    })))
}

// ── Fork ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ForkRepoRequest {
    pub name: Option<String>, // defaults to source repo name
}

/// POST /api/v1/repos/:owner/:repo/fork
pub async fn fork_repo(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, name)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ForkRepoRequest>,
) -> Result<(StatusCode, Json<RepoResponse>)> {
    // iCaptcha gate (inert unless ICAPTCHA_MODE is set). Fork is the third
    // repo-creation entrypoint alongside create_repo/register, so it must be
    // gated too. Verify up front (reject invalid/missing proofs early); the
    // proof is only spent just before the first write, so a rejected fork (bad
    // name, conflict, withheld subtree) never burns a valid proof.
    let proof = crate::icaptcha::verify_request(&headers, &auth.0)?;

    // Enforce read visibility on the source before cloning: an unauthorized
    // caller must not be able to fork (full mirror) a repo they cannot read.
    let (source, rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, Some(auth.0.as_str()), "/").await?;

    // #98: the "/" check above only proves root read. A full `git clone --mirror`
    // would still copy out any path-scoped subtree withheld from this caller, so
    // refuse the fork when the caller has any withheld glob. Fail closed with a
    // not-found response (mirrors authorize_repo_read's Deny) so the existence of
    // a subtree the caller cannot see is not leaked. Runs before repo_store.acquire
    // so no withheld object is ever materialized on disk.
    if fork_withheld_blocks(&rules, source.is_public, &source.owner_did, auth.0.as_str()) {
        tracing::warn!(
            owner = %owner, repo = %name, forker = %auth.0,
            "fork rejected — source has a path-scoped subtree withheld from the caller"
        );
        return Err(AppError::RepoNotFound(format!("{owner}/{name}")));
    }

    let fork_name = req.name.unwrap_or_else(|| source.name.clone());
    let forker_did = auth.0;

    // Validate fork name
    if !fork_name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AppError::BadRequest(
            "repo name must contain only alphanumeric characters, hyphens, and underscores".into(),
        ));
    }

    // Materialize the SOURCE on local disk BEFORE taking the target lock
    // (downloads from Tigris on cache miss). On a cold source (archive-only, no
    // local dir) this download takes a nested advisory lock on the write
    // lock_pool for the source's OWN namespace; doing it under the held target
    // lock would need two lock-pool connections at once from a pool sized
    // one-per-writer. The source is a read-only, different-namespace concern and
    // needs no target-namespace protection, and nothing under the lock below
    // depends on it beyond the clone reading source_path.
    let source_path = state
        .repo_store
        .acquire(&source.owner_did, &source.name)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;

    // Serialize against a concurrent same-key purge or creation on the FORK
    // TARGET namespace, mirroring create_repo's lock above (same rationale,
    // same 503 mapping). Held across the conflict check, clone, durable upload,
    // and row insert, so none of it can interleave with a purge's delete-row +
    // remove-dir window, and so the row is only published after the archive
    // durably landed. Released explicitly on both exits below; the guard's
    // Drop frees the lock on every intermediate error path.
    let repo_lock = state
        .repo_store
        .lock_repo_blocking(&forker_did, &fork_name)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?
        .ok_or_else(|| {
            AppError::Unavailable(format!(
                "could not acquire repo lock for {forker_did}/{fork_name}: held by a live writer or purge"
            ))
        })?;

    // Check no name conflict under the forker's ownership
    let forker_short = crate::db::normalize_owner_key(&forker_did);
    if state.db.get_repo(forker_short, &fork_name).await?.is_some() {
        return Err(AppError::BadRequest(format!(
            "you already have a repo named {fork_name}"
        )));
    }

    // Request is admissible — spend the proof now, immediately before the write.
    let verified_proof = proof.consume(&state.db).await?;

    let disk_path = store::repo_disk_path(&state.config.repos_dir, &forker_did, &fork_name);

    // Clone the source repo as a mirror, bounded so a pathological or huge source
    // cannot pin the held target lock (and its lock-pool connection)
    // indefinitely. Reuses the served-git ceiling (git_service_timeout_secs,
    // generous for large clones); after the source reorder above source_path is a
    // LOCAL path so a normal clone is fast and never approaches the bound, which
    // is a safety ceiling only. tokio::process with kill_on_drop tears the child
    // down when the timeout drops the future.
    let clone_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);
    let output = match tokio::time::timeout(
        clone_timeout,
        tokio::process::Command::new("git")
            .args([
                "clone",
                "--mirror",
                source_path.to_str().unwrap_or(""),
                disk_path.to_str().unwrap_or(""),
            ])
            .kill_on_drop(true)
            .output(),
    )
    .await
    {
        Ok(Ok(output)) => output,
        // Spawn/IO failure, or the clone exceeded the bound (child killed on
        // drop). Clear any partial mirror and fail the fork with the same
        // retryable shape the durable-upload arm below returns, before any
        // RepoRecord exists.
        Ok(Err(e)) => {
            if let Err(rm) = std::fs::remove_dir_all(&disk_path) {
                tracing::warn!(fork = %fork_name, err = %rm,
                    "failed to remove fork mirror after a failed clone spawn");
            }
            repo_lock.release().await;
            return Err(AppError::Git(format!("git clone --mirror failed: {e}")));
        }
        Err(_elapsed) => {
            if let Err(rm) = std::fs::remove_dir_all(&disk_path) {
                tracing::warn!(fork = %fork_name, err = %rm,
                    "failed to remove fork mirror after a clone timeout");
            }
            repo_lock.release().await;
            return Err(AppError::Git(format!(
                "git clone --mirror timed out after {}s for {fork_name}",
                clone_timeout.as_secs()
            )));
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // git clone --mirror can create the destination dir then exit non-zero
        // (authz, corrupt/partial source), leaving a half-created mirror. Clear
        // it best-effort and free the lock, matching the timeout/spawn arms, so
        // a retry is not blocked by an existing dest and a same-name create sees
        // an empty path.
        if let Err(rm) = std::fs::remove_dir_all(&disk_path) {
            tracing::warn!(fork = %fork_name, err = %rm,
                "failed to remove fork mirror after a non-zero clone exit");
        }
        repo_lock.release().await;
        return Err(AppError::Git(format!(
            "git clone --mirror failed: {stderr}"
        )));
    }

    // Upload the fork to durable storage under the held target lock, bounded by
    // the release-upload timeout. Publish-after-durability: an attempted upload
    // that failed or timed out fails the fork (the sibling write paths' 5xx)
    // BEFORE any RepoRecord exists, and removes the cloned mirror so no later
    // acquire serves a fork whose archive never landed. Store-less nodes take
    // the success arm (nothing to upload is not a failure).
    if !state
        .repo_store
        .upload_under_guard(&forker_did, &fork_name, &repo_lock)
        .await
    {
        if let Err(e) = std::fs::remove_dir_all(&disk_path) {
            tracing::warn!(fork = %fork_name, err = %e,
                "failed to remove fork mirror after failed durable upload");
        }
        repo_lock.release().await;
        return Err(AppError::Git(format!(
            "durable storage upload failed for {fork_name}"
        )));
    }

    let now = Utc::now();
    let record = crate::db::RepoRecord {
        id: Uuid::new_v4().to_string(),
        name: fork_name.clone(),
        owner_did: forker_did.clone(),
        description: source.description.clone(),
        is_public: source.is_public,
        default_branch: source.default_branch.clone(),
        created_at: now,
        updated_at: now,
        disk_path: disk_path.to_string_lossy().to_string(),
        forked_from: Some(source.id.clone()),
        machine_id: state.machine_id.clone(),
    };

    // The mirror is cloned and (with a store configured) the durable archive is
    // already uploaded, so a create_repo failure here would orphan BOTH with no
    // repos row: a retry blocks on the existing dest, and a later same-key
    // create could download the stale archive. Roll both back best-effort, free
    // the lock, then fail the fork. delete_archive is a no-op on a store-less
    // node, so this is safe regardless of configuration.
    if let Err(e) = state.db.create_repo(&record).await {
        if let Err(rm) = std::fs::remove_dir_all(&disk_path) {
            tracing::warn!(fork = %fork_name, err = %rm,
                "failed to remove fork mirror after a failed row insert");
        }
        if let Err(del) = state
            .repo_store
            .delete_archive(&forker_did, &fork_name)
            .await
        {
            tracing::warn!(fork = %fork_name, err = %del,
                "failed to delete fork archive after a failed row insert");
        }
        repo_lock.release().await;
        return Err(e.into());
    }

    // Row, archive, and on-disk dir now all exist consistently; the race window
    // is closed, so the target lock can be released before the best-effort tail.
    repo_lock.release().await;

    // Persist the proof so the fork carries it when it propagates to peers.
    if let Some(p) = verified_proof {
        if let Err(e) = p.record_for_repo(&state.db, &record.id).await {
            tracing::warn!(fork = %fork_name, err = %e, "failed to record iCaptcha proof for fork");
        }
    }

    tracing::info!(fork = %fork_name, source = %source.name, forker = %forker_did, "forked repository");

    Ok((StatusCode::CREATED, Json(to_response(&record, &state, 0))))
}

/// GET /api/v1/repos/{owner}/{repo}/icaptcha-proof
///
/// Returns the iCaptcha proof token this repo was created with (`null` if none).
/// A peer mirroring this repo fetches it and re-verifies it offline before
/// admitting the mirror (see [`crate::icaptcha::admit_mirror`]). Not owner-gated,
/// but gated on whole-repo `"/"` read like the other replication endpoints, so a
/// private repo's proof is never disclosed.
pub async fn get_icaptcha_proof(
    State(state): State<AppState>,
    auth: Option<Extension<AuthenticatedDid>>,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &repo, caller, "/").await?;
    let proof = state.db.get_repo_proof_token(&record.id).await?;
    Ok(Json(serde_json::json!({
        "repo": format!("{owner}/{repo}"),
        "proof": proof,
    })))
}

// ── Pkt-line parsing ──────────────────────────────────────────────────────

struct RefUpdate {
    old_sha: String,
    new_sha: String,
    ref_name: String,
}

/// Parse git receive-pack pkt-line ref updates from the request body.
/// Format per line: `<40-hex-old> <40-hex-new> <refname>[NUL capabilities]\n`
fn parse_ref_updates(body: &[u8]) -> Vec<RefUpdate> {
    let mut updates = Vec::new();
    let mut pos = 0;

    while pos + 4 <= body.len() {
        let len_str = match std::str::from_utf8(&body[pos..pos + 4]) {
            Ok(s) => s,
            Err(_) => break,
        };
        let len = match usize::from_str_radix(len_str, 16) {
            Ok(l) => l,
            Err(_) => break,
        };

        // Flush packet — end of ref-update section
        if len == 0 {
            break;
        }

        if len < 4 || pos + len > body.len() {
            break;
        }

        let data = &body[pos + 4..pos + len];
        pos += len;

        let line = match std::str::from_utf8(data) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Strip capabilities (after NUL) and trailing newline
        let line = line
            .split('\0')
            .next()
            .unwrap_or(line)
            .trim_end_matches('\n');

        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() == 3 && parts[0].len() == 40 && parts[1].len() == 40 {
            updates.push(RefUpdate {
                old_sha: parts[0].to_string(),
                new_sha: parts[1].to_string(),
                ref_name: parts[2].to_string(),
            });
        }
    }

    updates
}

// ── Helpers ───────────────────────────────────────────────────────────────
//
// For a non-key DID owner, `normalize_owner_key` returns the full DID, so
// `clone_url` becomes `/did:gitlawb:z6.../repo.git`. That resolves through
// `get_repo`, but the colon-bearing path segment would break the `sync.rs`
// disk-path join (`owner_slug/repo`). Not reachable today (auth is
// did:key-only), so this is a forward constraint to handle before non-key
// ownership lands: the owner-first disk layout must either reject colons or
// encode them.

fn to_response(record: &crate::db::RepoRecord, state: &AppState, star_count: i64) -> RepoResponse {
    let owner_short = crate::db::normalize_owner_key(&record.owner_did);

    let base_url = state
        .config
        .public_url
        .as_deref()
        .unwrap_or("http://127.0.0.1:7545")
        .trim_end_matches('/');

    RepoResponse {
        id: record.id.clone(),
        name: record.name.clone(),
        owner_did: record.owner_did.clone(),
        description: record.description.clone(),
        is_public: record.is_public,
        default_branch: record.default_branch.clone(),
        clone_url: format!("{}/{}/{}.git", base_url, owner_short, record.name),
        star_count,
        created_at: record.created_at.to_rfc3339(),
        updated_at: record.updated_at.to_rfc3339(),
        forked_from: record.forked_from.clone(),
    }
}

/// Collapse short-owner mirror rows and canonical `did:key:` rows that point at the
/// same logical repo into a single entry, so profile/list surfaces don't render the
/// same repo twice (issue #6).
///
/// Rows are grouped by `(normalized owner, name)`, where the normalized owner is the
/// key segment after the last `:` (so `did:key:z6Mk…` and the bare `z6Mk…` mirror row
/// collapse together). Within a group the canonical row wins: a non-mirror row is
/// preferred over a mirror, ties broken by earliest `created_at` then `id`. A mirror
/// row is identified structurally by its slash-form `id` (`{owner_short}/{name}`,
/// written only by `Db::upsert_mirror_repo`), not by its user-settable description.
/// The survivor inherits the group's most recent `updated_at` so a gossip push that
/// only touches the mirror row still floats the repo to the top.
///
/// This mirrors the SQL dedup applied on the paged/unfiltered paths via
/// `Db::DEDUP_CTE`; the marker and the `id` tiebreak must stay in sync with it.
fn dedupe_canonical_repos(rows: Vec<(RepoRecord, i64)>) -> Vec<(RepoRecord, i64)> {
    use std::collections::HashMap;

    // Mirror rows carry a slash-form id, written only by Db::upsert_mirror_repo;
    // canonical rows use a UUID id (no slash). Structural, not user-settable.
    fn is_mirror(r: &RepoRecord) -> bool {
        r.id.contains('/')
    }

    // Strictly more canonical: non-mirror beats mirror; on equal mirror-status the
    // earlier created_at wins, and a full tie falls back to id ASC so the survivor
    // matches SQL's DISTINCT ON (… created_at ASC, id ASC).
    fn outranks(candidate: &RepoRecord, current: &RepoRecord) -> bool {
        match (is_mirror(candidate), is_mirror(current)) {
            (false, true) => true,
            (true, false) => false,
            _ => (candidate.created_at, &candidate.id) < (current.created_at, &current.id),
        }
    }

    // Preserve first-seen group order so output ordering stays deterministic.
    let mut order: Vec<(String, String)> = Vec::new();
    let mut winners: HashMap<(String, String), (RepoRecord, i64)> = HashMap::new();
    let mut latest: HashMap<(String, String), DateTime<Utc>> = HashMap::new();

    for (rec, stars) in rows {
        // did:key-aware owner key: strip a `did:key:` prefix so the bare mirror id
        // and its `did:key:` canonical collapse, but leave any other DID method
        // whole so `did:key:X` and `did:gitlawb:X` never merge. The `!contains(':')`
        // guard mirrors did_matches' `key_id` check: a stripped value that still
        // holds a `:` is a non-key full DID (e.g. malformed `did:key:did:gitlawb:X`)
        // and must keep its full form, not collapse onto the bare method DID. Stays
        // byte-equivalent to the SQL CASE in Db::DEDUP_CTE / count_repos_deduped.
        let owner_key = rec
            .owner_did
            .strip_prefix("did:key:")
            .filter(|rest| !rest.contains(':'))
            .unwrap_or(&rec.owner_did)
            .to_string();
        let key = (owner_key, rec.name.clone());

        latest
            .entry(key.clone())
            .and_modify(|u| {
                if rec.updated_at > *u {
                    *u = rec.updated_at;
                }
            })
            .or_insert(rec.updated_at);

        match winners.get(&key) {
            None => {
                order.push(key.clone());
                winners.insert(key, (rec, stars));
            }
            Some((current, _)) if outranks(&rec, current) => {
                winners.insert(key, (rec, stars));
            }
            Some(_) => {}
        }
    }

    order
        .into_iter()
        .filter_map(|key| {
            let max_updated = latest.get(&key).copied();
            winners.remove(&key).map(|(mut rec, stars)| {
                if let Some(u) = max_updated {
                    rec.updated_at = u;
                }
                (rec, stars)
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::caller_authorized_to_push;
    use crate::error::AppError;
    use gitlawb_core::identity::Keypair;

    const OWNER_DID: &str = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
    const OWNER_SHORT: &str = "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
    const STRANGER_DID: &str = "did:key:z6Mkffonly5tranger0000000000000000000000000000000";

    #[test]
    fn git_service_app_error_classifies_timeout_bad_request_and_git() {
        // GitServiceTimeout carried through anyhow -> 504 Timeout.
        let timeout_err: anyhow::Error = smart_http::GitServiceTimeout.into();
        assert!(matches!(
            git_service_app_error(&timeout_err),
            AppError::Timeout(_)
        ));
        // A malformed client request -> 400.
        let bad = anyhow::anyhow!("fatal: bad line length character: 0000");
        assert!(matches!(
            git_service_app_error(&bad),
            AppError::BadRequest(_)
        ));
        // The `protocol error` marker (with no "bad line length" substring) also
        // -> 400, exercising the second arm of the classifier independently.
        let proto = anyhow::anyhow!("fatal: protocol error: unexpected flush packet");
        assert!(matches!(
            git_service_app_error(&proto),
            AppError::BadRequest(_)
        ));
        // Anything else -> 500 git error.
        let other = anyhow::anyhow!("some other git failure");
        assert!(matches!(git_service_app_error(&other), AppError::Git(_)));
    }

    fn repo_owned_by(owner_did: &str) -> crate::db::RepoRecord {
        let now = chrono::Utc::now();
        crate::db::RepoRecord {
            id: "repo-id".into(),
            name: "demo".into(),
            owner_did: owner_did.into(),
            description: None,
            is_public: true,
            default_branch: "main".into(),
            created_at: now,
            updated_at: now,
            disk_path: "/tmp/demo".into(),
            forked_from: None,
            machine_id: None,
        }
    }

    /// `announce` is the single boolean that gates every network-facing emission
    /// of a push: gossip, Arweave anchoring, and the GraphQL subscription
    /// broadcast (the last one added in this change). It must be false for a repo
    /// the anonymous public cannot read, or the unauthenticated `/graphql/ws`
    /// subscription leaks live private-repo ref metadata. Pin both directions of
    /// the decision the broadcast now sits behind. No disk access: a non-announce
    /// repo returns early, and a public repo with no path-scoped rule skips the
    /// withheld walk.
    #[tokio::test]
    async fn replication_announce_false_for_private_true_for_public() {
        let dummy = std::path::PathBuf::from("/nonexistent");

        // Private: no rules at all.
        let (announce, _) = replication_withheld_set(None, OWNER_DID, false, dummy.clone()).await;
        assert!(!announce, "private repo (no rules) must not announce");

        // Private: empty rule set, is_public=false → still not listable at root.
        let (announce, _) =
            replication_withheld_set(Some(vec![]), OWNER_DID, false, dummy.clone()).await;
        assert!(!announce, "private repo (empty rules) must not announce");

        // Public: empty rule set, is_public=true → listable at root, announces.
        let (announce, _) = replication_withheld_set(Some(vec![]), OWNER_DID, true, dummy).await;
        assert!(announce, "public repo must announce");
    }

    /// A rejection must be a 403 Forbidden (authenticated but not authorized),
    /// not a 400 — some git/CI clients retry 400s.
    fn assert_forbidden(rejection: Option<AppError>) {
        assert!(
            matches!(rejection, Some(AppError::Forbidden(_))),
            "expected Some(Forbidden), got {rejection:?}"
        );
    }

    #[test]
    fn smart_http_repo_name_rejects_empty_after_git_suffix() {
        assert_eq!(smart_http_repo_name("demo.git").unwrap(), "demo");
        assert_eq!(smart_http_repo_name("demo").unwrap(), "demo");
        // Only one suffix is stripped: a repo literally named "demo.git"
        // stays addressable and never aliases to "demo".
        assert_eq!(smart_http_repo_name("demo.git.git").unwrap(), "demo.git");
        assert!(matches!(
            smart_http_repo_name(".git"),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            smart_http_repo_name(""),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn enforced_allows_owner_full_did() {
        let repo = repo_owned_by(OWNER_DID);
        assert!(owner_push_rejection(true, &repo, Some(OWNER_DID)).is_none());
    }

    #[test]
    fn enforced_allows_owner_short_did() {
        // Owners are accepted in bare-multibase form, matching the rest of the
        // codebase's owner comparisons.
        let repo = repo_owned_by(OWNER_DID);
        assert!(owner_push_rejection(true, &repo, Some(OWNER_SHORT)).is_none());
    }

    #[test]
    fn enforced_rejects_non_owner_with_forbidden() {
        let repo = repo_owned_by(OWNER_DID);
        assert_forbidden(owner_push_rejection(true, &repo, Some(STRANGER_DID)));
    }

    #[test]
    fn enforced_rejects_missing_did_with_forbidden() {
        // Fail closed: an absent authenticated identity is rejected, not allowed.
        let repo = repo_owned_by(OWNER_DID);
        assert_forbidden(owner_push_rejection(true, &repo, None));
    }

    #[test]
    fn disabled_allows_non_owner_and_missing_did() {
        // Flag off → legacy behavior: authentication-only, no owner gate.
        let repo = repo_owned_by(OWNER_DID);
        assert!(owner_push_rejection(false, &repo, Some(STRANGER_DID)).is_none());
        assert!(owner_push_rejection(false, &repo, None).is_none());
    }

    #[test]
    fn caller_authorized_to_push_is_owner_only_in_phase_1() {
        let repo = repo_owned_by(OWNER_DID);
        assert!(caller_authorized_to_push(&repo, OWNER_DID));
        assert!(caller_authorized_to_push(&repo, OWNER_SHORT));
        assert!(!caller_authorized_to_push(&repo, STRANGER_DID));
    }

    // ── fork_withheld_blocks (#98 path-scoped fork gate) ──
    // A path-scoped visibility rule is an allow-list keyed by `reader_dids`, so
    // the fork gate must ask the per-caller question "is anything withheld from
    // this caller?" (`withheld_globs` non-empty), not the structural "does any
    // non-`/` rule exist?". `READER_DID` is a non-owner who is granted a subtree.
    const READER_DID: &str = "did:key:z6Mkreader000000000000000000000000000000000000000";

    fn vis_rule(path_glob: &str, readers: &[&str]) -> crate::db::VisibilityRule {
        crate::db::VisibilityRule {
            id: "rule-id".into(),
            repo_id: "repo-id".into(),
            path_glob: path_glob.into(),
            mode: crate::db::VisibilityMode::B,
            reader_dids: readers.iter().map(|s| s.to_string()).collect(),
            created_by: OWNER_DID.into(),
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn fork_owner_full_did_with_path_rule_allowed() {
        // Owner reads everything (implicit reader), so nothing is withheld.
        let rules = [vis_rule("/secret/**", &[])];
        assert!(!fork_withheld_blocks(&rules, true, OWNER_DID, OWNER_DID));
    }

    #[test]
    fn fork_owner_short_did_with_path_rule_allowed() {
        // Owner recognized in bare short-form via visibility_check's is_owner.
        let rules = [vis_rule("/secret/**", &[])];
        assert!(!fork_withheld_blocks(&rules, true, OWNER_DID, OWNER_SHORT));
    }

    #[test]
    fn fork_non_owner_denied_subtree_refused() {
        // Core #98 regression: caller is not a reader of /secret, so it is
        // withheld and the full-mirror fork must be refused.
        let rules = [vis_rule("/secret/**", &[])];
        assert!(fork_withheld_blocks(&rules, true, OWNER_DID, STRANGER_DID));
    }

    #[test]
    fn fork_non_owner_granted_subtree_allowed() {
        // The case the structural predicate got wrong: a listed reader of
        // /secret can read it on the read path, so the fork must be allowed.
        let rules = [vis_rule("/secret/**", &[READER_DID])];
        assert!(!fork_withheld_blocks(&rules, true, OWNER_DID, READER_DID));
    }

    #[test]
    fn fork_non_owner_root_rule_only_allowed() {
        // Whole-repo "/" rules are excluded by withheld_globs; nothing withheld.
        // is_public=true models the caller having passed authorize_repo_read("/").
        let rules = [vis_rule("/", &[])];
        assert!(!fork_withheld_blocks(&rules, true, OWNER_DID, STRANGER_DID));
    }

    #[test]
    fn fork_non_owner_no_rules_public_allowed() {
        assert!(!fork_withheld_blocks(&[], true, OWNER_DID, STRANGER_DID));
    }

    #[test]
    fn fork_non_owner_mixed_root_and_denied_subtree_refused() {
        // A permissive root rule does not rescue a denied path-scoped subtree.
        let rules = [vis_rule("/", &[]), vis_rule("/secret/**", &[])];
        assert!(fork_withheld_blocks(&rules, true, OWNER_DID, STRANGER_DID));
    }

    #[test]
    fn fork_partial_reader_still_refused() {
        // Caller granted /secret/public but denied the rest of /secret still
        // cannot read all of /secret, so the full mirror is refused (a filtered
        // fork is Option 2 / deferred).
        let rules = [
            vis_rule("/secret/**", &[]),
            vis_rule("/secret/public/**", &[READER_DID]),
        ];
        assert!(fork_withheld_blocks(&rules, true, OWNER_DID, READER_DID));
    }

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn record(id: &str, owner_did: &str, name: &str, desc: &str, updated: &str) -> RepoRecord {
        RepoRecord {
            id: id.to_string(),
            name: name.to_string(),
            owner_did: owner_did.to_string(),
            description: Some(desc.to_string()),
            is_public: true,
            default_branch: "main".to_string(),
            created_at: ts("2026-01-01T00:00:00Z"),
            updated_at: ts(updated),
            disk_path: format!("/srv/{id}"),
            forked_from: None,
            machine_id: None,
        }
    }

    #[test]
    fn canonical_row_wins_over_short_owner_mirror() {
        // Order deliberately puts the mirror row first to prove ranking, not input order, decides.
        let mirror = record(
            "z6Mkwbud/nipmod",
            "z6Mkwbud",
            "nipmod",
            "mirrored from peer",
            "2026-02-01T00:00:00Z",
        );
        let canonical = record(
            "9d92186a",
            "did:key:z6Mkwbud",
            "nipmod",
            "Decentralized npm for agents on Gitlawb",
            "2026-01-15T00:00:00Z",
        );

        let out = dedupe_canonical_repos(vec![(mirror, 3), (canonical, 7)]);

        assert_eq!(out.len(), 1, "the two rows collapse into one logical repo");
        let (rec, stars) = &out[0];
        assert_eq!(
            rec.owner_did, "did:key:z6Mkwbud",
            "canonical did:key row wins"
        );
        assert_eq!(
            rec.description.as_deref(),
            Some("Decentralized npm for agents on Gitlawb"),
            "canonical description and metadata survive, not the mirror placeholder",
        );
        assert_eq!(*stars, 7, "star count follows the canonical row");
        // Survivor inherits the group's most recent updated_at (here the mirror's).
        assert_eq!(rec.updated_at, ts("2026-02-01T00:00:00Z"));
    }

    #[test]
    fn distinct_repos_are_preserved_in_order() {
        let a = record(
            "id-a",
            "did:key:z6Aaa",
            "alpha",
            "first",
            "2026-03-01T00:00:00Z",
        );
        let b = record(
            "id-b",
            "did:key:z6Bbb",
            "beta",
            "second",
            "2026-03-02T00:00:00Z",
        );

        let out = dedupe_canonical_repos(vec![(a, 1), (b, 2)]);

        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0.name, "alpha");
        assert_eq!(out[1].0.name, "beta");
    }

    #[test]
    fn same_short_owner_different_repo_does_not_collapse() {
        // `one` is a real mirror row: slash-form id is the structural marker.
        let one = record(
            "z6Mkwbud/nipmod",
            "z6Mkwbud",
            "nipmod",
            "mirrored from peer",
            "2026-01-01T00:00:00Z",
        );
        let two = record(
            "id-2",
            "did:key:z6Mkwbud",
            "other",
            "real",
            "2026-01-01T00:00:00Z",
        );

        let out = dedupe_canonical_repos(vec![(one, 0), (two, 0)]);

        assert_eq!(
            out.len(),
            2,
            "different repo names stay separate under one owner"
        );
    }

    #[test]
    fn distinct_did_methods_sharing_a_base58_id_do_not_collapse() {
        // `did:key` and `did:gitlawb` share the base58 id space, so a trailing
        // segment key would treat these as one repo. The did:key-aware key keeps
        // them apart, matching crate::api::did_matches.
        let keyed = record(
            "id-keyed",
            "did:key:z6Mkwbud",
            "nipmod",
            "owned via did:key",
            "2026-01-01T00:00:00Z",
        );
        let gitlawb = record(
            "id-gitlawb",
            "did:gitlawb:z6Mkwbud",
            "nipmod",
            "owned via did:gitlawb",
            "2026-01-01T00:00:00Z",
        );

        let out = dedupe_canonical_repos(vec![(keyed, 1), (gitlawb, 2)]);

        assert_eq!(
            out.len(),
            2,
            "same name and base58 id under different DID methods are distinct repos"
        );
    }

    #[test]
    fn bare_id_and_did_key_form_of_same_owner_collapse() {
        // A bare mirror id and its did:key canonical are the same owner and must
        // collapse, the mirror-vs-canonical case stated in owner-key terms.
        let mirror = record(
            "z6Mkwbud/nipmod",
            "z6Mkwbud",
            "nipmod",
            "mirrored from peer",
            "2026-02-01T00:00:00Z",
        );
        let canonical = record(
            "canon-id",
            "did:key:z6Mkwbud",
            "nipmod",
            "real",
            "2026-01-15T00:00:00Z",
        );

        let out = dedupe_canonical_repos(vec![(mirror, 0), (canonical, 5)]);

        assert_eq!(out.len(), 1, "bare id and its did:key form are one owner");
        assert_eq!(out[0].0.owner_did, "did:key:z6Mkwbud", "canonical row wins");
    }

    #[test]
    fn did_key_wrapping_a_full_did_does_not_collapse_onto_the_bare_method_did() {
        // Residual-colon guard, mirroring did_matches' `!key_id().contains(':')`:
        // a malformed `did:key:did:gitlawb:X` strips to `did:gitlawb:X`, which still
        // holds a `:`, so it must keep its full form and NOT collapse with a real
        // `did:gitlawb:X` repo of the same name.
        let wrapped = record(
            "id-wrapped",
            "did:key:did:gitlawb:z6Mkwbud",
            "nipmod",
            "malformed nested DID",
            "2026-01-01T00:00:00Z",
        );
        let method = record(
            "id-method",
            "did:gitlawb:z6Mkwbud",
            "nipmod",
            "real method DID",
            "2026-01-02T00:00:00Z",
        );

        let out = dedupe_canonical_repos(vec![(wrapped, 1), (method, 2)]);

        assert_eq!(
            out.len(),
            2,
            "a did:key-wrapped full DID stays distinct from the bare method DID"
        );
        // Assert identity, not just count: each owner survives unmerged, so a
        // regression that kept two rows but mis-keyed the survivor is also caught.
        let mut owners: Vec<&str> = out.iter().map(|(r, _)| r.owner_did.as_str()).collect();
        owners.sort_unstable();
        assert_eq!(
            owners,
            vec!["did:gitlawb:z6Mkwbud", "did:key:did:gitlawb:z6Mkwbud"],
            "both owner DIDs survive in their full form"
        );
    }

    #[test]
    fn empty_did_key_residual_keys_to_empty_string_consistently() {
        // Degenerate boundary the reviewers flagged: `did:key:` with no id strips to
        // an empty residual (no colon), so the key is "". A bare empty owner also
        // keys to "", so the two collapse — proving the Rust strip path maps the
        // empty residual exactly like the SQL `substr(owner_did, 9)` / `position`
        // path (mirrored in the db-level test). A real did:key id keys separately.
        let empty_did_key = record(
            "id-empty-didkey",
            "did:key:",
            "nipmod",
            "empty residual",
            "2026-01-01T00:00:00Z",
        );
        let empty_bare = record(
            "id-empty-bare",
            "",
            "nipmod",
            "empty owner",
            "2026-01-02T00:00:00Z",
        );
        let real = record(
            "id-real",
            "did:key:z6Mkwbud",
            "nipmod",
            "real id",
            "2026-01-03T00:00:00Z",
        );

        let out = dedupe_canonical_repos(vec![(empty_did_key, 0), (empty_bare, 0), (real, 0)]);

        assert_eq!(
            out.len(),
            2,
            "`did:key:` and the empty owner share the empty key and collapse; the real id stays separate"
        );
    }

    #[test]
    fn two_mirror_rows_break_tie_by_earliest_created_at() {
        // Both are mirror rows (slash-form ids); earliest created_at wins.
        let mut older = record(
            "z6X/r",
            "z6X",
            "r",
            "mirrored from peer",
            "2026-02-01T00:00:00Z",
        );
        older.created_at = ts("2026-01-01T00:00:00Z");
        let mut newer = record(
            "z6X/r-dup",
            "z6X",
            "r",
            "mirrored from peer",
            "2026-03-01T00:00:00Z",
        );
        newer.created_at = ts("2026-01-10T00:00:00Z");

        let out = dedupe_canonical_repos(vec![(newer, 0), (older, 0)]);

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.id, "z6X/r", "earliest created_at wins the tie");
    }

    #[test]
    fn canonical_with_mirror_description_is_treated_as_canonical() {
        // Marker robustness: the canonical row carries the literal mirror
        // description (user-settable) but a UUID id; the true mirror has the
        // slash id and was created earlier. The canonical must still win — dedup
        // keys on the structural id, not the description.
        let canonical = record(
            "9d92186a-uuid",
            "did:key:z6Mkwbud",
            "nipmod",
            "mirrored from peer",
            "2026-02-01T00:00:00Z",
        );
        let mirror = record(
            "z6Mkwbud/nipmod",
            "z6Mkwbud",
            "nipmod",
            "a normal description",
            "2026-01-01T00:00:00Z",
        );

        let out = dedupe_canonical_repos(vec![(canonical, 5), (mirror, 1)]);

        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].0.id, "9d92186a-uuid",
            "canonical wins by structural id marker despite the mirror description"
        );
    }

    #[test]
    fn full_tie_resolves_by_id_asc() {
        // Two canonical rows in one group, identical created_at; only id differs.
        // Survivor is id ASC, matching SQL's DISTINCT ON (… created_at ASC, id ASC).
        let bbb = record(
            "bbb",
            "did:key:z6Same",
            "repo",
            "real",
            "2026-01-01T00:00:00Z",
        );
        let aaa = record("aaa", "z6Same", "repo", "real", "2026-01-01T00:00:00Z");

        let out = dedupe_canonical_repos(vec![(bbb, 0), (aaa, 0)]);

        assert_eq!(out.len(), 1, "same group collapses");
        assert_eq!(
            out[0].0.id, "aaa",
            "id ASC breaks a full tie deterministically"
        );
    }

    // A multi-ref push must fan out one /sync/notify request per ref, each
    // carrying that ref's real old_sha. Regression guard for the handler that
    // used to flatten the push to ref_updates_clone.first() with a hardcoded
    // zero old_sha (#26 / PR #72) — drops every ref after the first and the
    // wrong previous SHA.
    #[tokio::test]
    async fn test_notify_peer_of_refs_sends_one_request_per_ref_with_real_old_sha() {
        let mut server = mockito::Server::new_async().await;
        let keypair = Keypair::generate();
        let http_client = reqwest::Client::new();

        let (ref_a, old_a, new_a) = (
            "refs/heads/main",
            "1111111111111111111111111111111111111111",
            "2222222222222222222222222222222222222222",
        );
        let (ref_b, old_b, new_b) = (
            "refs/heads/feature",
            "3333333333333333333333333333333333333333",
            "4444444444444444444444444444444444444444",
        );

        // Two distinct mocks, each requiring one ref's real per-ref values.
        // The old flattening bug (one request, first ref, zero old_sha) would
        // satisfy neither: ref A's request would carry zeros, ref B none at all.
        let _mock_a = server
            .mock("POST", SYNC_NOTIFY_PATH)
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::PartialJsonString(format!(r#"{{"ref_name":"{ref_a}"}}"#)),
                mockito::Matcher::PartialJsonString(format!(r#"{{"old_sha":"{old_a}"}}"#)),
                mockito::Matcher::PartialJsonString(format!(r#"{{"new_sha":"{new_a}"}}"#)),
                mockito::Matcher::PartialJsonString(
                    r#"{"owner_did":"did:key:zOwner"}"#.to_string(),
                ),
            ]))
            .with_status(200)
            .expect(1)
            .create_async()
            .await;
        let _mock_b = server
            .mock("POST", SYNC_NOTIFY_PATH)
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::PartialJsonString(format!(r#"{{"ref_name":"{ref_b}"}}"#)),
                mockito::Matcher::PartialJsonString(format!(r#"{{"old_sha":"{old_b}"}}"#)),
                mockito::Matcher::PartialJsonString(format!(r#"{{"new_sha":"{new_b}"}}"#)),
                mockito::Matcher::PartialJsonString(
                    r#"{"owner_did":"did:key:zOwner"}"#.to_string(),
                ),
            ]))
            .with_status(200)
            .expect(1)
            .create_async()
            .await;

        let notify_url = format!("{}{SYNC_NOTIFY_PATH}", server.url());
        let ref_updates = vec![
            (ref_a.to_string(), old_a.to_string(), new_a.to_string()),
            (ref_b.to_string(), old_b.to_string(), new_b.to_string()),
        ];

        notify_peer_of_refs(
            &http_client,
            &keypair,
            "did:key:zPeer",
            &notify_url,
            "owner/repo",
            &ref_updates,
            "did:key:zNode",
            "did:key:zPusher",
            "did:key:zOwner",
        )
        .await;

        _mock_a.assert_async().await;
        _mock_b.assert_async().await;
    }

    // A newly created ref carries the all-zeros hash as its real old_sha — the
    // helper must forward it verbatim, not substitute a different placeholder.
    #[tokio::test]
    async fn test_notify_peer_of_refs_forwards_all_zeros_for_created_ref() {
        let mut server = mockito::Server::new_async().await;
        let keypair = Keypair::generate();
        let http_client = reqwest::Client::new();

        let zero = ZERO_SHA;
        let new_sha = "5555555555555555555555555555555555555555";
        let _mock = server
            .mock("POST", SYNC_NOTIFY_PATH)
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::PartialJsonString(format!(r#"{{"old_sha":"{zero}"}}"#)),
                mockito::Matcher::PartialJsonString(format!(r#"{{"new_sha":"{new_sha}"}}"#)),
                mockito::Matcher::PartialJsonString(
                    r#"{"owner_did":"did:key:zOwner"}"#.to_string(),
                ),
            ]))
            .with_status(200)
            .expect(1)
            .create_async()
            .await;

        let notify_url = format!("{}{SYNC_NOTIFY_PATH}", server.url());
        let ref_updates = vec![(
            "refs/heads/new".to_string(),
            zero.to_string(),
            new_sha.to_string(),
        )];

        notify_peer_of_refs(
            &http_client,
            &keypair,
            "did:key:zPeer",
            &notify_url,
            "owner/repo",
            &ref_updates,
            "did:key:zNode",
            "did:key:zPusher",
            "did:key:zOwner",
        )
        .await;

        _mock.assert_async().await;
    }

    #[tokio::test]
    async fn to_response_generates_correct_clone_url_slug() {
        let state = crate::test_support::test_state_lazy();
        let now = chrono::Utc::now();

        // 1. did:key owner (should strip did:key: prefix)
        let repo_key = crate::db::RepoRecord {
            id: "uuid-1".into(),
            name: "my-repo".into(),
            owner_did: "did:key:z6Mkwbud".into(),
            description: None,
            is_public: true,
            default_branch: "main".into(),
            created_at: now,
            updated_at: now,
            disk_path: "/tmp/my-repo".into(),
            forked_from: None,
            machine_id: None,
        };
        let response_key = to_response(&repo_key, &state, 5);
        assert!(
            response_key.clone_url.contains("/z6Mkwbud/my-repo.git"),
            "clone_url should use the bare did:key ID. got: {}",
            response_key.clone_url
        );

        // 2. did:gitlawb owner (non-key DID method, should NOT strip)
        let repo_non_key = crate::db::RepoRecord {
            id: "uuid-2".into(),
            name: "other-repo".into(),
            owner_did: "did:gitlawb:z6Mkwbud".into(),
            description: None,
            is_public: true,
            default_branch: "main".into(),
            created_at: now,
            updated_at: now,
            disk_path: "/tmp/other-repo".into(),
            forked_from: None,
            machine_id: None,
        };
        let response_non_key = to_response(&repo_non_key, &state, 10);
        assert!(
            response_non_key
                .clone_url
                .contains("/did:gitlawb:z6Mkwbud/other-repo.git"),
            "clone_url should preserve the full non-key owner DID. got: {}",
            response_non_key.clone_url
        );
    }

    /// The receive-pack *advertisement* (`GET info/refs?service=git-receive-pack`)
    /// must be throttled by the per-IP push limiter BEFORE it does the fresh
    /// Tigris acquire — otherwise the flood brake on the POST is bypassable via
    /// the cheaper unauthenticated GET (PR #152 review P1). Pre-filling the
    /// bucket makes the assertion deterministic and keeps the test off the
    /// acquire path entirely.
    #[sqlx::test]
    async fn receive_pack_advertisement_is_rate_limited(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::{Method, Request, StatusCode};
        use std::net::SocketAddr;
        use std::time::Duration;
        use tower::ServiceExt;

        let mut state = crate::test_support::test_state(pool).await;
        // Tiny limit, keyed on the socket peer (no trusted proxy).
        state.push_rate_limiter = crate::rate_limit::RateLimiter::new(1, Duration::from_secs(60));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state
            .db
            .upsert_mirror_repo("z6advowner", "adv", "/tmp/adv", None, false)
            .await
            .unwrap();

        let peer: SocketAddr = "203.0.113.55:6000".parse().unwrap();
        // Exhaust this peer's single-request budget up front.
        assert!(state.push_rate_limiter.check(&peer.ip().to_string()).await);

        let router = crate::server::build_router(state);
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/z6advowner/adv/info/refs?service=git-receive-pack")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));

        let status = router.oneshot(req).await.unwrap().status();
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "receive-pack advertisement must be throttled before the Tigris acquire"
        );
    }

    /// The receive-pack advertisement 429 must carry a window-derived Retry-After,
    /// consistent with the other push 429 sites (U5). Before the fix this site
    /// returned a bare 429 with no Retry-After header at all — a client had nothing
    /// to back off on. A freshly-filled bucket's oldest
    /// entry is ~now, so the advertised delay must be close to the whole window
    /// (100s), never missing and never the old constant 60.
    #[sqlx::test]
    async fn receive_pack_advertisement_429_carries_window_derived_retry_after(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::{Method, Request, StatusCode};
        use std::net::SocketAddr;
        use std::time::Duration;
        use tower::ServiceExt;

        let mut state = crate::test_support::test_state(pool).await;
        // Budget 1, 100s window, keyed on the socket peer (no trusted proxy).
        state.push_rate_limiter = crate::rate_limit::RateLimiter::new(1, Duration::from_secs(100));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state
            .db
            .upsert_mirror_repo("z6advretry", "adv", "/tmp/advretry", None, false)
            .await
            .unwrap();

        let peer: SocketAddr = "203.0.113.56:6000".parse().unwrap();
        // Fill the single-request budget so the handler's own check rejects.
        assert!(state.push_rate_limiter.check(&peer.ip().to_string()).await);

        let router = crate::server::build_router(state);
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/z6advretry/adv/info/refs?service=git-receive-pack")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry: u64 = resp
            .headers()
            .get("retry-after")
            .expect("advertisement 429 must carry a retry-after header")
            .to_str()
            .unwrap()
            .parse()
            .expect("retry-after must be an integer number of seconds");
        assert!(
            (95..=100).contains(&retry),
            "freshly-filled bucket must advertise ~window (95..=100s), got {retry} \
             (missing header or constant-60 bug otherwise)"
        );
    }

    // U2/R3/AE1: a fully-received push must complete server-side even when the
    // client disconnects during the apply. The pack is buffered before the
    // handler runs, so the acquire→receive→release core is detached from the
    // handler future; dropping that future (the disconnect) must NOT cancel the
    // push. A sleeping pre-receive hook creates a deterministic mid-apply window;
    // dropping the handler during it kills the git group on the inline (pre-fix)
    // code but not on the detached code, so the hook completes and the ref lands
    // only after the fix. RED pre-fix (marker + ref absent), GREEN after.
    #[sqlx::test]
    async fn fully_received_push_completes_after_client_disconnect(pool: sqlx::PgPool) {
        use axum::extract::{Path as AxPath, State};
        use axum::Extension;
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};
        use std::time::Duration;

        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tempfile::TempDir::new().unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(
            repos_dir.path().to_path_buf(),
            pool.clone(),
        );

        let owner = "z6u2pushowner";
        let name = "u2push";
        let owner_slug = owner.replace([':', '/'], "_");
        let bare = repos_dir
            .path()
            .join(&owner_slug)
            .join(format!("{name}.git"));

        state
            .db
            .upsert_mirror_repo(owner, name, &bare.to_string_lossy(), None, false)
            .await
            .unwrap();

        // Helper: run git, asserting success.
        fn git(args: &[&str], dir: &std::path::Path) -> String {
            let out = Command::new("git")
                .args(args)
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        // Build a commit in a scratch working repo.
        let work = tempfile::TempDir::new().unwrap();
        git(&["init", "-q", "-b", "main", "."], work.path());
        git(&["config", "user.email", "t@t"], work.path());
        git(&["config", "user.name", "t"], work.path());
        std::fs::write(work.path().join("f.txt"), "hi").unwrap();
        git(&["add", "f.txt"], work.path());
        git(&["commit", "-q", "-m", "c"], work.path());
        let oid = git(&["rev-parse", "HEAD"], work.path());

        // Server bare repo: has the object (from the clone) but no refs/heads/main,
        // so the push is a create satisfiable with an empty pack.
        std::fs::create_dir_all(bare.parent().unwrap()).unwrap();
        let out = Command::new("git")
            .args([
                "clone",
                "--bare",
                "-q",
                &work.path().to_string_lossy(),
                &bare.to_string_lossy(),
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "clone --bare failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        git(
            &[
                "-C",
                &bare.to_string_lossy(),
                "update-ref",
                "-d",
                "refs/heads/main",
            ],
            work.path(),
        );

        // Sleeping pre-receive hook — the mid-apply window; writes a marker at the
        // end so we can see the git child ran to completion.
        let marker = repos_dir.path().join("hook_ran.marker");
        let hook = bare.join("hooks").join("pre-receive");
        std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
        std::fs::write(
            &hook,
            format!(
                "#!/bin/sh\ncat >/dev/null\nsleep 2\necho done > '{}'\nexit 0\n",
                marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Receive-pack POST body: create refs/heads/main -> oid, plus an empty pack.
        let zero = "0".repeat(40);
        let cmd = format!("{zero} {oid} refs/heads/main\0report-status\n");
        let mut body = Vec::new();
        let len = cmd.len() + 4;
        body.extend_from_slice(format!("{len:04x}").as_bytes());
        body.extend_from_slice(cmd.as_bytes());
        body.extend_from_slice(b"0000");
        let pack = Command::new("git")
            .args([
                "-C",
                &bare.to_string_lossy(),
                "pack-objects",
                "--stdout",
                "-q",
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            pack.status.success(),
            "pack-objects failed: {}",
            String::from_utf8_lossy(&pack.stderr)
        );
        body.extend_from_slice(&pack.stdout);
        let body = Bytes::from(body);

        // Drive the handler, then DROP it mid-hook (the "client disconnect").
        let handler = super::git_receive_pack(
            State(state.clone()),
            AxPath((owner.to_string(), format!("{name}.git"))),
            Extension(crate::auth::AuthenticatedDid(owner.to_string())),
            body,
        );
        let _ = tokio::time::timeout(Duration::from_millis(800), handler).await;

        // Wait past the hook's sleep so a surviving (detached) push can finish.
        tokio::time::sleep(Duration::from_millis(3000)).await;

        let ref_present = bare.join("refs/heads/main").exists()
            || std::fs::read_to_string(bare.join("packed-refs"))
                .unwrap_or_default()
                .contains("refs/heads/main");
        assert!(
            marker.exists(),
            "pre-receive hook must run to completion despite the client disconnect (detached push)"
        );
        assert!(
            ref_present,
            "refs/heads/main must be created after a fully-received push despite client disconnect"
        );
    }

    // U1/R1: a fully-received push must produce its metadata + fan-out TAIL even
    // when the client disconnects mid-apply. The pre-fix handler detaches only
    // acquire→receive→release; the whole success tail (touch_repo, record_push,
    // certs, webhooks, replication, ref broadcast) runs inline in the cancellable
    // request future, so a disconnect after receive-pack succeeds commits the git
    // refs (in the surviving task) but drops the tail — a split-brain: committed
    // git, no push record. Here we drop the handler mid-apply (sleeping hook), let
    // the surviving task finish, and assert the push record landed. RED pre-fix
    // (push_events row absent), GREEN after (tail folded into the detached task).
    #[sqlx::test]
    async fn push_metadata_tail_completes_after_client_disconnect(pool: sqlx::PgPool) {
        use axum::extract::{Path as AxPath, State};
        use axum::Extension;
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};
        use std::time::Duration;

        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tempfile::TempDir::new().unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(
            repos_dir.path().to_path_buf(),
            pool.clone(),
        );

        let owner = "z6u1tailowner";
        let name = "u1tail";
        let owner_slug = owner.replace([':', '/'], "_");
        let bare = repos_dir
            .path()
            .join(&owner_slug)
            .join(format!("{name}.git"));

        state
            .db
            .upsert_mirror_repo(owner, name, &bare.to_string_lossy(), None, false)
            .await
            .unwrap();

        fn git(args: &[&str], dir: &std::path::Path) -> String {
            let out = Command::new("git")
                .args(args)
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        // Build a commit in a scratch working repo.
        let work = tempfile::TempDir::new().unwrap();
        git(&["init", "-q", "-b", "main", "."], work.path());
        git(&["config", "user.email", "t@t"], work.path());
        git(&["config", "user.name", "t"], work.path());
        std::fs::write(work.path().join("f.txt"), "hi").unwrap();
        git(&["add", "f.txt"], work.path());
        git(&["commit", "-q", "-m", "c"], work.path());
        let oid = git(&["rev-parse", "HEAD"], work.path());

        std::fs::create_dir_all(bare.parent().unwrap()).unwrap();
        let out = Command::new("git")
            .args([
                "clone",
                "--bare",
                "-q",
                &work.path().to_string_lossy(),
                &bare.to_string_lossy(),
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "clone --bare failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        git(
            &[
                "-C",
                &bare.to_string_lossy(),
                "update-ref",
                "-d",
                "refs/heads/main",
            ],
            work.path(),
        );

        // Sleeping pre-receive hook: the deterministic mid-apply window we drop in.
        let hook = bare.join("hooks").join("pre-receive");
        std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
        std::fs::write(&hook, "#!/bin/sh\ncat >/dev/null\nsleep 2\nexit 0\n").unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Receive-pack POST body: create refs/heads/main -> oid, plus a real pack.
        let zero = "0".repeat(40);
        let cmd = format!("{zero} {oid} refs/heads/main\0report-status\n");
        let mut body = Vec::new();
        let len = cmd.len() + 4;
        body.extend_from_slice(format!("{len:04x}").as_bytes());
        body.extend_from_slice(cmd.as_bytes());
        body.extend_from_slice(b"0000");
        let pack = Command::new("git")
            .args([
                "-C",
                &bare.to_string_lossy(),
                "pack-objects",
                "--stdout",
                "-q",
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            pack.status.success(),
            "pack-objects failed: {}",
            String::from_utf8_lossy(&pack.stderr)
        );
        body.extend_from_slice(&pack.stdout);
        let body = Bytes::from(body);

        // Drive the handler, then DROP it mid-hook (the "client disconnect").
        let handler = super::git_receive_pack(
            State(state.clone()),
            AxPath((owner.to_string(), format!("{name}.git"))),
            Extension(crate::auth::AuthenticatedDid(owner.to_string())),
            body,
        );
        let _ = tokio::time::timeout(Duration::from_millis(800), handler).await;

        // Poll for the tail's push record past the hook's sleep. The pusher DID is
        // the repo owner, so the push_events count for `owner` becomes 1 once the
        // surviving task runs the tail.
        let mut pushes = 0i64;
        for _ in 0..40 {
            pushes = state.db.get_push_count(owner).await.unwrap();
            if pushes >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        assert_eq!(
            pushes, 1,
            "the push-metadata tail (record_push) must land after a fully-received \
             push despite the client disconnect — it must run in the detached task, \
             not the cancelled request future"
        );
    }

    // U1/R1 no-regression: a CONNECTED push (handler awaited to completion) must
    // still get report-status back over the oneshot AND run the full tail. Guards
    // the two ways the refactor could regress a connected client: the response
    // coupling to tail completion (a latency regression), and the oneshot never
    // delivering (client would see a spurious 500).
    #[sqlx::test]
    async fn connected_push_returns_report_status_and_runs_tail(pool: sqlx::PgPool) {
        use axum::extract::{Path as AxPath, State};
        use axum::Extension;
        use std::process::{Command, Stdio};
        use std::time::Duration;

        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tempfile::TempDir::new().unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(
            repos_dir.path().to_path_buf(),
            pool.clone(),
        );

        let owner = "z6u1connowner";
        let name = "u1conn";
        let owner_slug = owner.replace([':', '/'], "_");
        let bare = repos_dir
            .path()
            .join(&owner_slug)
            .join(format!("{name}.git"));

        state
            .db
            .upsert_mirror_repo(owner, name, &bare.to_string_lossy(), None, false)
            .await
            .unwrap();

        fn git(args: &[&str], dir: &std::path::Path) -> String {
            let out = Command::new("git")
                .args(args)
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        let work = tempfile::TempDir::new().unwrap();
        git(&["init", "-q", "-b", "main", "."], work.path());
        git(&["config", "user.email", "t@t"], work.path());
        git(&["config", "user.name", "t"], work.path());
        std::fs::write(work.path().join("f.txt"), "hi").unwrap();
        git(&["add", "f.txt"], work.path());
        git(&["commit", "-q", "-m", "c"], work.path());
        let oid = git(&["rev-parse", "HEAD"], work.path());

        std::fs::create_dir_all(bare.parent().unwrap()).unwrap();
        let out = Command::new("git")
            .args([
                "clone",
                "--bare",
                "-q",
                &work.path().to_string_lossy(),
                &bare.to_string_lossy(),
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "clone --bare failed");
        git(
            &[
                "-C",
                &bare.to_string_lossy(),
                "update-ref",
                "-d",
                "refs/heads/main",
            ],
            work.path(),
        );

        // No hook: the push applies immediately, so the handler returns promptly.
        let zero = "0".repeat(40);
        let cmd = format!("{zero} {oid} refs/heads/main\0report-status\n");
        let mut body = Vec::new();
        let len = cmd.len() + 4;
        body.extend_from_slice(format!("{len:04x}").as_bytes());
        body.extend_from_slice(cmd.as_bytes());
        body.extend_from_slice(b"0000");
        let pack = Command::new("git")
            .args([
                "-C",
                &bare.to_string_lossy(),
                "pack-objects",
                "--stdout",
                "-q",
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(pack.status.success(), "pack-objects failed");
        body.extend_from_slice(&pack.stdout);
        let body = Bytes::from(body);

        // Await the handler to completion (connected client) and assert it returned
        // report-status (200) over the oneshot — not a 500 from a dropped sender.
        let resp = super::git_receive_pack(
            State(state.clone()),
            AxPath((owner.to_string(), format!("{name}.git"))),
            Extension(crate::auth::AuthenticatedDid(owner.to_string())),
            body,
        )
        .await
        .expect("connected push must return report-status");
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        // And the tail runs (detached task): the push record lands.
        let mut pushes = 0i64;
        for _ in 0..40 {
            pushes = state.db.get_push_count(owner).await.unwrap();
            if pushes >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        assert_eq!(pushes, 1, "the tail must run on a connected push too");
    }

    // P1 data-loss regression: when the durable (Tigris) upload in release()
    // times out, the refs are applied on local disk but never persisted to
    // object storage. The pre-fix handler still reported 200 to the client AND
    // ran the success tail, so the client trusted a push that the NEXT
    // acquire_write would revert from the stale pre-push archive — silent data
    // loss. The fix surfaces a failed/timed-out upload as a FAILED push (5xx) so
    // the idempotent client re-pushes, and skips the whole success tail. Here we
    // stall the upload past a tiny release timeout, drive a fully-applied push,
    // and assert (a) the client gets a non-2xx and (b) the tail did NOT run
    // (no push record). RED pre-fix: 200 + push record present.
    #[sqlx::test]
    async fn durable_upload_timeout_fails_push_and_skips_tail(pool: sqlx::PgPool) {
        use axum::extract::{Path as AxPath, State};
        use axum::response::IntoResponse;
        use axum::Extension;
        use std::path::Path as StdPath;
        use std::process::{Command, Stdio};
        use std::time::Duration;

        // Object store whose upload() parks forever: the release() timeout is the
        // only thing that unblocks it. `exists()` is false so acquire_write never
        // downloads over the fresh local bare repo.
        struct StallStore;
        #[async_trait::async_trait]
        impl crate::git::tigris::ObjectStore for StallStore {
            async fn exists(&self, _o: &str, _r: &str) -> anyhow::Result<bool> {
                Ok(false)
            }
            async fn upload(&self, _o: &str, _r: &str, _p: &StdPath) -> anyhow::Result<()> {
                std::future::pending::<()>().await;
                Ok(())
            }
            async fn download(&self, _o: &str, _r: &str, _p: &StdPath) -> anyhow::Result<()> {
                Ok(())
            }
            async fn delete(&self, _o: &str, _r: &str) -> anyhow::Result<()> {
                Ok(())
            }
        }

        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tempfile::TempDir::new().unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::new(
            repos_dir.path().to_path_buf(),
            Some(std::sync::Arc::new(StallStore)),
            pool.clone(),
        )
        .with_release_upload_timeout(Duration::from_millis(200));

        let owner = "z6durablefailowner";
        let name = "durablefail";
        let owner_slug = owner.replace([':', '/'], "_");
        let bare = repos_dir
            .path()
            .join(&owner_slug)
            .join(format!("{name}.git"));

        state
            .db
            .upsert_mirror_repo(owner, name, &bare.to_string_lossy(), None, false)
            .await
            .unwrap();

        fn git(args: &[&str], dir: &std::path::Path) -> String {
            let out = Command::new("git")
                .args(args)
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        let work = tempfile::TempDir::new().unwrap();
        git(&["init", "-q", "-b", "main", "."], work.path());
        git(&["config", "user.email", "t@t"], work.path());
        git(&["config", "user.name", "t"], work.path());
        std::fs::write(work.path().join("f.txt"), "hi").unwrap();
        git(&["add", "f.txt"], work.path());
        git(&["commit", "-q", "-m", "c"], work.path());
        let oid = git(&["rev-parse", "HEAD"], work.path());

        std::fs::create_dir_all(bare.parent().unwrap()).unwrap();
        let out = Command::new("git")
            .args([
                "clone",
                "--bare",
                "-q",
                &work.path().to_string_lossy(),
                &bare.to_string_lossy(),
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "clone --bare failed");
        git(
            &[
                "-C",
                &bare.to_string_lossy(),
                "update-ref",
                "-d",
                "refs/heads/main",
            ],
            work.path(),
        );

        // No hook: the push applies immediately; the stall is entirely in release().
        let zero = "0".repeat(40);
        let cmd = format!("{zero} {oid} refs/heads/main\0report-status\n");
        let mut body = Vec::new();
        let len = cmd.len() + 4;
        body.extend_from_slice(format!("{len:04x}").as_bytes());
        body.extend_from_slice(cmd.as_bytes());
        body.extend_from_slice(b"0000");
        let pack = Command::new("git")
            .args([
                "-C",
                &bare.to_string_lossy(),
                "pack-objects",
                "--stdout",
                "-q",
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(pack.status.success(), "pack-objects failed");
        body.extend_from_slice(&pack.stdout);
        let body = Bytes::from(body);

        // Await the handler: acquire → receive-pack (applies) → release (upload
        // stalls, timing out after 200ms). The client MUST see a failure, not 200.
        let resp = super::git_receive_pack(
            State(state.clone()),
            AxPath((owner.to_string(), format!("{name}.git"))),
            Extension(crate::auth::AuthenticatedDid(owner.to_string())),
            body,
        )
        .await;
        let status = match resp {
            Ok(r) => r.status(),
            Err(e) => e.into_response().status(),
        };
        assert!(
            status.is_server_error(),
            "a timed-out durable upload must fail the push (5xx) so the client \
             retries — got {status}, which the client trusts as a landed push \
             that a later acquire_write would silently revert"
        );

        // And the success tail must NOT have run: no push record for a push whose
        // durable copy never landed. Give the (detached) tail time to run if it
        // were going to, then assert it did not.
        tokio::time::sleep(Duration::from_millis(400)).await;
        let pushes = state.db.get_push_count(owner).await.unwrap();
        assert_eq!(
            pushes, 0,
            "the success tail (record_push) must NOT run when the durable upload \
             failed — the push was not durably accepted"
        );
    }

    // Rollback completeness on the receive-pack path: a failed durable upload
    // must restore the EXACT pre-push snapshot (a ref the push updated is
    // rewound AND a ref the push created is deleted) while the advisory lock
    // is held, so the local fast path never serves refs that never landed
    // durably. RED with the cleanup closure reverted to `|_| {}` (or with
    // restore_refs not deleting created refs): main stays at the pushed tip
    // and/or the created ref survives.
    #[sqlx::test]
    async fn push_failed_upload_rolls_back_created_and_updated_refs(pool: sqlx::PgPool) {
        use axum::extract::{Path as AxPath, State};
        use axum::response::IntoResponse;
        use axum::Extension;
        use std::path::Path as StdPath;
        use std::process::{Command, Stdio};
        use std::time::Duration;

        struct StallStore;
        #[async_trait::async_trait]
        impl crate::git::tigris::ObjectStore for StallStore {
            async fn exists(&self, _o: &str, _r: &str) -> anyhow::Result<bool> {
                Ok(false)
            }
            async fn upload(&self, _o: &str, _r: &str, _p: &StdPath) -> anyhow::Result<()> {
                std::future::pending::<()>().await;
                Ok(())
            }
            async fn download(&self, _o: &str, _r: &str, _p: &StdPath) -> anyhow::Result<()> {
                Ok(())
            }
            async fn delete(&self, _o: &str, _r: &str) -> anyhow::Result<()> {
                Ok(())
            }
        }

        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tempfile::TempDir::new().unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::new(
            repos_dir.path().to_path_buf(),
            Some(std::sync::Arc::new(StallStore)),
            pool.clone(),
        )
        .with_release_upload_timeout(Duration::from_millis(200));

        let owner = "z6refrollbackowner";
        let name = "refrollback";
        let owner_slug = owner.replace([':', '/'], "_");
        let bare = repos_dir
            .path()
            .join(&owner_slug)
            .join(format!("{name}.git"));

        state
            .db
            .upsert_mirror_repo(owner, name, &bare.to_string_lossy(), None, false)
            .await
            .unwrap();

        fn git(args: &[&str], dir: &std::path::Path) -> String {
            let out = Command::new("git")
                .args(args)
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        // Two commits in a scratch repo: the bare repo starts at c1 and the
        // push advances main to c2 AND creates a second ref at c2.
        let work = tempfile::TempDir::new().unwrap();
        git(&["init", "-q", "-b", "main", "."], work.path());
        git(&["config", "user.email", "t@t"], work.path());
        git(&["config", "user.name", "t"], work.path());
        std::fs::write(work.path().join("f.txt"), "one").unwrap();
        git(&["add", "f.txt"], work.path());
        git(&["commit", "-q", "-m", "c1"], work.path());
        let old_oid = git(&["rev-parse", "HEAD"], work.path());
        std::fs::write(work.path().join("f.txt"), "two").unwrap();
        git(&["add", "f.txt"], work.path());
        git(&["commit", "-q", "-m", "c2"], work.path());
        let new_oid = git(&["rev-parse", "HEAD"], work.path());

        // Bare clone (has both commits' objects), then rewind main to c1 so the
        // push is a genuine update satisfiable with an empty pack.
        std::fs::create_dir_all(bare.parent().unwrap()).unwrap();
        let out = Command::new("git")
            .args([
                "clone",
                "--bare",
                "-q",
                &work.path().to_string_lossy(),
                &bare.to_string_lossy(),
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "clone --bare failed");
        git(
            &[
                "-C",
                &bare.to_string_lossy(),
                "update-ref",
                "refs/heads/main",
                &old_oid,
            ],
            work.path(),
        );

        let snapshot = store::list_refs(&bare).unwrap();
        assert_eq!(
            snapshot,
            vec![("refs/heads/main".to_string(), old_oid.clone())],
            "pre-push snapshot must be exactly main at c1"
        );

        // Two commands: update main c1 -> c2, create refs/heads/feature at c2.
        let zero = "0".repeat(40);
        let mut body = Vec::new();
        let cmd1 = format!("{old_oid} {new_oid} refs/heads/main\0report-status\n");
        body.extend_from_slice(format!("{:04x}", cmd1.len() + 4).as_bytes());
        body.extend_from_slice(cmd1.as_bytes());
        let cmd2 = format!("{zero} {new_oid} refs/heads/feature\n");
        body.extend_from_slice(format!("{:04x}", cmd2.len() + 4).as_bytes());
        body.extend_from_slice(cmd2.as_bytes());
        body.extend_from_slice(b"0000");
        let pack = Command::new("git")
            .args([
                "-C",
                &bare.to_string_lossy(),
                "pack-objects",
                "--stdout",
                "-q",
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(pack.status.success(), "pack-objects failed");
        body.extend_from_slice(&pack.stdout);
        let body = Bytes::from(body);

        let resp = super::git_receive_pack(
            State(state.clone()),
            AxPath((owner.to_string(), format!("{name}.git"))),
            Extension(crate::auth::AuthenticatedDid(owner.to_string())),
            body,
        )
        .await;
        let status = match resp {
            Ok(r) => r.status(),
            Err(e) => e.into_response().status(),
        };
        assert!(
            status.is_server_error(),
            "a timed-out durable upload must fail the push (5xx), got {status}"
        );

        // The refs must equal the pre-push snapshot EXACTLY: the created ref is
        // gone and the updated ref is rewound.
        let after = store::list_refs(&bare).unwrap();
        assert_eq!(
            after, snapshot,
            "a failed durable upload must restore the exact pre-push snapshot \
             (created ref deleted, updated ref rewound)"
        );
    }

    // Fail-closed fence on the pre-push ref snapshot, driven through the real
    // handler: when `store::list_refs` on the acquired disk path fails, the
    // handler must refuse the push (Internal, 5xx) BEFORE running receive-pack,
    // because without a snapshot a failed durable upload has no restore plan.
    // The repo on disk is a real bare repo whose config declares
    // repositoryformatversion=999, so every git invocation in it fails
    // deterministically at repo-setup time (`for-each-ref` included) while the
    // directory itself is untouched valid state. No object store is configured,
    // so acquire_write's local fast path uses the existing directory as-is and
    // never repairs or re-downloads it.
    //
    // Load-bearing (RED) checks: remove the fence at the `store::list_refs`
    // match in `git_receive_pack` (e.g. fall back to `.ok()` and proceed) and
    // the failure comes from receive-pack instead, so the "cannot snapshot
    // pre-push refs" assertion on the error text fails. The directory-listing
    // comparison pins that nothing mutated the repo before the refusal.
    #[sqlx::test]
    async fn push_fails_closed_when_ref_snapshot_unavailable(pool: sqlx::PgPool) {
        use axum::extract::{Path as AxPath, State};
        use axum::response::IntoResponse;
        use std::process::{Command, Stdio};

        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tempfile::TempDir::new().unwrap();
        // No object store: acquire_write takes the local fast path and hands the
        // on-disk directory to the handler exactly as seeded below.
        state.repo_store = crate::git::repo_store::RepoStore::new(
            repos_dir.path().to_path_buf(),
            None,
            pool.clone(),
        );

        let owner = "z6snapshotfenceowner";
        let name = "snapfence";
        let owner_slug = owner.replace([':', '/'], "_");
        let bare = repos_dir
            .path()
            .join(&owner_slug)
            .join(format!("{name}.git"));

        state
            .db
            .upsert_mirror_repo(owner, name, &bare.to_string_lossy(), None, false)
            .await
            .unwrap();

        fn git(args: &[&str], dir: &std::path::Path) -> String {
            let out = Command::new("git")
                .args(args)
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        // A scratch repo provides a real oid and a well-formed (empty) pack so
        // the request body is a genuine push, not garbage the parser rejects.
        let work = tempfile::TempDir::new().unwrap();
        git(&["init", "-q", "-b", "main", "."], work.path());
        git(&["config", "user.email", "t@t"], work.path());
        git(&["config", "user.name", "t"], work.path());
        std::fs::write(work.path().join("f.txt"), "hi").unwrap();
        git(&["add", "f.txt"], work.path());
        git(&["commit", "-q", "-m", "c"], work.path());
        let oid = git(&["rev-parse", "HEAD"], work.path());

        // Seed the target: a REAL bare repo, then declare an unsupported
        // repository format version. Discovery still finds the repo (HEAD,
        // objects/, refs/ all present) but every git command in it dies with
        // "expected git repo version <= 1": the deterministic corruption that
        // makes `list_refs` fail without any racy filesystem state.
        std::fs::create_dir_all(bare.parent().unwrap()).unwrap();
        let out = Command::new("git")
            .args(["init", "--bare", "-q", &bare.to_string_lossy()])
            .output()
            .unwrap();
        assert!(out.status.success(), "git init --bare failed");
        std::fs::write(
            bare.join("config"),
            "[core]\n\trepositoryformatversion = 999\n\tbare = true\n",
        )
        .unwrap();
        assert!(
            store::list_refs(&bare).is_err(),
            "precondition: list_refs must fail on the corrupted repo"
        );

        // Recursive sorted listing of the repo dir, to pin "nothing modified".
        fn listing(root: &std::path::Path) -> Vec<String> {
            fn walk(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) {
                for entry in std::fs::read_dir(dir).unwrap() {
                    let p = entry.unwrap().path();
                    out.push(p.strip_prefix(root).unwrap().to_string_lossy().into_owned());
                    if p.is_dir() {
                        walk(root, &p, out);
                    }
                }
            }
            let mut out = Vec::new();
            walk(root, root, &mut out);
            out.sort();
            out
        }
        let before = listing(&bare);

        // Minimal push body: create refs/heads/main at the scratch oid plus an
        // empty pack (same shape as the rollback test above).
        let zero = "0".repeat(40);
        let cmd = format!("{zero} {oid} refs/heads/main\0report-status\n");
        let mut body = Vec::new();
        body.extend_from_slice(format!("{:04x}", cmd.len() + 4).as_bytes());
        body.extend_from_slice(cmd.as_bytes());
        body.extend_from_slice(b"0000");
        let pack = Command::new("git")
            .args([
                "-C",
                &work.path().to_string_lossy(),
                "pack-objects",
                "--stdout",
                "-q",
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(pack.status.success(), "pack-objects failed");
        body.extend_from_slice(&pack.stdout);
        let body = Bytes::from(body);

        let resp = super::git_receive_pack(
            State(state.clone()),
            AxPath((owner.to_string(), format!("{name}.git"))),
            Extension(crate::auth::AuthenticatedDid(owner.to_string())),
            body,
        )
        .await;
        let err = match resp {
            Ok(r) => panic!(
                "push must fail closed when the ref snapshot is unavailable, got {}",
                r.status()
            ),
            Err(e) => e,
        };
        let msg = err.to_string();
        let status = err.into_response().status();
        assert!(
            status.is_server_error(),
            "snapshot failure must surface as a 5xx, got {status}"
        );
        // This is the fence-specific assert: without the fail-closed branch the
        // failure comes from receive-pack ("git error: ...") instead.
        assert!(
            msg.contains("cannot snapshot pre-push refs"),
            "the refusal must come from the snapshot fence, before receive-pack; got: {msg}"
        );

        // Nothing ran against the repo: the directory contents are unchanged
        // (no new refs, no objects, no receive-pack side effects).
        let after = listing(&bare);
        assert_eq!(
            after, before,
            "the corrupted repo must not be modified by a refused push"
        );
    }

    // A bare repo at HEAD with one commit on main, for the rollback-decision
    // unit tests below. Returns the tempdirs (kept alive by the caller), the
    // bare path, and main's oid.
    fn seeded_bare_repo() -> (
        tempfile::TempDir,
        tempfile::TempDir,
        std::path::PathBuf,
        String,
    ) {
        use std::process::Command;

        fn git(args: &[&str], dir: &std::path::Path) -> String {
            let out = Command::new("git")
                .args(args)
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        let work = tempfile::TempDir::new().unwrap();
        git(&["init", "-q", "-b", "main", "."], work.path());
        git(&["config", "user.email", "t@t"], work.path());
        git(&["config", "user.name", "t"], work.path());
        std::fs::write(work.path().join("f.txt"), "hi").unwrap();
        git(&["add", "f.txt"], work.path());
        git(&["commit", "-q", "-m", "c"], work.path());
        let oid = git(&["rev-parse", "HEAD"], work.path());

        let dir = tempfile::TempDir::new().unwrap();
        let bare = dir.path().join("repo.git");
        let out = Command::new("git")
            .args([
                "clone",
                "--bare",
                "-q",
                &work.path().to_string_lossy(),
                &bare.to_string_lossy(),
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "clone --bare failed");
        (work, dir, bare, oid)
    }

    // The None arm of the rollback decision: a failed pre-push listing means
    // "snapshot unavailable", and the rollback must be SKIPPED: the repo's
    // existing refs survive. RED on the pre-fix shape (unwrap_or_default + an
    // unconditional restore_refs), which reads the error as an empty snapshot
    // and deletes every ref.
    #[test]
    fn ref_rollback_skips_when_snapshot_unavailable() {
        let (_work, _dir, bare, oid) = seeded_bare_repo();

        super::rollback_push_refs(&bare, "r", &None);

        assert_eq!(
            store::list_refs(&bare).unwrap(),
            vec![("refs/heads/main".to_string(), oid)],
            "a None snapshot (listing failed) must skip the rollback, not \
             mass-delete the repo's refs"
        );
    }

    // The must-keep negative of the fix: a genuinely EMPTY repo snapshots as
    // Some(vec![]) and still rolls back, deleting the refs the failed push
    // created. Guards against the `.ok()` change accidentally widening the
    // skip to empty snapshots.
    #[test]
    fn ref_rollback_empty_snapshot_still_deletes_created_refs() {
        let (_work, _dir, bare, _oid) = seeded_bare_repo();

        super::rollback_push_refs(&bare, "r", &Some(vec![]));

        assert_eq!(
            store::list_refs(&bare).unwrap(),
            Vec::<(String, String)>::new(),
            "an empty (but present) snapshot must still roll back: the ref the \
             push created has to be deleted"
        );
    }

    /// Repo creation must be throttled by the per-IP creation limiter BEFORE
    /// signature verification — otherwise a DID farm (one throwaway did:key per
    /// repo, each carrying a valid but machine-solved iCaptcha proof) walks past
    /// the per-DID limiter and floods the network, as in the recurring spam-repo
    /// incidents. A 429 (not a 401) on an unsigned request from an exhausted IP
    /// proves the IP brake runs outermost, ahead of auth.
    #[sqlx::test]
    async fn repo_creation_is_rate_limited_by_ip(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::{Method, Request, StatusCode};
        use std::net::SocketAddr;
        use std::time::Duration;
        use tower::ServiceExt;

        let mut state = crate::test_support::test_state(pool).await;
        // Tiny limit, keyed on the socket peer (no trusted proxy).
        state.create_ip_rate_limiter =
            crate::rate_limit::RateLimiter::new(1, Duration::from_secs(60));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;

        let peer: SocketAddr = "203.0.113.77:7000".parse().unwrap();
        // Exhaust this peer's single-request budget up front.
        assert!(
            state
                .create_ip_rate_limiter
                .check(&peer.ip().to_string())
                .await
        );

        let router = crate::server::build_router(state);
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/repos")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"flood","is_public":true}"#))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));

        let status = router.oneshot(req).await.unwrap().status();
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "repo creation must be IP-throttled before signature verification"
        );
    }

    // Shared request driver for the per-IP write-brake tests below: build a
    // request with the given method/uri/headers/body, attach the socket peer as
    // ConnectInfo (what the IP limiter keys on), send it through the router, and
    // return the status. Mirrors post_from/post_with in rate_limit.rs.
    async fn send_from(
        router: &axum::Router,
        method: axum::http::Method,
        uri: &str,
        headers: &[(&str, &str)],
        body: axum::body::Body,
        peer: std::net::SocketAddr,
    ) -> axum::http::StatusCode {
        use tower::ServiceExt;
        let mut b = axum::http::Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let mut req = b.body(body).unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(peer));
        router.clone().oneshot(req).await.unwrap().status()
    }

    #[sqlx::test]
    async fn write_route_is_rate_limited_by_ip(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::http::{Method, StatusCode};
        use std::net::SocketAddr;
        use std::time::Duration;

        let mut state = crate::test_support::test_state(pool).await;
        // Tiny write bucket, keyed on the socket peer (no trusted proxy).
        state.write_rate_limiter = crate::rate_limit::RateLimiter::new(1, Duration::from_secs(60));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;

        let peer: SocketAddr = "203.0.113.88:7000".parse().unwrap();
        // Exhaust this peer's single-request write budget up front.
        assert!(state.write_rate_limiter.check(&peer.ip().to_string()).await);

        let router = crate::server::build_router(state);
        // A write_routes sink (star). The IP brake is outermost, so the 429
        // fires before auth/handler — the path only needs to match.
        let status = send_from(
            &router,
            Method::PUT,
            "/api/v1/repos/someowner/somerepo/star",
            &[],
            Body::empty(),
            peer,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "a write_routes sink must be IP-throttled before signature verification"
        );
    }

    // KTD-1: the write bucket is separate from the creation bucket, so a write
    // flood must not consume the creation budget (and vice versa).
    #[sqlx::test]
    async fn write_flood_does_not_drain_creation_budget(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::http::{Method, StatusCode};
        use std::net::SocketAddr;
        use std::time::Duration;

        let mut state = crate::test_support::test_state(pool).await;
        // Exhaust the write bucket for this peer; leave the creation bucket ample.
        state.write_rate_limiter = crate::rate_limit::RateLimiter::new(1, Duration::from_secs(60));
        state.create_ip_rate_limiter =
            crate::rate_limit::RateLimiter::new(1000, Duration::from_secs(60));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;

        let peer: SocketAddr = "203.0.113.99:7000".parse().unwrap();
        assert!(state.write_rate_limiter.check(&peer.ip().to_string()).await);

        let router = crate::server::build_router(state);

        // Anchor the test: prove the write bucket is genuinely drained at the
        // router (a write sink from this peer 429s) so the creation assertion
        // below cannot pass vacuously on some unrelated non-429 status.
        assert_eq!(
            send_from(
                &router,
                Method::PUT,
                "/api/v1/repos/someowner/somerepo/star",
                &[],
                Body::empty(),
                peer,
            )
            .await,
            StatusCode::TOO_MANY_REQUESTS,
            "write bucket must be drained for this peer (test precondition)"
        );

        // Creation from the same peer must NOT be 429 — its bucket is untouched.
        // (It fails later on missing signature; the point is it is not throttled.)
        let status = send_from(
            &router,
            Method::POST,
            "/api/v1/repos",
            &[("content-type", "application/json")],
            Body::from(r#"{"name":"legit","is_public":true}"#),
            peer,
        )
        .await;
        assert_ne!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "an exhausted write bucket must not throttle repo creation (separate buckets)"
        );
    }

    // KTD-5: /graphql POST (the MutationRoot surface) draws from the write bucket.
    #[sqlx::test]
    async fn graphql_post_is_rate_limited_by_ip(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::http::{Method, StatusCode};
        use std::net::SocketAddr;
        use std::time::Duration;

        let mut state = crate::test_support::test_state(pool).await;
        state.write_rate_limiter = crate::rate_limit::RateLimiter::new(1, Duration::from_secs(60));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;

        let peer: SocketAddr = "203.0.113.111:7000".parse().unwrap();
        assert!(state.write_rate_limiter.check(&peer.ip().to_string()).await);

        let router = crate::server::build_router(state);
        let status = send_from(
            &router,
            Method::POST,
            "/graphql",
            &[("content-type", "application/json")],
            Body::from(r#"{"query":"{ __typename }"}"#),
            peer,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "/graphql must be IP-throttled by the write brake"
        );
    }

    // Representative REST write group (issue comment) — same attachment as the
    // task/bounty/profile groups.
    #[sqlx::test]
    async fn issue_comment_is_rate_limited_by_ip(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::http::{Method, StatusCode};
        use std::net::SocketAddr;
        use std::time::Duration;

        let mut state = crate::test_support::test_state(pool).await;
        state.write_rate_limiter = crate::rate_limit::RateLimiter::new(1, Duration::from_secs(60));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;

        let peer: SocketAddr = "203.0.113.122:7000".parse().unwrap();
        assert!(state.write_rate_limiter.check(&peer.ip().to_string()).await);

        let router = crate::server::build_router(state);
        let status = send_from(
            &router,
            Method::POST,
            "/api/v1/repos/someowner/somerepo/issues/1/comments",
            &[("content-type", "application/json")],
            Body::from(r#"{"body":"flood"}"#),
            peer,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "issue-write routes must be IP-throttled by the write brake"
        );
    }

    // Adoption floor: an under-limit write must NOT be throttled. Guards against
    // an off-by-one that braked the first request (invisible to the 429 tests,
    // which all pre-exhaust the bucket).
    #[sqlx::test]
    async fn under_limit_write_is_not_throttled(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::http::{Method, StatusCode};
        use std::net::SocketAddr;
        use std::time::Duration;

        let mut state = crate::test_support::test_state(pool).await;
        // Ample budget; bucket NOT exhausted.
        state.write_rate_limiter =
            crate::rate_limit::RateLimiter::new(100, Duration::from_secs(60));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        let peer: SocketAddr = "203.0.113.150:7000".parse().unwrap();

        let router = crate::server::build_router(state);
        assert_ne!(
            send_from(
                &router,
                Method::PUT,
                "/api/v1/repos/someowner/somerepo/star",
                &[],
                Body::empty(),
                peer,
            )
            .await,
            StatusCode::TOO_MANY_REQUESTS,
            "an under-limit write must pass the brake, not be 429'd"
        );
    }

    // GITLAWB_WRITE_RATE_LIMIT=0 disables the brake end-to-end: no write is 429'd
    // however many arrive from one IP.
    #[sqlx::test]
    async fn write_rate_limit_zero_disables_the_brake(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::http::{Method, StatusCode};
        use std::net::SocketAddr;
        use std::time::Duration;

        let mut state = crate::test_support::test_state(pool).await;
        state.write_rate_limiter = crate::rate_limit::RateLimiter::new(0, Duration::from_secs(60));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        let peer: SocketAddr = "203.0.113.151:7000".parse().unwrap();

        let router = crate::server::build_router(state);
        for _ in 0..5 {
            assert_ne!(
                send_from(
                    &router,
                    Method::PUT,
                    "/api/v1/repos/someowner/somerepo/star",
                    &[],
                    Body::empty(),
                    peer,
                )
                .await,
                StatusCode::TOO_MANY_REQUESTS,
                "a 0 write limit must disable the brake"
            );
        }
    }

    // The task/bounty/profile write groups share the write brake (same
    // attachment as write_routes); prove each 429s at the route level.
    #[sqlx::test]
    async fn task_bounty_profile_writes_are_rate_limited(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::http::{Method, StatusCode};
        use std::net::SocketAddr;
        use std::time::Duration;

        let mut state = crate::test_support::test_state(pool).await;
        state.write_rate_limiter = crate::rate_limit::RateLimiter::new(1, Duration::from_secs(60));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        let peer: SocketAddr = "203.0.113.152:7000".parse().unwrap();
        assert!(state.write_rate_limiter.check(&peer.ip().to_string()).await);

        let router = crate::server::build_router(state);
        for (method, uri) in [
            (Method::POST, "/api/v1/tasks"),
            (Method::POST, "/api/v1/repos/o/r/bounties"),
            (Method::PUT, "/api/v1/profile"),
        ] {
            assert_eq!(
                send_from(
                    &router,
                    method,
                    uri,
                    &[("content-type", "application/json")],
                    Body::from("{}"),
                    peer,
                )
                .await,
                StatusCode::TOO_MANY_REQUESTS,
                "write group {uri} must be IP-throttled by the write brake"
            );
        }
    }

    // /graphql/ws (subscriptions) is deliberately mounted AFTER the write brake
    // layer, so it must stay unbraked even when the write bucket is exhausted.
    #[sqlx::test]
    async fn graphql_ws_is_not_braked(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::http::{Method, StatusCode};
        use std::net::SocketAddr;
        use std::time::Duration;

        let mut state = crate::test_support::test_state(pool).await;
        state.write_rate_limiter = crate::rate_limit::RateLimiter::new(1, Duration::from_secs(60));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        let peer: SocketAddr = "203.0.113.153:7000".parse().unwrap();
        assert!(state.write_rate_limiter.check(&peer.ip().to_string()).await);

        let router = crate::server::build_router(state);
        // Not a real ws upgrade, so the subscription service rejects it with some
        // non-429 status; the point is the write brake never sees it.
        assert_ne!(
            send_from(
                &router,
                Method::GET,
                "/graphql/ws",
                &[],
                Body::empty(),
                peer
            )
            .await,
            StatusCode::TOO_MANY_REQUESTS,
            "/graphql/ws must not be behind the write brake"
        );
    }

    // Adoption floor, per group: with an un-exhausted bucket, a write to EVERY
    // braked group passes the brake (reaches auth/handler), not 429. Guards each
    // group's grant path, not just the star representative.
    #[sqlx::test]
    async fn every_write_group_passes_under_limit(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::http::{Method, StatusCode};
        use std::net::SocketAddr;
        use std::time::Duration;

        let mut state = crate::test_support::test_state(pool).await;
        state.write_rate_limiter =
            crate::rate_limit::RateLimiter::new(100, Duration::from_secs(60));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        let peer: SocketAddr = "203.0.113.160:7000".parse().unwrap();

        let router = crate::server::build_router(state);
        for (method, uri) in [
            (Method::PUT, "/api/v1/repos/o/r/star"),
            (Method::POST, "/graphql"),
            (Method::POST, "/api/v1/repos/o/r/issues/1/comments"),
            (Method::POST, "/api/v1/tasks"),
            (Method::POST, "/api/v1/repos/o/r/bounties"),
            (Method::PUT, "/api/v1/profile"),
        ] {
            assert_ne!(
                send_from(
                    &router,
                    method,
                    uri,
                    &[("content-type", "application/json")],
                    Body::from(r#"{"query":"{ __typename }"}"#),
                    peer,
                )
                .await,
                StatusCode::TOO_MANY_REQUESTS,
                "under-limit write to {uri} must pass the brake, not 429"
            );
        }
    }

    // ── U6/R6: create_repo serializes against a same-key purge ───────────────

    // create_repo must take the SAME per-owner/name advisory lock the purge holds
    // (try_lock_repo / RepoLockGuard), so a create cannot slip into the purge's
    // delete-row -> [window] -> remove-dir gap and land a repos row pointing at a
    // directory the purge then removes (a dangling row). Deterministic form of the
    // race: hold the purge lock, then prove create BLOCKS on it rather than
    // proceeding into the window — it must not insert its row while the lock is
    // held, and must complete cleanly (row + on-disk dir both present) once the
    // lock frees. RED on base (create takes no lock): the row lands while the lock
    // is held. GREEN after (create serializes on the same key).
    #[sqlx::test]
    async fn create_repo_serializes_against_purge_lock(
        pool_opts: sqlx::postgres::PgPoolOptions,
        connect_opts: sqlx::postgres::PgConnectOptions,
    ) {
        use axum::extract::State;
        use axum::Extension;
        use std::time::Duration;

        // Multi-connection pool: while the purge guard pins one connection for the
        // held lock, create's own try_lock_repo attempt must get a DIFFERENT
        // connection and observe the advisory lock held (Ok(None) -> it retries),
        // not merely block on pool exhaustion.
        let pool = pool_opts
            .max_connections(5)
            .connect_with(connect_opts)
            .await
            .unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tempfile::TempDir::new().unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(
            repos_dir.path().to_path_buf(),
            pool.clone(),
        );

        let owner = "did:key:z6MkCreatePurgeRaceAAAAAAAAAAAAAAAAAAAAAAAA";
        let name = "racerepo";

        // The purge path holds this exact per-repo advisory lock across its
        // delete-row + remove-dir. Take it via the same helper the purge uses.
        let purge_guard = state
            .repo_store
            .try_lock_repo(owner, name)
            .await
            .unwrap()
            .expect("lock is free before the create");

        // Kick off a create for the SAME owner/name while the purge holds the lock.
        let state2 = state.clone();
        let owner2 = owner.to_string();
        let handle = tokio::spawn(async move {
            super::create_repo(
                State(state2),
                Extension(crate::auth::AuthenticatedDid(owner2)),
                axum::http::HeaderMap::new(),
                Json(CreateRepoRequest {
                    name: name.to_string(),
                    description: None,
                    is_public: true,
                    default_branch: "main".to_string(),
                }),
            )
            .await
        });

        // While the purge lock is held, create must NOT complete its init+insert.
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(
            state.db.get_repo(owner, name).await.unwrap().is_none(),
            "create_repo must not insert a repos row while a purge holds the same-key \
             lock (RED on base: create takes no lock and the row lands in the window)"
        );
        assert!(
            !handle.is_finished(),
            "create must be blocked on the purge lock, not have completed"
        );

        // Purge releases; create can now proceed and create cleanly.
        purge_guard.release().await;

        let created = tokio::time::timeout(Duration::from_secs(8), handle)
            .await
            .expect("create should finish once the lock frees")
            .expect("create task join")
            .expect("create_repo returns Ok once it wins the lock");
        assert_eq!(created.0, StatusCode::CREATED);

        // End state is consistent: the row AND its on-disk dir are both present —
        // never a row pointing at a removed directory.
        assert!(
            state.db.get_repo(owner, name).await.unwrap().is_some(),
            "repos row must be present after the create wins the lock"
        );
        let dir = repos_dir
            .path()
            .join(owner.replace([':', '/'], "_"))
            .join(format!("{name}.git"));
        assert!(
            dir.exists(),
            "the created repo's on-disk dir must be present — no dangling row"
        );
    }

    // U6 no-regression: with no concurrent purge, create_repo still succeeds and
    // leaves a consistent row + on-disk dir. Guards against the lock acquisition
    // wedging the uncontended hot path.
    #[sqlx::test]
    async fn create_repo_succeeds_without_lock_contention(
        pool_opts: sqlx::postgres::PgPoolOptions,
        connect_opts: sqlx::postgres::PgConnectOptions,
    ) {
        use axum::extract::State;
        use axum::Extension;

        let pool = pool_opts
            .max_connections(5)
            .connect_with(connect_opts)
            .await
            .unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tempfile::TempDir::new().unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(
            repos_dir.path().to_path_buf(),
            pool.clone(),
        );

        let owner = "did:key:z6MkCreateNoContendBBBBBBBBBBBBBBBBBBBBBBBB";
        let name = "solo";

        let created = super::create_repo(
            State(state.clone()),
            Extension(crate::auth::AuthenticatedDid(owner.to_string())),
            axum::http::HeaderMap::new(),
            Json(CreateRepoRequest {
                name: name.to_string(),
                description: None,
                is_public: true,
                default_branch: "main".to_string(),
            }),
        )
        .await
        .expect("uncontended create_repo must succeed");
        assert_eq!(created.0, StatusCode::CREATED);

        assert!(
            state.db.get_repo(owner, name).await.unwrap().is_some(),
            "row present after an uncontended create"
        );
        let dir = repos_dir
            .path()
            .join(owner.replace([':', '/'], "_"))
            .join(format!("{name}.git"));
        assert!(
            dir.exists(),
            "on-disk dir present after an uncontended create"
        );
    }

    // ── U3/R2/R4: fork tail, guarded span, publish only after durability ─────

    const FORK_SRC_OWNER: &str = "z6forksrcowner";
    const FORK_SRC_NAME: &str = "forksrc";

    /// Build a state whose repo_store AND config.repos_dir point at `repos_dir`
    /// (fork_repo computes its clone target from config.repos_dir, so the two
    /// must agree), seeded with a bare public source repo any caller may fork.
    async fn fork_test_state(
        repos_dir: &std::path::Path,
        repo_store: crate::git::repo_store::RepoStore,
        pool: sqlx::PgPool,
    ) -> AppState {
        let mut state = crate::test_support::test_state(pool).await;
        state.repo_store = repo_store;
        let mut cfg = (*state.config).clone();
        cfg.repos_dir = repos_dir.to_path_buf();
        state.config = std::sync::Arc::new(cfg);

        let bare = repos_dir
            .join(FORK_SRC_OWNER) // slug == owner: no ':' or '/' to replace
            .join(format!("{FORK_SRC_NAME}.git"));
        std::fs::create_dir_all(bare.parent().unwrap()).unwrap();
        let out = std::process::Command::new("git")
            .args(["init", "--bare", "-q", &bare.to_string_lossy()])
            .output()
            .unwrap();
        assert!(out.status.success(), "git init --bare failed");
        state
            .db
            .upsert_mirror_repo(
                FORK_SRC_OWNER,
                FORK_SRC_NAME,
                &bare.to_string_lossy(),
                None,
                false,
            )
            .await
            .unwrap();
        state
    }

    async fn call_fork(
        state: &AppState,
        forker: &str,
        fork_name: &str,
    ) -> Result<axum::response::Response> {
        use axum::extract::{Path as AxPath, State};
        use axum::response::IntoResponse;
        use axum::Extension;
        super::fork_repo(
            State(state.clone()),
            Extension(crate::auth::AuthenticatedDid(forker.to_string())),
            AxPath((FORK_SRC_OWNER.to_string(), FORK_SRC_NAME.to_string())),
            axum::http::HeaderMap::new(),
            Json(ForkRepoRequest {
                name: Some(fork_name.to_string()),
            }),
        )
        .await
        .map(|r| r.into_response())
    }

    // R2: fork must take the SAME per-owner/name advisory lock on its TARGET
    // namespace that purge and create hold, so it cannot interleave with a
    // purge's delete-row + remove-dir (or another creator) on that key.
    // Deterministic form: hold the target lock, prove the fork BLOCKS (no clone
    // dir, no repos row) rather than proceeding, then completes cleanly once the
    // lock frees. RED on base: fork takes no lock and completes in the window.
    #[sqlx::test]
    async fn fork_serializes_against_target_namespace_lock(
        pool_opts: sqlx::postgres::PgPoolOptions,
        connect_opts: sqlx::postgres::PgConnectOptions,
    ) {
        use std::time::Duration;

        // Multi-connection pool: the held guard pins one connection, so the
        // fork's own lock attempt must get a DIFFERENT one and observe the key
        // held (Ok(None) -> retry), not merely block on pool exhaustion.
        let pool = pool_opts
            .max_connections(5)
            .connect_with(connect_opts)
            .await
            .unwrap();
        let repos_dir = tempfile::TempDir::new().unwrap();
        let repo_store = crate::git::repo_store::RepoStore::for_testing(
            repos_dir.path().to_path_buf(),
            pool.clone(),
        );
        let state = fork_test_state(repos_dir.path(), repo_store, pool).await;

        let forker = "did:key:z6MkForkSerializeAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let fork_name = "serialfork";

        // A purge (or another creator) holds the fork target's advisory lock.
        let held = state
            .repo_store
            .try_lock_repo(forker, fork_name)
            .await
            .unwrap()
            .expect("target lock free before the fork");

        let state2 = state.clone();
        let forker2 = forker.to_string();
        let fork_name2 = fork_name.to_string();
        let handle = tokio::spawn(async move { call_fork(&state2, &forker2, &fork_name2).await });

        // While the target lock is held the fork must make no progress past it.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let clone_dir = store::repo_disk_path(&state.config.repos_dir, forker, fork_name);
        assert!(
            state
                .db
                .get_repo(forker, fork_name)
                .await
                .unwrap()
                .is_none(),
            "fork must not insert a repos row while the target-namespace lock is \
             held (RED on base: fork takes no lock and the row lands in the window)"
        );
        assert!(
            !clone_dir.exists(),
            "fork must not clone the mirror while the target-namespace lock is held"
        );
        assert!(
            !handle.is_finished(),
            "fork must be blocked on the target lock, not have completed"
        );

        held.release().await;
        let resp = tokio::time::timeout(Duration::from_secs(8), handle)
            .await
            .expect("fork should finish once the lock frees")
            .expect("fork task join")
            .expect("fork_repo returns Ok once it wins the lock");
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert!(
            state
                .db
                .get_repo(forker, fork_name)
                .await
                .unwrap()
                .is_some(),
            "repos row present after the fork wins the lock"
        );
        assert!(clone_dir.exists(), "cloned mirror present after the fork");
    }

    // R4: publish-after-durability. When the fork's durable upload stalls, the
    // fork must fail (5xx) within the release-upload bound, insert NO repos row,
    // and remove the half-created mirror from disk. RED on base: the foreground
    // upload's unbounded PUT hangs the handler on a stall (and an erroring
    // upload would return 201 + insert the row despite the failed upload).
    #[sqlx::test]
    async fn fork_durable_upload_failure_fails_before_row_insert(pool: sqlx::PgPool) {
        use axum::response::IntoResponse;
        use std::path::Path as StdPath;
        use std::time::Duration;

        // Object store whose upload() parks forever: the fork-tail upload bound
        // is the only thing that unblocks it. `exists()` is false so acquire
        // never downloads over the local source repo.
        struct StallStore;
        #[async_trait::async_trait]
        impl crate::git::tigris::ObjectStore for StallStore {
            async fn exists(&self, _o: &str, _r: &str) -> anyhow::Result<bool> {
                Ok(false)
            }
            async fn upload(&self, _o: &str, _r: &str, _p: &StdPath) -> anyhow::Result<()> {
                std::future::pending::<()>().await;
                Ok(())
            }
            async fn download(&self, _o: &str, _r: &str, _p: &StdPath) -> anyhow::Result<()> {
                Ok(())
            }
            async fn delete(&self, _o: &str, _r: &str) -> anyhow::Result<()> {
                Ok(())
            }
        }

        let repos_dir = tempfile::TempDir::new().unwrap();
        let repo_store = crate::git::repo_store::RepoStore::new(
            repos_dir.path().to_path_buf(),
            Some(std::sync::Arc::new(StallStore)),
            pool.clone(),
        )
        .with_release_upload_timeout(Duration::from_millis(200));
        let state = fork_test_state(repos_dir.path(), repo_store, pool).await;

        let forker = "did:key:z6MkForkUploadFailAAAAAAAAAAAAAAAAAAAAAAAAA";
        let fork_name = "failfork";

        let resp =
            tokio::time::timeout(Duration::from_secs(5), call_fork(&state, forker, fork_name))
                .await
                .expect(
                    "fork must fail within the upload bound when the durable upload \
             stalls (RED on base: the unbounded foreground PUT hangs the handler)",
                );
        let status = match resp {
            Ok(r) => r.status(),
            Err(e) => e.into_response().status(),
        };
        assert!(
            status.is_server_error(),
            "a failed durable upload must fail the fork (5xx); got {status}, \
             which the client trusts as a fork whose archive never landed"
        );

        // Publish-after-durability: no repos row for a fork with no archive.
        assert!(
            state
                .db
                .get_repo(forker, fork_name)
                .await
                .unwrap()
                .is_none(),
            "no repos row may exist for a fork whose durable upload failed"
        );
        let clone_dir = store::repo_disk_path(&state.config.repos_dir, forker, fork_name);
        assert!(
            !clone_dir.exists(),
            "the cloned mirror must be removed when the durable upload fails"
        );
    }

    // KTD-2 trap case (must-not-break negative): a store-less node has nothing
    // to upload, so fork succeeds exactly as today: "no object store" is
    // nothing-to-do, never a failed upload. GREEN both before and after the fix.
    #[sqlx::test]
    async fn fork_without_object_store_succeeds(pool: sqlx::PgPool) {
        let repos_dir = tempfile::TempDir::new().unwrap();
        let repo_store = crate::git::repo_store::RepoStore::for_testing(
            repos_dir.path().to_path_buf(),
            pool.clone(),
        );
        let state = fork_test_state(repos_dir.path(), repo_store, pool).await;

        let forker = "did:key:z6MkForkNoStoreAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let fork_name = "nostorefork";

        let resp = call_fork(&state, forker, fork_name)
            .await
            .expect("a store-less fork must succeed");
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert!(
            state
                .db
                .get_repo(forker, fork_name)
                .await
                .unwrap()
                .is_some(),
            "repos row present after a store-less fork"
        );
        let clone_dir = store::repo_disk_path(&state.config.repos_dir, forker, fork_name);
        assert!(clone_dir.exists(), "cloned mirror present after the fork");
    }

    // R2: a target lock held past the fork's bounded wait must surface as the
    // same retryable 503 create_repo returns, with no repos row and no clone
    // residue. RED on base: fork ignores the lock and completes with a 201.
    #[sqlx::test]
    async fn fork_lock_contention_returns_503(
        pool_opts: sqlx::postgres::PgPoolOptions,
        connect_opts: sqlx::postgres::PgConnectOptions,
    ) {
        use axum::response::IntoResponse;

        let pool = pool_opts
            .max_connections(5)
            .connect_with(connect_opts)
            .await
            .unwrap();
        let repos_dir = tempfile::TempDir::new().unwrap();
        let repo_store = crate::git::repo_store::RepoStore::for_testing(
            repos_dir.path().to_path_buf(),
            pool.clone(),
        );
        let state = fork_test_state(repos_dir.path(), repo_store, pool).await;

        let forker = "did:key:z6MkForkContendedAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let fork_name = "contendedfork";

        // Held for the whole test: the fork's bounded wait must give up.
        let held = state
            .repo_store
            .try_lock_repo(forker, fork_name)
            .await
            .unwrap()
            .expect("target lock free before the fork");

        let resp = call_fork(&state, forker, fork_name).await;
        let status = match resp {
            Ok(r) => r.status(),
            Err(e) => e.into_response().status(),
        };
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "a target lock held past the bounded wait must 503 like create_repo \
             (RED on base: fork ignores the lock and returns 201)"
        );
        assert!(
            state
                .db
                .get_repo(forker, fork_name)
                .await
                .unwrap()
                .is_none(),
            "no repos row after a 503'd fork"
        );
        let clone_dir = store::repo_disk_path(&state.config.repos_dir, forker, fork_name);
        assert!(!clone_dir.exists(), "no clone residue after a 503'd fork");
        held.release().await;
    }

    // Finding 1: forking a COLD source (archive-only, no local dir) must
    // materialize the source out from under the target lock, so it works even
    // when the write lock_pool is sized 1. On a cold source, acquire()'s
    // download takes a nested advisory lock on that SAME lock_pool for the
    // SOURCE's namespace; if the target lock (which pins the pool's one
    // connection) were held first, that nested acquire would find the pool
    // exhausted, PoolTimedOut -> the source publish degrades -> the source never
    // lands on disk -> the clone of a missing source fails the fork. RED on the
    // pre-reorder code (source acquire AFTER lock_repo_blocking): fork fails
    // with a 5xx at a size-1 lock pool. GREEN after: acquire runs before the
    // lock, so the two nested acquires never overlap.
    #[sqlx::test]
    async fn fork_cold_source_materializes_before_target_lock_at_pool_size_one(
        pool_opts: sqlx::postgres::PgPoolOptions,
        connect_opts: sqlx::postgres::PgConnectOptions,
    ) {
        use std::path::Path as StdPath;

        // An object store standing in for a cold source: exists() is always
        // true, and download() materializes a valid bare repo at the target path
        // (mirroring the real store's extract-then-swap), so acquire() publishes
        // the source on disk. upload() succeeds so the fork's own durable upload
        // is a no-op success.
        struct ColdMaterializeStore;
        #[async_trait::async_trait]
        impl crate::git::tigris::ObjectStore for ColdMaterializeStore {
            async fn exists(&self, _o: &str, _r: &str) -> anyhow::Result<bool> {
                Ok(true)
            }
            async fn upload(&self, _o: &str, _r: &str, _p: &StdPath) -> anyhow::Result<()> {
                Ok(())
            }
            async fn download(&self, _o: &str, _r: &str, p: &StdPath) -> anyhow::Result<()> {
                if p.exists() {
                    std::fs::remove_dir_all(p)?;
                }
                crate::git::store::init_bare(p)?;
                Ok(())
            }
            async fn delete(&self, _o: &str, _r: &str) -> anyhow::Result<()> {
                Ok(())
            }
        }

        // App pool for state.db (get_repo / proof.consume / create_repo), sized
        // generously so unrelated app work never contends. The hazard under test
        // is on the SEPARATE lock pool below.
        let app_pool = pool_opts
            .max_connections(5)
            .connect_with(connect_opts.clone())
            .await
            .unwrap();
        // The write lock_pool sized to ONE connection: a target lock plus an
        // overlapping source-namespace lock cannot both be satisfied from it, so
        // this size is exactly what surfaces the double-hold hazard.
        let lock_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(2))
            .min_connections(0)
            .connect_with(connect_opts)
            .await
            .unwrap();

        let repos_dir = tempfile::TempDir::new().unwrap();
        let repo_store = crate::git::repo_store::RepoStore::new(
            repos_dir.path().to_path_buf(),
            Some(std::sync::Arc::new(ColdMaterializeStore)),
            lock_pool,
        );

        // Build state WITHOUT creating the source bare on disk: the source lives
        // only in the object store, so acquire() must download it. (fork_test_state
        // would materialize it locally, which is the warm path, not this one.)
        let mut state = crate::test_support::test_state(app_pool).await;
        state.repo_store = repo_store;
        let mut cfg = (*state.config).clone();
        cfg.repos_dir = repos_dir.path().to_path_buf();
        state.config = std::sync::Arc::new(cfg);
        state
            .db
            .upsert_mirror_repo(
                FORK_SRC_OWNER,
                FORK_SRC_NAME,
                "unused-cold-path",
                None,
                false,
            )
            .await
            .unwrap();
        // The source must NOT be on local disk, or acquire takes the warm path
        // and never exercises the cold download + nested lock.
        let src_local =
            store::repo_disk_path(&state.config.repos_dir, FORK_SRC_OWNER, FORK_SRC_NAME);
        assert!(!src_local.exists(), "source must be cold (absent locally)");

        let forker = "did:key:z6MkForkColdSrcAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let fork_name = "coldfork";

        let resp = call_fork(&state, forker, fork_name)
            .await
            .expect("cold-source fork must succeed at a size-1 lock pool");
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert!(
            state
                .db
                .get_repo(forker, fork_name)
                .await
                .unwrap()
                .is_some(),
            "repos row present after the cold-source fork"
        );
        let clone_dir = store::repo_disk_path(&state.config.repos_dir, forker, fork_name);
        assert!(
            clone_dir.exists(),
            "cloned mirror present after the cold-source fork"
        );
    }

    // Finding 1: a `git clone --mirror` that exits non-zero after the dest dir
    // exists must clear that dest and free the lock, so a retry of the same fork
    // name is not permanently blocked by a leftover half-mirror. Driven by
    // pre-seeding the dest so the clone fails "destination already exists"
    // (exit 128, the `!output.status.success()` arm, not the timeout/spawn
    // arms). RED on base: the arm returns without removing the dest, so the dest
    // survives and the second fork's clone fails the same way (5xx forever).
    #[sqlx::test]
    async fn fork_nonzero_clone_exit_cleans_dest_and_allows_retry(pool: sqlx::PgPool) {
        let repos_dir = tempfile::TempDir::new().unwrap();
        let repo_store = crate::git::repo_store::RepoStore::for_testing(
            repos_dir.path().to_path_buf(),
            pool.clone(),
        );
        let state = fork_test_state(repos_dir.path(), repo_store, pool).await;

        let forker = "did:key:z6MkForkCloneNonzeroAAAAAAAAAAAAAAAAAAAAAA";
        let fork_name = "nonzerofork";

        // Seed the dest as a non-empty dir so `git clone --mirror` refuses it and
        // exits 128, standing in for a half-created mirror a prior failed clone
        // (authz, corrupt source) would leave behind.
        let clone_dir = store::repo_disk_path(&state.config.repos_dir, forker, fork_name);
        std::fs::create_dir_all(&clone_dir).unwrap();
        std::fs::write(clone_dir.join("stale.txt"), b"half-created mirror").unwrap();

        let resp = call_fork(&state, forker, fork_name).await;
        let status = match resp {
            Ok(r) => r.status(),
            Err(e) => {
                use axum::response::IntoResponse;
                e.into_response().status()
            }
        };
        assert!(
            status.is_server_error(),
            "a non-zero clone exit must fail the fork (5xx); got {status}"
        );
        assert!(
            !clone_dir.exists(),
            "the leftover dest must be removed after a non-zero clone exit \
             (RED on base: the !success arm leaves it, blocking every retry)"
        );

        // The dest is clean and the lock freed, so re-forking the same name now
        // clones fresh and succeeds.
        let resp2 = call_fork(&state, forker, fork_name)
            .await
            .expect("a retry after the dest is cleaned must succeed");
        assert_eq!(resp2.status(), StatusCode::CREATED);
        assert!(
            state
                .db
                .get_repo(forker, fork_name)
                .await
                .unwrap()
                .is_some(),
            "repos row present after the successful retry"
        );
        assert!(clone_dir.exists(), "cloned mirror present after the retry");
    }

    // Finding 2: when the row insert fails AFTER the durable upload landed, the
    // fork must roll back BOTH the on-disk mirror and the just-uploaded archive,
    // so no orphaned dest blocks a retry and no stale archive can be downloaded
    // into a later same-key repo. The insert failure is injected deterministically
    // via the `disk_path UNIQUE` constraint: a decoy row occupying the fork's
    // exact disk_path passes the owner+name conflict guard (different owner/name)
    // yet collides on insert, which happens only after upload_under_guard. RED on
    // base: the `?` short-circuits, leaving the mirror dir and the archive behind.
    #[sqlx::test]
    async fn fork_row_insert_failure_rolls_back_mirror_and_archive(pool: sqlx::PgPool) {
        use axum::response::IntoResponse;
        use std::path::Path as StdPath;
        use std::sync::{Arc, Mutex};

        // Store double that uploads OK and records/removes the archive key so the
        // test can assert the rollback deleted it. exists() is false so acquire
        // never downloads over the local source.
        type Archives = Arc<Mutex<std::collections::HashSet<(String, String)>>>;
        struct TrackingStore {
            archives: Archives,
        }
        #[async_trait::async_trait]
        impl crate::git::tigris::ObjectStore for TrackingStore {
            async fn exists(&self, _o: &str, _r: &str) -> anyhow::Result<bool> {
                Ok(false)
            }
            async fn upload(&self, o: &str, r: &str, _p: &StdPath) -> anyhow::Result<()> {
                self.archives
                    .lock()
                    .unwrap()
                    .insert((o.to_string(), r.to_string()));
                Ok(())
            }
            async fn download(&self, _o: &str, _r: &str, _p: &StdPath) -> anyhow::Result<()> {
                Ok(())
            }
            async fn delete(&self, o: &str, r: &str) -> anyhow::Result<()> {
                self.archives
                    .lock()
                    .unwrap()
                    .remove(&(o.to_string(), r.to_string()));
                Ok(())
            }
        }

        let archives: Archives = Arc::new(Mutex::new(std::collections::HashSet::new()));
        let repos_dir = tempfile::TempDir::new().unwrap();
        let repo_store = crate::git::repo_store::RepoStore::new(
            repos_dir.path().to_path_buf(),
            Some(Arc::new(TrackingStore {
                archives: archives.clone(),
            })),
            pool.clone(),
        );
        let state = fork_test_state(repos_dir.path(), repo_store, pool).await;

        let forker = "did:key:z6MkForkInsertFailAAAAAAAAAAAAAAAAAAAAAAAAA";
        let fork_name = "insertfailfork";
        // The store keys on the slugified owner DID (`:`/`/` -> `_`), the same
        // transform local_path applies. Track the FORK's archive specifically:
        // the source repo is independently (re)uploaded via the read acquire, so
        // the set is not empty even when the fork's archive is correctly rolled
        // back.
        let fork_archive = (forker.replace([':', '/'], "_"), fork_name.to_string());

        // Pre-insert a decoy row that occupies the fork's exact disk_path but has
        // a different owner/name, so the fork's own insert violates disk_path's
        // UNIQUE constraint. get_repo(forker, fork_name) still returns None, so the
        // handler proceeds past its conflict guard, clones, and uploads first.
        let clone_dir = store::repo_disk_path(&state.config.repos_dir, forker, fork_name);
        let now = Utc::now();
        let decoy = crate::db::RepoRecord {
            id: Uuid::new_v4().to_string(),
            name: "decoyname".to_string(),
            owner_did: "did:key:z6MkDecoyOwnerBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
            description: None,
            is_public: true,
            default_branch: "main".to_string(),
            created_at: now,
            updated_at: now,
            disk_path: clone_dir.to_string_lossy().to_string(),
            forked_from: None,
            machine_id: None,
        };
        state.db.create_repo(&decoy).await.unwrap();

        let resp = call_fork(&state, forker, fork_name).await;
        let status = match resp {
            Ok(r) => r.status(),
            Err(e) => e.into_response().status(),
        };
        assert!(
            status.is_server_error(),
            "a row-insert failure must fail the fork (5xx); got {status}"
        );
        assert!(
            state
                .db
                .get_repo(forker, fork_name)
                .await
                .unwrap()
                .is_none(),
            "no fork row may exist after the insert failure"
        );
        assert!(
            !clone_dir.exists(),
            "the cloned mirror must be removed after the failed insert \
             (RED on base: the `?` short-circuits and leaves it)"
        );
        assert!(
            !archives.lock().unwrap().contains(&fork_archive),
            "the uploaded fork archive must be deleted after the failed insert \
             (RED on base: the archive is orphaned)"
        );

        // The target lock must be free again for a retry.
        let probe = state
            .repo_store
            .try_lock_repo(forker, fork_name)
            .await
            .unwrap()
            .expect("target lock freed after the rolled-back fork");
        probe.release().await;

        // Remove the decoy so the retry's insert can land, then re-fork the same
        // name: dest is clean, lock is free, and the archive is re-uploaded.
        state.db.delete_repo_by_id(&decoy.id).await.unwrap();
        let resp2 = call_fork(&state, forker, fork_name)
            .await
            .expect("a retry after the rollback must succeed");
        assert_eq!(resp2.status(), StatusCode::CREATED);
        assert!(
            state
                .db
                .get_repo(forker, fork_name)
                .await
                .unwrap()
                .is_some(),
            "repos row present after the successful retry"
        );
        assert!(
            archives.lock().unwrap().contains(&fork_archive),
            "the retry re-uploads the fork archive"
        );
    }

    // create_repo must NOT take its serialization lock from the APP pool. Doing so
    // pins an app-pool connection in the lock guard while the create's own work
    // (get_repo / proof.consume / db.create_repo, all on state.db = the app pool)
    // still needs an app connection. At GITLAWB_DB_MAX_CONNECTIONS=1 (a supported
    // config) the guard holds the only app connection and get_repo self-deadlocks
    // (PoolTimedOut -> 500). Locking on the separate write lock_pool instead keeps
    // the lock and the work on different pools, so a size-1 app pool never wedges.
    // RED on the app-pool-lock code: create times out -> Err. GREEN after reverting
    // create to lock on lock_pool.
    #[sqlx::test]
    async fn create_repo_does_not_self_deadlock_at_one_app_connection(
        pool_opts: sqlx::postgres::PgPoolOptions,
        connect_opts: sqlx::postgres::PgConnectOptions,
    ) {
        use axum::extract::State;
        use axum::Extension;
        use std::time::Duration;

        // Migrate the per-test DB on a normal pool: `migrate()` pins one connection for
        // its cross-process advisory lock while applying statements on a second, so it
        // needs >1 connection and cannot itself run on the size-1 pool under test.
        let migrate_pool = pool_opts.connect_with(connect_opts.clone()).await.unwrap();
        let mut state = crate::test_support::test_state(migrate_pool).await;

        // Now point state.db at an APP pool of MAX size 1 on the SAME database, the
        // minimal supported config (GITLAWB_DB_MAX_CONNECTIONS=1). The schema is
        // already applied, so this pool only serves create's work (get_repo -> insert).
        // A short acquire timeout makes the RED case (the lock guard pinning this one
        // connection while get_repo waits for another) fail fast instead of hanging.
        let app_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(2))
            .connect_with(connect_opts.clone())
            .await
            .unwrap();
        state.db = std::sync::Arc::new(crate::db::Db::for_testing(app_pool.clone()));

        // A SEPARATE write lock pool (where create's serialization lock belongs). Its
        // being separate is the whole point: the lock guard must not draw from the app
        // pool the create work runs on.
        let lock_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect_with(connect_opts.clone())
            .await
            .unwrap();
        let repos_dir = tempfile::TempDir::new().unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(
            repos_dir.path().to_path_buf(),
            lock_pool.clone(),
        );

        let owner = "did:key:z6MkOneAppConnNoDeadlockDDDDDDDDDDDDDDDDDDDD";
        let name = "solo";
        let created = super::create_repo(
            State(state.clone()),
            Extension(crate::auth::AuthenticatedDid(owner.to_string())),
            axum::http::HeaderMap::new(),
            Json(CreateRepoRequest {
                name: name.to_string(),
                description: None,
                is_public: true,
                default_branch: "main".to_string(),
            }),
        )
        .await
        .expect("create must not self-deadlock at app-pool size 1 (lock on lock_pool)");
        assert_eq!(created.0, StatusCode::CREATED);
        assert!(
            state.db.get_repo(owner, name).await.unwrap().is_some(),
            "row present after a create with a size-1 app pool"
        );
    }
}
