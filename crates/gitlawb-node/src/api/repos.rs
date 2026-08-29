use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Json;
use bytes::Bytes;
use std::sync::Arc;

use crate::auth::{caller_authorized_to_push, AuthenticatedDid};
use crate::db::RepoRecord;
use chrono::{DateTime, Utc};
use gitlawb_core::node_denial::NodeDenial;
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
            if !state.push_rate_limiter.check(&key).await {
                tracing::warn!(repo = %name, key = %key, "receive-pack advertisement rate limited");
                return Err(AppError::TooManyRequests(
                    "push rate limit exceeded — try again later".into(),
                ));
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

/// How hard the sender retries a peer that says "not now".
///
/// Passed in rather than read from a constant so the tests can pin the attempt
/// counts without sleeping for real seconds (tokio's `start_paused` needs the
/// `test-util` feature, which this crate does not carry).
struct NotifyRetryPolicy {
    /// Backoff before each retry. The length IS the retry count, so a ref gets
    /// `backoff.len() + 1` attempts.
    backoff: &'static [std::time::Duration],
    /// Total time one peer's whole fan-out may spend sleeping between
    /// retries, shared across every ref in the push.
    ///
    /// A per-ref bound alone is not enough: a `git push --mirror` of 600
    /// branches fans out 600 requests, so a per-ref budget multiplies by the
    /// ref count and would keep the background task alive against a wedged
    /// peer for hours. With a shared budget the whole fan-out adds at most
    /// this much wall clock, however wide the push.
    ///
    /// The tradeoff, stated plainly because it is not obvious from the code:
    /// the budget is spent first-come, so on a peer rejecting every ref the
    /// first ~10 failing refs consume all of it and every later ref gets a
    /// single attempt with no retry at all. That is deliberate — retries are
    /// worth most on a peer that is briefly rejecting and worth nothing on one
    /// that is rejecting everything, and the alternative (dividing the budget
    /// by the ref count) would make each share too small to ride out anything.
    /// Refs that do not land are reported, not silently dropped.
    budget: std::time::Duration,
}

/// Backoff before each retry of a retryable `/sync/notify` rejection.
const NOTIFY_RETRY_BACKOFF: [std::time::Duration; 2] = [
    std::time::Duration::from_secs(1),
    std::time::Duration::from_secs(5),
];

/// Production retry policy for the peer sync fan-out. 60s is the total sleep
/// budget shared across every peer in one push's fan-out, not per peer, so an
/// attacker-fillable peer set cannot multiply retry wall clock.
const NOTIFY_RETRY_POLICY: NotifyRetryPolicy = NotifyRetryPolicy {
    backoff: &NOTIFY_RETRY_BACKOFF,
    budget: std::time::Duration::from_secs(60),
};

/// What a peer's response status says the sender should do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotifyDisposition {
    Delivered,
    /// The peer did not apply the update and said "not now". Re-sending is
    /// safe because `sign_request` mints a fresh nonce per attempt, so the
    /// retry carries a signature the peer's ledger has never seen.
    Retryable,
    /// Anything else, including 409 `signature_replayed`: the peer already
    /// admitted this signed request, so re-sending risks a duplicate apply.
    Fatal,
}

/// Classify a peer's `/sync/notify` response.
///
/// The gate is the peer's `X-Gitlawb-Error` code, not the status. Only two
/// codes mean "the write did not happen and another attempt can clear it":
/// `signature_ledger_full` (the per-identity spent-signature cap, which drains
/// as entries expire) and `signature_ledger_unavailable`. Everything else is
/// `Fatal`, including a 429 or 503 carrying any other code and one carrying no
/// code at all.
///
/// Status alone is not enough because the peer's per-client flood brake answers
/// 429 on this route too, and on a peer running the default config (where
/// `require_signed_peer_writes` is off) `/sync/notify` never reaches the ledger
/// at all — so every 429 the sender can see is the brake. Retrying that spends
/// the whole budget on the one class it can never recover from (the brake's
/// window is an hour, the budget is a minute) while pushing the sender further
/// into the peer's peer-write bucket, which `/peers/announce` shares.
///
/// The status still has to agree with the code, so a stray `signature_ledger_full`
/// header on a 409 cannot turn "the peer already applied this" into a retry.
/// The result of one `/sync/notify` attempt, with the reason kept for the
/// end-of-fan-out summary.
#[must_use]
enum NotifyAttempt {
    Delivered,
    Retryable(String),
    Fatal(String),
}

fn classify_notify_status(status: reqwest::StatusCode, code: Option<&str>) -> NotifyDisposition {
    if status.is_success() {
        return NotifyDisposition::Delivered;
    }
    // `from_code` rather than string literals: this is the second consumer of
    // the same wire vocabulary as `gl`, with the same drift exposure, and the
    // enum is what makes a new code a compile error rather than a silent miss.
    match code.and_then(NodeDenial::from_code) {
        Some(denial @ (NodeDenial::LedgerFull | NodeDenial::LedgerUnavailable))
            if status.as_u16() == denial.status() =>
        {
            NotifyDisposition::Retryable
        }
        _ => NotifyDisposition::Fatal,
    }
}

/// Send one signed `/sync/notify` request for a single ref update.
///
/// The receiver is single-ref, so a multi-ref push fans out one request per
/// ref — each signed over its own body — carrying that ref's real `old_sha`.
///
/// One attempt only. Whether a failure is worth another attempt is the
/// caller's call, because the retry budget is shared across the whole fan-out.
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
) -> NotifyAttempt {
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
            return NotifyAttempt::Fatal(format!("body not serializable: {e}"));
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
        Ok(r) => {
            let status = r.status();
            let peer_code = crate::api::peers::peer_error_code(r.headers());
            let code = peer_code.unwrap_or("none").to_string();
            match classify_notify_status(status, peer_code) {
                NotifyDisposition::Delivered => {
                    tracing::info!(peer = %peer_did, repo = %repo_slug, ref_name = %ref_name, "notified peer to sync");
                    NotifyAttempt::Delivered
                }
                NotifyDisposition::Retryable => {
                    tracing::warn!(peer = %peer_did, ref_name = %ref_name, status = %status, error_code = %code, "peer sync notify returned error");
                    NotifyAttempt::Retryable(format!("{status} {code}"))
                }
                NotifyDisposition::Fatal => {
                    tracing::warn!(peer = %peer_did, ref_name = %ref_name, status = %status, error_code = %code, "peer sync notify returned error");
                    NotifyAttempt::Fatal(format!("{status} {code}"))
                }
            }
        }
        // A transport error is never retried: the request may well have
        // reached the peer and been applied, with only the response lost, and
        // re-sending a mutation on that guess is exactly what the spent
        // signature ledger exists to stop.
        Err(e) => {
            tracing::warn!(peer = %peer_did, ref_name = %ref_name, err = %e, "failed to notify peer");
            NotifyAttempt::Fatal(format!("transport error: {e}"))
        }
    }
}

/// What one peer's fan-out achieved. The refs that never landed are named
/// rather than merely counted, so the summary log and the tests are reading the
/// same fact: a ref the peer rejected past the bound is reported unfederated,
/// not quietly dropped.
#[derive(Debug, Default, PartialEq, Eq)]
struct FanOutSummary {
    total: usize,
    unfederated: Vec<String>,
    /// Why the last failing ref failed, as `"<status> <code>"` or a transport
    /// message. Empty when nothing failed.
    last_reason: String,
}

/// Notify a single peer of every ref in a push — one request per ref.
///
/// Looping here (rather than sending one flattened request) is what keeps a
/// multi-ref push from collapsing to its first ref; each ref carries its real
/// `old_sha`.
///
/// Because every request in the fan-out is signed by the same node keypair, a
/// peer that requires signed peer writes charges them all to one identity, so a
/// ref the peer is briefly rejecting with `signature_ledger_full` is worth
/// another attempt: `sign_request` draws a fresh nonce per attempt, so the
/// retry carries a signature the peer has never seen rather than a replay.
///
/// What the retry does NOT solve is a wide push against a peer whose ledger cap
/// is genuinely exceeded (`git push --mirror` of hundreds of branches against a
/// few-hundred-row cap with minutes of retention). There the rejection clears
/// only when the window ages out, which is longer than the whole fan-out's
/// budget, so those refs do not federate however many times they are retried.
/// They are counted and reported in one summary line — a per-ref warning inside
/// a 600-ref loop is not something an operator will ever correlate back to the
/// push — and returned to the caller so a test can assert on them.
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
    retry: &NotifyRetryPolicy,
    shared_sleep_budget: &mut std::time::Duration,
) -> FanOutSummary {
    let mut failed: Vec<&str> = Vec::new();
    let mut last_reason = String::new();

    for (ref_name, old_sha, new_sha) in ref_updates {
        let mut attempt = 0usize;
        loop {
            let outcome = notify_peer_of_ref(
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

            let reason = match outcome {
                NotifyAttempt::Delivered => break,
                NotifyAttempt::Fatal(reason) => reason,
                NotifyAttempt::Retryable(reason) => {
                    // Two bounds, both required. `backoff` caps the attempts
                    // for this ref; `shared_sleep_budget` caps the sleeping for
                    // the whole fan-out across every peer and ref. Either one
                    // running out ends this ref here.
                    match retry.backoff.get(attempt) {
                        Some(&wait) if wait <= *shared_sleep_budget => {
                            *shared_sleep_budget -= wait;
                            attempt += 1;
                            tokio::time::sleep(wait).await;
                            continue;
                        }
                        _ => reason,
                    }
                }
            };
            failed.push(ref_name);
            last_reason = reason;
            break;
        }
    }

    if !failed.is_empty() {
        tracing::warn!(
            peer = %peer_did,
            repo = %repo_slug,
            failed = failed.len(),
            total = ref_updates.len(),
            first_failed_ref = %failed[0],
            last_reason = %last_reason,
            "refs failed to federate to peer; they will not be retried again"
        );
    }

    FanOutSummary {
        total: ref_updates.len(),
        unfederated: failed.into_iter().map(str::to_string).collect(),
        last_reason,
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
    let guard = state
        .repo_store
        .acquire_write(&record.owner_did, &record.name)
        .await
        .map_err(|e| {
            tracing::error!(repo = %name, err = %e, "acquire_write failed");
            AppError::Git(e.to_string())
        })?;
    let disk_path = guard.path().to_path_buf();
    tracing::debug!(repo = %name, path = %disk_path.display(), "running git receive-pack");
    let body_len = body.len();
    let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);
    let receive_result = smart_http::receive_pack(&disk_path, body, git_timeout).await;

    // Always release the advisory lock — even on error — to prevent stale locks
    // from blocking subsequent pushes. Only upload to Tigris when the push
    // succeeded; uploading a half-applied repo would propagate corruption.
    guard.release(receive_result.is_ok()).await;

    let result = receive_result.map_err(|e| {
        let app = git_service_app_error(&e);
        match &app {
            AppError::Timeout(_) => tracing::warn!(repo = %name, "git receive-pack timed out"),
            AppError::BadRequest(msg) => {
                tracing::warn!(repo = %name, err = %msg, "git receive-pack: bad client request")
            }
            _ => tracing::error!(repo = %name, err = %e, "git receive-pack failed"),
        }
        app
    })?;

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
            if let Some(rules) = rules_for_enc.filter(|r| visibility_pack::has_path_scoped_rule(r))
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
            let cid_map: std::collections::HashMap<String, String> = pinned.into_iter().collect();

            // Record branch→CID for each ref update and publish gossip
            for (ref_name, old_sha, new_sha) in &ref_updates_clone {
                let cid = cid_map.get(new_sha).map(|s| s.as_str());

                if let Some(cid_str) = cid {
                    let _ = db_clone
                        .upsert_branch_cid(&repo_slug, ref_name, new_sha, cid_str, &node_did_str)
                        .await;
                }

                if announce {
                    if let Some(p2p) = &p2p_handle {
                        p2p.publish_ref_update(crate::p2p::RefUpdateEvent {
                            node_did: node_did_str.clone(),
                            pusher_did: pusher_did_clone.clone(),
                            repo: repo_slug.clone(),
                            owner_did: Some(record.owner_did.clone()),
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
                        ref_name: ref_name.clone(),
                        old_sha: old_sha.clone(),
                        new_sha: new_sha.clone(),
                        pusher_did: pusher_did_clone.clone(),
                        node_did: node_did_str.clone(),
                        timestamp: now_ts.clone(),
                        owner_did: record.owner_did.clone(),
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
                    match crate::arweave::anchor_ref_update(&http_client, &irys_url, &anchor).await
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
                        Err(e) => tracing::warn!(repo=%repo_slug, err=%e, "Arweave anchor failed"),
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
                    let mut shared_retry_sleep = NOTIFY_RETRY_POLICY.budget;
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
                            &NOTIFY_RETRY_POLICY,
                            &mut shared_retry_sleep,
                        )
                        .await;
                    }
                }
            }
        });
    }

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

    // Check no name conflict under the forker's ownership
    let forker_short = crate::db::normalize_owner_key(&forker_did);
    if state.db.get_repo(forker_short, &fork_name).await?.is_some() {
        return Err(AppError::BadRequest(format!(
            "you already have a repo named {fork_name}"
        )));
    }

    // Request is admissible — spend the proof now, immediately before the write.
    let verified_proof = proof.consume(&state.db).await?;

    // Ensure source repo is on local disk (downloads from Tigris on cache miss)
    let source_path = state
        .repo_store
        .acquire(&source.owner_did, &source.name)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;

    let disk_path = store::repo_disk_path(&state.config.repos_dir, &forker_did, &fork_name);

    // Clone the source repo as a mirror
    let output = std::process::Command::new("git")
        .args([
            "clone",
            "--mirror",
            source_path.to_str().unwrap_or(""),
            disk_path.to_str().unwrap_or(""),
        ])
        .output()
        .map_err(|e| AppError::Git(format!("git clone --mirror failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::Git(format!(
            "git clone --mirror failed: {stderr}"
        )));
    }

    // Upload fork to Tigris
    state
        .repo_store
        .release_after_write(&forker_did, &fork_name)
        .await;

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

    state.db.create_repo(&record).await?;

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

    #[allow(clippy::too_many_arguments)]
    async fn notify_peer_with_budget(
        http_client: &reqwest::Client,
        node_keypair: &Keypair,
        peer_did: &str,
        notify_url: &str,
        repo_slug: &str,
        ref_updates: &[(String, String, String)],
        node_did: &str,
        pusher_did: &str,
        owner_did: &str,
        retry: &NotifyRetryPolicy,
    ) -> FanOutSummary {
        let mut sleep_budget = retry.budget;
        notify_peer_of_refs(
            http_client,
            node_keypair,
            peer_did,
            notify_url,
            repo_slug,
            ref_updates,
            node_did,
            pusher_did,
            owner_did,
            retry,
            &mut sleep_budget,
        )
        .await
    }

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

        notify_peer_with_budget(
            &http_client,
            &keypair,
            "did:key:zPeer",
            &notify_url,
            "owner/repo",
            &ref_updates,
            "did:key:zNode",
            "did:key:zPusher",
            "did:key:zOwner",
            &NOTIFY_RETRY_POLICY,
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

        notify_peer_with_budget(
            &http_client,
            &keypair,
            "did:key:zPeer",
            &notify_url,
            "owner/repo",
            &ref_updates,
            "did:key:zNode",
            "did:key:zPusher",
            "did:key:zOwner",
            &NOTIFY_RETRY_POLICY,
        )
        .await;

        _mock.assert_async().await;
    }

    // ── retry of a retryable peer rejection ──────────────────────────────
    //
    // A peer running signed peer writes charges every /sync/notify against a
    // per-identity spent-signature ledger. A wide push fans out one signed
    // request per ref under the same node identity, so the tail of a large
    // push hits the cap and gets 429 signature_ledger_full, a retryable rate
    // condition. Without a sending-side retry those refs never federate.
    //
    // The tests drive a millisecond-scale policy so they pin the attempt
    // counts without sleeping for real seconds; the production numbers are
    // pinned separately by notify_retry_policy_bound_is_what_we_think.

    const FAST_BACKOFF: [std::time::Duration; 2] = [
        std::time::Duration::from_millis(5),
        std::time::Duration::from_millis(10),
    ];

    /// Same shape as the production policy (two retries), budgeted for exactly
    /// two fully retried refs.
    const FAST_POLICY: NotifyRetryPolicy = NotifyRetryPolicy {
        backoff: &FAST_BACKOFF,
        budget: std::time::Duration::from_millis(30),
    };

    fn refs(n: usize) -> Vec<(String, String, String)> {
        (0..n)
            .map(|i| {
                (
                    format!("refs/heads/b{i}"),
                    format!("{i:040x}"),
                    format!("{:040x}", i + 100),
                )
            })
            .collect()
    }

    // The production bound is a real operational number, so state it once here
    // rather than leave it implied by constants nobody reads.
    #[test]
    fn notify_retry_policy_bound_is_what_we_think() {
        assert_eq!(
            NOTIFY_RETRY_BACKOFF.len() + 1,
            3,
            "one send plus two retries per ref"
        );
        assert_eq!(NOTIFY_RETRY_POLICY.backoff, &NOTIFY_RETRY_BACKOFF);
        let per_ref: u64 = NOTIFY_RETRY_BACKOFF.iter().map(|d| d.as_secs()).sum();
        assert_eq!(per_ref, 6, "1s + 5s of backoff per retried ref");
        assert_eq!(
            NOTIFY_RETRY_POLICY.budget.as_secs(),
            60,
            "the whole fan-out across every peer adds at most one minute of retry sleep"
        );
    }

    // Retry sleep budget is shared across peers in one push fan-out, not minted
    // fresh per announced peer.
    #[tokio::test]
    async fn notify_fanout_retry_budget_is_shared_across_peers() {
        let mut server_a = mockito::Server::new_async().await;
        let mut server_b = mockito::Server::new_async().await;
        let keypair = Keypair::generate();
        let http_client = reqwest::Client::new();

        let mock_a = server_a
            .mock("POST", SYNC_NOTIFY_PATH)
            .with_status(429)
            .with_header("x-gitlawb-error", "signature_ledger_full")
            .expect(6)
            .create_async()
            .await;
        let mock_b = server_b
            .mock("POST", SYNC_NOTIFY_PATH)
            .with_status(429)
            .with_header("x-gitlawb-error", "signature_ledger_full")
            .expect(1)
            .create_async()
            .await;

        let mut shared_sleep = FAST_POLICY.budget;
        notify_peer_of_refs(
            &http_client,
            &keypair,
            "did:key:zPeerA",
            &format!("{}{SYNC_NOTIFY_PATH}", server_a.url()),
            "owner/repo",
            &refs(2),
            "did:key:zNode",
            "did:key:zPusher",
            "did:key:zOwner",
            &FAST_POLICY,
            &mut shared_sleep,
        )
        .await;
        notify_peer_of_refs(
            &http_client,
            &keypair,
            "did:key:zPeerB",
            &format!("{}{SYNC_NOTIFY_PATH}", server_b.url()),
            "owner/repo",
            &refs(1),
            "did:key:zNode",
            "did:key:zPusher",
            "did:key:zOwner",
            &FAST_POLICY,
            &mut shared_sleep,
        )
        .await;

        mock_a.assert_async().await;
        mock_b.assert_async().await;
    }

    // 429 twice then 200: a peer whose ledger rejection clears within the
    // budget does federate, and the attempt count is pinned so the bound
    // cannot silently grow.
    //
    // This proves the TRANSIENT case only. It is not evidence for the wide
    // push that motivated the retry: there the cap is exceeded for as long as
    // the retention window, which outlasts the whole fan-out's budget, and
    // `notify_peer_reports_refs_a_permanently_429_peer_never_took` is what
    // pins that outcome.
    #[tokio::test]
    async fn notify_peer_retries_a_transient_ledger_rejection_and_federates_on_retry() {
        let mut server = mockito::Server::new_async().await;
        let keypair = Keypair::generate();
        let http_client = reqwest::Client::new();

        let rejected = server
            .mock("POST", SYNC_NOTIFY_PATH)
            .with_status(429)
            .with_header("x-gitlawb-error", "signature_ledger_full")
            .expect(2)
            .create_async()
            .await;
        // Created second, so it only serves once the 429 mock has taken its
        // two hits; it also catches any attempt beyond the third.
        let accepted = server
            .mock("POST", SYNC_NOTIFY_PATH)
            .with_status(200)
            .expect(1)
            .create_async()
            .await;

        let notify_url = format!("{}{SYNC_NOTIFY_PATH}", server.url());

        notify_peer_with_budget(
            &http_client,
            &keypair,
            "did:key:zPeer",
            &notify_url,
            "owner/repo",
            &refs(1),
            "did:key:zNode",
            "did:key:zPusher",
            "did:key:zOwner",
            &FAST_POLICY,
        )
        .await;

        rejected.assert_async().await;
        accepted.assert_async().await;
    }

    // The wide-push shape the retry cannot fix: a peer whose ledger stays at
    // its cap answers 429 for the whole fan-out. Two things must hold. It stops
    // at the bound rather than spinning (an unbounded retry never terminates,
    // and an off-by-one shows up in the count), and the ref it never delivered
    // comes back named as unfederated rather than being dropped on the floor.
    #[tokio::test]
    async fn notify_peer_reports_refs_a_permanently_429_peer_never_took() {
        let mut server = mockito::Server::new_async().await;
        let keypair = Keypair::generate();
        let http_client = reqwest::Client::new();

        let mock = server
            .mock("POST", SYNC_NOTIFY_PATH)
            .with_status(429)
            .with_header("x-gitlawb-error", "signature_ledger_full")
            .expect(FAST_BACKOFF.len() + 1)
            .create_async()
            .await;

        let notify_url = format!("{}{SYNC_NOTIFY_PATH}", server.url());

        let summary = notify_peer_with_budget(
            &http_client,
            &keypair,
            "did:key:zPeer",
            &notify_url,
            "owner/repo",
            &refs(1),
            "did:key:zNode",
            "did:key:zPusher",
            "did:key:zOwner",
            &FAST_POLICY,
        )
        .await;

        mock.assert_async().await;
        assert_eq!(summary.total, 1);
        assert_eq!(
            summary.unfederated,
            vec!["refs/heads/b0".to_string()],
            "a ref the peer never took must be reported unfederated, not dropped",
        );
        assert!(
            summary.last_reason.contains("signature_ledger_full"),
            "the reason must name the peer's code, got: {}",
            summary.last_reason,
        );
    }

    // The retry budget is shared across the whole per-peer fan-out, so a
    // wedged peer cannot multiply the bound by the ref count: a 600-ref mirror
    // push must not cost 600 times the per-ref retry budget.
    #[tokio::test]
    async fn notify_peer_retry_budget_is_shared_across_the_fan_out() {
        let mut server = mockito::Server::new_async().await;
        let keypair = Keypair::generate();
        let http_client = reqwest::Client::new();

        // Each fully retried ref spends 5ms + 10ms of the 30ms budget, so the
        // first two refs get three attempts each and the third, with the
        // budget gone, gets a single attempt.
        let per_ref: u128 = FAST_BACKOFF.iter().map(|d| d.as_millis()).sum();
        let budgeted = (FAST_POLICY.budget.as_millis() / per_ref) as usize;
        assert_eq!(budgeted, 2, "test constants drifted");

        let mock = server
            .mock("POST", SYNC_NOTIFY_PATH)
            .with_status(429)
            .with_header("x-gitlawb-error", "signature_ledger_full")
            .expect(budgeted * (FAST_BACKOFF.len() + 1) + 1)
            .create_async()
            .await;

        let notify_url = format!("{}{SYNC_NOTIFY_PATH}", server.url());

        notify_peer_with_budget(
            &http_client,
            &keypair,
            "did:key:zPeer",
            &notify_url,
            "owner/repo",
            &refs(budgeted + 1),
            "did:key:zNode",
            "did:key:zPusher",
            "did:key:zOwner",
            &FAST_POLICY,
        )
        .await;

        mock.assert_async().await;
    }

    // A peer's per-IP flood brake also answers 429, and the sender can never
    // clear it inside the retry budget (the brake's window is an hour). Only
    // the ledger's own 429 is worth another attempt, so a 429 carrying any
    // other code — or no code at all — is a single attempt.
    #[tokio::test]
    async fn notify_peer_does_not_retry_a_429_with_an_unrelated_code() {
        for headers in [
            vec![("x-gitlawb-error", "rate_limited")],
            vec![("x-gitlawb-error", "some_code_from_a_newer_node")],
            vec![],
        ] {
            let mut server = mockito::Server::new_async().await;
            let keypair = Keypair::generate();
            let http_client = reqwest::Client::new();

            let mut m = server.mock("POST", SYNC_NOTIFY_PATH).with_status(429);
            for (k, v) in &headers {
                m = m.with_header(*k, v);
            }
            let mock = m.expect(1).create_async().await;

            let notify_url = format!("{}{SYNC_NOTIFY_PATH}", server.url());
            notify_peer_with_budget(
                &http_client,
                &keypair,
                "did:key:zPeer",
                &notify_url,
                "owner/repo",
                &refs(1),
                "did:key:zNode",
                "did:key:zPusher",
                "did:key:zOwner",
                &FAST_POLICY,
            )
            .await;

            mock.assert_async().await;
        }
    }

    // Same rule on the other retryable status: only the ledger's own 503 is
    // worth another attempt.
    #[tokio::test]
    async fn notify_peer_does_not_retry_a_503_with_an_unrelated_code() {
        let mut server = mockito::Server::new_async().await;
        let keypair = Keypair::generate();
        let http_client = reqwest::Client::new();

        let mock = server
            .mock("POST", SYNC_NOTIFY_PATH)
            .with_status(503)
            .expect(1)
            .create_async()
            .await;

        let notify_url = format!("{}{SYNC_NOTIFY_PATH}", server.url());
        notify_peer_with_budget(
            &http_client,
            &keypair,
            "did:key:zPeer",
            &notify_url,
            "owner/repo",
            &refs(1),
            "did:key:zNode",
            "did:key:zPusher",
            "did:key:zOwner",
            &FAST_POLICY,
        )
        .await;

        mock.assert_async().await;
    }

    // 409 signature_replayed means the peer ALREADY admitted this signed
    // request. Re-sending risks a duplicate apply, which is what the ledger
    // exists to prevent, so it must stay a single attempt.
    #[tokio::test]
    async fn notify_peer_does_not_retry_a_409_replay_rejection() {
        let mut server = mockito::Server::new_async().await;
        let keypair = Keypair::generate();
        let http_client = reqwest::Client::new();

        let mock = server
            .mock("POST", SYNC_NOTIFY_PATH)
            .with_status(409)
            .with_header("x-gitlawb-error", "signature_replayed")
            .expect(1)
            .create_async()
            .await;

        let notify_url = format!("{}{SYNC_NOTIFY_PATH}", server.url());

        notify_peer_with_budget(
            &http_client,
            &keypair,
            "did:key:zPeer",
            &notify_url,
            "owner/repo",
            &refs(1),
            "did:key:zNode",
            "did:key:zPusher",
            "did:key:zOwner",
            &FAST_POLICY,
        )
        .await;

        mock.assert_async().await;
    }

    // A transport error may mean the peer applied the update and only the
    // response was lost, so it is never retried. There is no mock to count
    // here, so the assertion is wall clock against a backoff long enough that
    // a single retry could not hide inside it.
    #[tokio::test]
    async fn notify_peer_does_not_retry_a_transport_error() {
        const SLOW_BACKOFF: [std::time::Duration; 2] = [
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
        ];
        const SLOW_POLICY: NotifyRetryPolicy = NotifyRetryPolicy {
            backoff: &SLOW_BACKOFF,
            budget: std::time::Duration::from_secs(60),
        };

        let keypair = Keypair::generate();
        let http_client = reqwest::Client::new();
        // Port 1 is reserved and nothing listens there: connect refused.
        let notify_url = format!("http://127.0.0.1:1{SYNC_NOTIFY_PATH}");

        let started = std::time::Instant::now();
        notify_peer_with_budget(
            &http_client,
            &keypair,
            "did:key:zPeer",
            &notify_url,
            "owner/repo",
            &refs(1),
            "did:key:zNode",
            "did:key:zPusher",
            "did:key:zOwner",
            &SLOW_POLICY,
        )
        .await;

        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "a transport error slept on the backoff, so it was retried: {:?}",
            started.elapsed(),
        );
    }

    // The happy path must not gain a single extra request: N refs, N POSTs.
    #[tokio::test]
    async fn notify_peer_sends_exactly_one_request_per_ref_on_success() {
        let mut server = mockito::Server::new_async().await;
        let keypair = Keypair::generate();
        let http_client = reqwest::Client::new();

        let ref_updates = refs(3);
        let mock = server
            .mock("POST", SYNC_NOTIFY_PATH)
            .with_status(200)
            .expect(ref_updates.len())
            .create_async()
            .await;

        let notify_url = format!("{}{SYNC_NOTIFY_PATH}", server.url());
        notify_peer_with_budget(
            &http_client,
            &keypair,
            "did:key:zPeer",
            &notify_url,
            "owner/repo",
            &ref_updates,
            "did:key:zNode",
            "did:key:zPusher",
            "did:key:zOwner",
            &FAST_POLICY,
        )
        .await;

        mock.assert_async().await;
    }

    #[test]
    fn classify_notify_status_separates_retryable_from_fatal() {
        use reqwest::StatusCode;
        assert_eq!(
            classify_notify_status(StatusCode::OK, None),
            NotifyDisposition::Delivered
        );
        assert_eq!(
            classify_notify_status(StatusCode::TOO_MANY_REQUESTS, Some("signature_ledger_full")),
            NotifyDisposition::Retryable,
            "the ledger's own 429 is the retryable rate condition"
        );
        assert_eq!(
            classify_notify_status(
                StatusCode::SERVICE_UNAVAILABLE,
                Some("signature_ledger_unavailable")
            ),
            NotifyDisposition::Retryable,
            "503 signature_ledger_unavailable did not apply the write"
        );
        assert_eq!(
            classify_notify_status(StatusCode::CONFLICT, Some("signature_replayed")),
            NotifyDisposition::Fatal,
            "409 signature_replayed means the peer already applied it"
        );
        assert_eq!(
            classify_notify_status(StatusCode::FORBIDDEN, None),
            NotifyDisposition::Fatal
        );
        assert_eq!(
            classify_notify_status(StatusCode::BAD_REQUEST, None),
            NotifyDisposition::Fatal
        );
    }

    // The gate is the code, not the status. Every one of these is a 429 or a
    // 503 — retryable under the old status-only rule — and every one must be
    // fatal.
    #[test]
    fn classify_notify_status_gates_on_the_code_not_the_status() {
        use reqwest::StatusCode;
        for (status, code) in [
            // The peer's per-IP flood brake: an hour-long window the sender
            // cannot clear inside a 60s budget.
            (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")),
            (StatusCode::SERVICE_UNAVAILABLE, Some("rate_limited")),
            // No code at all — a bare status, or a proxy that stripped the
            // header. Absence is not evidence of a ledger rejection.
            (StatusCode::TOO_MANY_REQUESTS, None),
            (StatusCode::SERVICE_UNAVAILABLE, None),
            // A code from some other node, or a newer one this build predates.
            (StatusCode::TOO_MANY_REQUESTS, Some("")),
            (StatusCode::TOO_MANY_REQUESTS, Some("upstream_overloaded")),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Some("signature_ledger_full"), // right code, wrong status
            ),
        ] {
            assert_eq!(
                classify_notify_status(status, code),
                NotifyDisposition::Fatal,
                "{status} with code {code:?} must not be retried",
            );
        }
    }

    // A 409 carries "the peer already admitted this signed request", so it is
    // fatal no matter what code rides along — including a header claiming the
    // ledger is full, which a hostile or confused peer could send to talk the
    // sender into re-applying a mutation.
    #[test]
    fn classify_notify_status_never_retries_a_409() {
        use reqwest::StatusCode;
        for code in [
            None,
            Some("signature_replayed"),
            Some("signature_ledger_full"),
            Some("signature_ledger_unavailable"),
            Some("rate_limited"),
        ] {
            assert_eq!(
                classify_notify_status(StatusCode::CONFLICT, code),
                NotifyDisposition::Fatal,
                "409 with code {code:?} must never be retried",
            );
        }
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
}
