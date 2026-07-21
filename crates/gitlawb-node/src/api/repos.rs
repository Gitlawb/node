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
    git_bin: String,
    timeout: std::time::Duration,
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
                crate::git::visibility_pack::withheld_blob_oids_bounded(
                    &disk_path, &git_bin, timeout, &rules, is_public, &owner_did, None,
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
    git_bin: String,
    timeout: std::time::Duration,
) -> Vec<String> {
    tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<String>> {
        let allowed = crate::git::visibility_pack::replicable_blob_set_bounded(
            &disk_path, &git_bin, timeout, &rules, is_public, &owner_did,
        )?;
        let all_blobs = crate::git::push_delta::all_blob_oids(&disk_path, &git_bin, std::time::Instant::now() + timeout)?;
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
    let service = query
        .service
        .ok_or_else(|| AppError::BadRequest("missing ?service= parameter".into()))?;
    // Reject an unsupported service BEFORE taking a read slot or doing any DB/Tigris
    // work (#174 P2-1). git_info_refs otherwise treats everything that is not
    // git-receive-pack as a read op, so an unauthenticated `?service=anything` to a
    // public repo would consume a read permit and the visibility/Tigris work before
    // validate_service rejected it downstream in smart_http.
    if service != "git-upload-pack" && service != "git-receive-pack" {
        return Err(AppError::BadRequest(format!(
            "unsupported git service: {service}"
        )));
    }
    // #62 cheap pre-DB load shed: if the pool this service draws from is already
    // saturated, shed with 503 before any DB/disk work. Best-effort (holds no
    // permit); the authoritative hold is `git_permit` below, after the per-source
    // cap. Restores the shed-before-DB property the reordered held acquire alone
    // would drop, while the reorder still prevents one source from occupying global
    // slots during the DB/visibility window.
    {
        // The receive-pack advertisement peeks its DEDICATED advert pool, not the
        // write pool the authenticated POST uses (#174) — matching the held acquire
        // below, so the pre-DB shed and the authoritative hold agree on the pool.
        let pool = if service == "git-receive-pack" {
            &state.git_push_advert_semaphore
        } else {
            &state.git_read_semaphore
        };
        if pool.available_permits() == 0 {
            tracing::warn!(
                "served-git concurrency cap reached; shedding request with 503 (pre-DB)"
            );
            return Err(AppError::Overloaded(
                "git service at capacity, retry shortly".into(),
            ));
        }
    }
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

    // Per-source concurrency sub-cap (#174), keyed on the resolved source IP and
    // acquired AFTER the visibility + push-rate gates (KTD7) so a denied or
    // rate-limited request never consumes a slot; held for the whole op. The
    // upload-pack advertisement is bounded on the read pool (git_read_per_caller).
    // The receive-pack advertisement draws from the write pool, so it is bounded per
    // source (git_push_advert_per_caller) instead: without this, an anonymous
    // multi-source flood of push-handshake advertisements could hold the write pool's
    // slots across acquire_fresh and shed authenticated pushes, since the per-IP push
    // rate limiter caps rate, not concurrency (#174 review fix).
    let caller_key = read_caller_key(&headers, peer, state.push_limiter_trust);
    let _caller_permit = if service == "git-receive-pack" {
        acquire_read_caller_permit(
            &state.git_push_advert_per_caller,
            caller_key.as_deref(),
            name,
            "receive-pack advert",
        )?
    } else {
        acquire_read_caller_permit(
            &state.git_read_per_caller,
            caller_key.as_deref(),
            name,
            "info/refs",
        )?
    };

    // Shed with a 503 before spawning git when the concurrency cap is saturated;
    // held for the whole op (incl. the smart_http call), released on return. Taken
    // AFTER the per-source cap above so one source cannot occupy global slots it
    // would be sub-cap-denied for during the DB/visibility window and starve other
    // sources; still before acquire_fresh/git so it bounds the fresh Tigris acquire
    // and git exec (INV-10). The receive-pack advertisement is phase one of a push,
    // but it is ANON-reachable, so it draws from the dedicated advert pool
    // (`git_push_advert_semaphore`), NOT the write pool the authenticated POST uses:
    // an advert flood can at worst exhaust the advert pool, never a permit a push
    // POST needs at admission (#174 U2). A clone flood on the read pool likewise
    // can't touch either. The upload-pack advertisement stays on the read pool with
    // its per-caller sub-cap.
    let _permit = if service == "git-receive-pack" {
        git_permit(&state.git_push_advert_semaphore)?
    } else {
        git_permit(&state.git_read_semaphore)?
    };

    // For receive-pack (push), download the latest from Tigris so the client
    // sees the same refs that acquire_write() will operate on.
    //
    // Bound the acquire under `git_acquire_timeout_secs`: the concurrency permit is
    // already held above, and `git_service_timeout_secs` only starts once git spawns,
    // so an un-deadlined acquire (a hung Tigris HEAD/GET here) pins the permit until
    // the pool drains (#174 P1-2). On expiry the handler-local `_permit`/`_caller_permit`
    // drop on the early return (the AdmissionGuard is not built until after acquire),
    // so the shed frees the slot; return a bounded 503.
    let acquire_deadline = std::time::Duration::from_secs(state.config.git_acquire_timeout_secs);
    let acquire_fut = async {
        if service == "git-receive-pack" {
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
    };
    let disk_path = tokio::time::timeout(acquire_deadline, acquire_fut)
        .await
        .map_err(|_elapsed| {
            tracing::warn!(repo = %name, service = %service, "repo acquire timed out; shedding with 503");
            AppError::Overloaded("git service acquisition timed out, retry shortly".into())
        })?
        .map_err(|e| {
            tracing::error!(repo = %name, service = %service, err = %e, "repo acquire failed");
            AppError::Git(e.to_string())
        })?;

    // Move the admission permits into the guard so they release only after the spawned
    // git process group is confirmed reaped, on complete/timeout/disconnect — not the
    // instant a disconnect drops this future while the detached reaper is still tearing
    // the group down (#174 P1-a). The handler keeps no copy: `_permit`/`_caller_permit`
    // are moved in, so admission tracks the real process lifetime.
    let admission = smart_http::AdmissionGuard::new(_permit, _caller_permit);
    let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);
    smart_http::info_refs("git", &service, &disk_path, git_timeout, Some(admission))
        .await
        .map_err(|e| {
            let app = git_service_app_error(&e);
            match &app {
                AppError::Timeout(_) => {
                    tracing::warn!(repo = %name, service = %service, "info/refs advertisement timed out")
                }
                _ => {
                    tracing::error!(repo = %name, service = %service, err = %e, "info_refs git failed")
                }
            }
            app
        })
}

/// Acquire a permit from the served-git concurrency semaphore, or shed the
/// request with a 503 + Retry-After when every slot is in use. Bind the returned
/// permit to a named local so it is held for the whole git op (it releases on
/// drop); a bare `_` would release it immediately.
fn git_permit(
    sem: &std::sync::Arc<tokio::sync::Semaphore>,
) -> Result<tokio::sync::OwnedSemaphorePermit> {
    sem.clone().try_acquire_owned().map_err(|_| {
        // Surface the shed so operators can see the cap engaging, mirroring the
        // receive-pack rate-limit warn above. A silent 503 makes a saturated or
        // misconfigured cap look like a client problem instead of a capacity one.
        tracing::warn!("served-git concurrency cap reached; shedding request with 503");
        AppError::Overloaded("git service at capacity, retry shortly".into())
    })
}

/// Resolve the per-caller key for the read sub-cap (#174): always the resolved
/// source IP (`client_key`), never the signed DID. Public read routes accept any
/// valid `did:key` via `optional_signature` with no admission step, so keying on
/// the DID would let one host mint disposable DIDs to multiply its per-source
/// budget; the push path already throttles on the resolved source IP for exactly
/// this DID-farm reason (`rate_limit.rs`, `IpRateLimiter`). `None` when no key
/// resolves (no trusted header and no peer): such a request is bounded by the
/// global read pool only, never a 500. The per-source-IP key is only as granular
/// as `trust`; see the `max_concurrent_reads_per_caller` config doc.
fn read_caller_key(
    headers: &axum::http::HeaderMap,
    peer: Option<std::net::SocketAddr>,
    trust: crate::rate_limit::TrustedProxy,
) -> Option<String> {
    crate::rate_limit::client_key(headers, peer, trust)
}

/// Acquire the per-caller read sub-cap permit (#174), or shed with a 503. `key` is
/// `None` when no caller key resolves — that request is bounded by the global read
/// pool only and is never shed here (returns `Ok(None)`). `handler` labels the shed
/// log line. Shared by both read handlers so the two acquire sites cannot drift.
fn acquire_read_caller_permit(
    limiter: &crate::rate_limit::PerCallerConcurrency,
    key: Option<&str>,
    repo: &str,
    handler: &str,
) -> Result<Option<crate::rate_limit::PerCallerPermit>> {
    match key {
        Some(k) => match limiter.try_acquire(k) {
            Some(p) => Ok(Some(p)),
            None => {
                tracing::warn!(repo = %repo, caller = %k, handler, "per-caller cap reached; shedding with 503");
                Err(AppError::Overloaded(
                    "git service at capacity for this caller, retry shortly".into(),
                ))
            }
        },
        None => Ok(None),
    }
}

/// Acquire an encryption-walk admission permit, then run the bounded withheld-blob
/// recipients walk. Blocks (defers) when `git_encrypt_semaphore` is full rather than
/// shedding — the walk is background so added latency is fine, and dropping it would
/// lose the withheld-blob recovery copy (#174 P1-e). Bounds the number of concurrent
/// post-push encryption walks so N fast completed pushes cannot spawn N concurrent
/// full-history git walks. Mirrors the original `spawn_blocking(...).await` return
/// shape so the caller's `Ok(Ok(recipients))` match is unchanged.
async fn withheld_recipients_gated(
    encrypt_sem: std::sync::Arc<tokio::sync::Semaphore>,
    repo_path: std::path::PathBuf,
    git_bin: String,
    timeout: std::time::Duration,
    rules: Vec<crate::db::VisibilityRule>,
    is_public: bool,
    owner_did: String,
) -> std::result::Result<
    anyhow::Result<std::collections::HashMap<String, std::collections::BTreeSet<String>>>,
    tokio::task::JoinError,
> {
    let _permit = encrypt_sem
        .acquire_owned()
        .await
        .expect("git_encrypt_semaphore is never closed");
    tokio::task::spawn_blocking(move || {
        crate::git::visibility_pack::withheld_blob_recipients_bounded(
            &repo_path, &git_bin, timeout, &rules, is_public, &owner_did,
        )
    })
    .await
}

/// Everything the detached post-push replication task needs that does not change
/// between requeue passes. Cloned once from `AppState` at the spawn site so the task
/// is self-contained (the handler keeps no copy).
struct PostPushReplication {
    db: std::sync::Arc<crate::db::Db>,
    disk_path: std::path::PathBuf,
    git_bin: String,
    timeout: std::time::Duration,
    ipfs_api: String,
    repo_id: String,
    encrypt_sem: std::sync::Arc<tokio::sync::Semaphore>,
    node_seed: [u8; 32],
    node_did: String,
    repo_name: String,
    irys_url: String,
    http_client: std::sync::Arc<reqwest::Client>,
}

/// The requeue enumeration for the pin half: a fail-closed FULL scan of the current
/// object DB under the REFRESHED rules. The coalesced push's ref tips are gone by the
/// time we requeue, so the delta path is unavailable; the whole-repo scan is the safe
/// superset. Never pins the bare `list_all_objects` output — that includes
/// dangling/withheld blobs — it feeds it as CANDIDATES to the same fail-closed filter
/// the push path's full-scan branch uses, which drops dangling and visibility-withheld
/// blobs before anything is pinned.
async fn requeue_full_scan_object_list(
    disk_path: &std::path::Path,
    git_bin: &str,
    timeout: std::time::Duration,
    rules: Vec<crate::db::VisibilityRule>,
    is_public: bool,
    owner_did: String,
) -> Vec<String> {
    let disk = disk_path.to_path_buf();
    let gb = git_bin.to_string();
    let candidates = tokio::task::spawn_blocking(move || {
        crate::git::push_delta::list_all_objects(&disk, &gb, std::time::Instant::now() + timeout)
    })
    .await
    .ok()
    .and_then(|r| {
        r.map_err(|e| {
            tracing::warn!(err = %e, "requeue full-scan enumeration failed; pinning nothing this pass")
        })
        .ok()
    })
    .unwrap_or_default();
    fail_closed_full_scan_objects(
        disk_path.to_path_buf(),
        rules,
        is_public,
        owner_did,
        candidates,
        git_bin.to_string(),
        timeout,
    )
    .await
}

/// The detached post-push encryption + local-IPFS pin task, as a REQUEUE LOOP.
///
/// Pass one uses the spawn-time captures (`first_*`) — the delta the push handler
/// already computed. At the TASK TAIL (unconditional on the encrypt gate below and on
/// walk success) it consults the coalescing dirty flag: if a push coalesced during the
/// window it re-reads repo state (rules, is_public, owner_did, withheld) FRESH from the
/// DB, re-enumerates the pin set fail-closed, and runs another pass — so the coalesced
/// push is covered before the task exits. Otherwise it releases the key and returns.
///
/// The tail placement is load-bearing: the encrypt+anchor block only runs under a
/// path-scoped rule, so a check-and-clear placed inside that gate would never run for a
/// public/rules-free repo or a failed walk, dropping exactly the pin-half push this
/// requeue must cover.
#[allow(clippy::too_many_arguments)]
async fn run_post_push_replication(
    mut guard: crate::state::EncryptInflightGuard,
    ctx: PostPushReplication,
    first_object_list: Vec<String>,
    first_rules: Option<Vec<crate::db::VisibilityRule>>,
    first_is_public: bool,
    first_owner_did: String,
    first_withheld: std::collections::HashSet<String>,
) {
    let mut object_list = first_object_list;
    let mut rules_opt = first_rules;
    let mut is_public = first_is_public;
    let mut owner_did = first_owner_did;
    // The task only spawns when `withheld.is_some()`, so pass one always replicates.
    let mut withheld: Option<std::collections::HashSet<String>> = Some(first_withheld);

    loop {
        if withheld.is_some() {
            // Pin new git objects to the local IPFS node (no-op if ipfs_api is empty).
            crate::ipfs_pin::pin_new_objects(
                &ctx.ipfs_api,
                &ctx.disk_path,
                &ctx.git_bin,
                ctx.timeout,
                object_list.clone(),
                &ctx.db,
                &ctx.repo_id,
            )
            .await;

            // Option B1: encrypt-then-pin the withheld blobs. No path-scoped rule can
            // withhold a blob, so a rules-free repo has nothing to seal; skip. Mirrors
            // the has_path_scoped_rule gate on the other two withheld-walk sites.
            if let Some(rules) = rules_opt
                .clone()
                .filter(|r| visibility_pack::has_path_scoped_rule(r))
            {
                let recip = withheld_recipients_gated(
                    ctx.encrypt_sem.clone(),
                    ctx.disk_path.clone(),
                    ctx.git_bin.clone(),
                    ctx.timeout,
                    rules,
                    is_public,
                    owner_did.clone(),
                )
                .await;
                if let Ok(Ok(recipients)) = recip {
                    let delta = crate::encrypted_pin::encrypt_and_pin(
                        &ctx.ipfs_api,
                        &ctx.disk_path,
                        &ctx.db,
                        &ctx.repo_id,
                        &ctx.node_seed,
                        &recipients,
                    )
                    .await;

                    // Option B3: anchor a per-push manifest of the sealed blobs to
                    // Arweave. Best-effort; never fails the push.
                    if !delta.is_empty() && !ctx.irys_url.is_empty() {
                        let owner_short = crate::db::normalize_owner_key(&owner_did);
                        let repo_slug = format!("{owner_short}/{}", ctx.repo_name);
                        let ts = chrono::Utc::now().to_rfc3339();
                        let manifest = crate::arweave::EncryptedManifest {
                            repo: &repo_slug,
                            owner_did: &owner_did,
                            node_did: &ctx.node_did,
                            timestamp: &ts,
                            blobs: &delta,
                        };
                        match crate::arweave::anchor_encrypted_manifest(
                            &ctx.http_client,
                            &ctx.irys_url,
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
        }

        // TASK TAIL — unconditional check-and-clear, atomic with the release decision.
        if !guard.requeue_or_release() {
            break;
        }

        // A push coalesced during this pass. Re-read repo state FRESH (never the stale
        // spawn-time captures) so a coalesced push that changed `.gitlawb` withholding
        // is walked under the new policy, then re-enumerate the pin set fail-closed.
        let (r_rules, r_is_public, r_owner) = match ctx.db.get_repo_by_id(&ctx.repo_id).await {
            Ok(Some(rec)) => (
                ctx.db.list_visibility_rules(&ctx.repo_id).await.ok(),
                rec.is_public,
                rec.owner_did,
            ),
            Ok(None) => {
                tracing::debug!(repo = %ctx.repo_id, "repo gone before requeue pass; releasing");
                (None, false, String::new())
            }
            Err(e) => {
                tracing::warn!(repo = %ctx.repo_id, err = %e, "requeue repo re-read failed; skipping this pass's work");
                (None, false, String::new())
            }
        };
        let (_announce, r_withheld) = replication_withheld_set(
            r_rules.clone(),
            &r_owner,
            r_is_public,
            ctx.disk_path.clone(),
            ctx.git_bin.clone(),
            ctx.timeout,
        )
        .await;
        object_list = match &r_withheld {
            Some(_) => {
                requeue_full_scan_object_list(
                    &ctx.disk_path,
                    &ctx.git_bin,
                    ctx.timeout,
                    r_rules.clone().unwrap_or_default(),
                    r_is_public,
                    r_owner.clone(),
                )
                .await
            }
            None => Vec::new(),
        };
        rules_opt = r_rules;
        is_public = r_is_public;
        owner_did = r_owner;
        withheld = r_withheld;
    }
}

/// Test-only entry point: build the `PostPushReplication` context from a test
/// `AppState` (with an overridable `ipfs_api` for a mock Kubo server and an explicit
/// `disk_path` for the fixture repo) and run the requeue loop. Keeps
/// `PostPushReplication` and `run_post_push_replication` private to this module.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_post_push_replication_for_test(
    state: &AppState,
    guard: crate::state::EncryptInflightGuard,
    disk_path: std::path::PathBuf,
    repo_id: String,
    ipfs_api: String,
    is_public: bool,
    owner_did: String,
    object_list: Vec<String>,
    rules: Option<Vec<crate::db::VisibilityRule>>,
    withheld: std::collections::HashSet<String>,
) {
    let ctx = PostPushReplication {
        db: state.db.clone(),
        disk_path: disk_path.clone(),
        git_bin: state.git_bin.clone(),
        timeout: std::time::Duration::from_secs(state.config.git_service_timeout_secs),
        ipfs_api,
        repo_id,
        encrypt_sem: state.git_encrypt_semaphore.clone(),
        node_seed: *state.node_keypair.to_seed(),
        node_did: state.node_did.to_string(),
        repo_name: String::new(),
        irys_url: String::new(),
        http_client: std::sync::Arc::clone(&state.http_client),
    };
    run_post_push_replication(
        guard,
        ctx,
        object_list,
        rules,
        is_public,
        owner_did,
        withheld,
    )
    .await;
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
    crate::rate_limit::PeerAddr(peer): crate::rate_limit::PeerAddr,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Result<Response> {
    // #62 cheap pre-DB load shed (see git_info_refs): shed before DB when the read
    // pool is saturated; the authoritative hold is `git_permit` below, after the
    // per-source cap.
    if state.git_read_semaphore.available_permits() == 0 {
        tracing::warn!("served-git concurrency cap reached; shedding request with 503 (pre-DB)");
        return Err(AppError::Overloaded(
            "git service at capacity, retry shortly".into(),
        ));
    }
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

    // Per-caller read sub-cap (#174): after the visibility gate (KTD7) so a
    // visibility-denied caller never consumes a scarce read slot. Keyed on the
    // resolved source IP (never the signed DID, #174 U1); no resolvable key ->
    // global read pool only.
    let caller_key = read_caller_key(&headers, peer, state.push_limiter_trust);
    let _caller_permit = acquire_read_caller_permit(
        &state.git_read_per_caller,
        caller_key.as_deref(),
        name,
        "upload-pack",
    )?;

    // Shed with a 503 before spawning git when the concurrency cap is saturated;
    // held for the whole op (incl. the smart_http call), released on return. Taken
    // AFTER the per-source cap above so one source cannot occupy global slots it
    // would be sub-cap-denied for during the DB/visibility window and starve other
    // sources; still before acquire/git so it bounds the Tigris acquire and git
    // exec (INV-10).
    let _permit = git_permit(&state.git_read_semaphore)?;

    // Bound the acquire under `git_acquire_timeout_secs` so a hung Tigris HEAD/GET
    // cannot pin the read permit indefinitely (#174 P1-2). The permit is a handler
    // local here (moved into the AdmissionGuard only below, once git is spawned), so
    // the early return on timeout drops it and frees the slot; shed a bounded 503.
    let acquire_deadline = std::time::Duration::from_secs(state.config.git_acquire_timeout_secs);
    let disk_path = tokio::time::timeout(
        acquire_deadline,
        state.repo_store.acquire(&record.owner_did, &record.name),
    )
    .await
    .map_err(|_elapsed| {
        tracing::warn!(repo = %name, "repo acquire timed out; shedding with 503");
        AppError::Overloaded("git service acquisition timed out, retry shortly".into())
    })?
    .map_err(|e| AppError::Git(e.to_string()))?;
    let body_len = body.len();

    // No path-scoped rule can withhold an individual blob, and the whole-repo
    // "/" gate above already enforced repo-level access. Skip the per-blob
    // withheld walk and serve the pack directly.
    let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);
    let resp = if !visibility_pack::has_path_scoped_rule(&rules) {
        // Plain (non-path-scoped) serve: move both admission permits into the guard so
        // they release only after the spawned git group is reaped, on
        // complete/timeout/disconnect — not the instant a disconnect drops this future
        // (#174 P1-a). The handler keeps no copy.
        let admission = smart_http::AdmissionGuard::new(_permit, _caller_permit);
        smart_http::upload_pack(&state.git_bin, &disk_path, body, git_timeout, Some(admission)).await
    } else {
        // withheld_blob_oids walks every ref with blocking `git ls-tree`; keep that
        // off the async worker thread. Move BOTH admission permits INTO the blocking
        // task so they are held for the walk's real duration: spawn_blocking cannot be
        // cancelled, so on a client disconnect the handler future drops but the walk
        // keeps running — and now so do its permits, released only when the walk
        // finishes rather than the instant the future drops (#174 P1-b). On success the
        // task hands the permits back so the serve phase below keeps them; on a
        // dropped future the returned tuple (with the permits) is discarded only when
        // the blocking task completes, so admission tracks the real git work.
        let (withheld, _permit, _caller_permit) = {
            let path = disk_path.clone();
            let rules = rules.clone();
            let owner_did = record.owner_did.clone();
            let caller_owned = caller.map(str::to_string);
            let is_public = record.is_public;
            let git_bin = state.git_bin.clone();
            tokio::task::spawn_blocking(move || {
                let withheld = visibility_pack::withheld_blob_oids_bounded(
                    &path,
                    &git_bin,
                    git_timeout,
                    &rules,
                    is_public,
                    &owner_did,
                    caller_owned.as_deref(),
                );
                (withheld, _permit, _caller_permit)
            })
            .await
            .map_err(|e| AppError::Git(e.to_string()))?
        };
        // A walk that hit its deadline carries GitServiceTimeout; map it to 504 like
        // the smart_http paths, not a generic 500 (#174 U3).
        let withheld = withheld.map_err(|e| git_service_app_error(&e))?;

        if withheld.is_empty() {
            // No blobs to withhold: serve the plain pack, moving the permits returned by
            // the walk into the guard so admission tracks the served git group's reap
            // (the walk already held them per be0cdd6; this hands them to the serve).
            let admission = smart_http::AdmissionGuard::new(_permit, _caller_permit);
            smart_http::upload_pack(&state.git_bin, &disk_path, body, git_timeout, Some(admission)).await
        } else {
            tracing::info!(repo = %name, caller = ?caller, withheld = withheld.len(), "serving filtered pack");
            // Move both admission permits into the guard so they release only after the
            // filtered serve's git group (rev-list then pack-objects) is reaped, on
            // complete/timeout/disconnect — not the instant a disconnect drops this
            // future. Without this, disconnect-spam on a path-scoped repo could hold PIDs
            // past the concurrency cap while the permits were already freed (#174 P1-a,
            // R2). The guard rides both stages inside upload_pack_excluding.
            let admission = smart_http::AdmissionGuard::new(_permit, _caller_permit);
            smart_http::upload_pack_excluding(&disk_path, body, &withheld, git_timeout, Some(admission))
                .await
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
) {
    let body = serde_json::json!({
        "repo": repo_slug,
        "ref_name": ref_name,
        "new_sha": new_sha,
        "node_did": node_did,
        "pusher_did": pusher_did,
        "old_sha": old_sha,
        "timestamp": chrono::Utc::now().to_rfc3339(),
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
        )
        .await;
    }
}

/// POST /:owner/:repo.git/git-receive-pack  (AUTH REQUIRED — enforced by middleware)
pub async fn git_receive_pack(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    Extension(auth): Extension<AuthenticatedDid>,
    crate::rate_limit::PeerAddr(peer): crate::rate_limit::PeerAddr,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let name = smart_http_repo_name(&repo)?;
    // Per-source write sub-cap (#174 P1-d): before the global write permit so one
    // source IP cannot occupy the whole write pool via many slow authenticated pushes
    // and 503 every other source. Owner enforcement defaults off, so any valid did:key
    // is accepted (auth != authz), and the 600/hour push limiter bounds arrival RATE,
    // not in-flight concurrency — so without this a single host minting disposable DIDs
    // saturates the pool. Keyed on the resolved source IP, NEVER the signed DID (a DID
    // farm defeats a DID key); no resolvable key -> global write pool only.
    let caller_key = read_caller_key(&headers, peer, state.push_limiter_trust);
    let _caller_permit = acquire_read_caller_permit(
        &state.git_write_per_caller,
        caller_key.as_deref(),
        name,
        "receive-pack",
    )?;
    // Shed with a 503 before spawning git when the concurrency cap is saturated.
    // Pushes draw from the dedicated WRITE pool, separate from reads, so a flood of
    // anonymous reads cannot shed an authenticated push (#174). Taken after the
    // per-source cap above so one source cannot occupy global slots it would be
    // sub-cap-denied for; still before the Tigris acquire_write, bounding concurrent
    // fresh acquires (INV-10); held for the whole op.
    let _permit = git_permit(&state.git_write_semaphore)?;
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
    // Bound the write acquire under `git_acquire_timeout_secs`. acquire_write's
    // advisory-lock loop already caps at ~60s, but its per-iteration
    // `pg_try_advisory_lock().fetch_one(&pool)` can block indefinitely on a hung /
    // exhausted Postgres pool (so the 60-count never advances) — and the write permit
    // is held the whole time, draining the pool (#174 P1-2). The outer
    // `tokio::time::timeout` cancels a mid-sleep/mid-`fetch_one` future, so it bounds
    // both the loop and a hung iteration without any repo_store.rs change (KTD3). The
    // permit is a handler local here (moved into the AdmissionGuard only after this),
    // so the early return on timeout drops it and frees the slot; shed a bounded 503.
    let acquire_deadline = std::time::Duration::from_secs(state.config.git_acquire_timeout_secs);
    let guard = tokio::time::timeout(
        acquire_deadline,
        state
            .repo_store
            .acquire_write(&record.owner_did, &record.name),
    )
    .await
    .map_err(|_elapsed| {
        tracing::warn!(repo = %name, "acquire_write timed out; shedding with 503");
        AppError::Overloaded("git service acquisition timed out, retry shortly".into())
    })?
    .map_err(|e| {
        tracing::error!(repo = %name, err = %e, "acquire_write failed");
        AppError::Git(e.to_string())
    })?;
    let disk_path = guard.path().to_path_buf();
    tracing::debug!(repo = %name, path = %disk_path.display(), "running git receive-pack");
    let body_len = body.len();
    let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);
    // Move both admission permits into the guard so they release only after the spawned
    // receive-pack process group is reaped, on complete/timeout/disconnect — not the
    // instant a disconnect drops this future while the detached reaper runs (#174 P1-a).
    // The handler keeps no copy. This is independent of the write-lock `guard.release`
    // below: admission tracks the git process lifetime, the write lock tracks the repo.
    let admission = smart_http::AdmissionGuard::new(_permit, _caller_permit);
    let receive_result = smart_http::receive_pack(
        &state.git_bin,
        &disk_path,
        body,
        git_timeout,
        Some(admission),
    )
    .await;

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
        state.git_bin.clone(),
        std::time::Duration::from_secs(state.config.git_service_timeout_secs),
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
            state.git_bin.clone(),
            std::time::Duration::from_secs(state.config.git_service_timeout_secs),
        )
        .await;
        if pin_set.full_scan {
            fail_closed_full_scan_objects(
                disk_path.clone(),
                rules_opt.clone().unwrap_or_default(),
                record.is_public,
                record.owner_did.clone(),
                pin_set.candidates,
                state.git_bin.clone(),
                std::time::Duration::from_secs(state.config.git_service_timeout_secs),
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
    //
    // Coalesce per repo (#174 P2-2): only spawn a task if none is in flight for this
    // repo; otherwise `try_begin` marks the repo DIRTY and the in-flight task requeues
    // one more pass (re-reading fresh repo state) before it exits. This bounds the
    // outstanding parked-task set to one per repo while covering every coalesced push —
    // there is no reconciliation sweep, so a dropped job would be lost forever (#173 F3).
    if let Some(withheld_set) = withheld.clone() {
        match state.encrypt_inflight.try_begin(&record.id) {
            None => {
                tracing::debug!(
                    repo = %record.id,
                    "post-push encryption task already in flight for this repo; coalescing \
                     (the in-flight task will requeue one more pass to cover this push)"
                );
            }
            Some(inflight_guard) => {
                let ctx = PostPushReplication {
                    db: state.db.clone(),
                    disk_path: disk_path.clone(),
                    git_bin: state.git_bin.clone(),
                    timeout: std::time::Duration::from_secs(state.config.git_service_timeout_secs),
                    ipfs_api: state.config.ipfs_api.clone(),
                    repo_id: record.id.clone(),
                    encrypt_sem: state.git_encrypt_semaphore.clone(),
                    node_seed: *state.node_keypair.to_seed(),
                    node_did: state.node_did.to_string(),
                    repo_name: record.name.clone(),
                    irys_url: state.config.irys_url.clone(),
                    http_client: std::sync::Arc::clone(&state.http_client),
                };
                tokio::spawn(run_post_push_replication(
                    inflight_guard,
                    ctx,
                    object_list.clone(),
                    rules_opt.clone(),
                    record.is_public,
                    record.owner_did.clone(),
                    withheld_set,
                ));
            }
        }
    }

    // Pin new git objects to Pinata, then record branch→CID and gossip.
    //
    // #174 P2-2 scope note: this SECOND detached spawn is deliberately NOT brought
    // under the per-repo encryption coalescing above. Two reasons: (1) it does not
    // park on `git_encrypt_semaphore` (or any semaphore) — the Pinata `pin_new_objects`
    // is a bounded reqwest round-trip, so it does not form the unbounded PARKED-waiter
    // set that is the P2-2 residual; it runs to completion under the HTTP client's
    // network timeouts. (2) Unlike the idempotent recovery-copy walk, this task does
    // PER-PUSH, PER-REF work — branch→CID upserts, gossip publish, GraphQL subscription
    // broadcast, Arweave anchoring, and peer notify, each keyed to THIS push's
    // ref_updates. Coalescing it against an in-flight task for the same repo would DROP
    // a later push's ref-update announcements (a correctness regression), not merely
    // delay a duplicate. So it is scoped out with rationale, not brought under the bound.
    {
        let pinata_jwt = state.config.pinata_jwt.clone();
        let pinata_upload_url = state.config.pinata_upload_url.clone();
        let repo_path_clone = disk_path.clone();
        let db_clone = state.db.clone();
        let repo_id = record.id.clone();
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
                    &repo_id,
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

    #[test]
    fn git_permit_sheds_at_capacity_and_releases() {
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let p1 = git_permit(&sem).expect("first acquire succeeds");
        // At capacity the next request is shed with Overloaded (-> 503), not queued.
        assert!(matches!(git_permit(&sem), Err(AppError::Overloaded(_))));
        // Releasing the permit frees the slot for the next request.
        drop(p1);
        assert!(git_permit(&sem).is_ok());
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
        let (announce, _) = replication_withheld_set(
            None,
            OWNER_DID,
            false,
            dummy.clone(),
            "git".into(),
            std::time::Duration::from_secs(600),
        )
        .await;
        assert!(!announce, "private repo (no rules) must not announce");

        // Private: empty rule set, is_public=false → still not listable at root.
        let (announce, _) = replication_withheld_set(
            Some(vec![]),
            OWNER_DID,
            false,
            dummy.clone(),
            "git".into(),
            std::time::Duration::from_secs(600),
        )
        .await;
        assert!(!announce, "private repo (empty rules) must not announce");

        // Public: empty rule set, is_public=true → listable at root, announces.
        let (announce, _) = replication_withheld_set(
            Some(vec![]),
            OWNER_DID,
            true,
            dummy,
            "git".into(),
            std::time::Duration::from_secs(600),
        )
        .await;
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

    #[cfg(unix)]
    fn write_fake_git(dir: &std::path::Path, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("fakegit");
        std::fs::write(&p, body).unwrap();
        let mut perm = std::fs::metadata(&p).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&p, perm).unwrap();
        p.to_str().unwrap().to_string()
    }

    /// #174 (write-pool twin, vetted by execution not reasoning): the receive-pack
    /// post-push replication walk is bounded. Drive `replication_withheld_set` with an
    /// injected fake git that hangs on `rev-list` and a short budget: it must RETURN
    /// within the budget (so `git_receive_pack` releases the write permit it holds
    /// across this await, rather than pinning it for the hang) AND fail closed
    /// (announce suppressed) because the walk could not be vetted. Proves this path
    /// funnels through the bounded `blob_paths`, on the write-permit-holding side.
    #[cfg(unix)]
    #[tokio::test]
    async fn replication_walk_is_bounded_and_fails_closed_on_a_hung_git() {
        use std::time::Duration;
        let tmp = tempfile::TempDir::new().unwrap();
        let body = "#!/bin/sh\ncase \"$1\" in\n  rev-list) sleep 30 ;;\n  rev-parse) echo deadbeef ;;\n  *) : ;;\nesac\nexit 0\n";
        let git_bin = write_fake_git(tmp.path(), body);
        // Public root (announceable) + a path-scoped rule, so the walk actually runs
        // rather than taking the has_path_scoped_rule short-circuit.
        let rules = Some(vec![vis_rule("/secret/**", &[])]);

        let result = tokio::time::timeout(
            Duration::from_secs(10),
            replication_withheld_set(
                rules,
                OWNER_DID,
                true,
                tmp.path().to_path_buf(),
                git_bin,
                Duration::from_millis(200),
            ),
        )
        .await
        .expect(
            "replication_withheld_set must return within the budget; a hung walk must \
             not pin the write permit git_receive_pack holds across it",
        );
        assert_eq!(
            result,
            (false, None),
            "a walk that could not be vetted must suppress the announce (fail closed)"
        );
    }

    /// #174 (serve-path 504, vetted by execution): a hung withheld-blob walk on the
    /// upload-pack POST maps to 504, not a generic 500. Real repo dir on disk (so
    /// acquire's fast path returns it) + a path-scoped rule (so the walk runs) +
    /// an injected fake git that hangs on rev-list. The handler must return 504,
    /// proving git_upload_pack routes the walk's GitServiceTimeout through
    /// git_service_app_error end to end.
    #[cfg(unix)]
    #[sqlx::test]
    async fn upload_pack_hung_withheld_walk_returns_504(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::{Method, Request, StatusCode};
        use std::net::SocketAddr;
        use tower::ServiceExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let body = "#!/bin/sh\ncase \"$1\" in\n  rev-list) sleep 30 ;;\n  rev-parse) echo deadbeef ;;\n  *) : ;;\nesac\nexit 0\n";
        let fake = write_fake_git(tmp.path(), body);

        let mut state = crate::test_support::test_state(pool).await;
        state.git_bin = fake;
        let mut cfg = (*state.config).clone();
        cfg.git_service_timeout_secs = 1;
        state.config = std::sync::Arc::new(cfg);
        state
            .db
            .upsert_mirror_repo("z6srv504", "sv", "/tmp/z6srv504-sv", None, false)
            .await
            .unwrap();
        let rec = state.db.get_repo("z6srv504", "sv").await.unwrap().unwrap();
        // Path-scoped rule so has_path_scoped_rule() is true and the walk runs; the
        // public root still lets an anonymous caller past the "/" gate.
        state
            .db
            .set_visibility_rule(
                &rec.id,
                "/secret/**",
                crate::db::VisibilityMode::B,
                &[],
                OWNER_DID,
            )
            .await
            .unwrap();
        // acquire()'s fast path returns the local path when it exists on disk.
        let disk = std::path::Path::new("/tmp/z6srv504/sv.git");
        std::fs::create_dir_all(disk).unwrap();

        let peer: SocketAddr = "203.0.113.91:7000".parse().unwrap();
        let router = crate::server::build_router(state);
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/z6srv504/sv/git-upload-pack")
            .body(Body::from(&b"0000"[..]))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        let status = router.oneshot(req).await.unwrap().status();
        let _ = std::fs::remove_dir_all("/tmp/z6srv504");
        assert_eq!(
            status,
            StatusCode::GATEWAY_TIMEOUT,
            "a hung withheld-blob walk must surface as 504, not a generic 500"
        );
    }

    /// #174 (F2 sizing edge, vetted by execution): the receive-pack advertisement
    /// per-source cap is derived in main.rs as `(max_concurrent_git_pushes / 8).max(1)`,
    /// so it is never 0 even at the minimum write-pool size (1). A 0 cap would make
    /// PerCallerConcurrency shed EVERY receive-pack advertisement and break all pushes.
    #[test]
    fn advert_per_caller_cap_sizing_is_never_zero() {
        let cap = |pushes: usize| (pushes / 8).max(1);
        for pushes in [1usize, 4, 8, 32, 256] {
            assert!(
                cap(pushes) >= 1,
                "advert cap must be >= 1 for pushes={pushes}"
            );
        }
        assert_eq!(cap(1), 1, "minimum write pool must derive cap 1, not 0");
        assert_eq!(
            cap(32),
            4,
            "default write pool 32 derives cap 4 (~8 source IPs to fill)"
        );
        // A cap of 1 admits one and sheds the second from the same source.
        let lim = crate::rate_limit::PerCallerConcurrency::new(cap(1), 100);
        let _held = lim.try_acquire("src").expect("first advert admitted");
        assert!(
            lim.try_acquire("src").is_none(),
            "second advert from the same source is shed"
        );
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

    /// #174 P2-1: an unsupported `?service=` must be rejected with 400 BEFORE taking a
    /// read slot or doing DB/Tigris work. Isolate it: exhaust the read pool so a read
    /// op WOULD shed 503 at the pre-DB check — a garbage service must still return 400
    /// (validation runs first), proving `?service=anything` cannot consume the read
    /// pool. Removing the validation makes this 503 (RED).
    #[sqlx::test]
    async fn info_refs_rejects_unsupported_service_before_the_read_slot(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::{Method, Request, StatusCode};
        use std::net::SocketAddr;
        use std::sync::Arc;
        use tokio::sync::Semaphore;
        use tower::ServiceExt;

        let mut state = crate::test_support::test_state(pool).await;
        state
            .db
            .upsert_mirror_repo("z6svcowner", "svc", "/tmp/svc", None, false)
            .await
            .unwrap();
        // Exhaust the read pool: a read op would shed 503 at the pre-DB check.
        state.git_read_semaphore = Arc::new(Semaphore::new(0));

        let router = crate::server::build_router(state);
        let peer: SocketAddr = "203.0.113.90:7000".parse().unwrap();
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/z6svcowner/svc/info/refs?service=git-explode")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));

        let status = router.oneshot(req).await.unwrap().status();
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an unsupported ?service= must be 400 before the read-pool shed, not 503"
        );
    }

    /// #174 (jatmn P1): the anon-reachable receive-pack advertisement
    /// (`GET info/refs?service=git-receive-pack`) draws from a DEDICATED advert pool
    /// (`git_push_advert_semaphore`), NOT the write pool the authenticated POST uses.
    /// Proven at the handler by saturating each pool to zero and checking who shares
    /// it (INV-10, across the auth boundary). The load-bearing pair:
    ///   * advert pool at 0 -> the advert SHEDS 503 (it is bound to that pool);
    ///   * write pool at 0 -> the advert SURVIVES (it can NOT consume a permit the
    ///     authenticated POST needs — the reservation jatmn asked for).
    /// Revert the branch to `git_write_semaphore` and BOTH flip: the advert-pool-0
    /// case stops shedding and the write-pool-0 case starts shedding (the exact
    /// anon-sheds-authed-push starvation).
    #[sqlx::test]
    async fn receive_pack_advertisement_draws_from_dedicated_advert_pool(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::{Method, Request, StatusCode};
        use std::net::SocketAddr;
        use std::sync::Arc;
        use tokio::sync::Semaphore;
        use tower::ServiceExt;

        // Build a fresh state with the three pools sized independently, then drive one
        // info/refs advertisement for `service` and return its handler status.
        async fn advert_status(
            pool: &sqlx::PgPool,
            read_permits: usize,
            write_permits: usize,
            advert_permits: usize,
            service: &str,
        ) -> StatusCode {
            let mut state = crate::test_support::test_state(pool.clone()).await;
            state.git_read_semaphore = Arc::new(Semaphore::new(read_permits));
            state.git_write_semaphore = Arc::new(Semaphore::new(write_permits));
            state.git_push_advert_semaphore = Arc::new(Semaphore::new(advert_permits));
            state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
            state
                .db
                .upsert_mirror_repo("z6wpadv", "wp", "/tmp/wp-nonexistent", None, false)
                .await
                .unwrap();
            let peer: SocketAddr = "203.0.113.61:6000".parse().unwrap();
            let router = crate::server::build_router(state);
            let mut req = Request::builder()
                .method(Method::GET)
                .uri(format!("/z6wpadv/wp/info/refs?service={service}"))
                .body(Body::empty())
                .unwrap();
            req.extensions_mut().insert(ConnectInfo(peer));
            router.oneshot(req).await.unwrap().status()
        }

        // Advert pool saturated (read + write free): the receive-pack advert SHEDS,
        // proving it is bound to the dedicated advert pool.
        assert_eq!(
            advert_status(&pool, 8, 8, 0, "git-receive-pack").await,
            StatusCode::SERVICE_UNAVAILABLE,
            "receive-pack advertisement draws from the dedicated advert pool: a saturated advert pool sheds it 503"
        );
        // WRITE pool saturated (advert + read free): the advert SURVIVES. This is the
        // reservation — an advert flood can never occupy a permit the authenticated
        // push POST relies on at admission.
        assert_ne!(
            advert_status(&pool, 8, 0, 8, "git-receive-pack").await,
            StatusCode::SERVICE_UNAVAILABLE,
            "receive-pack advertisement must NOT draw from the write pool: a saturated write pool must not shed it"
        );
        // Read pool saturated (advert + write free): the advert SURVIVES (never on the read pool).
        assert_ne!(
            advert_status(&pool, 0, 8, 8, "git-receive-pack").await,
            StatusCode::SERVICE_UNAVAILABLE,
            "receive-pack advertisement must not draw from the read pool"
        );
        // Read pool saturated: the upload-pack advertisement still SHEDS (unchanged).
        assert_eq!(
            advert_status(&pool, 0, 8, 8, "git-upload-pack").await,
            StatusCode::SERVICE_UNAVAILABLE,
            "upload-pack advertisement stays on the read pool: a saturated read pool sheds it 503"
        );
        // Write + advert pools saturated, read free: the upload-pack advertisement is
        // UNAFFECTED, proving reads never touch either write-side pool.
        assert_ne!(
            advert_status(&pool, 8, 0, 0, "git-upload-pack").await,
            StatusCode::SERVICE_UNAVAILABLE,
            "upload-pack advertisement never touches the write or advert pool"
        );
    }

    /// #174 U2: the receive-pack advertisement is a write-path op, so it must not be
    /// shed by the READ per-caller sub-cap even when the caller's source IP has
    /// exhausted its read budget (e.g. concurrent clones from the same host). Fill
    /// the IP's read per-caller slot, then the receive-pack advertisement from that
    /// same IP must still get through. Restore the unconditional read-cap acquire on
    /// the receive-pack branch and this goes 503.
    #[sqlx::test]
    async fn receive_pack_advertisement_ignores_read_per_caller_cap(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::{Method, Request, StatusCode};
        use std::net::SocketAddr;
        use tower::ServiceExt;

        let mut state = crate::test_support::test_state(pool).await;
        state.git_read_per_caller = crate::rate_limit::PerCallerConcurrency::new(1, 100);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state
            .db
            .upsert_mirror_repo("z6wpc", "wp", "/tmp/wp-nonexistent", None, false)
            .await
            .unwrap();

        let peer: SocketAddr = "203.0.113.71:6000".parse().unwrap();
        // Exhaust the source IP's single READ per-caller slot, as concurrent clones
        // from the same host would.
        let _slot = state
            .git_read_per_caller
            .try_acquire(&peer.ip().to_string())
            .expect("fill the IP's read per-caller slot");

        let router = crate::server::build_router(state);
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/z6wpc/wp/info/refs?service=git-receive-pack")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        assert_ne!(
            router.oneshot(req).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "receive-pack advertisement must not be shed by the read per-caller cap: it is a write-path op"
        );
    }

    /// #174 (review fix): the anon-reachable receive-pack advertisement draws from
    /// the write pool, so it is bounded per source by `git_push_advert_per_caller` to
    /// stop one source from monopolizing the write pool and shedding authenticated
    /// pushes. Fill one source IP's advert slot; its next receive-pack advertisement
    /// sheds 503, while a different source and the upload-pack advertisement are
    /// unaffected. Remove the advert-cap acquisition and the same-source assertion
    /// goes green-not-503.
    #[sqlx::test]
    async fn receive_pack_advertisement_capped_per_source(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::{Method, Request, StatusCode};
        use std::net::SocketAddr;
        use tower::ServiceExt;

        let mut state = crate::test_support::test_state(pool).await;
        state.git_push_advert_per_caller = crate::rate_limit::PerCallerConcurrency::new(1, 100);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state
            .db
            .upsert_mirror_repo("z6advcap", "ac", "/tmp/ac-nonexistent", None, false)
            .await
            .unwrap();

        let peer: SocketAddr = "203.0.113.81:6000".parse().unwrap();
        // Fill this source IP's single receive-pack-advertisement slot.
        let _slot = state
            .git_push_advert_per_caller
            .try_acquire(&peer.ip().to_string())
            .expect("first advert slot for this source IP");

        // Same source: the receive-pack advertisement sheds 503 (advert cap full).
        let router = crate::server::build_router(state.clone());
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/z6advcap/ac/info/refs?service=git-receive-pack")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        assert_eq!(
            router.oneshot(req).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a source at its receive-pack advertisement cap must shed 503, so it cannot monopolize the write pool"
        );

        // A DIFFERENT source keeps its own advert budget -> not shed.
        let other: SocketAddr = "203.0.113.82:6000".parse().unwrap();
        let router2 = crate::server::build_router(state.clone());
        let mut req2 = Request::builder()
            .method(Method::GET)
            .uri("/z6advcap/ac/info/refs?service=git-receive-pack")
            .body(Body::empty())
            .unwrap();
        req2.extensions_mut().insert(ConnectInfo(other));
        assert_ne!(
            router2.oneshot(req2).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a different source must keep its own receive-pack advertisement budget"
        );

        // The upload-pack advertisement is NOT bounded by the receive-pack advert cap.
        let router3 = crate::server::build_router(state);
        let mut req3 = Request::builder()
            .method(Method::GET)
            .uri("/z6advcap/ac/info/refs?service=git-upload-pack")
            .body(Body::empty())
            .unwrap();
        req3.extensions_mut().insert(ConnectInfo(peer));
        assert_ne!(
            router3.oneshot(req3).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "the upload-pack advertisement must not be shed by the receive-pack advert cap"
        );
    }

    /// #174 SC2 (info_refs probe): the per-caller read sub-cap sheds a caller that
    /// is already at its concurrency budget on the upload-pack advertisement, while
    /// a DIFFERENT caller still enters. Remove the sub-cap from `git_info_refs` and
    /// the same-caller assertion goes green-not-503 — this is the info_refs half of
    /// the two-handler mutation probe.
    #[sqlx::test]
    async fn info_refs_per_caller_cap_sheds_one_caller_not_others(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::{Method, Request, StatusCode};
        use std::net::SocketAddr;
        use tower::ServiceExt;

        let mut state = crate::test_support::test_state(pool).await;
        state.git_read_per_caller = crate::rate_limit::PerCallerConcurrency::new(1, 100);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state
            .db
            .upsert_mirror_repo("z6pcadv", "pc", "/tmp/pc-nonexistent", None, false)
            .await
            .unwrap();

        let peer: SocketAddr = "203.0.113.31:5000".parse().unwrap();
        // Fill this caller's single read slot (a clone shares the Arc-backed map).
        let _slot = state
            .git_read_per_caller
            .try_acquire(&peer.ip().to_string())
            .expect("first slot for this caller");

        // Same caller (IP) at its cap -> shed 503 before the git/Tigris work.
        let router = crate::server::build_router(state.clone());
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/z6pcadv/pc/info/refs?service=git-upload-pack")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        assert_eq!(
            router.oneshot(req).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a caller already at its per-caller read cap must shed the advertisement with 503"
        );

        // A DIFFERENT caller (IP) has its own budget -> not shed by the per-caller cap.
        let other: SocketAddr = "203.0.113.32:5000".parse().unwrap();
        let router2 = crate::server::build_router(state.clone());
        let mut req2 = Request::builder()
            .method(Method::GET)
            .uri("/z6pcadv/pc/info/refs?service=git-upload-pack")
            .body(Body::empty())
            .unwrap();
        req2.extensions_mut().insert(ConnectInfo(other));
        assert_ne!(
            router2.oneshot(req2).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a different caller must not be shed by another caller's saturated budget"
        );
    }

    /// #174 SC2 (upload_pack probe): the same per-caller shed on the POST
    /// upload-pack path. Remove the sub-cap from `git_upload_pack` and this goes
    /// green-not-503 — the upload_pack half of the two-handler mutation probe.
    #[sqlx::test]
    async fn upload_pack_per_caller_cap_sheds_one_caller_not_others(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::{Method, Request, StatusCode};
        use std::net::SocketAddr;
        use tower::ServiceExt;

        let mut state = crate::test_support::test_state(pool).await;
        state.git_read_per_caller = crate::rate_limit::PerCallerConcurrency::new(1, 100);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state
            .db
            .upsert_mirror_repo("z6pcupl", "pc", "/tmp/pc-nonexistent", None, false)
            .await
            .unwrap();

        let peer: SocketAddr = "203.0.113.41:5000".parse().unwrap();
        let _slot = state
            .git_read_per_caller
            .try_acquire(&peer.ip().to_string())
            .expect("first slot for this caller");

        let router = crate::server::build_router(state.clone());
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/z6pcupl/pc/git-upload-pack")
            .body(Body::from(&b"0000"[..]))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        assert_eq!(
            router.oneshot(req).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a caller already at its per-caller read cap must shed upload-pack with 503"
        );

        let other: SocketAddr = "203.0.113.42:5000".parse().unwrap();
        let router2 = crate::server::build_router(state.clone());
        let mut req2 = Request::builder()
            .method(Method::POST)
            .uri("/z6pcupl/pc/git-upload-pack")
            .body(Body::from(&b"0000"[..]))
            .unwrap();
        req2.extensions_mut().insert(ConnectInfo(other));
        assert_ne!(
            router2.oneshot(req2).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a different caller must not be shed by another caller's saturated budget"
        );
    }

    /// #174 (review fix): the per-source caller cap is an independent brake that
    /// sheds a capped source even when the global pool has free capacity — the
    /// sub-cap is not a mere pre-filter for pool exhaustion. Proven by leaving the
    /// global read pool with capacity (so the pre-DB early shed passes) AND
    /// pre-holding the source's upload-pack read sub-cap: the request reaches the
    /// caller cap and sheds there, so its 503 body reads "for this caller". Remove
    /// the `acquire_read_caller_permit` call and the capped source falls through to
    /// the git op instead of shedding with "for this caller" — this is the
    /// caller-cap acquire probe for the info/refs upload-pack branch.
    #[sqlx::test]
    async fn info_refs_upload_pack_per_source_cap_sheds_with_global_capacity(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::{Method, Request, StatusCode};
        use std::net::SocketAddr;
        use std::sync::Arc;
        use tokio::sync::Semaphore;
        use tower::ServiceExt;

        let mut state = crate::test_support::test_state(pool).await;
        // Global read pool has free capacity (early shed passes); source pre-held at
        // its per-caller cap so it sheds on the caller cap, not the global pool.
        state.git_read_semaphore = Arc::new(Semaphore::new(4));
        state.git_read_per_caller = crate::rate_limit::PerCallerConcurrency::new(1, 100);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state
            .db
            .upsert_mirror_repo("z6ordir", "oi", "/tmp/oi-nonexistent", None, false)
            .await
            .unwrap();

        let peer: SocketAddr = "203.0.113.91:5000".parse().unwrap();
        // Pin this source at its single upload-pack read slot.
        let _slot = state
            .git_read_per_caller
            .try_acquire(&peer.ip().to_string())
            .expect("first read slot for this source IP");

        let router = crate::server::build_router(state);
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/z6ordir/oi/info/refs?service=git-upload-pack")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a source at its read sub-cap must shed 503 even with global pool capacity"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let body = String::from_utf8_lossy(&bytes);
        assert!(
            body.contains("for this caller"),
            "the per-source cap is an independent brake: with global capacity free, the capped source must still shed with the caller-cap body, got {body}"
        );
    }

    /// #174 (review fix): same independent-brake guarantee for the receive-pack
    /// advertisement branch of info/refs — its per-source cap
    /// (`git_push_advert_per_caller`) sheds a capped source even when the global
    /// write pool has capacity. Leave the global write pool with capacity (so the
    /// pre-DB early shed passes) and pre-hold the source's advert slot: the request
    /// reaches the caller cap, so the 503 body reads "for this caller". Remove the
    /// caller-cap acquire and the capped source falls through instead of shedding
    /// with "for this caller". The push rate limiter is left permissive so the
    /// request reaches the caller cap.
    #[sqlx::test]
    async fn info_refs_receive_pack_per_source_cap_sheds_with_global_capacity(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::{Method, Request, StatusCode};
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::sync::Semaphore;
        use tower::ServiceExt;

        let mut state = crate::test_support::test_state(pool).await;
        // Global write pool has free capacity (early shed passes); source pre-held at
        // its advert sub-cap so it sheds on the caller cap, not the global pool.
        state.git_write_semaphore = Arc::new(Semaphore::new(4));
        state.git_push_advert_per_caller = crate::rate_limit::PerCallerConcurrency::new(1, 100);
        // Permissive push rate limiter so the advertisement passes the rate gate and
        // reaches the per-source concurrency cap.
        state.push_rate_limiter = crate::rate_limit::RateLimiter::new(100, Duration::from_secs(60));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state
            .db
            .upsert_mirror_repo("z6ordrp", "or", "/tmp/or-nonexistent", None, false)
            .await
            .unwrap();

        let peer: SocketAddr = "203.0.113.92:5000".parse().unwrap();
        // Pin this source at its single receive-pack advertisement slot.
        let _slot = state
            .git_push_advert_per_caller
            .try_acquire(&peer.ip().to_string())
            .expect("first advert slot for this source IP");

        let router = crate::server::build_router(state);
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/z6ordrp/or/info/refs?service=git-receive-pack")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a source at its advert sub-cap must shed 503 even with global write pool capacity"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let body = String::from_utf8_lossy(&bytes);
        assert!(
            body.contains("for this caller"),
            "the per-source advert cap is an independent brake: with global write capacity free, the capped source must still shed with the caller-cap body, got {body}"
        );
    }

    /// #174 (review fix): same independent-brake guarantee for the POST upload-pack
    /// handler — its per-source read cap sheds a capped source even when the global
    /// read pool has capacity. Leave the global read pool with capacity (so the
    /// pre-DB early shed passes) and pre-hold the source's read slot: the request
    /// reaches the caller cap, so the 503 body reads "for this caller". Remove the
    /// caller-cap acquire and the capped source falls through instead of shedding
    /// with "for this caller".
    #[sqlx::test]
    async fn upload_pack_per_source_cap_sheds_with_global_capacity(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::{Method, Request, StatusCode};
        use std::net::SocketAddr;
        use std::sync::Arc;
        use tokio::sync::Semaphore;
        use tower::ServiceExt;

        let mut state = crate::test_support::test_state(pool).await;
        // Global read pool has free capacity (early shed passes); source pre-held at
        // its per-caller cap so it sheds on the caller cap, not the global pool.
        state.git_read_semaphore = Arc::new(Semaphore::new(4));
        state.git_read_per_caller = crate::rate_limit::PerCallerConcurrency::new(1, 100);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state
            .db
            .upsert_mirror_repo("z6ordup", "ou", "/tmp/ou-nonexistent", None, false)
            .await
            .unwrap();

        let peer: SocketAddr = "203.0.113.93:5000".parse().unwrap();
        // Pin this source at its single read slot.
        let _slot = state
            .git_read_per_caller
            .try_acquire(&peer.ip().to_string())
            .expect("first read slot for this source IP");

        let router = crate::server::build_router(state);
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/z6ordup/ou/git-upload-pack")
            .body(Body::from(&b"0000"[..]))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a source at its read sub-cap must shed 503 even with global pool capacity"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let body = String::from_utf8_lossy(&bytes);
        assert!(
            body.contains("for this caller"),
            "the per-source cap is an independent brake: with global capacity free, the capped source must still shed with the caller-cap body, got {body}"
        );
    }

    /// #174 U3 (P1-b, RED-before/GREEN-after): a client disconnect during the
    /// path-scoped withheld-blob walk must NOT release the read admission while the
    /// uncancellable `spawn_blocking` walk is still running. The handler takes the
    /// global read permit, enters the walk (a fake git hangs on rev-list), then the
    /// request future is dropped mid-walk. With both permits moved into the blocking
    /// task the global slot stays occupied until the walk finishes; on the pre-fix code
    /// the handler-local permits drop on future-drop and the slot frees instantly (RED),
    /// letting disconnect-spam exceed the cap while real git work keeps running.
    #[sqlx::test]
    async fn upload_pack_permit_held_through_walk_after_disconnect(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::{Method, Request};
        use std::net::SocketAddr;
        use std::sync::Arc;
        use tokio::sync::Semaphore;
        use tower::ServiceExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let revlist_pid = tmp.path().join("revlist.pid");
        // Fake git: resolve refs fast, hang on rev-list (recording its pid first). The
        // ~6s sleep bounds the walk so a broken fix cannot wedge the suite.
        let body = format!(
            "#!/bin/sh\ncase \"$1\" in\n  rev-list) echo $$ > \"{}\" ; sleep 6 ;;\n  rev-parse) echo deadbeef ;;\n  *) : ;;\nesac\nexit 0\n",
            revlist_pid.display()
        );
        let git_path = tmp.path().join("fakegit");
        std::fs::write(&git_path, &body).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&git_path).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&git_path, perm).unwrap();
        }

        let mut state = crate::test_support::test_state(pool.clone()).await;
        // Root the repo store at this test's TempDir so the bare repo is isolated per
        // run (the default for_testing store uses a fixed /tmp path that would collide
        // across runs).
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.git_read_semaphore = Arc::new(Semaphore::new(1));
        state.git_bin = git_path.to_str().unwrap().to_string();
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;

        let owner = "z6up3rd";
        let name = "up3";
        state
            .db
            .upsert_mirror_repo(owner, name, "/unused", None, false)
            .await
            .unwrap();
        let rec = state.db.get_repo(owner, name).await.unwrap().unwrap();
        // Real bare repo at the path acquire() computes, so the handler reaches the walk.
        state
            .repo_store
            .init(&rec.owner_did, &rec.name)
            .await
            .unwrap();
        // A path-scoped rule so has_path_scoped_rule() is true (the walk path) without
        // denying the "/" gate for the public repo.
        state
            .db
            .set_visibility_rule(
                &rec.id,
                "src/**",
                crate::db::VisibilityMode::B,
                &["did:key:z6MkU3ReaderAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()],
                &rec.owner_did,
            )
            .await
            .unwrap();

        let sem = state.git_read_semaphore.clone();
        assert_eq!(
            sem.available_permits(),
            1,
            "one read slot before the request"
        );

        let router = crate::server::build_router(state);
        let peer: SocketAddr = "203.0.113.77:5000".parse().unwrap();
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(format!("/{owner}/{name}/git-upload-pack"))
            .body(Body::from(&b"0000"[..]))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));

        let mut fut = Box::pin(router.oneshot(req));
        // Drive until the walk's rev-list starts (its pidfile appears) — i.e. the
        // request is inside the spawn_blocking walk, holding the global read permit.
        let mut in_walk = false;
        for _ in 0..500 {
            let _ = tokio::time::timeout(std::time::Duration::from_millis(10), &mut fut).await;
            if revlist_pid.exists() {
                in_walk = true;
                break;
            }
        }
        assert!(
            in_walk,
            "the walk's rev-list must start (request reached the spawn_blocking walk)"
        );
        assert_eq!(
            sem.available_permits(),
            0,
            "the read slot is held while the walk runs"
        );

        // Client disconnect: drop the request future mid-walk.
        drop(fut);

        // Load-bearing: the slot must STAY held while the uncancellable walk runs. On
        // the pre-fix code the handler-local permits drop here and the slot frees at
        // once (RED).
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(
            sem.available_permits(),
            0,
            "on disconnect the read admission must be held until the spawn_blocking walk \
             finishes, not released the instant the future drops (P1-b)"
        );

        // Cleanup: let the walk finish so the slot releases and no blocking task leaks.
        for _ in 0..400 {
            if sem.available_permits() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        if let Some(p) = std::fs::read_to_string(&revlist_pid)
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok())
        {
            unsafe {
                libc::kill(p, libc::SIGKILL);
            }
        }
    }

    /// #174 U1 (P1-a, plain-spawn residual, RED-before/GREEN-after): on the PLAIN
    /// (non-path-scoped) upload-pack path a client disconnect must NOT release the
    /// global read admission while the detached process-group reaper is still tearing
    /// down a git group that ignores SIGTERM. The `be0cdd6` fix moved permits into the
    /// path-scoped `spawn_blocking` walk; this closes the residual plain path, where the
    /// permits were handler-locals that dropped the instant the future was dropped.
    ///
    /// Isolate the GLOBAL pool: read pool = 1, per-source cap + rate limiter permissive,
    /// so the only thing that can shed a replacement is the leaked global permit. Drive
    /// the handler until git spawns, disconnect, then assert the global slot stays held
    /// (`available_permits() == 0`) AND a replacement sheds 503 while the group is alive;
    /// after the reaper SIGKILLs+reaps the group the slot frees and a replacement is no
    /// longer shed by the global cap. On the pre-fix code the handler-local permit drops
    /// on future-drop and the slot frees at once (RED).
    #[cfg(unix)]
    #[sqlx::test]
    async fn upload_pack_plain_permit_held_through_group_reap_after_disconnect(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::{Method, Request, StatusCode};
        use std::net::SocketAddr;
        use std::sync::Arc;
        use tokio::sync::Semaphore;
        use tower::ServiceExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let descfile = tmp.path().join("desc.pid");
        // Fake git for the plain upload-pack path (invoked as `git upload-pack
        // --stateless-rpc <repo>`). It forks a descendant that TRAPS SIGTERM, records its
        // pid, and loops ~20s, then `wait`s — so on disconnect the group leader dies on
        // the reaper's SIGTERM but the descendant survives until the reaper escalates to
        // SIGKILL, keeping the group alive (ESRCH not reached) across the observation
        // window. Bounded so a broken fix leaks no permanent orphan.
        let body = format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
               upload-pack)\n\
                 sh -c 'trap \"\" TERM; echo $$ > \"{}\"; i=0; while [ $i -lt 20 ]; do sleep 1; i=$((i+1)); done' &\n\
                 wait ;;\n\
               *) : ;;\n\
             esac\n\
             exit 0\n",
            descfile.display()
        );
        let git_path = tmp.path().join("fakegit");
        std::fs::write(&git_path, &body).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&git_path).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&git_path, perm).unwrap();
        }

        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        // Isolate the global read pool: size 1; per-source cap + rate limiter permissive
        // so only the leaked global permit can shed the replacement.
        state.git_read_semaphore = Arc::new(Semaphore::new(1));
        state.git_read_per_caller = crate::rate_limit::PerCallerConcurrency::new(1000, 1000);
        state.git_bin = git_path.to_str().unwrap().to_string();
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;

        let owner = "z6up1st";
        let name = "up1";
        state
            .db
            .upsert_mirror_repo(owner, name, "/unused", None, false)
            .await
            .unwrap();
        let rec = state.db.get_repo(owner, name).await.unwrap().unwrap();
        // Real bare repo at the path acquire() computes, so the handler reaches the
        // spawn. No path-scoped rule -> the PLAIN serve branch (this test's target).
        state
            .repo_store
            .init(&rec.owner_did, &rec.name)
            .await
            .unwrap();

        let sem = state.git_read_semaphore.clone();
        assert_eq!(
            sem.available_permits(),
            1,
            "one read slot before the request"
        );

        let router = crate::server::build_router(state);
        let make_req = |peer: SocketAddr| {
            let mut req = Request::builder()
                .method(Method::POST)
                .uri(format!("/{owner}/{name}/git-upload-pack"))
                .body(Body::from(&b"0000"[..]))
                .unwrap();
            req.extensions_mut().insert(ConnectInfo(peer));
            req
        };

        let peer: SocketAddr = "203.0.113.71:5000".parse().unwrap();
        let mut fut = Box::pin(router.clone().oneshot(make_req(peer)));
        // Drive until git spawns (the descendant records its pid) — the request is
        // inside the plain serve, holding the global read permit. Stop polling the
        // instant the future completes (re-polling a completed oneshot panics); read the
        // descfile first so a spawn that recorded its pid then returned is still caught.
        let mut spawned: Option<i32> = None;
        let mut early = None;
        for _ in 0..500 {
            let done = tokio::time::timeout(std::time::Duration::from_millis(10), &mut fut).await;
            if let Some(p) = std::fs::read_to_string(&descfile)
                .ok()
                .and_then(|s| s.trim().parse::<i32>().ok())
            {
                spawned = Some(p);
                break;
            }
            if let Ok(resp) = done {
                early = Some(resp.map(|r| r.status()));
                break;
            }
        }
        let desc = spawned
            .unwrap_or_else(|| panic!("the fake git must have spawned; early finish: {early:?}"));
        // Kill the descendant regardless of outcome so a RED run leaks no orphan.
        struct ReapOnDrop(i32);
        impl Drop for ReapOnDrop {
            fn drop(&mut self) {
                unsafe {
                    libc::kill(self.0, libc::SIGKILL);
                }
            }
        }
        let _cleanup = ReapOnDrop(desc);
        assert!(
            unsafe { libc::kill(desc, 0) == 0 },
            "descendant should be running before the disconnect"
        );
        assert_eq!(
            sem.available_permits(),
            0,
            "the read slot is held while the git op runs"
        );

        // Client disconnect: drop the request future. The detached reaper now owns the
        // AdmissionGuard and will not drop it until the group is ESRCH-confirmed reaped.
        drop(fut);

        // Load-bearing: the slot must STAY held while the SIGTERM-ignoring group is still
        // alive. On the pre-fix code the handler-local permit drops here and the slot
        // frees at once (RED). Check quickly (before the reaper's ~2s SIGKILL escalation).
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            unsafe { libc::kill(desc, 0) == 0 },
            "the SIGTERM-ignoring descendant must still be alive during the hold window"
        );
        assert_eq!(
            sem.available_permits(),
            0,
            "on disconnect the read admission must be HELD until the process group is \
             reaped, not released the instant the future drops (P1-a)"
        );
        // A replacement request from a DIFFERENT source must shed 503 — the only pool
        // that can shed it is the leaked global permit (per-source cap is permissive).
        let peer2: SocketAddr = "203.0.113.72:5000".parse().unwrap();
        let resp = router.clone().oneshot(make_req(peer2)).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "while the prior group is still alive the held global permit must shed a \
             replacement with 503"
        );

        // After the reaper SIGKILLs + reaps the group the AdmissionGuard drops and the
        // slot frees. Poll for recovery.
        let mut freed = false;
        for _ in 0..400 {
            if sem.available_permits() == 1 {
                freed = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            freed,
            "once the reaper confirms the group gone the admission guard must drop and \
             free the global slot"
        );
        // A replacement is now no longer shed by the global cap (it proceeds past
        // admission; it then fails downstream on the fake git, which is not a 503).
        let peer3: SocketAddr = "203.0.113.73:5000".parse().unwrap();
        let resp = router.oneshot(make_req(peer3)).await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "after the group is reaped the freed slot must admit a replacement"
        );
    }

    /// #174 U1 (P1-a): the `None`-key arm — a request with no resolvable source key
    /// (no trusted-proxy header, no peer) is bounded by the GLOBAL read pool only, never
    /// a per-source cap. With the global read pool exhausted such a request still sheds
    /// 503, proving the plain path admits/sheds on the global pool for the `None` arm
    /// (the counterpart to the `Some(ip)` arm above). Complements the resolver-arm rule:
    /// neither arm is vacuous.
    #[tokio::test]
    async fn upload_pack_plain_none_key_arm_sheds_on_global_pool() {
        use axum::body::Body;
        use axum::http::{Method, Request, StatusCode};
        use axum::Router;
        use std::sync::Arc;
        use tokio::sync::Semaphore;
        use tower::ServiceExt;

        let mut state = crate::test_support::test_state_lazy();
        // Global read pool exhausted; per-source cap permissive so only the global pool
        // can shed. No ConnectInfo + no trusted header -> read_caller_key resolves None.
        state.git_read_semaphore = Arc::new(Semaphore::new(0));
        state.git_read_per_caller = crate::rate_limit::PerCallerConcurrency::new(1000, 1000);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;

        let router = Router::new()
            .route(
                "/{owner}/{repo}/git-upload-pack",
                axum::routing::post(crate::api::repos::git_upload_pack),
            )
            .with_state(state);
        // No ConnectInfo extension and no XFF header: the caller key is None.
        let req = Request::builder()
            .method(Method::POST)
            .uri("/alice/repo.git/git-upload-pack")
            .body(Body::from(&b"0000"[..]))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a None-key request must still shed 503 on the exhausted GLOBAL read pool"
        );
    }

    /// #174 U4 (P1-d, RED-before/GREEN-after): the authenticated receive-pack POST
    /// carries a per-source WRITE sub-cap so one source IP cannot monopolize the write
    /// pool with many slow pushes (owner enforcement defaults off, so disposable DIDs
    /// are free). Global write pool has capacity; the source is pre-held at its single
    /// write slot. A push from THAT source sheds (Overloaded/503) — which also proves
    /// the PeerAddr+HeaderMap extractors resolve a key (without them the key is None and
    /// the cap is inert, never shedding). A push from a DIFFERENT source is NOT shed by
    /// the cap. Called directly so the test needs no signed request; the handler is
    /// where the cap lives. Remove the `git_write_per_caller` acquire and the capped
    /// source no longer sheds (RED).
    #[sqlx::test]
    async fn receive_pack_per_source_write_cap_sheds_capped_source_not_others(pool: sqlx::PgPool) {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;
        use std::sync::Arc;
        use tokio::sync::Semaphore;

        let mut state = crate::test_support::test_state(pool).await;
        // Global write pool has capacity; the per-source cap is 1.
        state.git_write_semaphore = Arc::new(Semaphore::new(4));
        state.git_write_per_caller = crate::rate_limit::PerCallerConcurrency::new(1, 100);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state
            .db
            .upsert_mirror_repo("z6rp4wr", "rp4", "/tmp/rp4-nonexistent", None, false)
            .await
            .unwrap();

        let did = "did:key:z6MkReceivePackWriteCapProofDidAAAAAAAAAA";
        let capped: SocketAddr = "203.0.113.44:5000".parse().unwrap();
        let other: SocketAddr = "203.0.113.45:5000".parse().unwrap();

        // Pin the capped source at its single write slot.
        let _slot = state
            .git_write_per_caller
            .try_acquire(&capped.ip().to_string())
            .expect("first write slot for the capped source IP");

        // A push from the capped source must shed on the per-source write cap even with
        // global write capacity free. The shed also proves the source-IP key resolved
        // via the extractors (an inert None key would fall through to Ok(None)).
        let capped_result = git_receive_pack(
            State(state.clone()),
            Path(("z6rp4wr".to_string(), "rp4".to_string())),
            Extension(crate::auth::AuthenticatedDid(did.to_string())),
            crate::rate_limit::PeerAddr(Some(capped)),
            axum::http::HeaderMap::new(),
            axum::body::Bytes::from_static(b"0000"),
        )
        .await;
        assert!(
            matches!(capped_result, Err(AppError::Overloaded(_))),
            "a source at its per-source write cap must shed (Overloaded/503) with global \
             pool capacity free; got {capped_result:?}"
        );

        // A push from a DIFFERENT source must NOT be shed by the per-source cap — it
        // proceeds past admission (and fails later on the nonexistent repo, which is not
        // an Overloaded error).
        let other_result = git_receive_pack(
            State(state.clone()),
            Path(("z6rp4wr".to_string(), "rp4".to_string())),
            Extension(crate::auth::AuthenticatedDid(did.to_string())),
            crate::rate_limit::PeerAddr(Some(other)),
            axum::http::HeaderMap::new(),
            axum::body::Bytes::from_static(b"0000"),
        )
        .await;
        assert!(
            !matches!(other_result, Err(AppError::Overloaded(_))),
            "a different source must not be shed by the per-source write cap while the \
             capped source holds its slot; got {other_result:?}"
        );
    }

    /// #174 U2 (P1-2, RED-before/GREEN-after): the storage-acquisition phase is bounded
    /// by `git_acquire_timeout_secs`, so a stalled backend releases the admission permit
    /// and sheds a 503 instead of pinning the pool. The permit is taken BEFORE
    /// `acquire_write`, whose advisory-lock loop can spin ~60s (and whose per-iteration
    /// `pg_try_advisory_lock` can block indefinitely on a hung pool), so without the
    /// `tokio::time::timeout` wrapper the permit is held far past the deadline.
    ///
    /// Real stall (no `RepoStore` trait to fake): hold the SAME session-level advisory
    /// lock `acquire_write` derives (`advisory_lock_key(owner_slug, repo_name)`, where
    /// `owner_slug = owner_did.replace([':','/'], "_")`) on a second pooled connection,
    /// so the handler's `pg_try_advisory_lock` returns false every iteration and the loop
    /// must retry against the deadline. `git_acquire_timeout_secs = 2`; the request must
    /// return 503 (Overloaded) at ~2s (NOT ~59s), and the write permit must be released
    /// (`available_permits()` recovers to full once the shed returns). Covers R2.
    ///
    /// Load-bearing / mutation: remove the `tokio::time::timeout` wrapper on
    /// `acquire_write` and the loop runs to ~59s with the permit held the whole time —
    /// the `< DEADLINE_CEILING` timing assertion goes RED (observed ~59s) and the permit
    /// stays pinned past the deadline. Restore to return GREEN.
    #[sqlx::test]
    async fn receive_pack_acquire_deadline_sheds_and_releases_permit(pool: sqlx::PgPool) {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;
        use std::sync::Arc;
        use tokio::sync::Semaphore;

        // Reproduce acquire_write's session-level advisory-lock key exactly so the
        // second-connection lock collides with the handler's pg_try_advisory_lock
        // (repo_store.rs: advisory_lock_key over owner_slug then repo_name).
        fn advisory_lock_key(owner_slug: &str, repo_name: &str) -> i64 {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            owner_slug.hash(&mut hasher);
            repo_name.hash(&mut hasher);
            hasher.finish() as i64
        }

        let owner = "z6acqdead";
        let name = "acq1";
        // owner_slug as local_path() computes it from the record's owner_did. The
        // mirror row stores the short owner as owner_did, so slug == owner (no ':'/'/').
        let owner_slug = owner.replace([':', '/'], "_");
        let lock_key = advisory_lock_key(&owner_slug, name);

        let mut state = crate::test_support::test_state(pool.clone()).await;
        // Isolate the write pool at size 1 so available_permits() cleanly reports
        // held (0) vs released (1). Per-source cap + trust permissive so only the
        // write pool / acquire path can gate.
        state.git_write_semaphore = Arc::new(Semaphore::new(1));
        state.git_write_per_caller = crate::rate_limit::PerCallerConcurrency::new(1000, 1000);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        // Short acquire deadline: the fix must shed here, well before acquire_write's
        // ~59s advisory-lock loop would bail on its own.
        const ACQUIRE_TIMEOUT_SECS: u64 = 2;
        let mut cfg = (*state.config).clone();
        cfg.git_acquire_timeout_secs = ACQUIRE_TIMEOUT_SECS;
        // Keep the git-service timeout large so the deadline under test is the acquire
        // one, not git execution (which is never reached on the stalled path anyway).
        cfg.git_service_timeout_secs = 600;
        state.config = std::sync::Arc::new(cfg);

        state
            .db
            .upsert_mirror_repo(owner, name, "/tmp/z6acqdead-acq1", None, false)
            .await
            .unwrap();

        // Hold the advisory lock on a dedicated pooled connection (a distinct session),
        // so the handler's pg_try_advisory_lock($lock_key) returns false every iteration
        // and acquire_write's real loop must retry against the deadline. Released when
        // this connection drops at end of test.
        let mut lock_conn = pool
            .acquire()
            .await
            .expect("second connection for the lock");
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(lock_key)
            .execute(&mut *lock_conn)
            .await
            .expect("hold the advisory lock on the second connection");

        let did = "did:key:z6MkAcquireDeadlineProofDidAAAAAAAAAAAAAAAA";
        let peer: SocketAddr = "203.0.113.61:5000".parse().unwrap();

        let sem = state.git_write_semaphore.clone();
        assert_eq!(
            sem.available_permits(),
            1,
            "one write slot before the request"
        );

        // Drive the authenticated push in the background so we can observe the permit is
        // held while acquire_write stalls, then that it is released on the shed.
        let state_for_task = state.clone();
        let start = std::time::Instant::now();
        let handle = tokio::spawn(async move {
            git_receive_pack(
                State(state_for_task),
                Path((owner.to_string(), name.to_string())),
                Extension(crate::auth::AuthenticatedDid(did.to_string())),
                crate::rate_limit::PeerAddr(Some(peer)),
                axum::http::HeaderMap::new(),
                axum::body::Bytes::from_static(b"0000"),
            )
            .await
        });

        // The handler takes the write permit BEFORE acquire_write, so once it is stalled
        // in the advisory-lock loop the pool reports 0 available. Wait for that to prove
        // the permit is genuinely held during the stall (and the request really reached
        // acquire_write, not an earlier reject).
        let mut held = false;
        for _ in 0..200 {
            if sem.available_permits() == 0 {
                held = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            held,
            "the write permit must be held while acquire_write stalls on the advisory lock"
        );

        // The bounded acquire deadline must shed with 503 (Overloaded), NOT wait out the
        // ~59s advisory-lock loop. Ceiling is comfortably above the 2s deadline + task
        // scheduling but far below 59s, so a RED run (no wrapper -> ~59s) fails here.
        const DEADLINE_CEILING: std::time::Duration = std::time::Duration::from_secs(20);
        let result = tokio::time::timeout(
            DEADLINE_CEILING + std::time::Duration::from_secs(10),
            handle,
        )
        .await
        .expect("the handler must return within the ceiling — a hang means the acquire deadline is missing (RED)")
        .expect("the receive-pack task must not panic");
        let elapsed = start.elapsed();

        assert!(
            matches!(result, Err(AppError::Overloaded(_))),
            "a stalled acquire_write must shed with Overloaded/503 at the acquire deadline; \
             got {result:?}"
        );
        assert!(
            elapsed < DEADLINE_CEILING,
            "the shed must land at ~{ACQUIRE_TIMEOUT_SECS}s (the acquire deadline), not ~59s \
             (the advisory-lock loop). Observed {elapsed:?}; without the timeout wrapper this \
             is ~59s (RED)"
        );

        // Permit release on expiry: the Overloaded return drops the handler-local permit,
        // so the isolated write pool must recover to full. A leaked permit here means the
        // pool drains under a stalled backend (the #174 P1-2 bug).
        let mut freed = false;
        for _ in 0..200 {
            if sem.available_permits() == 1 {
                freed = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            freed,
            "on the acquire-deadline shed the write permit must be released; the pool did \
             not recover to full (permit leaked)"
        );

        // Follow-up admits once the contended lock is released: release the second-conn
        // lock, then a fresh push proceeds PAST admission (it fails later on the
        // nonexistent on-disk repo, which is NOT an Overloaded/503). Proves the freed
        // slot is usable, not merely counted.
        sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(lock_key)
            .execute(&mut *lock_conn)
            .await
            .expect("release the advisory lock");
        let followup = git_receive_pack(
            State(state.clone()),
            Path((owner.to_string(), name.to_string())),
            Extension(crate::auth::AuthenticatedDid(did.to_string())),
            crate::rate_limit::PeerAddr(Some("203.0.113.62:5000".parse().unwrap())),
            axum::http::HeaderMap::new(),
            axum::body::Bytes::from_static(b"0000"),
        )
        .await;
        assert!(
            !matches!(followup, Err(AppError::Overloaded(_))),
            "once the lock frees, a follow-up push must admit past the (recovered) write \
             pool and acquire; got {followup:?}"
        );
    }

    /// #174 U5 (P1-e, RED-before/GREEN-after): the post-push encryption walk acquires a
    /// `git_encrypt_semaphore` permit before running, so completed pushes cannot spawn
    /// unbounded concurrent full-history walks. With the pool exhausted the gated walk
    /// must DEFER (block on admission) and NOT run its rev-list; on the pre-fix code
    /// (no acquire) the walk runs regardless of the pool (RED). It defers rather than
    /// sheds — releasing the permit lets the SAME walk run and pin (durability stays
    /// fail-closed). Exercises the gating seam directly; the detached push task calls
    /// this exact helper.
    #[tokio::test]
    async fn encrypt_walk_defers_when_pool_exhausted() {
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::sync::Semaphore;

        let tmp = tempfile::TempDir::new().unwrap();
        let marker = tmp.path().join("revlist.ran");
        // Fake git records when rev-list runs (the walk's first git call).
        let body = format!(
            "#!/bin/sh\ncase \"$1\" in\n  rev-list) echo ran > \"{}\" ;;\n  *) : ;;\nesac\nexit 0\n",
            marker.display()
        );
        let git_path = tmp.path().join("fakegit");
        std::fs::write(&git_path, &body).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&git_path).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&git_path, perm).unwrap();
        }
        let git_bin = git_path.to_str().unwrap().to_string();
        let owner = "did:key:z6MkEncWalkOwnerAAAAAAAAAAAAAAAAAAAAAAAA".to_string();

        // Exhaust the pool: hold its only permit so a gated walk must defer.
        let sem = Arc::new(Semaphore::new(1));
        let held = sem.clone().acquire_owned().await.unwrap();

        // Blocked: the gated walk must NOT complete or run rev-list while exhausted.
        let blocked = tokio::time::timeout(
            Duration::from_millis(500),
            withheld_recipients_gated(
                sem.clone(),
                tmp.path().to_path_buf(),
                git_bin.clone(),
                Duration::from_secs(5),
                Vec::new(),
                true,
                owner.clone(),
            ),
        )
        .await;
        assert!(
            blocked.is_err(),
            "the encryption walk must defer (block on admission) when the pool is exhausted"
        );
        assert!(
            !marker.exists(),
            "the walk's rev-list must not run while its admission permit is unavailable (P1-e)"
        );

        // Release admission: the SAME walk now runs (defer, not shed) — rev-list fires.
        drop(held);
        let ran = withheld_recipients_gated(
            sem,
            tmp.path().to_path_buf(),
            git_bin,
            Duration::from_secs(5),
            Vec::new(),
            true,
            owner,
        )
        .await;
        assert!(
            ran.is_ok(),
            "with a permit the walk runs and joins: {ran:?}"
        );
        assert!(
            marker.exists(),
            "once admission is available the deferred walk runs its rev-list"
        );
    }

    // ---- #174 U4 (P2-2): post-push encryption task set bounded by per-repo coalescing ----
    //
    // The residual jatmn found is not the WALK (bounded by `git_encrypt_semaphore`,
    // proven by `encrypt_walk_defers_when_pool_exhausted` above) but the OUTER
    // `tokio::spawn` + its parked `acquire_owned().await` waiters: N rapid pushes to a
    // repo spawn N tasks that each park holding cloned object lists/rules/keys — an
    // unbounded outstanding set. U4 bounds it by coalescing per repo: before spawning,
    // if a task for the repo is in flight, skip the duplicate. Crucially this DEFERS a
    // duplicate walk (the newer push's objects are covered by the pending one) and does
    // NOT shed — there is no reconciliation sweep, so a dropped job would permanently
    // lose the withheld-blob recovery copy (`2a54c15`'s fail-closed durability stance).
    //
    // These drive the coalescing seam (`EncryptInflight`) that the detached spawn at
    // `repos.rs` consults directly (the try_begin gate on the in-flight set, guarded by
    // `withheld.is_some()`). Observing `encrypt_and_pin`'s IPFS effect end-to-end needs a live IPFS node
    // (`pin_git_object` hits the API), so the durability property is proven at this
    // layer: a coalesced repo's key is released when its task ends, so a later push for
    // that repo is processed once — NOT permanently skipped, which is exactly what a
    // coalesce->shed mutation would break by dropping the job with no sweep to recover it.

    /// Bounded outstanding set under saturation (R4). Simulate K rapid path-scoped
    /// pushes to the SAME repo while the encrypt pool is saturated (every spawned task
    /// would park, so none has finished and removed its key): the first `try_begin`
    /// admits (spawns), the rest coalesce (skip). The in-flight set holds at 1, not K.
    ///
    /// MUTATION (RED): removing the coalescing check makes every push spawn — modeled by
    /// `simulate_without_coalescing`, which reaches K. If the coalesced count equaled the
    /// un-coalesced one the gate would be a no-op; the strict inequality proves it bites.
    #[test]
    fn u4_outstanding_encrypt_set_is_bounded_to_one_per_repo_under_saturation() {
        let inflight = crate::state::EncryptInflight::new();
        let repo = "did:key:z6MkRepoOwnerAAAAAAAAAAAAAAAAAAAAAAAAAAAA/proj";
        const K: usize = 32;

        // Hold every admitted guard so the tasks are "still in flight" (the saturated
        // case: all parked on acquire_owned().await, none finished, none removed a key).
        let mut admitted = Vec::new();
        let mut coalesced = 0usize;
        for _ in 0..K {
            match inflight.try_begin(repo) {
                Some(g) => admitted.push(g),
                None => coalesced += 1,
            }
        }

        assert_eq!(
            admitted.len(),
            1,
            "exactly ONE detached task may spawn per repo while one is in flight — the \
             outstanding set is bounded to 1, not K parked waiters"
        );
        assert_eq!(
            coalesced,
            K - 1,
            "the other K-1 rapid pushes to the same repo coalesce (skip spawning)"
        );
        assert_eq!(
            inflight.len(),
            1,
            "the in-flight set holds at most one entry per repo under saturation"
        );

        let no_coalesce = simulate_without_coalescing(K);
        assert_eq!(
            no_coalesce, K,
            "sanity: without the coalescing check all K pushes spawn (the unbounded set \
             the fix prevents) — proves the bound above is not vacuously 1"
        );
        assert!(
            admitted.len() < no_coalesce,
            "coalesced set ({}) must be strictly smaller than the un-coalesced one ({})",
            admitted.len(),
            no_coalesce
        );
    }

    /// Coalescing is PER-REPO: distinct repos are never coalesced against each other, so
    /// one repo in flight cannot starve a second repo's recovery copy.
    #[test]
    fn u4_distinct_repos_each_admit_one_encrypt_task() {
        let inflight = crate::state::EncryptInflight::new();
        let a = inflight.try_begin("owner/repo-a");
        let b = inflight.try_begin("owner/repo-b");
        let c = inflight.try_begin("owner/repo-c");
        assert!(
            a.is_some() && b.is_some() && c.is_some(),
            "three distinct repos each admit their own encryption task"
        );
        assert_eq!(inflight.len(), 3, "one in-flight entry per distinct repo");
    }

    /// NO LOST RECOVERY COPY — the security guard (R4/R6). Coalescing must DELAY a
    /// duplicate walk, never permanently drop a repo's recovery copy. Observable
    /// property: once an in-flight task ENDS (its guard drops — completion, error, or
    /// panic-unwind) the repo key is released, so the NEXT push for that repo is admitted
    /// and processed again. A coalesce->shed mutation would drop the job AND never
    /// re-admit — with no reconciliation sweep the copy is lost forever. Here re-admission
    /// survives normal completion AND a panic, so no permanent skip / no leaked key.
    #[test]
    fn u4_coalesced_repo_is_reprocessed_after_task_ends_not_permanently_skipped() {
        let inflight = crate::state::EncryptInflight::new();
        let repo = "did:key:z6MkDurableRepoBBBBBBBBBBBBBBBBBBBBBBBBB/repo";

        // Push #1 admits and "spawns". A concurrent push #2 (task #1 still in flight)
        // coalesces — no duplicate spawn.
        let guard1 = inflight.try_begin(repo).expect("first push admits");
        assert!(
            inflight.try_begin(repo).is_none(),
            "while task #1 is in flight, push #2 to the same repo coalesces"
        );

        // Task #1 finishes (encrypt_and_pin ran or errored): guard drops, key released.
        drop(guard1);
        assert_eq!(
            inflight.len(),
            0,
            "when the in-flight task ends its repo key is released — the set does not leak"
        );

        // A LATER push for the SAME repo is admitted again (processed, not skipped
        // forever). This is what coalesce->shed breaks: shed drops the job and no sweep
        // re-derives the missing copy, so the recovery copy is permanently lost.
        let guard2 = inflight.try_begin(repo).expect(
            "a later push for a coalesced repo MUST be re-admitted — durability: the \
             deferred recovery copy is produced eventually, never dropped",
        );
        drop(guard2);
        assert_eq!(inflight.len(), 0);

        // Durability across PANIC: a task that panics mid-walk must still release its key
        // (Drop runs on unwind), so one crashed walk never permanently locks a repo out
        // of future recovery copies.
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = inflight.try_begin(repo).expect("admit before the panic");
            assert_eq!(inflight.len(), 1);
            panic!("simulate the detached encryption task panicking mid-walk");
        }));
        assert!(panicked.is_err(), "the simulated task panicked");
        assert_eq!(
            inflight.len(),
            0,
            "a panicked encryption task still releases its repo key (Drop on unwind) — no \
             permanent leak that would block every future recovery copy for the repo"
        );
        assert!(
            inflight.try_begin(repo).is_some(),
            "after a panicked task the repo can still be admitted — durability preserved"
        );
    }

    /// Degenerate state: the first push on a cold/empty in-flight set always admits
    /// (never a false coalesce on an empty set).
    #[test]
    fn u4_first_push_on_a_cold_set_always_admits() {
        let inflight = crate::state::EncryptInflight::new();
        assert!(inflight.is_empty(), "cold set is empty");
        assert!(
            inflight.try_begin("owner/first").is_some(),
            "the first push on a cold in-flight set must admit (never falsely coalesce)"
        );
    }

    // ---- U3 (#173 F3): dirty-flag requeue seam (the mechanics behind the end-to-end
    // requeue tests in test_support.rs) ----

    /// A coalesced push MARKS the repo dirty (not just "skip"), and the in-flight task's
    /// tail check-and-clear then runs ONE more pass before releasing: `requeue_or_release`
    /// returns `true` (loop) while dirty, clearing the flag, then `false` (release) when
    /// clean. This is the mechanism that makes a coalesced push requeued, not dropped.
    #[test]
    fn u3_try_begin_marks_dirty_then_requeue_loops_once_then_releases() {
        let inflight = crate::state::EncryptInflight::new();
        let repo = "did:key:z6MkU3DirtyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/proj";

        let mut guard = inflight.try_begin(repo).expect("first push admits");
        assert_eq!(inflight.dirty(repo), Some(false), "fresh task starts clean");

        // A push coalesces during the in-flight window: marked dirty, no new task.
        assert!(
            inflight.try_begin(repo).is_none(),
            "coalesced push does not spawn"
        );
        assert_eq!(
            inflight.dirty(repo),
            Some(true),
            "the coalesced push marked the repo dirty"
        );

        // Task tail, pass 1: dirty -> requeue (clear the flag, keep the key, loop).
        assert!(
            guard.requeue_or_release(),
            "dirty repo requeues one more pass"
        );
        assert_eq!(
            inflight.dirty(repo),
            Some(false),
            "the dirty flag is cleared for the next pass"
        );
        assert_eq!(
            inflight.len(),
            1,
            "the key is still held while the task loops"
        );

        // Task tail, pass 2: clean -> release (remove the key, exit).
        assert!(
            !guard.requeue_or_release(),
            "a clean repo releases and exits"
        );
        assert_eq!(inflight.len(), 0, "the key is removed on the clean release");
        assert_eq!(
            inflight.dirty(repo),
            None,
            "no in-flight entry after release"
        );
    }

    /// The check-and-clear is ATOMIC with the release decision, so no push lands in a
    /// "checked clean but still present" gap (scenario 6, race gap). A push that arrives
    /// BEFORE the tail check sets dirty -> the same pass requeues it. A push that arrives
    /// AFTER a clean release finds an empty set -> `try_begin` spawns a fresh task. Both
    /// directions covered; neither drops the push.
    #[test]
    fn u3_requeue_or_release_leaves_no_uncovered_gap() {
        let inflight = crate::state::EncryptInflight::new();
        let repo = "did:key:z6MkU3GapBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB/proj";

        // Case A: push arrives before the tail check -> requeue covers it.
        let mut guard = inflight.try_begin(repo).expect("admit");
        assert!(
            inflight.try_begin(repo).is_none(),
            "push arrives during the window"
        );
        assert!(
            guard.requeue_or_release(),
            "the pre-check push is covered by a requeue"
        );
        // Now clean: the task releases and exits.
        assert!(!guard.requeue_or_release(), "clean -> release");
        assert_eq!(inflight.len(), 0);

        // Case B: a push arriving after release starts a brand-new task (not dropped).
        let guard2 = inflight.try_begin(repo);
        assert!(
            guard2.is_some(),
            "a post-release push spawns a fresh task, never dropped"
        );
    }

    /// Drop is a PANIC BACKSTOP only. A task that panics before releasing still frees the
    /// key (so a crashed walk never permanently locks the repo out); a task that releases
    /// via `requeue_or_release` and then drops does not double-free.
    #[test]
    fn u3_drop_is_panic_backstop_for_unreleased_guard() {
        let inflight = crate::state::EncryptInflight::new();
        let repo = "did:key:z6MkU3PanicCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC/proj";

        // Normal release then drop: key already gone, drop is a no-op.
        let mut g = inflight.try_begin(repo).expect("admit");
        assert!(!g.requeue_or_release(), "clean release");
        assert_eq!(inflight.len(), 0);
        drop(g);
        assert_eq!(
            inflight.len(),
            0,
            "dropping an already-released guard does not resurrect a key"
        );

        // Panic before releasing: Drop-on-unwind frees the key.
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = inflight.try_begin(repo).expect("admit before panic");
            assert_eq!(inflight.len(), 1);
            panic!("task panics before reaching its tail check-and-clear");
        }));
        assert!(panicked.is_err(), "the simulated task panicked");
        assert_eq!(
            inflight.len(),
            0,
            "a panic before release still frees the key (backstop), so the repo is not locked out"
        );
        assert!(
            inflight.try_begin(repo).is_some(),
            "the repo can be admitted again after a panic"
        );
    }

    /// Model of the pre-fix / mutated code: no coalescing check, so every push spawns.
    /// Returns the count of tasks spawned (== the size of the unbounded outstanding set
    /// the fix prevents), used as the RED comparison in the bound test above.
    fn simulate_without_coalescing(pushes: usize) -> usize {
        (0..pushes).count()
    }

    /// #174 SC2 (per-source key, U1): the per-caller read sub-cap keys on the
    /// resolved source IP, NOT the signed DID, so a disposable-DID farm cannot
    /// multiply its budget. Fill the source IP's single read slot, then drive two
    /// requests signed under DIFFERENT DIDs from that SAME IP: both must shed 503
    /// (keyed by the saturated IP, not their own free DID slots). A signed request
    /// from a DIFFERENT source IP keeps its own budget. Revert `read_caller_key` to
    /// prefer the DID and the same-IP assertions go green-not-503 (each fresh DID
    /// gets a free slot) -- the farm-defeat mutation probe.
    #[sqlx::test]
    async fn info_refs_per_caller_cap_keys_on_ip_not_did(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::{Method, Request, StatusCode};
        use std::net::SocketAddr;
        use tower::ServiceExt;

        let mut state = crate::test_support::test_state(pool).await;
        state.git_read_per_caller = crate::rate_limit::PerCallerConcurrency::new(1, 100);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state
            .db
            .upsert_mirror_repo("z6pcip", "pc", "/tmp/pc-nonexistent", None, false)
            .await
            .unwrap();

        let did_a = "did:key:z6MkPerCallerKeyingProofDidAAAAAAAAAAAAAAAA";
        let did_b = "did:key:z6MkPerCallerKeyingProofDidBBBBBBBBBBBBBBBB";
        let peer: SocketAddr = "203.0.113.51:5000".parse().unwrap();

        // Fill the SOURCE IP's single read slot; both DIDs' own slots stay free.
        let _slot = state
            .git_read_per_caller
            .try_acquire(&peer.ip().to_string())
            .expect("first slot for this source IP");

        // Signed as DID_A from `peer`: keyed by the saturated source IP -> shed 503.
        let router = crate::server::build_router(state.clone());
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/z6pcip/pc/info/refs?service=git-upload-pack")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        req.extensions_mut()
            .insert(crate::auth::AuthenticatedDid(did_a.to_string()));
        assert_eq!(
            router.oneshot(req).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a signed caller must be keyed by its source IP, not its DID: the saturated IP must shed it 503"
        );

        // Same IP, a DIFFERENT DID: still keyed by the same saturated IP -> also shed.
        // The farm defeat: minting a fresh DID buys no fresh per-source budget.
        let router2 = crate::server::build_router(state.clone());
        let mut req2 = Request::builder()
            .method(Method::GET)
            .uri("/z6pcip/pc/info/refs?service=git-upload-pack")
            .body(Body::empty())
            .unwrap();
        req2.extensions_mut().insert(ConnectInfo(peer));
        req2.extensions_mut()
            .insert(crate::auth::AuthenticatedDid(did_b.to_string()));
        assert_eq!(
            router2.oneshot(req2).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a second DID from the same source IP must also shed 503: a DID farm cannot multiply the per-source budget"
        );

        // A signed caller from a DIFFERENT source IP keeps its own budget -> not shed.
        let other: SocketAddr = "203.0.113.52:5000".parse().unwrap();
        let router3 = crate::server::build_router(state.clone());
        let mut req3 = Request::builder()
            .method(Method::GET)
            .uri("/z6pcip/pc/info/refs?service=git-upload-pack")
            .body(Body::empty())
            .unwrap();
        req3.extensions_mut().insert(ConnectInfo(other));
        req3.extensions_mut()
            .insert(crate::auth::AuthenticatedDid(did_a.to_string()));
        assert_ne!(
            router3.oneshot(req3).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a signed caller from a different source IP must keep its own per-source budget"
        );
    }

    /// #174 SC2 (None-key): a request with no resolvable caller key (no ConnectInfo,
    /// no trusted header) must NOT be shed by the per-caller cap even when another
    /// caller's budget is full — it is bounded by the global read pool only. A None
    /// key never keys into the map, so it never 503s from the per-caller sub-cap.
    #[sqlx::test]
    async fn info_refs_none_key_bypasses_per_caller_cap(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::http::{Method, Request, StatusCode};
        use tower::ServiceExt;

        let mut state = crate::test_support::test_state(pool).await;
        state.git_read_per_caller = crate::rate_limit::PerCallerConcurrency::new(1, 100);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state
            .db
            .upsert_mirror_repo("z6pcnone", "pc", "/tmp/pc-nonexistent", None, false)
            .await
            .unwrap();
        // Saturate an unrelated caller's budget; the None-key request must be
        // unaffected because it never keys into the per-caller map.
        let _slot = state
            .git_read_per_caller
            .try_acquire("203.0.113.99")
            .expect("hold an unrelated caller's slot");

        // No ConnectInfo inserted -> PeerAddr is None -> no per-caller key.
        let router = crate::server::build_router(state.clone());
        let req = Request::builder()
            .method(Method::GET)
            .uri("/z6pcnone/pc/info/refs?service=git-upload-pack")
            .body(Body::empty())
            .unwrap();
        assert_ne!(
            router.oneshot(req).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a request with no resolvable caller key must not be shed by the per-caller cap"
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
