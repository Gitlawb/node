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
///
/// The walk arm runs under a `git_encrypt_semaphore` admission permit (#174 F4):
/// by the time the receive-pack tail calls this, the handler's write permit has
/// already been released (receive_pack's AdmissionGuard drops when the git group
/// is reaped), so without the gate a burst of completed pushes accumulates
/// unbounded concurrent full-history walks. `encrypt_sem` is threaded in so the
/// no-walk fast paths (not announceable; no path-scoped rule) never touch it.
async fn replication_withheld_set(
    encrypt_sem: std::sync::Arc<tokio::sync::Semaphore>,
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
            // Scan admission (#174 F4): DEFER, never shed — dropping the walk
            // would skip the vetting and fail the push's replication closed for
            // no reason. Residuals at `acquire_scan_permit`.
            let permit =
                crate::state::acquire_scan_permit(encrypt_sem, &disk_path, "withheld walk").await;
            tokio::task::spawn_blocking(move || {
                // The permit lives inside the blocking closure: a started walk
                // always completes holding it.
                let _permit = permit;
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
///
/// Always walks (there is no no-git arm), so the whole blocking scan runs under
/// one `git_encrypt_semaphore` admission permit (#174 F4) — see
/// `acquire_scan_permit` for the defer rationale and the honest residuals.
#[allow(clippy::too_many_arguments)]
async fn fail_closed_full_scan_objects(
    encrypt_sem: std::sync::Arc<tokio::sync::Semaphore>,
    disk_path: std::path::PathBuf,
    rules: Vec<crate::db::VisibilityRule>,
    is_public: bool,
    owner_did: String,
    candidates: Vec<String>,
    git_bin: String,
    timeout: std::time::Duration,
) -> Vec<String> {
    // Scan admission (#174 F4): DEFER, never shed; the permit moves into the
    // closure so a started scan always completes holding it.
    let permit =
        crate::state::acquire_scan_permit(encrypt_sem, &disk_path, "fail-closed full scan").await;
    tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<String>> {
        let _permit = permit;
        // One whole-scan deadline shared across both phases (#174 F4). A fresh
        // `Instant::now() + timeout` for phase 2 let a large-but-successful phase 1 plus
        // a full phase 2 hold the scan permit ~2x the configured budget. Sharing the
        // deadline caps total occupancy at ~1x: phase 1 runs against the remaining
        // budget, and if it consumes the budget phase 2 gets what is left and fails
        // closed (pins nothing) rather than over-holding — the safe direction. The cost
        // is honest: a genuinely large repo whose phase 1 nears the budget under-pins
        // this push rather than the previous silent ~2x hold; size the budget so both
        // phases normally fit.
        let deadline = std::time::Instant::now() + timeout;
        let allowed = crate::git::visibility_pack::replicable_blob_set_bounded(
            &disk_path,
            &git_bin,
            deadline.saturating_duration_since(std::time::Instant::now()),
            &rules,
            is_public,
            &owner_did,
        )?;
        let all_blobs = crate::git::push_delta::all_blob_oids(&disk_path, &git_bin, deadline)?;
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
    // #62 cheap load shed: if the pool this service draws from is ALREADY saturated,
    // shed this request with a 503 before it does any DB/disk work. Best-effort and
    // permit-less, so it is a snapshot, not admission: it spares THIS request's DB
    // work once the pool has filled, and nothing more. It is NOT a bound on the DB
    // window. Permits are only held from `git_permit` below, after the visibility and
    // rate gates, so a burst arriving while permits are free all proceeds into the DB
    // and none of it sheds here. That ordering is deliberate (a denied or rate-limited
    // request must consume no slot, and one source must not hold global slots through
    // the DB/visibility window); bounding the DB window itself would need an admission
    // mechanism this peek is not.
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
    // The receive-pack advertisement draws from its own dedicated advert pool
    // (git_push_advert_semaphore, see the _permit block below), so it is bounded per
    // source by git_push_advert_per_caller instead: without this, an anonymous
    // multi-source flood of push-handshake advertisements could hold every advert-pool
    // slot across acquire_fresh and shed other sources' advertisements, since the
    // per-IP push rate limiter caps rate, not concurrency (#174 review fix).
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
    smart_http::info_refs(
        &state.git_bin,
        &service,
        &disk_path,
        git_timeout,
        Some(admission),
    )
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
    let permit = encrypt_sem
        .acquire_owned()
        .await
        .expect("git_encrypt_semaphore is never closed");
    tokio::task::spawn_blocking(move || {
        // The permit lives inside the blocking closure (#174 U4, the F4 contract): a
        // started walk always completes holding it, so a dropped future cannot free
        // the slot while this uncancellable walk still occupies a thread and a PID.
        let _permit = permit;
        crate::git::visibility_pack::withheld_blob_recipients_bounded(
            &repo_path, &git_bin, timeout, &rules, is_public, &owner_did,
        )
    })
    .await
}

/// Everything the detached post-push pin/encrypt task needs, cloned once at spawn
/// and shared by the snapshot iteration and every coalesced-drain iteration
/// (#174 F5).
struct EncryptTaskCtx {
    ipfs_api: String,
    repo_path: std::path::PathBuf,
    db: Arc<crate::db::Db>,
    repo_id: String,
    owner_did: String,
    repo_name: String,
    irys_url: String,
    http_client: Arc<reqwest::Client>,
    node_did: String,
    node_keypair: Arc<gitlawb_core::identity::Keypair>,
    git_bin: String,
    git_timeout: std::time::Duration,
    encrypt_sem: Arc<tokio::sync::Semaphore>,
    pin_sem: Arc<tokio::sync::Semaphore>,
}

/// The detached post-push pin/encrypt task (#174 P2-2 + F5): run this push's own
/// pre-resolved snapshot through the pipeline, then loop-drain every push that
/// coalesced against the in-flight key until a finish attempt finds nothing
/// pending (which releases the key in the same critical section).
///
/// The loop holds NO encrypt-pool permit at the task level: each helper it calls
/// (`replication_withheld_set`, `resolve_candidates_for_push`,
/// `fail_closed_full_scan_objects`, `withheld_recipients_gated`) acquires and
/// releases its own walk permit, so the drain makes progress at pool size 1 — a
/// task-level permit would nest over those same-semaphore acquires and deadlock.
async fn run_encrypt_pin_task(
    ctx: EncryptTaskCtx,
    guard: crate::state::EncryptInflightGuard,
    snapshot_objects: Vec<String>,
    snapshot_rules: Option<Vec<crate::db::VisibilityRule>>,
    snapshot_is_public: bool,
) {
    // The snapshot is this push's own work, resolved before spawn, so it belongs
    // to the id captured at spawn.
    pin_and_encrypt_objects(
        &ctx,
        &ctx.repo_id,
        snapshot_objects,
        snapshot_rules,
        snapshot_is_public,
    )
    .await;
    let mut guard = guard;
    loop {
        match guard.finish_or_take_pending() {
            crate::state::FinishOutcome::Finished(_) => break,
            crate::state::FinishOutcome::Pending(g, pending) => {
                guard = g;
                // `drain_repo_id`, not ctx.repo_id: see resolve_drain_object_list.
                if let Some((drain_repo_id, object_list, rules, is_public)) =
                    resolve_drain_object_list(&ctx, pending).await
                {
                    pin_and_encrypt_objects(&ctx, &drain_repo_id, object_list, rules, is_public)
                        .await;
                }
            }
        }
    }
}

/// Resolve a coalesced-drain iteration's replicable object list. Re-fetches the
/// repo record and visibility rules FRESH — rules tightened between the coalesced
/// push and its drain must be honored, fail closed: a newly-withheld blob is not
/// pinned, and a repo that is no longer announceable (or whose record cannot be
/// re-read) pins nothing at all (`None`). Returns the filtered object list plus
/// the fresh rules/is_public snapshot for the encrypt stage — the same
/// resolution → withheld-filter pipeline the receive-pack tail runs.
/// The returned `String` is the repo id the drain's encrypt/anchor writes must
/// use: the id from the FRESH re-fetch, never `ctx.repo_id` frozen at task spawn.
/// A delete+recreate under the same slug gives the row a new id, and metadata
/// written against the dead id is invisible to readers on the live row (#174 U3).
async fn resolve_drain_object_list(
    ctx: &EncryptTaskCtx,
    pending: crate::state::PendingWork,
) -> Option<(
    String,
    Vec<String>,
    Option<Vec<crate::db::VisibilityRule>>,
    bool,
)> {
    let record = match ctx.db.get_repo(&ctx.owner_did, &ctx.repo_name).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            tracing::warn!(
                repo = %ctx.repo_id,
                "coalesced drain: repo record is gone; dropping the pending work"
            );
            return None;
        }
        Err(e) => {
            tracing::warn!(
                repo = %ctx.repo_id,
                err = %e,
                "coalesced drain: repo re-fetch failed; pinning nothing (fail closed)"
            );
            return None;
        }
    };
    // record.id, never the spawn-time ctx.repo_id: the record above is re-fetched
    // fresh by owner/name, and a delete+re-create between spawn and drain gives
    // the row a NEW id — rules read against the stale id come back empty and
    // would fail open for the new row.
    let rules_opt = ctx.db.list_visibility_rules(&record.id).await.ok();
    let (_announce, withheld) = replication_withheld_set(
        ctx.encrypt_sem.clone(),
        rules_opt.clone(),
        &record.owner_did,
        record.is_public,
        ctx.repo_path.clone(),
        ctx.git_bin.clone(),
        ctx.git_timeout,
    )
    .await;
    let withheld_set = match withheld {
        Some(w) => w,
        None => {
            tracing::info!(
                repo = %ctx.repo_id,
                "coalesced drain: repo is not announceable under current rules; \
                 pinning nothing (fail closed)"
            );
            return None;
        }
    };
    let (new_tips, old_tips, force_full_scan) = match pending {
        crate::state::PendingWork::Tips(pairs) => {
            let new_tips: Vec<String> = pairs
                .iter()
                .map(|(_, n)| n.clone())
                .filter(|s| s != ZERO_SHA)
                .collect();
            let old_tips: Vec<String> = pairs
                .into_iter()
                .map(|(o, _)| o)
                .filter(|s| s != ZERO_SHA)
                .collect();
            (new_tips, old_tips, false)
        }
        // The overflow marker forces the full scan via the explicit flag. It must
        // never be encoded as a plain empty-tips call: empty tips resolve to an
        // empty delta and would pin nothing (the F5 silent loss again).
        crate::state::PendingWork::FullScan => (Vec::new(), Vec::new(), true),
    };
    let pin_set = crate::git::push_delta::resolve_candidates_for_push(
        ctx.encrypt_sem.clone(),
        ctx.repo_path.clone(),
        new_tips,
        old_tips,
        ctx.git_bin.clone(),
        ctx.git_timeout,
        force_full_scan,
    )
    .await;
    let object_list = if pin_set.full_scan {
        fail_closed_full_scan_objects(
            ctx.encrypt_sem.clone(),
            ctx.repo_path.clone(),
            rules_opt.clone().unwrap_or_default(),
            record.is_public,
            record.owner_did.clone(),
            pin_set.candidates,
            ctx.git_bin.clone(),
            ctx.git_timeout,
        )
        .await
    } else {
        crate::git::visibility_pack::replicable_objects(pin_set.candidates, &withheld_set)
    };
    // record.id, never ctx.repo_id: the record above is re-fetched fresh by
    // owner/name, and a delete+re-create between spawn and drain gives the row a
    // NEW id. This is the same rule the rules read a few lines up already follows.
    Some((record.id, object_list, rules_opt, record.is_public))
}

/// Re-derive the Pinata replication object set for a push from its ref-update
/// tuples (#174 F2 / KTD-3).
///
/// The detached Pinata task used to MOVE the push's full pre-resolved object list
/// into its closure and hold it across the `pin_semaphore` await. Under a slow
/// Pinata backend every later push then parked a fresh task each still retaining
/// an MB-scale OID list, so outstanding memory grew O(pushes x object-list) —
/// unbounded. The task now captures only the small `(ref, old, new)` tuples and
/// calls this once a pin slot frees, re-deriving the SAME OID set via
/// `git rev-list` (the delta scan) filtered by the current withheld set. Retained
/// memory is O(ref tuples); the object list is materialized only inside the
/// pin-bounded section, so at most `pin_semaphore` permits' worth exist at once.
///
/// Coalescing / shedding were rejected because the task's per-ref work is
/// non-idempotent (branch->CID upsert, gossip, GraphQL broadcast, Arweave anchor,
/// peer-notify); dropping a later push's task drops its announcements. Only the
/// retained object list is dropped here, not the task, so every push's effects
/// still fire exactly once.
///
/// Exactly like `resolve_drain_object_list`: the withheld and candidate sets are
/// recomputed from the rules snapshot captured at post-receive tail start (NOT a
/// fresh read at pin-worker time), so a rule tightened up to that point is honored
/// and the filter always fails closed (a newly-withheld blob is not pinned; a
/// no-longer-announceable repo pins nothing). A tightening AFTER tail-start — before
/// a slow re-derivation runs — is not reflected, matching the old retained-list
/// behavior. Every git child runs through the same INV-22 bounded,
/// process-group-reaped helpers the sibling post-receive scans use
/// (`replication_withheld_set`, `resolve_candidates_for_push`,
/// `fail_closed_full_scan_objects`).
#[allow(clippy::too_many_arguments)]
async fn pinata_object_list_for_refs(
    encrypt_sem: Arc<tokio::sync::Semaphore>,
    disk_path: std::path::PathBuf,
    ref_updates: &[(String, String, String)],
    rules_opt: Option<Vec<crate::db::VisibilityRule>>,
    is_public: bool,
    owner_did: String,
    git_bin: String,
    timeout: std::time::Duration,
) -> (bool, Vec<String>) {
    let (announce, withheld) = replication_withheld_set(
        encrypt_sem.clone(),
        rules_opt.clone(),
        &owner_did,
        is_public,
        disk_path.clone(),
        git_bin.clone(),
        timeout,
    )
    .await;
    // Not announceable, or the withheld walk failed: replicate nothing (fail
    // closed), mirroring the receive-pack tail's `withheld == None` handling. The
    // announce decision is returned with the list because this recomputation is the
    // tail's only walk once coalescing runs ahead of it (#174 F2a): a repo whose
    // walk is failing must still suppress gossip, the GraphQL broadcast, Arweave and
    // peer-notify, and `announce` is false on exactly those arms.
    let withheld_set = match withheld {
        Some(w) => w,
        None => return (announce, Vec::new()),
    };
    let new_tips: Vec<String> = ref_updates
        .iter()
        .map(|(_, _, new)| new.clone())
        .filter(|s| s != ZERO_SHA)
        .collect();
    let old_tips: Vec<String> = ref_updates
        .iter()
        .map(|(_, old, _)| old.clone())
        .filter(|s| s != ZERO_SHA)
        .collect();
    let pin_set = crate::git::push_delta::resolve_candidates_for_push(
        encrypt_sem.clone(),
        disk_path.clone(),
        new_tips,
        old_tips,
        git_bin.clone(),
        timeout,
        false,
    )
    .await;
    let object_list = if pin_set.full_scan {
        fail_closed_full_scan_objects(
            encrypt_sem,
            disk_path,
            rules_opt.unwrap_or_default(),
            is_public,
            owner_did,
            pin_set.candidates,
            git_bin,
            timeout,
        )
        .await
    } else {
        crate::git::visibility_pack::replicable_objects(pin_set.candidates, &withheld_set)
    };
    (announce, object_list)
}

/// The pin/encrypt pipeline shared by the snapshot iteration and the
/// coalesced-drain iterations: local IPFS pin, then (path-scoped rules only) the
/// admission-gated recipients walk → encrypt-then-pin → Arweave manifest anchor.
/// Pin `object_list` to the local IPFS node under the global pin-admission permit
/// (#174 F6). `EncryptInflight` bounds the pin-task COUNT to one per repo, but each
/// pin loop holds a full per-push object-id list while walking it; this permit bounds
/// how many pin loops RUN CONCURRENTLY, and therefore how many such MB-scale lists are
/// held WHILE BEING PINNED. DEFERS (waits) when the pool is full and never drops, since
/// a dropped pin loses the replication copy.
///
/// What it does NOT bound, stated plainly rather than implied closed: on this path the
/// caller materializes `object_list` BEFORE this function acquires, so a task that is
/// parked here waiting for a permit is still holding its full list. The parked-task
/// count is capped only per repo by `EncryptInflight`, so across distinct repos the
/// retained list memory is not bounded by this pool. Bounding that is a real change to
/// the capture shape and is deliberately not attempted here; the Pinata twin below
/// avoids it by acquiring BEFORE it derives its list.
async fn pin_new_objects_gated(
    pin_sem: &Arc<tokio::sync::Semaphore>,
    ipfs_api: &str,
    repo_path: &std::path::Path,
    object_list: Vec<String>,
    db: &Arc<crate::db::Db>,
) -> Vec<(String, String)> {
    // Nothing to pin: answer before taking a permit (#174 F2b). The permit bounds how
    // many pin loops run concurrently, and an empty list does no pinning, so parking
    // here would spend a global pin slot on no work. The pool DEFERS rather
    // than sheds, so those calls stall pins for every other repo. Empty is the normal
    // shape for a push whose walk failed or that may replicate nothing.
    if object_list.is_empty() {
        return Vec::new();
    }
    let _permit = pin_sem
        .clone()
        .acquire_owned()
        .await
        .expect("pin_semaphore is never closed");
    crate::ipfs_pin::pin_new_objects(
        ipfs_api,
        repo_path,
        // The literal, not `state.git_bin`: tests point that at a fake walk git, and
        // this is the same choice `api/ipfs`'s bounded call sites already document.
        "git",
        object_list,
        db,
        crate::ipfs_pin::PIN_BATCH_BUDGET,
    )
    .await
}

/// `repo_id` is passed explicitly rather than read from `ctx` so the two callers
/// stay honest about which id they mean: the snapshot iteration passes
/// `ctx.repo_id` (its own push's row), while a coalesced drain passes the id from
/// its fresh re-fetch, which differs after a delete+recreate (#174 U3).
async fn pin_and_encrypt_objects(
    ctx: &EncryptTaskCtx,
    repo_id: &str,
    object_list: Vec<String>,
    rules: Option<Vec<crate::db::VisibilityRule>>,
    is_public: bool,
) {
    let pinned = pin_new_objects_gated(
        &ctx.pin_sem,
        &ctx.ipfs_api,
        &ctx.repo_path,
        object_list,
        &ctx.db,
    )
    .await;
    if !pinned.is_empty() {
        tracing::info!(count = pinned.len(), "pinned git objects to IPFS");
        for (sha, cid) in &pinned {
            tracing::info!(sha = %sha, %cid, "pinned");
        }
    }

    // Option B1: encrypt-then-pin the withheld blobs so authorized readers can
    // recover them when the origin cannot serve them. No path-scoped rule can
    // withhold a blob, so withheld_blob_recipients would return an empty map
    // after a full per-ref walk; skip it. Mirrors the has_path_scoped_rule gate
    // on the other two withheld-walk sites.
    if let Some(rules) = rules.filter(|r| visibility_pack::has_path_scoped_rule(r)) {
        // Bound the number of concurrent post-push encryption walks (#174 P1-e):
        // acquire an admission permit before the full-history walk, deferring
        // when the pool is full rather than shedding the recovery pin.
        let recip = withheld_recipients_gated(
            ctx.encrypt_sem.clone(),
            ctx.repo_path.clone(),
            ctx.git_bin.clone(),
            ctx.git_timeout,
            rules,
            is_public,
            ctx.owner_did.clone(),
        )
        .await;
        if let Ok(Ok(recipients)) = recip {
            let node_seed = ctx.node_keypair.to_seed();
            let delta = crate::encrypted_pin::encrypt_and_pin(
                &ctx.ipfs_api,
                &ctx.repo_path,
                &ctx.db,
                repo_id,
                &node_seed,
                &recipients,
            )
            .await;

            // Option B3: anchor a per-push manifest of the blobs sealed this
            // push to Arweave, so the oid->cid index survives total node loss.
            // Best-effort; never fails the push.
            if !delta.is_empty() && !ctx.irys_url.is_empty() {
                let owner_short = crate::db::normalize_owner_key(&ctx.owner_did);
                let repo_slug = format!("{owner_short}/{}", ctx.repo_name);
                let ts = chrono::Utc::now().to_rfc3339();
                let manifest = crate::arweave::EncryptedManifest {
                    repo: &repo_slug,
                    owner_did: &ctx.owner_did,
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
    // #62 cheap load shed. Permit-less snapshot, not admission; see git_info_refs for
    // what it does and does not bound. The authoritative hold is `git_permit` below,
    // after the per-source cap.
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
    // Whether this POST finalized negotiation (carries `done`), computed before
    // `body` is moved into upload_pack. Gates the completed-fetch metric below.
    let finalizes_fetch = request_finalizes_fetch(&body);

    // No path-scoped rule can withhold an individual blob, and the whole-repo
    // "/" gate above already enforced repo-level access. Skip the per-blob
    // withheld walk and serve the pack directly.
    let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);
    // The filtered serve path (upload_pack_excluding) replies NAK + a self-contained
    // full pack regardless of negotiation, completing a fetch on the single POST that
    // reaches it even when that POST carries no `done`. Track it so the completed-
    // fetch metric counts that path too (#192 F1, filtered case).
    let mut served_filtered_pack = false;
    let (resp, served_pack) = if !visibility_pack::has_path_scoped_rule(&rules) {
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
        // ONE deadline spans the walk AND the serve below (#174 U1 follow-up). A fresh
        // `git_timeout` for the serve let a slow-but-successful walk plus a full serve
        // hold this read permit ~2x the configured budget. Sharing the deadline caps
        // that at ~1x: the walk runs against the remaining budget, and if it consumes
        // the budget the serve gets what is left and is reaped rather than over-holding
        // — the safe direction, same tradeoff as `fail_closed_full_scan_objects` and
        // `build_filtered_pack`. The cost is honest: a genuinely slow walk on a large
        // repo 504s this clone instead of silently holding the pool for ~2x, so size
        // `GITLAWB_GIT_SERVICE_TIMEOUT_SECS` so both phases normally fit.
        let deadline = std::time::Instant::now() + git_timeout;
        let (withheld, _permit, _caller_permit) = {
            let path = disk_path.clone();
            let rules = rules.clone();
            let owner_did = record.owner_did.clone();
            let caller_owned = caller.map(str::to_string);
            let is_public = record.is_public;
            let git_bin = state.git_bin.clone();
            tokio::task::spawn_blocking(move || {
                // Derive the walk's budget from the shared deadline HERE, inside the
                // closure, not on the async side before the task is queued. The walk
                // starts its own clock when it runs, so a budget computed at queue time
                // would hand it a full budget measured from whenever the blocking pool
                // got to it, leaving the permit held for queue-delay PLUS the budget.
                // Computing it at task start charges that queue delay against the
                // shared deadline, which is what makes the ~1x bound true rather than
                // approximate.
                let walk_budget = deadline.saturating_duration_since(std::time::Instant::now());
                let withheld = visibility_pack::withheld_blob_oids_bounded(
                    &path,
                    &git_bin,
                    walk_budget,
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

        // Move the permits returned by the walk into the guard, ONE construction
        // site for both serve arms below, so admission tracks the served git group's
        // reap (complete/timeout/disconnect) whether the pack is plain or filtered.
        // The handler keeps no copy (F1: handler-local permits would drop the
        // instant a disconnect drops this future, mid-reap).
        let admission = smart_http::AdmissionGuard::new(_permit, _caller_permit);
        // Computed AFTER the walk's await, so the serve gets what the walk left, not a
        // second full budget. A walk that consumed the whole budget saturates this to
        // zero, which the serve surfaces as GitServiceTimeout -> 504 rather than
        // running unbounded.
        let serve_budget = deadline.saturating_duration_since(std::time::Instant::now());
        if withheld.is_empty() {
            // No blobs to withhold: serve the plain pack (the walk already held the
            // permits per be0cdd6; the guard hands them to the serve).
            smart_http::upload_pack(
                &state.git_bin,
                &disk_path,
                body,
                serve_budget,
                Some(admission),
            )
            .await
        } else {
            served_filtered_pack = true;
            tracing::info!(repo = %name, caller = ?caller, withheld = withheld.len(), "serving filtered pack");
            // The guard threads through both filtered-pack stages (rev-list, then
            // pack-objects), so a disconnect mid-stage keeps the permits held until
            // that stage's process group is reaped (F1).
            smart_http::upload_pack_excluding(
                &state.git_bin,
                &disk_path,
                body,
                &withheld,
                serve_budget,
                Some(admission),
            )
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
    // Count a completed fetch (and observe the pack) only on the POST that actually
    // completes one, keyed off the RESPONSE outcome rather than the request (#192
    // F1/F2). On the plain path that is the POST whose response delivered a pack:
    // this catches a `no-done` completion (server replies `ACK <oid> ready` + pack)
    // and skips a negotiation-only round (ACK/NAK, no pack), so an N-round
    // stateless-RPC fetch counts exactly once. The filtered path always builds a
    // self-contained pack and can't tell an accepted fresh clone from a rejected
    // mid-negotiation response, so it is gated on the finalizing `done` round.
    // NOTE: observe_pack_size still measures the request body, not the served pack;
    // that mislabel predates this change and is tracked as a follow-up.
    if should_count_fetch(finalizes_fetch, served_filtered_pack, served_pack) {
        crate::metrics::record_fetch(&format!("{owner}/{name}"));
        crate::metrics::observe_pack_size(body_len as f64);
    }
    Ok(resp)
}

/// Whether an upload-pack POST completed a fetch and should be counted once.
///
/// Completion is signalled by the response outcome, split by serve path (#192
/// F1/F2):
///
/// - Plain path (`served_filtered_pack == false`): count exactly when the
///   response delivered a pack (`response_served_pack`). This counts a `no-done`
///   completion (server streams `ACK <oid> ready` + pack even though the request
///   carried no `done`) and does NOT count a negotiation-only round (ACK/NAK, no
///   pack), so a multi-round fetch is one completion, not N.
/// - Filtered path (`served_filtered_pack == true`): `upload_pack_excluding`
///   always builds a self-contained pack, so `response_served_pack` can't
///   distinguish an accepted fresh clone from a rejected mid-negotiation response.
///   Gate on the finalizing `done` round: a fresh filtered clone carries
///   `want`+`done`; the pre-#191 rejected two-POST scenario carries no `done`, so
///   it is not counted (and not double-counted). Interim until #191 makes filtered
///   negotiation valid.
///
/// The rule is one isolated expression: the filtered branch is
/// `served_filtered_pack && finalizes_fetch` (reduces to `finalizes_fetch` here),
/// the plain branch is `response_served_pack`.
fn should_count_fetch(
    finalizes_fetch: bool,
    served_filtered_pack: bool,
    response_served_pack: bool,
) -> bool {
    if served_filtered_pack {
        finalizes_fetch
    } else {
        response_served_pack
    }
}

/// True when an upload-pack request body carries a `done` pkt-line, i.e. the
/// client finished negotiation and is asking the server to stream the pack.
///
/// The HTTP smart protocol runs upload-pack as stateless RPC: the client sends one
/// `git-upload-pack` POST per negotiation round, but only the finalizing round
/// sends `done`; the earlier flush-terminated rounds negotiate common history and
/// produce no pack. Counting a fetch only when this returns true keeps an N-round
/// incremental fetch from being recorded as N completed fetches (#192 F1). Parses
/// pkt-lines and fails closed (returns false) on a malformed body, so a garbled
/// request is never counted.
fn request_finalizes_fetch(body: &[u8]) -> bool {
    let mut i = 0;
    while i + 4 <= body.len() {
        let Ok(hdr) = std::str::from_utf8(&body[i..i + 4]) else {
            return false;
        };
        let Ok(len) = usize::from_str_radix(hdr, 16) else {
            return false;
        };
        // 0000/0001/0002 are flush/delim/response-end markers: a 4-byte header
        // with no payload. 0003 is not a valid pkt-line length (a pkt-line is
        // either one of those markers or has length >= 4), so reject it as
        // malformed framing rather than treating it as a marker.
        if len < 4 {
            if len == 3 {
                return false;
            }
            i += 4;
            continue;
        }
        if i + len > body.len() {
            return false; // truncated/malformed: do not over-count
        }
        let payload = &body[i + 4..i + len];
        if payload.strip_suffix(b"\n").unwrap_or(payload) == b"done" {
            // A `done` pkt-line finalizes the request; it must be the last thing
            // in the body. Trailing bytes after it are malformed framing, so fail
            // closed rather than count.
            return i + len == body.len();
        }
        i += len;
    }
    false
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
    verified: Option<&crate::auth::VerifiedUcan>,
) -> Option<AppError> {
    if !enforce {
        return None;
    }
    match caller {
        Some(did) if caller_authorized_to_push(record, did, verified) => None,
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

/// POST /:owner/:repo.git/git-receive-pack  (AUTH REQUIRED — enforced by middleware)
pub async fn git_receive_pack(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    Extension(auth): Extension<AuthenticatedDid>,
    // `X-Ucan` is optional, so the extension may be absent: axum extracts that as
    // `None` rather than rejecting the request. Present only when the middleware
    // validated a chain.
    verified: Option<Extension<crate::auth::VerifiedUcan>>,
    crate::rate_limit::PeerAddr(peer): crate::rate_limit::PeerAddr,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let name = smart_http_repo_name(&repo)?;
    // Fast-path shed before the DB lookup when the write pool is ALREADY saturated, so a
    // push flood against a full pool does not hit Postgres per request. Best-effort
    // (racy) and NON-holding: a snapshot, not admission. It spares this request's DB
    // work once the pool has filled; pushes arriving while permits are free all proceed
    // into the DB, so it does not bound that window. The authoritative, held permit is
    // taken after the per-repo lease below, so a lease-blocked waiter pins no write slot
    // (#174 F3 review).
    if state.git_write_semaphore.available_permits() == 0 {
        return Err(AppError::Overloaded(
            "git service at capacity, retry shortly".into(),
        ));
    }
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
        verified.as_ref().map(|Extension(v)| v),
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

    // Per-repo in-process write lease (#174 U2/F3): SUPPLEMENTS the cluster-wide pg
    // advisory lock. Acquire it BEFORE acquire_write (one consistent order everywhere,
    // so the two serializers can never invert into a self-hang) so a second SAME-NODE
    // push to this repo blocks here rather than racing a disconnected first push's git
    // group while its detached reaper is still tearing it down over the shared local
    // objects/ dir. Taking it before the pg lock also means a blocked second writer pins
    // no pooled pg connection while it waits. The lease rides the write-path
    // AdmissionGuard into the reaper (clone (a)) and spans the clean-path Tigris upload
    // in guard.release (clone (b)); it frees only when the LAST clone drops. steal_after
    // is sized above ONE legitimate hold (a full receive-pack under git_service_timeout +
    // the ~4s reaper cap + the Tigris upload). It is NOT a guarantee that only a leaked
    // lease is reclaimed: a waiter's timeout starts at acquire(), not at the head of the
    // FIFO queue, so a same-repo backlog whose CUMULATIVE wait exceeds steal_after can
    // steal while an earlier waiter is still writing. Correctness does not rest on the
    // bound — on the non-disconnect path the retained pg advisory lock still serializes
    // the stealer at acquire_write (a spurious 503, not a race); the only corruption-capable
    // overlap is the ~4s disconnect/reap window, which the reaper-carried clone (a) covers.
    // Saturating, not unchecked. `GIT_SERVICE_TIMEOUT_SECS_MAX` now keeps every parsed
    // value inside this arithmetic, so on the configured path this cannot overflow; it is
    // deliberate defense in depth for the construction paths clap does not cover (tests
    // build `Config` by mutation, and nothing stops a future caller doing the same). The
    // failure it holds off is not cosmetic: unchecked, `* 2 + 60` panics the push in debug
    // and in release WRAPS to a bound short enough for a waiter to steal a live push's
    // lease. Saturating also states the intent — a timeout that large means no steal, which
    // is what an effectively-disabled service bound implies.
    let lease_steal_after = std::time::Duration::from_secs(
        state
            .config
            .git_service_timeout_secs
            .saturating_mul(2)
            .saturating_add(60),
    );

    // Parked waiters are bounded INSIDE the lease, not by an admission permit taken above
    // it. `body: Bytes` means axum has already buffered the whole pack before this handler
    // runs, and the park runs to steal_after (1260s at defaults), so an unbounded waiter
    // set would let same-repo pushes stack buffered bodies. `acquire` therefore counts its
    // LIVE WAITERS against GITLAWB_REPO_LEASE_MAX_WAITERS and returns None past the cap,
    // which sheds here as a 503 + Retry-After like the other admission paths. The cap is
    // per repo and counts only handlers actually parked, so it denies same-repo
    // concurrency on the contended repo alone: a push to any other repo, from any source,
    // is untouched. Taking a per-source or global admission permit above the park instead
    // is what the F1 review rejected, since GITLAWB_TRUSTED_PROXY defaults to unset and
    // every pusher behind a proxy/NAT then resolves to ONE key, turning one contended repo
    // into a node-wide denial.
    // The stable disk identity, never record.id: the row id rotates on a
    // delete+recreate under the same slug while the bare repo on disk is reused,
    // and an id-keyed lease stops serializing exactly across that rotation.
    let repo_key = crate::state::repo_identity_key(&record.owner_did, &record.name);
    let lease = state
        .repo_write_leases
        .acquire(&repo_key, lease_steal_after)
        .await
        .ok_or_else(|| {
            tracing::warn!(
                repo = %name,
                "repo write-lease waiter cap reached; shedding with 503"
            );
            AppError::Overloaded("repo is busy with another push, retry shortly".into())
        })?;

    // Admission permits are taken HERE, AFTER the per-repo lease and BEFORE acquire_write.
    // Ordering is the fix (#174 P2 DoS): the lease is a block-and-wait serializer, so a
    // second same-repo push can park on `acquire` above for up to steal_after. Taking the
    // scarce write permits only once we own the lease means a lease-blocked waiter pins NO
    // write-pool slot while it waits. Otherwise a few hostile sources could stack same-repo
    // pushes, hold every global slot on zero-byte lease-waiters, and shed 503 on every push
    // to every OTHER repo node-wide. The per-source sub-cap belongs below the park for the
    // same reason: its key is the resolved source IP, which collapses to one key for every
    // pusher when GITLAWB_TRUSTED_PROXY is unset (the default), so above the park it sheds
    // cross-tenant too. Still before acquire_write, so the git op stays admission-gated
    // (INV-10) and a saturated pool sheds 503 before spawning git.
    //
    // Per-source sub-cap first (#174 P1-d): one source IP cannot occupy the whole write
    // pool via many slow pushes. Owner enforcement defaults off, so any valid did:key is
    // accepted (auth != authz) and the push rate limiter bounds arrival RATE, not in-flight
    // concurrency. Keyed on the resolved source IP, NEVER the signed DID (a DID farm defeats
    // a DID key); no resolvable key -> global write pool only. Then the global write permit:
    // pushes draw from the dedicated WRITE pool, separate from reads, and it is held for the
    // whole op (moved into the AdmissionGuard below).
    let caller_key = read_caller_key(&headers, peer, state.push_limiter_trust);
    let _caller_permit = acquire_read_caller_permit(
        &state.git_write_per_caller,
        caller_key.as_deref(),
        name,
        "receive-pack",
    )?;
    let _permit = git_permit(&state.git_write_semaphore)?;

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
    // Clone (a) of the write lease rides this AdmissionGuard: on a client disconnect the
    // guard moves into KillGroupOnDrop's detached reaper, so the lease frees only after
    // the receive-pack group is reaped — NOT at the disconnect instant (which is exactly
    // when RepoWriteGuard::Drop frees the pg lock). Tying the lease to RepoWriteGuard
    // instead would drop it at disconnect and reopen the F3 race.
    let admission =
        smart_http::AdmissionGuard::new(_permit, _caller_permit).with_lease(lease.clone());
    let receive_result = smart_http::receive_pack(
        &state.git_bin,
        &disk_path,
        body,
        git_timeout,
        Some(admission),
    )
    .await;

    // #174 F2/U5: the post-receive replication tail runs in an independently owned
    // task. It parks on `git_encrypt_semaphore` (withheld / candidate / full-scan
    // resolution), so leaving it in the request future means a client/proxy disconnect
    // while parked silently drops this push's pins, recovery copy, and announcements.
    //
    // Spawned HERE, ABOVE `guard.release()`, because `release` is itself cancellable:
    // on success it awaits the Tigris upload and then the advisory unlock, both while
    // this future is still tied to the client connection, and the pack has ALREADY
    // landed on disk by then. Spawning below `release` left exactly that window open,
    // where a disconnect meant a durable push with no tail (the same class F2 closed,
    // one step earlier).
    //
    // The success gate is explicit rather than the `?` below, because that `?` now
    // sits under this spawn: `release` runs on failure too, so anchoring the tail on
    // it would pin and announce a half-applied repo, the state `release(false)`
    // deliberately refuses to upload and one a hostile pusher can produce on demand
    // by aborting a pack mid-transfer.
    //
    // The tail is read-only on `disk_path` (walk plus plumbing) and takes neither the
    // write lease nor the advisory lock, so running it concurrently with the upload
    // below waits on nothing this handler still holds. Everything after (touch_repo,
    // metrics, trust score, certificates, webhooks) stays in the cancellable handler.
    //
    // The tail also runs CONCURRENTLY with certificate issuance rather than after it,
    // so a ref can be announced before its signed certificate exists. That window is
    // accepted: cert issuance already fails open (errors are logged and skipped) and
    // the gossip event carries `cert_id: None` regardless, so no announce consumer
    // reads a certificate out of it. Each push owns its own tail, including its own
    // always-spawned announce, so per-push announcements are never coalesced away.
    //
    // ACCEPTED RESIDUAL, and it is the cost of this ordering: the tail also runs
    // concurrently with the Tigris upload inside `release` below, where before it ran
    // after. So a ref can be announced while the shared durable copy is still the old
    // one, and on a disconnect here the upload is cancelled outright while the
    // detached tail still pins and announces. What makes that acceptable is that
    // upload-then-announce was never actually guaranteed: `release` tolerates a failed
    // upload by design (it warns and continues to the unlock), so an announce over a
    // stale Tigris copy was already reachable before this reorder, and it self-heals,
    // since `acquire_fresh` falls back to the local copy and the next push re-uploads.
    // The alternative, detaching `release` and the tail together to keep the ordering,
    // would return 200 to the pusher before the durable copy lands, which is a larger
    // change to the client contract than the window it closes.
    let push_succeeded = receive_result.is_ok();
    if push_succeeded {
        tokio::spawn(post_receive_replication_tail(
            state.clone(),
            record.clone(),
            ref_updates.clone(),
            disk_path.clone(),
            auth.0.to_string(),
        ));
    }

    // Always release the advisory lock — even on error — to prevent stale locks
    // from blocking subsequent pushes. Only upload to Tigris when the push
    // succeeded; uploading a half-applied repo would propagate corruption.
    guard.release(push_succeeded).await;
    // Clean path: clone (a) already dropped inside run_git_service when the receive-pack
    // group was reaped; clone (b) held here spanned the success-only Tigris upload that
    // ran inside release() above. Drop it now so a second same-repo push proceeds the
    // moment this write is durable, rather than at end of the (longer) handler tail. On
    // the disconnect path this line is never reached — clone (a) rides the reaper (F3).
    drop(lease);

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

    Ok(result)
}

/// The detached post-receive replication tail (#174 F2): everything a landed push
/// still owes after its git response has been returned: the replication decision,
/// the per-repo-coalesced pin/encrypt task, and this push's own Pinata + announce
/// task. Split out of `git_receive_pack` so the ordering the coalescing gate depends
/// on is directly testable; the handler spawns it and returns.
async fn post_receive_replication_tail(
    state: AppState,
    record: RepoRecord,
    ref_updates: Vec<RefUpdate>,
    disk_path: std::path::PathBuf,
    did: String,
) {
    // Replication enforcement (Phase 2): decide once per push whether the public
    // may read this repo at all and, if so, which blob OIDs must not leave the
    // node. `withheld == None` means this push pins nothing (private / mode A /
    // undetermined, or a walk that failed): skip every pin so even commit and tree
    // objects (which withheld_blob_oids never lists) stay local. Fail closed: a
    // private or undetermined repo never leaks. The announce decision that gates
    // the network-facing sends is taken separately, below.
    let rules_opt = state.db.list_visibility_rules(&record.id).await.ok();

    // #174 F2a: take the per-repo coalescing key BEFORE the walk, not after it.
    // `replication_withheld_set` decides announceability from the rules snapshot
    // alone and returns `(false, None)` before it touches the scan pool or spawns
    // any git, so the same predicate can be evaluated here and used to gate
    // `try_begin`. With the gate below the walk, rapid pushes to one repo each
    // parked on `git_encrypt_semaphore` and re-ran the walk plus the object-list
    // materialization before finding out they were going to coalesce; now a push
    // that will coalesce does none of that. Not announceable is the same as
    // before: nothing replicates, so no key is taken and no walk runs.
    let announce_at_root = match &rules_opt {
        Some(rules) => {
            crate::visibility::listable_at_root(rules, record.is_public, &record.owner_did, None)
        }
        None => false,
    };
    let mut coalesced = false;
    let mut inflight = None;
    if announce_at_root {
        let tip_pairs: Vec<(String, String)> = ref_updates
            .iter()
            .map(|u| (u.old_sha.clone(), u.new_sha.clone()))
            .collect();
        // Same stable disk identity as the lease above (#174 U2): keyed on
        // record.id, a post-recreate push would take a fresh key and run a second
        // encrypt task against the same on-disk repo instead of coalescing.
        let coalesce_key = crate::state::repo_identity_key(&record.owner_did, &record.name);
        match state.encrypt_inflight.try_begin(&coalesce_key, tip_pairs) {
            crate::state::BeginOutcome::Coalesced => {
                coalesced = true;
                tracing::debug!(
                    repo = %record.id,
                    "post-push encryption task already in flight for this repo; coalesced \
                     — this push's tip pairs are queued for that task's drain"
                );
            }
            crate::state::BeginOutcome::Admitted(guard) => inflight = Some(guard),
        }
    }

    // The walk feeds this push's own pin/encrypt snapshot, so it is skipped both
    // when nothing may replicate and when this push coalesced (the in-flight
    // task drains its tips). The walk's own announce decision is deliberately
    // not kept here: it does not exist on the coalesced path, and the Pinata /
    // announce tail below re-derives it (see `do_pinata_replication`).
    let withheld = if coalesced || !announce_at_root {
        None
    } else {
        replication_withheld_set(
            state.git_encrypt_semaphore.clone(),
            rules_opt.clone(),
            &record.owner_did,
            record.is_public,
            disk_path.clone(),
            state.git_bin.clone(),
            std::time::Duration::from_secs(state.config.git_service_timeout_secs),
        )
        .await
        .1
    };

    // #174 F2b: did THIS push run its own walk and have it fail? An admitted push that
    // could not be vetted must not go on to take a pin permit and re-run the same
    // failing walk in the Pinata worker below. Only the COALESCED path needs the
    // rules-only predicate there: it has no walk of its own, so the worker's
    // re-derivation is its only fail-closed source.
    let own_walk_failed = announce_at_root && !coalesced && withheld.is_none();

    // Resolve the per-push pin candidate set once, off the async worker, then
    // filter to what may actually replicate. Delta path: the reachable-only
    // `withheld` set suffices (delta objects are reachable). Full-scan path: the
    // candidate set can include dangling blobs the withheld set never classified,
    // so fail closed — replicate a blob only if it is reachable AND
    // visibility-allowed (#99). Only computed when something will actually
    // replicate; every degraded path logs rather than failing silently.
    let object_list: Vec<String> = if let Some(withheld_set) = withheld {
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
            state.git_encrypt_semaphore.clone(),
            disk_path.clone(),
            new_tips,
            old_tips,
            state.git_bin.clone(),
            std::time::Duration::from_secs(state.config.git_service_timeout_secs),
            false,
        )
        .await;
        if pin_set.full_scan {
            fail_closed_full_scan_objects(
                state.git_encrypt_semaphore.clone(),
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
    // Skipped entirely when the public cannot read the repo (no key was taken).
    //
    // Coalesce-and-requeue per repo (#174 P2-2 + F5): the spawned task's walks park
    // on `git_encrypt_semaphore` (which DEFERS when the pool is full rather than
    // dropping the recovery copy). To bound the OUTSTANDING task set, at most one
    // task per repo is in flight; a push arriving while one is in flight does NOT
    // spawn a duplicate — and is NOT dropped either. The in-flight task pins only
    // its own pre-spawn object-list snapshot, so this push's (old, new) tip pairs
    // are merged into the in-flight key's pending slot in the same critical section
    // as the presence check, and the task loop-drains them (fresh rules, fail
    // closed) before releasing the key. Without the requeue a coalesced push's pins
    // and recovery copies would be silently absent until an unrelated later push
    // (the F5 loss). The guard still releases the key on panic (Drop on unwind), so
    // a crashed walk never permanently locks the repo out.
    //
    // #174 F2a: the key was taken above, so this is only the spawn. An admitted
    // push ALWAYS spawns, including when its own walk failed and `object_list` is
    // therefore empty: pushes can have coalesced into the pending slot while that
    // walk ran, and the task's drain loop is what consumes them. Releasing or
    // dropping the guard instead would discard that work with a warn (the F5 loss
    // class again), and the two are indistinguishable from outside (Drop removes
    // the key whenever the guard is still armed).
    if let Some(inflight_guard) = inflight {
        let ctx = EncryptTaskCtx {
            ipfs_api: state.config.ipfs_api.clone(),
            repo_path: disk_path.clone(),
            db: state.db.clone(),
            repo_id: record.id.clone(),
            owner_did: record.owner_did.clone(),
            repo_name: record.name.clone(),
            irys_url: state.config.irys_url.clone(),
            http_client: std::sync::Arc::clone(&state.http_client),
            node_did: state.node_did.to_string(),
            node_keypair: std::sync::Arc::clone(&state.node_keypair),
            git_bin: state.git_bin.clone(),
            git_timeout: std::time::Duration::from_secs(state.config.git_service_timeout_secs),
            encrypt_sem: state.git_encrypt_semaphore.clone(),
            pin_sem: state.pin_semaphore.clone(),
        };
        tokio::spawn(run_encrypt_pin_task(
            ctx,
            inflight_guard,
            object_list,
            rules_opt.clone(),
            record.is_public,
        ));
    }

    // Pin new git objects to Pinata, then record branch→CID and gossip.
    //
    // #174 P2-2 scope note: this SECOND detached spawn is deliberately NOT brought
    // under the per-repo encryption coalescing above, because unlike the idempotent
    // recovery-copy walk it does PER-PUSH, PER-REF work — branch→CID upserts, gossip
    // publish, GraphQL subscription broadcast, Arweave anchoring, and peer notify, each
    // keyed to THIS push's ref_updates. Coalescing (or shedding) it against an in-flight
    // task for the same repo would DROP a later push's ref-update announcements (a
    // correctness regression), not merely delay a duplicate. So the task stays one per
    // push and every push's effects fire exactly once.
    //
    // #174 F2 / KTD-3: {bounded memory, no dropped effects, no handler latency} are
    // jointly unsatisfiable by coalesce/shed/block, so instead of retaining the full
    // object list we bound the thing that actually accumulates. The task captures only
    // the small ref tuples and RE-DERIVES the object set inside the worker once a pin
    // slot frees (see `pinata_object_list_for_refs`); the MB-scale OID list is never
    // held by a parked task.
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
        // #174 F2a: gated on the cheap announce predicate, not on `withheld`.
        // `withheld` is None for a push that coalesced (it never walked), and
        // this task's work is per-push and non-idempotent, so keying it on the
        // walk result would silently stop pinning and stop recording a branch to
        // CID mapping for every coalesced push. The fail-closed source for this
        // path is now `pinata_object_list_for_refs`'s own recomputation of
        // `replication_withheld_set` inside the pin permit: it returns an empty
        // list AND announce=false when the walk fails or the repo may not
        // replicate, so neither blobs nor announcements escape an unvetted push.
        //
        // #174 F2b: except when THIS push already ran that walk and it failed. The
        // re-derivation would fail the same way, so it buys nothing, and it would buy
        // it at the price of a global pin permit plus a second round of git children.
        // The pin pool DEFERS rather than sheds, so enough such pushes stall pins
        // node-wide. A coalesced push never walked, so it is unaffected.
        let do_pinata_replication = announce_at_root && !own_walk_failed;
        // #174 F2 / KTD-3: capture only the small inputs the re-derivation needs; the
        // MB-scale object list is NOT moved in. `pinata_object_list_for_refs` recomputes
        // it from these once a pin slot frees. rules/owner/is_public drive the fresh
        // fail-closed withheld filter; encrypt_sem + git_bin + timeout keep the re-derive
        // git children under the same INV-22 bounded, group-reaped scan admission.
        let pinata_rules_opt = rules_opt.clone();
        let pinata_owner_did = record.owner_did.clone();
        let pinata_is_public = record.is_public;
        let pinata_git_bin = state.git_bin.clone();
        let pinata_git_timeout =
            std::time::Duration::from_secs(state.config.git_service_timeout_secs);
        let pinata_encrypt_sem = state.git_encrypt_semaphore.clone();
        // Same global pin-admission bound as the IPFS loop (#174 F6): the Pinata pin
        // loop holds a re-derived object-id list while pinning it, so it shares the cap.
        // It DEFERS on a full pool rather than dropping the pin.
        let pin_sem_pinata = state.pin_semaphore.clone();
        tokio::spawn(async move {
            // `announce` comes back from the re-derivation below rather than from
            // the tail's own walk (#174 F2a): a coalesced push has no walk of its
            // own, and this is the recomputation that fails closed for it. When
            // the repo is not announceable at root there is no re-derivation and
            // no announcement either, which is the same answer the walk gave.
            let (announce, pinned) = if do_pinata_replication {
                let _pin_permit = pin_sem_pinata
                    .acquire_owned()
                    .await
                    .expect("pin_semaphore is never closed");
                // Re-derive the object set now that a pin slot is free (#174 F2 /
                // KTD-3). A parked task retained only `ref_updates_clone` (O(ref
                // tuples)), never this list, so a slow Pinata backend cannot grow
                // outstanding memory O(pushes x object-list). Fresh + fail-closed;
                // each git child is INV-22 bounded and process-group reaped.
                let (announce, object_list) = pinata_object_list_for_refs(
                    pinata_encrypt_sem,
                    repo_path_clone.clone(),
                    &ref_updates_clone,
                    pinata_rules_opt,
                    pinata_is_public,
                    pinata_owner_did,
                    pinata_git_bin,
                    pinata_git_timeout,
                )
                .await;
                (
                    announce,
                    crate::pinata::pin_new_objects(
                        &http_client,
                        &pinata_upload_url,
                        &pinata_jwt,
                        &repo_path_clone,
                        // The literal, not `state.git_bin`: tests point that at a fake
                        // walk git, and this read must run the real one.
                        "git",
                        object_list,
                        &db_clone,
                        crate::ipfs_pin::PIN_BATCH_BUDGET,
                    )
                    .await,
                )
            } else {
                (false, Vec::new())
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

/// `Clone` so `git_receive_pack` can hand the parsed updates to the detached
/// replication tail at the durability boundary while the certificate and webhook
/// loops below still iterate their own copy (#174 U5).
#[derive(Clone)]
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
    fn upload_pack_request_finalizes_only_with_done_pktline() {
        let want = "0032want 1111111111111111111111111111111111111111\n";
        let have = "0032have 2222222222222222222222222222222222222222\n";
        // Finalizing round: wants + flush + done.
        let done_round = format!("{want}00000009done\n").into_bytes();
        assert!(request_finalizes_fetch(&done_round));
        // Negotiation-only round: wants + flush + haves + flush, no done.
        let nego_round = format!("{want}0000{have}0000").into_bytes();
        assert!(!request_finalizes_fetch(&nego_round));
        // Degenerate: empty and a bare flush never finalize.
        assert!(!request_finalizes_fetch(b""));
        assert!(!request_finalizes_fetch(b"0000"));
        // `done` with no trailing newline (0008done) still finalizes.
        assert!(request_finalizes_fetch(b"00000008done"));
        // A payload that merely contains the substring "done" is not a done pkt
        // (000c -> len 12 -> payload "wantdone").
        assert!(!request_finalizes_fetch(b"000cwantdone"));
        // A malformed length prefix does not panic and does not count.
        assert!(!request_finalizes_fetch(b"zzzzdone\n"));
        // 0003 is a len<4 value that is NOT a valid marker (only 0000/0001/0002
        // are); treating it as a marker would skip 4 bytes and read the trailing
        // `0009done\n` as a finalizer. Reject the malformed framing.
        assert!(!request_finalizes_fetch(b"00030009done\n"));
        // A trailing byte after the `done` pkt-line is malformed; fail closed.
        assert!(!request_finalizes_fetch(b"0009done\nx"));
    }

    #[test]
    fn should_count_fetch_uses_response_outcome_split_by_path() {
        // Plain path (served_filtered_pack = false): count == response_served_pack.
        assert!(should_count_fetch(false, false, true)); // no-done, pack in response
        assert!(should_count_fetch(true, false, true)); // done, pack in response
        assert!(!should_count_fetch(false, false, false)); // negotiation-only, no pack
        assert!(!should_count_fetch(true, false, false)); // no pack served -> not counted

        // Filtered path (served_filtered_pack = true): count == finalizes_fetch.
        assert!(should_count_fetch(true, true, true)); // fresh clone: want+done
        assert!(!should_count_fetch(false, true, true)); // rejected mid-negotiation: no done
        assert!(!should_count_fetch(false, true, false));
    }

    // (a) #192 F1 — a `no-done` fetch: the client finishes a flush-terminated
    // round and the server answers `ACK <oid> ready` + pack, with no `done` in the
    // request. It must count exactly one completion. RED under the old
    // `finalizes || served_filtered_pack` rule (both false across every round -> 0);
    // GREEN once the plain path counts off the response pack.
    #[test]
    fn no_done_plain_fetch_counts_once() {
        crate::metrics::init("0.0.0-test", "did:key:test");
        let (pack_bearing, negotiation_only) = smart_http::upload_pack_result_fixtures();

        let want = "0032want 1111111111111111111111111111111111111111\n";
        let no_done = format!("{want}0000").into_bytes(); // no `done` pkt-line

        // Two rounds, neither request carrying `done`: a negotiation round (no pack
        // in the response) then the completing round (pack in the response).
        let rounds: [(&[u8], &[u8]); 2] = [
            (no_done.as_slice(), &negotiation_only),
            (no_done.as_slice(), &pack_bearing),
        ];
        let label = "fetchgate/no-done-plain";
        let before = crate::metrics::fetch_count_for_test(label);
        for (req, output) in rounds {
            let finalizes = request_finalizes_fetch(req);
            let served_pack = smart_http::response_served_pack(output);
            if should_count_fetch(finalizes, false, served_pack) {
                crate::metrics::record_fetch(label);
            }
        }
        assert_eq!(
            crate::metrics::fetch_count_for_test(label) - before,
            1,
            "a no-done fetch (server sends pack, request has no `done`) must count once"
        );
    }

    // (b) A plain negotiation-only round (server replies ACK/NAK with no pack)
    // must count zero, so the intermediate rounds of a multi-round fetch never
    // over-count.
    #[test]
    fn plain_negotiation_only_round_counts_zero() {
        crate::metrics::init("0.0.0-test", "did:key:test");
        let (_pack_bearing, negotiation_only) = smart_http::upload_pack_result_fixtures();

        let want = "0032want 1111111111111111111111111111111111111111\n";
        let no_done = format!("{want}0000").into_bytes();
        let label = "fetchgate/plain-negotiation-only";
        let before = crate::metrics::fetch_count_for_test(label);
        let served_pack = smart_http::response_served_pack(&negotiation_only);
        if should_count_fetch(request_finalizes_fetch(&no_done), false, served_pack) {
            crate::metrics::record_fetch(label);
        }
        assert_eq!(
            crate::metrics::fetch_count_for_test(label) - before,
            0,
            "a plain negotiation-only round (no pack in the response) must not count"
        );
    }

    // (c) #192 F2 — the pre-#191 rejected filtered scenario: the node answers a
    // mid-negotiation POST with NAK + a full pack, real git rejects it and (before
    // #191) the exchange spans two filtered POSTs, neither carrying `done`. It must
    // count zero, not two. RED under the old rule (each filtered POST set the flag
    // -> counted twice); GREEN once the filtered path is gated on `done`.
    #[test]
    fn rejected_filtered_fetch_counts_zero_not_two() {
        crate::metrics::init("0.0.0-test", "did:key:test");
        let want = "0032want 1111111111111111111111111111111111111111\n";
        let no_done = format!("{want}0000").into_bytes(); // no `done`
        let label = "fetchgate/rejected-filtered";
        let before = crate::metrics::fetch_count_for_test(label);
        // Two filtered POSTs (served_filtered_pack = true, each response carries a
        // self-contained pack), neither carrying `done`.
        for _ in 0..2 {
            if should_count_fetch(request_finalizes_fetch(&no_done), true, true) {
                crate::metrics::record_fetch(label);
            }
        }
        assert_eq!(
            crate::metrics::fetch_count_for_test(label) - before,
            0,
            "a rejected filtered fetch (no `done`) must not count, and must not double-count"
        );
    }

    // (d) A fresh filtered clone carries `want`+`done` and the node serves a full
    // pack; it must count exactly one.
    #[test]
    fn fresh_filtered_clone_counts_once() {
        crate::metrics::init("0.0.0-test", "did:key:test");
        let want = "0032want 1111111111111111111111111111111111111111\n";
        let done = format!("{want}00000009done\n").into_bytes(); // want + done
        let label = "fetchgate/fresh-filtered-clone";
        let before = crate::metrics::fetch_count_for_test(label);
        if should_count_fetch(request_finalizes_fetch(&done), true, true) {
            crate::metrics::record_fetch(label);
        }
        assert_eq!(
            crate::metrics::fetch_count_for_test(label) - before,
            1,
            "a fresh filtered clone (want+done) must count exactly one"
        );
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
            std::sync::Arc::new(tokio::sync::Semaphore::new(64)),
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
            std::sync::Arc::new(tokio::sync::Semaphore::new(64)),
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
            std::sync::Arc::new(tokio::sync::Semaphore::new(64)),
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
        assert!(owner_push_rejection(true, &repo, Some(OWNER_DID), None).is_none());
    }

    #[test]
    fn enforced_allows_owner_short_did() {
        // Owners are accepted in bare-multibase form, matching the rest of the
        // codebase's owner comparisons.
        let repo = repo_owned_by(OWNER_DID);
        assert!(owner_push_rejection(true, &repo, Some(OWNER_SHORT), None).is_none());
    }

    #[test]
    fn enforced_rejects_non_owner_with_forbidden() {
        let repo = repo_owned_by(OWNER_DID);
        assert_forbidden(owner_push_rejection(true, &repo, Some(STRANGER_DID), None));
    }

    #[test]
    fn enforced_rejects_missing_did_with_forbidden() {
        // Fail closed: an absent authenticated identity is rejected, not allowed.
        let repo = repo_owned_by(OWNER_DID);
        assert_forbidden(owner_push_rejection(true, &repo, None, None));
    }

    #[test]
    fn disabled_allows_non_owner_and_missing_did() {
        // Flag off → legacy behavior: authentication-only, no owner gate.
        let repo = repo_owned_by(OWNER_DID);
        assert!(owner_push_rejection(false, &repo, Some(STRANGER_DID), None).is_none());
        assert!(owner_push_rejection(false, &repo, None, None).is_none());
    }

    /// Build a VerifiedUcan whose chain roots at `root_did` and which carries
    /// `git/push` for `repo`. The token's own issuer and audience do not matter
    /// here: the middleware has already bound them before this gate is reached.
    fn push_delegation(root_did: &str, repo: &crate::db::RepoRecord) -> crate::auth::VerifiedUcan {
        let agent = gitlawb_core::identity::Keypair::generate();
        let node = gitlawb_core::identity::Keypair::generate();
        let ucan = gitlawb_core::ucan::Ucan::issue(
            &agent,
            node.did(),
            vec![gitlawb_core::ucan::Capability::new(
                format!("gitlawb://repos/{}/{}", repo.owner_did, repo.name),
                gitlawb_core::ucan::caps::GIT_PUSH,
            )],
            None,
        )
        .expect("issue delegation");
        crate::auth::VerifiedUcan {
            ucan,
            root: root_did.parse().expect("root DID must parse"),
        }
    }

    #[test]
    fn enforced_allows_a_non_owner_holding_an_owner_rooted_push_capability() {
        // The regression owner-only push introduced: a CI or delegated key with a
        // valid capability was refused exactly like a stranger.
        let repo = repo_owned_by(OWNER_DID);
        let verified = push_delegation(OWNER_DID, &repo);
        assert!(
            owner_push_rejection(true, &repo, Some(STRANGER_DID), Some(&verified)).is_none(),
            "a delegation rooted at the owner must let a non-owner push"
        );
    }

    #[test]
    fn enforced_rejects_a_delegation_rooted_at_a_stranger() {
        // Anchoring is the whole point: a chain nobody the repo trusts started
        // grants nothing, even carrying a perfectly formed push capability.
        let repo = repo_owned_by(OWNER_DID);
        let verified = push_delegation(STRANGER_DID, &repo);
        assert_forbidden(owner_push_rejection(
            true,
            &repo,
            Some(STRANGER_DID),
            Some(&verified),
        ));
    }

    #[test]
    fn enforced_still_rejects_a_non_owner_with_no_capability() {
        let repo = repo_owned_by(OWNER_DID);
        assert_forbidden(owner_push_rejection(true, &repo, Some(STRANGER_DID), None));
    }

    #[test]
    fn caller_authorized_to_push_is_owner_only_in_phase_1() {
        let repo = repo_owned_by(OWNER_DID);
        assert!(caller_authorized_to_push(&repo, OWNER_DID, None));
        assert!(caller_authorized_to_push(&repo, OWNER_SHORT, None));
        assert!(!caller_authorized_to_push(&repo, STRANGER_DID, None));
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

    /// #174 U6: the `info/refs` advertisement must run the CONFIGURED git binary,
    /// like upload-pack and receive-pack already do. It passed a literal "git", so a
    /// fake-git harness could drive the pack paths but never the advertisement.
    ///
    /// MUTATION (RED): restore the `"git"` literal at the `smart_http::info_refs`
    /// call and the fake's marker never reaches the response body.
    #[cfg(unix)]
    #[sqlx::test]
    async fn u6_info_refs_runs_the_configured_git_binary(pool: sqlx::PgPool) {
        use axum::extract::{Path, Query, State};
        use http_body_util::BodyExt;

        let tmp = tempfile::TempDir::new().unwrap();
        // Distinctive advertisement so the assertion cannot pass on real git's output.
        let body = "#!/bin/sh\n\
                    case \"$1\" in\n\
                      upload-pack) printf 'U6-FAKE-ADVERTISEMENT' ;;\n\
                      *) : ;;\n\
                    esac\n\
                    exit 0\n";
        let git_bin = write_fake_git(tmp.path(), body);
        let state =
            f4_state_with_repo(pool.clone(), tmp.path(), &git_bin, "z6u6adv", "a1", false).await;

        let resp = git_info_refs(
            State(state),
            Path(("z6u6adv".to_string(), "a1".to_string())),
            Query(InfoRefsQuery {
                service: Some("git-upload-pack".to_string()),
            }),
            crate::rate_limit::PeerAddr(Some("203.0.113.95:5000".parse().unwrap())),
            axum::http::HeaderMap::new(),
            None,
        )
        .await
        .expect("the advertisement must succeed");

        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.contains("U6-FAKE-ADVERTISEMENT"),
            "info/refs must run state.git_bin, not a hardcoded \"git\"; body was: {text:?}"
        );
    }

    /// #174 U4: `withheld_recipients_gated` must hold its encrypt-scan permit INSIDE
    /// the blocking closure, matching every other post-receive scan helper (see
    /// `replication_withheld_set`, where the permit is moved in with "a started walk
    /// always completes holding it").
    ///
    /// Holding it in the async frame instead means dropping the future releases the
    /// permit while the uncancellable `spawn_blocking` walk keeps running, so the
    /// encrypt pool admits a replacement scan against a slot still occupied by a live
    /// git child.
    ///
    /// MUTATION (RED): hoist `_permit` back out of the closure and the
    /// still-held-after-drop assertion fails — the count returns to 1 immediately.
    #[cfg(unix)]
    #[tokio::test]
    async fn u4_encrypt_scan_permit_is_held_through_the_blocking_walk() {
        use std::time::Duration;
        let tmp = tempfile::TempDir::new().unwrap();
        let pidfile = tmp.path().join("u4_walk.pid");
        // Hang on the first real walk command, whatever it is; only rev-parse answers.
        let body = format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
               rev-parse) echo deadbeef ;;\n\
               *) echo $$ > \"{pid}\"; while true; do sleep 1; done ;;\n\
             esac\n\
             exit 0\n",
            pid = pidfile.display(),
        );
        let git_bin = write_fake_git(tmp.path(), &body);
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(1));

        let mut fut = Box::pin(withheld_recipients_gated(
            sem.clone(),
            tmp.path().to_path_buf(),
            git_bin,
            Duration::from_secs(600),
            vec![vis_rule("/secret/**", &[])],
            true,
            "did:key:z6MkU4OwnerAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        ));

        // Drive until the blocking walk's git child records its pid.
        let mut walk_pid: Option<i32> = None;
        for _ in 0..500 {
            let _ = tokio::time::timeout(Duration::from_millis(10), &mut fut).await;
            if let Some(p) = std::fs::read_to_string(&pidfile)
                .ok()
                .and_then(|s| s.trim().parse::<i32>().ok())
            {
                walk_pid = Some(p);
                break;
            }
        }
        let pid = walk_pid.expect("the fake git walk command must have spawned");
        struct ReapOnDrop(i32);
        impl Drop for ReapOnDrop {
            fn drop(&mut self) {
                unsafe {
                    libc::kill(self.0, libc::SIGKILL);
                }
            }
        }
        let _cleanup = ReapOnDrop(pid);

        assert_eq!(
            sem.available_permits(),
            0,
            "the scan permit must be held while the blocking walk runs"
        );

        drop(fut);
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(
            unsafe { libc::kill(pid, 0) } == 0,
            "precondition: the walk's git child must still be alive, or this \
             assertion proves nothing"
        );
        assert_eq!(
            sem.available_permits(),
            0,
            "dropping the future must NOT release the encrypt-scan permit while the \
             uncancellable blocking walk it admitted is still running"
        );

        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        let mut freed = false;
        for _ in 0..400 {
            if sem.available_permits() == 1 {
                freed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            freed,
            "once the blocking walk ends the scan permit must return to the pool"
        );
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
                std::sync::Arc::new(tokio::sync::Semaphore::new(64)),
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

    /// #174 U1 follow-up (RED-before/GREEN-after): the path-scoped upload-pack branch
    /// shares ONE deadline across the withheld-blob walk and the pack serve, so one
    /// clone cannot hold a read permit for ~2x `git_service_timeout_secs`. A walk that
    /// consumes most of the budget must leave the serve only the REMAINDER, so the
    /// serve is reaped and the request is a 504.
    ///
    /// Load-bearing: give the serve a fresh `git_timeout` instead of the remainder and
    /// the fake `upload-pack` (1.2s) fits inside a fresh 2s budget, completes, and the
    /// status is no longer 504 (RED). This is the ~2x-budget hold the unit removes.
    ///
    /// Plain-serve arm: the fake git lists no refs and fails `rev-parse`, so the walk
    /// yields an empty withheld set and the branch takes `upload_pack`. `rev-list`
    /// carries the walk's cost.
    #[cfg(unix)]
    #[sqlx::test]
    async fn upload_pack_shares_one_deadline_across_walk_and_plain_serve(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::{Method, Request, StatusCode};
        use std::net::SocketAddr;
        use tower::ServiceExt;

        let tmp = tempfile::TempDir::new().unwrap();
        // Walk: no refs (for-each-ref empty), HEAD does not resolve (rev-parse exit 1),
        // rev-list burns 1.2s of the 2s budget and lists no commits -> empty withheld.
        // Serve: upload-pack needs 1.2s, which does NOT fit the ~0.8s remainder but
        // WOULD fit a fresh 2s budget.
        let body = "#!/bin/sh\ncase \"$1\" in\n  rev-parse) exit 1 ;;\n  rev-list) sleep 1.2 ;;\n  upload-pack) sleep 1.2 ;;\n  *) : ;;\nesac\nexit 0\n";
        let fake = write_fake_git(tmp.path(), body);

        let mut state = crate::test_support::test_state(pool).await;
        state.git_bin = fake;
        let mut cfg = (*state.config).clone();
        cfg.git_service_timeout_secs = 2;
        state.config = std::sync::Arc::new(cfg);
        state
            .db
            .upsert_mirror_repo("z6shared1", "sv", "/tmp/z6shared1-sv", None, false)
            .await
            .unwrap();
        let rec = state.db.get_repo("z6shared1", "sv").await.unwrap().unwrap();
        // Path-scoped rule so has_path_scoped_rule() is true and the walk runs.
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
        let disk = std::path::Path::new("/tmp/z6shared1/sv.git");
        std::fs::create_dir_all(disk).unwrap();

        let peer: SocketAddr = "203.0.113.92:7000".parse().unwrap();
        let router = crate::server::build_router(state);
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/z6shared1/sv/git-upload-pack")
            .body(Body::from(&b"0000"[..]))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        let status = router.oneshot(req).await.unwrap().status();
        let _ = std::fs::remove_dir_all("/tmp/z6shared1");
        assert_eq!(
            status,
            StatusCode::GATEWAY_TIMEOUT,
            "the walk and the serve must share ONE deadline, so a walk that burns most \
             of the budget leaves the serve only the remainder and the serve is reaped; \
             a non-504 here means the serve got a fresh full budget (the ~2x hold)"
        );
    }

    /// #174 U1 follow-up, FILTERED arm (RED-before/GREEN-after): the shared deadline
    /// must reach `upload_pack_excluding` too, not just the plain `upload_pack`. Same
    /// property as the plain-arm test, different serve function, because the branch
    /// threads the remainder into both arms and a fix that missed one would leave the
    /// ~2x hold reachable by any clone of a repo that actually withholds something.
    ///
    /// The fake git yields a NON-EMPTY withheld set: one ref peeling to a commit, a
    /// resolvable HEAD, one commit, and an `ls-tree -rz` record placing a blob under
    /// `/secret/`, which the path-scoped rule denies to an anonymous caller. `ls-tree`
    /// carries the walk's cost (walk-only), and `pack-objects` carries the serve's, so
    /// the two phases are independently attributable.
    ///
    /// Load-bearing: hand the serve a fresh `git_timeout` and `pack-objects` (1.2s)
    /// fits a fresh 2s budget, completes, and the status is no longer 504 (RED).
    #[cfg(unix)]
    #[sqlx::test]
    async fn upload_pack_shares_one_deadline_across_walk_and_filtered_serve(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::{Method, Request, StatusCode};
        use std::net::SocketAddr;
        use tower::ServiceExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let commit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let blob = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        // for-each-ref lists one ref; cat-file peels it to a commit (the fail-closed
        // ref check); rev-parse resolves HEAD; rev-list lists the one commit; ls-tree
        // emits "<mode> blob <oid>\t<path>" (NUL-delimited) under secret/ and burns
        // 1.2s of the 2s budget; pack-objects is the serve's 1.2s cost.
        let body = format!(
            "#!/bin/sh\ncase \"$1\" in\n  \
             for-each-ref) echo refs/heads/main ;;\n  \
             cat-file) echo commit ;;\n  \
             rev-parse) echo {commit} ;;\n  \
             rev-list) echo {commit} ;;\n  \
             ls-tree) printf '100644 blob {blob}\\tsecret/f.txt' ; sleep 1.2 ;;\n  \
             pack-objects) sleep 1.2 ;;\n  \
             *) : ;;\nesac\nexit 0\n"
        );
        let fake = write_fake_git(tmp.path(), &body);

        let mut state = crate::test_support::test_state(pool).await;
        state.git_bin = fake;
        let mut cfg = (*state.config).clone();
        cfg.git_service_timeout_secs = 2;
        state.config = std::sync::Arc::new(cfg);
        state
            .db
            .upsert_mirror_repo("z6shared2", "sv", "/tmp/z6shared2-sv", None, false)
            .await
            .unwrap();
        let rec = state.db.get_repo("z6shared2", "sv").await.unwrap().unwrap();
        // Denies /secret/** to an anonymous caller, so the blob above is withheld and
        // the branch takes upload_pack_excluding rather than the plain serve.
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
        let disk = std::path::Path::new("/tmp/z6shared2/sv.git");
        std::fs::create_dir_all(disk).unwrap();

        let peer: SocketAddr = "203.0.113.93:7000".parse().unwrap();
        let router = crate::server::build_router(state);
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/z6shared2/sv/git-upload-pack")
            .body(Body::from(&b"0000"[..]))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        let status = router.oneshot(req).await.unwrap().status();
        let _ = std::fs::remove_dir_all("/tmp/z6shared2");
        assert_eq!(
            status,
            StatusCode::GATEWAY_TIMEOUT,
            "the FILTERED serve must also take the shared deadline's remainder; a \
             non-504 here means upload_pack_excluding got a fresh full budget and the \
             ~2x hold is still reachable whenever a repo withholds a blob"
        );
    }

    /// #174 (F2 sizing edge, vetted by execution): the receive-pack advertisement
    /// per-source cap comes from `rate_limit::per_source_push_cap`, the same helper
    /// both main.rs derivation sites call, so it is never 0 even at the minimum
    /// write-pool size (1). A 0 cap would make PerCallerConcurrency shed EVERY
    /// receive-pack advertisement and break all pushes.
    #[test]
    fn advert_per_caller_cap_sizing_is_never_zero() {
        let cap = crate::rate_limit::per_source_push_cap;
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

    /// #174 (review fix): the anon-reachable receive-pack advertisement draws from its
    /// own dedicated advert pool, so it is bounded per source by
    /// `git_push_advert_per_caller` to stop one source from monopolizing that pool and
    /// shedding other sources' advertisements. Fill one source IP's advert slot; its next receive-pack advertisement
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
            "a source at its receive-pack advertisement cap must shed 503, so it cannot monopolize the advert pool"
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
    ///
    /// Unix-only: the fake git is a `/bin/sh` script made executable through
    /// `PermissionsExt::set_mode`, and the hung `rev-list` is reaped with
    /// `libc::kill(SIGKILL)`. Neither exists on Windows, so without this gate the
    /// whole `gitlawb-node` test target fails to compile there (#228) and no test
    /// in the crate can run on a Windows checkout.
    #[cfg(unix)]
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

    /// F1 (filtered-serve residual of #174 P1-a, RED-before/GREEN-after): on the
    /// FILTERED (path-scoped, non-empty withheld) upload-pack branch a client
    /// disconnect mid-pack-objects must NOT release the read admission while the
    /// detached reaper is still tearing down the git group. Pre-fix the handler held
    /// the permits as locals (`_hold`) across `upload_pack_excluding`, so dropping
    /// the future released them instantly and disconnect-spam could exceed the read
    /// caps during each reap window (RED). The fix threads the AdmissionGuard through
    /// both filtered-pack stages so it rides `KillGroupOnDrop` into the reaper.
    ///
    /// Same isolation as the plain-path test above: read pool = 1, per-source cap
    /// permissive, so only the global permit can shed a replacement. The fake git
    /// serves the withheld walk (for-each-ref/rev-parse/rev-list/ls-tree) with a blob
    /// under the denied `/src/**` subtree so the filtered branch is taken, answers
    /// the pack build's rev-list fast, and hangs pack-objects in a SIGTERM-trapping
    /// descendant. The descendant hang is first-invocation-only (keyed on the
    /// pidfile's existence) so the post-reap replacement request completes fast.
    #[cfg(unix)]
    #[sqlx::test]
    async fn upload_pack_filtered_permit_held_through_group_reap_after_disconnect(
        pool: sqlx::PgPool,
    ) {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::{Method, Request, StatusCode};
        use std::net::SocketAddr;
        use std::sync::Arc;
        use tokio::sync::Semaphore;
        use tower::ServiceExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let descfile = tmp.path().join("desc.pid");
        let commit = "1111111111111111111111111111111111111111";
        let blob = "2222222222222222222222222222222222222222";
        let body = format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
               rev-parse) echo {commit} ;;\n\
               rev-list) echo {commit} ;;\n\
               ls-tree) printf '100644 blob {blob}\\tsrc/x.txt' ;;\n\
               pack-objects)\n\
                 if [ ! -e \"{desc}\" ]; then\n\
                   sh -c 'trap \"\" TERM; echo $$ > \"{desc}\"; i=0; while [ $i -lt 20 ]; do sleep 1; i=$((i+1)); done' &\n\
                   wait\n\
                 fi ;;\n\
               *) : ;;\n\
             esac\n\
             exit 0\n",
            desc = descfile.display()
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

        let owner = "z6upf1";
        let name = "upf";
        state
            .db
            .upsert_mirror_repo(owner, name, "/unused", None, false)
            .await
            .unwrap();
        let rec = state.db.get_repo(owner, name).await.unwrap().unwrap();
        // Real bare repo at the path acquire() computes, so the handler reaches the
        // walk and the filtered serve.
        state
            .repo_store
            .init(&rec.owner_did, &rec.name)
            .await
            .unwrap();
        // Path-scoped rule denying the anonymous caller under /src, matching the
        // fake ls-tree's blob path, so the withheld set is NON-EMPTY and the
        // filtered (upload_pack_excluding) branch is taken.
        state
            .db
            .set_visibility_rule(
                &rec.id,
                "/src/**",
                crate::db::VisibilityMode::B,
                &["did:key:z6MkUF1ReaderAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()],
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
        let make_req = |peer: SocketAddr| {
            let mut req = Request::builder()
                .method(Method::POST)
                .uri(format!("/{owner}/{name}/git-upload-pack"))
                .body(Body::from(&b"0000"[..]))
                .unwrap();
            req.extensions_mut().insert(ConnectInfo(peer));
            req
        };

        let peer: SocketAddr = "203.0.113.81:5000".parse().unwrap();
        let mut fut = Box::pin(router.clone().oneshot(make_req(peer)));
        // Drive until the pack-objects descendant records its pid: the request is
        // past the walk, inside the filtered serve's stage 2, holding the read permit.
        // Stop polling the instant the future completes (re-polling a completed
        // oneshot panics); read the descfile first so a spawn that recorded its pid
        // then returned is still caught.
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
        let desc = spawned.unwrap_or_else(|| {
            panic!("the fake pack-objects must have spawned; early finish: {early:?}")
        });
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
            "the read slot is held while the filtered serve runs"
        );

        // Client disconnect: drop the request future mid-pack-objects. The detached
        // reaper must now own the AdmissionGuard and hold it until ESRCH.
        drop(fut);

        // Load-bearing: the slot must STAY held while the SIGTERM-ignoring group is
        // still alive. On the pre-fix code the handler-local `_hold` drops here and
        // the slot frees at once (RED). Check quickly (before the reaper's ~2s
        // SIGKILL escalation).
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            unsafe { libc::kill(desc, 0) == 0 },
            "the SIGTERM-ignoring descendant must still be alive during the hold window"
        );
        assert_eq!(
            sem.available_permits(),
            0,
            "on disconnect the read admission must be HELD until the filtered serve's \
             process group is reaped, not released the instant the future drops (F1)"
        );
        // A replacement request from a DIFFERENT source must shed 503: the only pool
        // that can shed it is the held global permit (per-source cap is permissive).
        let peer2: SocketAddr = "203.0.113.82:5000".parse().unwrap();
        let resp = router.clone().oneshot(make_req(peer2)).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "while the prior group is still alive the held global permit must shed a \
             replacement with 503"
        );

        // After the reaper SIGKILLs + reaps the group the AdmissionGuard drops and
        // the slot frees. Poll for recovery.
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
        // A replacement is now admitted and completes: the fake pack-objects takes
        // its fast path (the descfile exists), so the filtered serve returns instead
        // of hanging.
        let peer3: SocketAddr = "203.0.113.83:5000".parse().unwrap();
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
            None,
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
            None,
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
        use crate::git::repo_store::advisory_lock_key;
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;
        use std::sync::Arc;
        use tokio::sync::Semaphore;

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
                None,
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
        // The follow-up asserts an ADMISSION property (the freed write slot is usable),
        // so it must not inherit the 2s acquire deadline the shed above is testing. That
        // budget covers a real advisory-lock round trip, and on a loaded machine it
        // expires and returns the same `Overloaded` this assertion reads as a drained
        // pool: a correct run going red for a reason the test is not about.
        let mut followup_cfg = (*state.config).clone();
        followup_cfg.git_acquire_timeout_secs = 120;
        state.config = std::sync::Arc::new(followup_cfg);
        let followup = git_receive_pack(
            State(state.clone()),
            Path((owner.to_string(), name.to_string())),
            Extension(crate::auth::AuthenticatedDid(did.to_string())),
            None,
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
    ///
    /// Unix-only for the same reason as
    /// `upload_pack_permit_held_through_walk_after_disconnect`: the fake git is a
    /// `/bin/sh` script made executable through `PermissionsExt::set_mode` (#228).
    #[cfg(unix)]
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

    /// F4 defer proof 1: `replication_withheld_set`'s WALK arm acquires a
    /// `git_encrypt_semaphore` permit before its spawn_blocking git walk, deferring
    /// (never shedding) when the pool is exhausted — while its no-walk fast paths
    /// (no path-scoped rule; not announceable) complete WITHOUT touching the pool.
    /// On ungated code the walk runs regardless of a zero-permit pool (RED).
    #[cfg(unix)]
    #[tokio::test]
    async fn replication_walk_defers_when_scan_pool_exhausted() {
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::sync::Semaphore;

        let tmp = tempfile::TempDir::new().unwrap();
        let marker = tmp.path().join("git.ran");
        // Fake git records ANY invocation (the walk's first call is rev-parse), then
        // behaves well enough for a successful empty walk: HEAD probe succeeds,
        // rev-list lists no commits.
        let body = format!(
            "#!/bin/sh\necho ran >> \"{}\"\ncase \"$1\" in\n  rev-parse) echo deadbeef ;;\n  *) : ;;\nesac\nexit 0\n",
            marker.display()
        );
        let git_bin = write_fake_git(tmp.path(), &body);
        let scoped_rules = || Some(vec![vis_rule("/secret/**", &[])]);

        // Zero-permit pool: every gated walk must park forever.
        let sem: Arc<Semaphore> = Arc::new(Semaphore::new(0));

        // Fast path A (negative arm): announceable, NO path-scoped rule -> zero git
        // work, must complete immediately without acquiring from the empty pool.
        let fast = tokio::time::timeout(
            Duration::from_millis(500),
            replication_withheld_set(
                sem.clone(),
                Some(vec![]),
                OWNER_DID,
                true,
                tmp.path().to_path_buf(),
                git_bin.clone(),
                Duration::from_secs(5),
            ),
        )
        .await
        .expect("the no-path-scoped-rule fast path must not park on the scan pool");
        assert_eq!(fast, (true, Some(std::collections::HashSet::new())));

        // Fast path B (negative arm): not announceable (no rules) -> zero git work,
        // must complete immediately without acquiring.
        let fast = tokio::time::timeout(
            Duration::from_millis(500),
            replication_withheld_set(
                sem.clone(),
                None,
                OWNER_DID,
                false,
                tmp.path().to_path_buf(),
                git_bin.clone(),
                Duration::from_secs(5),
            ),
        )
        .await
        .expect("the not-announceable fast path must not park on the scan pool");
        assert_eq!(fast, (false, None));
        assert!(!marker.exists(), "the fast paths must spawn no git at all");

        // Walk arm with the pool exhausted: must DEFER (park), spawning no git.
        let blocked = tokio::time::timeout(
            Duration::from_millis(500),
            replication_withheld_set(
                sem.clone(),
                scoped_rules(),
                OWNER_DID,
                true,
                tmp.path().to_path_buf(),
                git_bin.clone(),
                Duration::from_secs(5),
            ),
        )
        .await;
        assert!(
            blocked.is_err(),
            "the withheld walk must defer (park on admission) when the pool is exhausted"
        );
        assert!(
            !marker.exists(),
            "the withheld walk's git must not spawn while its admission permit is unavailable (F4)"
        );

        // Release admission: the SAME walk now runs (defer, not shed) and succeeds.
        sem.add_permits(1);
        let ran = replication_withheld_set(
            sem,
            scoped_rules(),
            OWNER_DID,
            true,
            tmp.path().to_path_buf(),
            git_bin,
            Duration::from_secs(5),
        )
        .await;
        assert!(
            marker.exists(),
            "once admission is available the deferred withheld walk runs its git"
        );
        assert_eq!(
            ran,
            (true, Some(std::collections::HashSet::new())),
            "the released walk completes and vets the (empty) withheld set"
        );
    }

    /// F4 defer proof 3: `fail_closed_full_scan_objects` ALWAYS walks, so its
    /// spawn_blocking is always admission-gated: with the pool exhausted it defers
    /// and spawns no git; with a permit the same call runs. Ungated it runs
    /// regardless (RED).
    #[cfg(unix)]
    #[tokio::test]
    async fn full_scan_pin_walk_defers_when_scan_pool_exhausted() {
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::sync::Semaphore;

        let tmp = tempfile::TempDir::new().unwrap();
        let marker = tmp.path().join("git.ran");
        let body = format!(
            "#!/bin/sh\necho ran >> \"{}\"\ncase \"$1\" in\n  rev-parse) echo deadbeef ;;\n  *) : ;;\nesac\nexit 0\n",
            marker.display()
        );
        let git_bin = write_fake_git(tmp.path(), &body);
        let candidates = vec!["3333333333333333333333333333333333333333".to_string()];

        let sem: Arc<Semaphore> = Arc::new(Semaphore::new(0));
        let blocked = tokio::time::timeout(
            Duration::from_millis(500),
            fail_closed_full_scan_objects(
                sem.clone(),
                tmp.path().to_path_buf(),
                vec![vis_rule("/secret/**", &[])],
                true,
                OWNER_DID.to_string(),
                candidates.clone(),
                git_bin.clone(),
                Duration::from_secs(5),
            ),
        )
        .await;
        assert!(
            blocked.is_err(),
            "the fail-closed full scan must defer (park on admission) when the pool is exhausted"
        );
        assert!(
            !marker.exists(),
            "the full scan's git must not spawn while its admission permit is unavailable (F4)"
        );

        // Release admission: the SAME scan now runs (defer, not shed).
        sem.add_permits(1);
        let _objs = fail_closed_full_scan_objects(
            sem,
            tmp.path().to_path_buf(),
            vec![vis_rule("/secret/**", &[])],
            true,
            OWNER_DID.to_string(),
            candidates,
            git_bin,
            Duration::from_secs(5),
        )
        .await;
        assert!(
            marker.exists(),
            "once admission is available the deferred full scan runs its git"
        );
    }

    /// #174 F4 (RED-before/GREEN-after): the two full-scan phases share ONE whole-scan
    /// deadline. Phase 1 (`replicable_blob_set_bounded`) succeeds but consumes almost
    /// the whole budget; phase 2 (`all_blob_oids`) then gets only the remainder. With a
    /// shared deadline phase 2 is reaped and the scan fails closed (pins nothing) — the
    /// safe direction. With a FRESH `Instant::now() + timeout` for phase 2 (pre-fix) it
    /// gets a full second budget, completes with an empty blob set, and the non-blob
    /// candidate is kept — so the result is NON-empty (RED) and the permit is held ~2x.
    #[cfg(unix)]
    #[tokio::test]
    async fn full_scan_shares_one_deadline_across_both_phases() {
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::sync::Semaphore;

        let tmp = tempfile::TempDir::new().unwrap();
        // Phase 1 (ls-tree) sleeps 1.5s and succeeds (empty tree); phase 2
        // (cat-file --batch-all-objects) sleeps 1.5s. With a 2s whole-scan budget the
        // shared deadline leaves phase 2 only ~0.5s, so it is reaped; a fresh 2s budget
        // would let it finish.
        let body = "#!/bin/sh\ncase \"$1\" in\n  rev-parse) echo deadbeef ;;\n  rev-list) echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ;;\n  ls-tree) sleep 1.5 ;;\n  cat-file) case \"$*\" in *--batch-all-objects*) sleep 1.5 ;; *) : ;; esac ;;\n  *) : ;;\nesac\nexit 0\n";
        let git_bin = write_fake_git(tmp.path(), body);
        // A candidate that is NOT a blob (never appears in all_blob_oids): kept by
        // replicable_objects_fail_closed only if phase 2 actually ran to completion.
        let candidates = vec!["cccccccccccccccccccccccccccccccccccccccc".to_string()];

        let sem: Arc<Semaphore> = Arc::new(Semaphore::new(1));
        let objs = fail_closed_full_scan_objects(
            sem,
            tmp.path().to_path_buf(),
            vec![vis_rule("/secret/**", &[])],
            true,
            OWNER_DID.to_string(),
            candidates,
            git_bin,
            Duration::from_secs(2),
        )
        .await;
        assert!(
            objs.is_empty(),
            "a large-but-successful phase 1 must leave phase 2 only the SHARED whole-scan \
             remainder, so it reaps and the scan fails closed; got {objs:?} (a fresh phase-2 \
             budget completed the scan and kept the candidate — the ~2x-budget bug)"
        );
    }

    /// #174 F6 (RED-before/GREEN-after): a post-push pin loop holds this push's full
    /// object-id list while walking it, so concurrent pin loops across many repos must
    /// be bounded by a global permit, not just the per-repo task count. `pin_new_objects_gated`
    /// DEFERS (waits) when the pin pool is exhausted rather than running unbounded.
    ///
    /// Load-bearing: without the permit acquire the pin loop runs immediately even with
    /// the pool held (RED — the deferral assertion fails). With it, it parks.
    #[sqlx::test]
    async fn pin_new_objects_gated_defers_when_pin_pool_exhausted(pool: sqlx::PgPool) {
        use std::sync::Arc;
        use tokio::sync::Semaphore;

        let state = crate::test_support::test_state(pool).await;
        let db = state.db.clone();
        let tmp = tempfile::TempDir::new().unwrap();
        let pin_sem = Arc::new(Semaphore::new(1));
        // Hold the only pin permit.
        let held = pin_sem.clone().acquire_owned().await.unwrap();

        // Empty ipfs_api makes the pin itself a no-op, but the loop must still DEFER on
        // the exhausted pin pool rather than run. The object list is non-empty because
        // an empty one takes no permit at all by design (#174 F2b).
        let objects = vec!["0123456789abcdef0123456789abcdef01234567".to_string()];
        let blocked = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            pin_new_objects_gated(&pin_sem, "", tmp.path(), objects.clone(), &db),
        )
        .await;
        assert!(
            blocked.is_err(),
            "a pin loop must defer while the pin pool is exhausted (#174 F6)"
        );

        // Release admission: the SAME call now completes.
        drop(held);
        let out = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            pin_new_objects_gated(&pin_sem, "", tmp.path(), objects, &db),
        )
        .await
        .expect("the pin loop completes once admission frees");
        assert!(out.is_empty(), "an empty ipfs_api pins nothing");
    }

    /// #174 F2b: the pin permit bounds how many pin loops run concurrently, so a call
    /// with NOTHING to pin must not take one. It otherwise spends a global pin slot on no
    /// work, and the pool DEFERS rather than sheds, so those calls stall pins for every
    /// other repo. The empty case is the normal shape for a push whose walk failed or
    /// that may replicate nothing.
    ///
    /// Load-bearing: without the guard this call parks on the exhausted pool exactly like
    /// the non-empty one above, and the completion assertion fails.
    #[sqlx::test]
    async fn pin_new_objects_gated_takes_no_permit_for_an_empty_object_list(pool: sqlx::PgPool) {
        use std::sync::Arc;
        use tokio::sync::Semaphore;

        let state = crate::test_support::test_state(pool).await;
        let db = state.db.clone();
        let tmp = tempfile::TempDir::new().unwrap();
        let pin_sem = Arc::new(Semaphore::new(1));
        // Hold the only pin permit for the whole call.
        let _held = pin_sem.clone().acquire_owned().await.unwrap();

        let out = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            pin_new_objects_gated(&pin_sem, "", tmp.path(), vec![], &db),
        )
        .await
        .expect("an empty object list must not wait on pin admission (#174 F2b)");
        assert!(out.is_empty(), "and it pins nothing");
        assert_eq!(
            pin_sem.available_permits(),
            0,
            "the test still holds the only permit, so the call never took one"
        );
    }

    /// Shared fixture for the F4 handler-layer tests: a state whose repo_store and
    /// git_bin point at the given tempdir/fake-git, plus a seeded on-disk repo,
    /// optionally with a path-scoped rule (so the post-receive walks actually run).
    #[cfg(unix)]
    async fn f4_state_with_repo(
        pool: sqlx::PgPool,
        tmp: &std::path::Path,
        git_bin: &str,
        owner: &str,
        name: &str,
        path_scoped: bool,
    ) -> AppState {
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.git_bin = git_bin.to_string();
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state
            .db
            .upsert_mirror_repo(owner, name, &format!("/unused-{owner}-{name}"), None, false)
            .await
            .unwrap();
        let rec = state.db.get_repo(owner, name).await.unwrap().unwrap();
        state
            .repo_store
            .init(&rec.owner_did, &rec.name)
            .await
            .unwrap();
        if path_scoped {
            state
                .db
                .set_visibility_rule(
                    &rec.id,
                    "/secret/**",
                    crate::db::VisibilityMode::B,
                    &["did:key:z6MkF4ReaderAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()],
                    &rec.owner_did,
                )
                .await
                .unwrap();
        }
        state
    }

    /// A pkt-line receive-pack body carrying one branch-create ref update, so the
    /// handler's post-receive tail resolves a non-empty new-tip set (the delta
    /// scan's git stages run).
    fn ref_update_body(new_sha: &str) -> axum::body::Bytes {
        let line = format!("{ZERO_SHA} {new_sha} refs/heads/main");
        axum::body::Bytes::from(format!("{:04x}{}0000", line.len() + 4, line))
    }

    /// F4 scenario 2 — push-burst bound at the handler layer: with a scan pool of
    /// ONE, two concurrent pushes to two path-scoped repos never have more than one
    /// scan's git alive at a time (an atomic mkdir lock in the fake git detects any
    /// overlap), and BOTH pushes still succeed 200 — defer, not shed. Two distinct
    /// repos on purpose: the per-repo advisory write lock must not be what
    /// serializes the scans.
    #[cfg(unix)]
    #[sqlx::test]
    async fn receive_pack_burst_scans_serialized_and_both_pushes_succeed(pool: sqlx::PgPool) {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;
        use std::sync::Arc;
        use tokio::sync::Semaphore;

        let tmp = tempfile::TempDir::new().unwrap();
        let lockdir = tmp.path().join("scan.lock");
        let ranfile = tmp.path().join("scan.ran");
        let overlap = tmp.path().join("scan.overlap");
        // receive-pack succeeds instantly; every candidate-scan git op (cat-file /
        // rev-list / ls-tree) holds an atomic mkdir lock for 150ms — a second scan
        // process alive at the same instant records an overlap.
        let body = format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
               receive-pack) cat > /dev/null 2>/dev/null ;;\n\
               rev-parse) echo deadbeef ;;\n\
               cat-file|rev-list|ls-tree)\n\
                 if mkdir \"{lock}\" 2>/dev/null; then\n\
                   echo 1 >> \"{ran}\"\n\
                   sleep 0.15\n\
                   rmdir \"{lock}\"\n\
                 else\n\
                   echo 1 >> \"{over}\"\n\
                 fi\n\
                 if [ \"$1\" = cat-file ]; then echo commit; fi ;;\n\
               *) : ;;\n\
             esac\n\
             exit 0\n",
            lock = lockdir.display(),
            ran = ranfile.display(),
            over = overlap.display(),
        );
        let git_bin = write_fake_git(tmp.path(), &body);

        let mut state =
            f4_state_with_repo(pool.clone(), tmp.path(), &git_bin, "z6f4burst1", "b1", true).await;
        // Second path-scoped repo on the same state/store.
        state
            .db
            .upsert_mirror_repo("z6f4burst2", "b2", "/unused-z6f4burst2-b2", None, false)
            .await
            .unwrap();
        let rec2 = state
            .db
            .get_repo("z6f4burst2", "b2")
            .await
            .unwrap()
            .unwrap();
        state
            .repo_store
            .init(&rec2.owner_did, &rec2.name)
            .await
            .unwrap();
        state
            .db
            .set_visibility_rule(
                &rec2.id,
                "/secret/**",
                crate::db::VisibilityMode::B,
                &["did:key:z6MkF4ReaderAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()],
                &rec2.owner_did,
            )
            .await
            .unwrap();
        // Scan pool of ONE: at most one post-receive walk may run at a time.
        state.git_encrypt_semaphore = Arc::new(Semaphore::new(1));

        let did = "did:key:z6MkF4BurstPusherAAAAAAAAAAAAAAAAAAAAAAAA";
        let new_sha = "1111111111111111111111111111111111111111";
        let push = |owner: &'static str, name: &'static str, peer: &'static str| {
            let state = state.clone();
            tokio::spawn(async move {
                git_receive_pack(
                    State(state),
                    Path((owner.to_string(), name.to_string())),
                    Extension(crate::auth::AuthenticatedDid(did.to_string())),
                    None,
                    crate::rate_limit::PeerAddr(Some(peer.parse::<SocketAddr>().unwrap())),
                    axum::http::HeaderMap::new(),
                    ref_update_body(new_sha),
                )
                .await
            })
        };

        let (a, b) = (
            push("z6f4burst1", "b1", "203.0.113.71:5000"),
            push("z6f4burst2", "b2", "203.0.113.72:5000"),
        );
        let a = tokio::time::timeout(std::time::Duration::from_secs(60), a)
            .await
            .expect("push A must complete — a scan gate must defer, never wedge")
            .expect("push A task must not panic");
        let b = tokio::time::timeout(std::time::Duration::from_secs(60), b)
            .await
            .expect("push B must complete — a scan gate must defer, never wedge")
            .expect("push B task must not panic");
        let a = a.expect("push A must succeed");
        let b = b.expect("push B must succeed");
        assert_eq!(a.status(), 200, "push A lands 200 despite scan contention");
        assert_eq!(b.status(), 200, "push B lands 200 despite scan contention");

        // Wait for both pushes' detached scan tails to drain through the pool of 1
        // before reading the detector files. The WHOLE tail (withheld walk included) now
        // runs detached (#174 F2), so poll until every expected scan has run rather than a
        // fixed sleep, which is load-sensitive under a parallel test run.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            let ran = std::fs::read_to_string(&ranfile)
                .unwrap_or_default()
                .lines()
                .count();
            if ran >= 6 || std::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        // Small settle so the last scan's rmdir has landed before the overlap check.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !overlap.exists(),
            "with a scan pool of 1, no two scans' git may ever be alive at once \
             (found overlap records: {:?})",
            std::fs::read_to_string(&overlap).unwrap_or_default()
        );
        let ran = std::fs::read_to_string(&ranfile).unwrap_or_default();
        assert!(
            ran.lines().count() >= 6,
            "both pushes' scans must actually have run (withheld walk + delta probe + \
             delta rev-list each); got {} runs",
            ran.lines().count()
        );
    }

    /// F4 scenario 3 — fast-path non-acquisition at the handler layer: a push to a
    /// public repo with NO path-scoped rules does zero post-receive git scanning
    /// (the withheld short-circuit; a deletion-free flush-only body resolves no new
    /// tips), so it must complete 200 even with the scan pool at ZERO permits.
    /// A gate that wrongly captured a no-walk path would park this push forever.
    /// Note: `resolve_candidates_for_push` spawns git for ANY non-empty new-tip set
    /// (the per-tip cat-file probe), so the genuinely git-free negative arm is the
    /// no-ref-update body, not a branch-create push.
    #[cfg(unix)]
    #[sqlx::test]
    async fn receive_pack_no_scan_fast_path_completes_with_zero_scan_permits(pool: sqlx::PgPool) {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;
        use std::sync::Arc;
        use tokio::sync::Semaphore;

        let tmp = tempfile::TempDir::new().unwrap();
        let marker = tmp.path().join("scan.ran");
        let body = format!(
            "#!/bin/sh\ncase \"$1\" in\n  receive-pack) cat > /dev/null 2>/dev/null ;;\n  cat-file|rev-list|ls-tree) echo 1 >> \"{}\" ;;\n  *) : ;;\nesac\nexit 0\n",
            marker.display()
        );
        let git_bin = write_fake_git(tmp.path(), &body);
        let mut state =
            f4_state_with_repo(pool.clone(), tmp.path(), &git_bin, "z6f4fast", "f1", false).await;
        state.git_encrypt_semaphore = Arc::new(Semaphore::new(0));

        let peer: SocketAddr = "203.0.113.73:5000".parse().unwrap();
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            git_receive_pack(
                State(state),
                Path(("z6f4fast".to_string(), "f1".to_string())),
                Extension(crate::auth::AuthenticatedDid(
                    "did:key:z6MkF4FastPusherAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                )),
                None,
                crate::rate_limit::PeerAddr(Some(peer)),
                axum::http::HeaderMap::new(),
                axum::body::Bytes::from_static(b"0000"),
            ),
        )
        .await
        .expect("a no-scan push must not park on the (empty) scan pool")
        .expect("the push must succeed");
        assert_eq!(resp.status(), 200);
        assert!(
            !marker.exists(),
            "the no-walk fast paths must spawn no scan git at all"
        );
    }

    /// F4 scenario 4 — landed-push-never-fails: a push whose post-receive walk must
    /// park (pool held elsewhere) DEFERS and then returns the receive-pack success
    /// once admission frees; contention never converts the landed push into a 5xx.
    /// #174 F2 (RED-before/GREEN-after): the post-receive replication tail parks on
    /// `git_encrypt_semaphore` (withheld/candidate/full-scan resolution). Leaving it in the
    /// request future means a client/proxy disconnect while parked silently loses this
    /// push's pins, recovery copy, and announcements (state.rs documented this residual).
    /// The fix moves the whole tail into an independently owned task, so the handler
    /// returns its receive-pack 200 WITHOUT waiting on the scan pool and a disconnect can
    /// no longer drop the work.
    ///
    /// Load-bearing: with the tail inline (pre-fix) the handler parks while the pool is
    /// held and does NOT return within the bound (RED — the timeout fires). With the
    /// detached tail it returns 200 promptly (GREEN).
    #[cfg(unix)]
    #[sqlx::test]
    async fn receive_pack_landed_push_returns_without_parking_on_scan_pool(pool: sqlx::PgPool) {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;
        use std::sync::Arc;
        use tokio::sync::Semaphore;

        let tmp = tempfile::TempDir::new().unwrap();
        let body = "#!/bin/sh\ncase \"$1\" in\n  receive-pack) cat > /dev/null 2>/dev/null ;;\n  rev-parse) echo deadbeef ;;\n  cat-file) echo commit ;;\n  *) : ;;\nesac\nexit 0\n";
        let git_bin = write_fake_git(tmp.path(), body);
        let mut state =
            f4_state_with_repo(pool.clone(), tmp.path(), &git_bin, "z6f4park", "p1", true).await;
        let sem = Arc::new(Semaphore::new(1));
        state.git_encrypt_semaphore = sem.clone();
        // Hold the pool's only permit: the post-receive scan would park if it ran in the
        // request future.
        let held = sem.clone().acquire_owned().await.unwrap();

        let peer: SocketAddr = "203.0.113.74:5000".parse().unwrap();
        // The handler must return its receive-pack 200 WITHOUT waiting on the held scan
        // pool — the tail is owned by a detached task. Pre-fix this times out.
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            git_receive_pack(
                State(state),
                Path(("z6f4park".to_string(), "p1".to_string())),
                Extension(crate::auth::AuthenticatedDid(
                    "did:key:z6MkF4ParkPusherAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                )),
                None,
                crate::rate_limit::PeerAddr(Some(peer)),
                axum::http::HeaderMap::new(),
                ref_update_body("2222222222222222222222222222222222222222"),
            ),
        )
        .await
        .expect("the handler must return without parking on the held scan pool")
        .expect("contention must never convert a landed push into an error");
        assert_eq!(
            resp.status(),
            200,
            "the response is the receive-pack success, returned before the detached tail runs"
        );

        // The detached tail is still owned: release admission and let it drain cleanly.
        drop(held);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
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
            match inflight.try_begin(repo, vec![]) {
                crate::state::BeginOutcome::Admitted(g) => admitted.push(g),
                crate::state::BeginOutcome::Coalesced => coalesced += 1,
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
        use crate::state::BeginOutcome;
        let inflight = crate::state::EncryptInflight::new();
        let a = inflight.try_begin("owner/repo-a", vec![]);
        let b = inflight.try_begin("owner/repo-b", vec![]);
        let c = inflight.try_begin("owner/repo-c", vec![]);
        assert!(
            matches!(&a, BeginOutcome::Admitted(_))
                && matches!(&b, BeginOutcome::Admitted(_))
                && matches!(&c, BeginOutcome::Admitted(_)),
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
        use crate::state::{BeginOutcome, FinishOutcome};
        let inflight = crate::state::EncryptInflight::new();
        let repo = "did:key:z6MkDurableRepoBBBBBBBBBBBBBBBBBBBBBBBBB/repo";

        // Push #1 admits and "spawns". A concurrent push #2 (task #1 still in flight)
        // coalesces — no duplicate spawn; its (empty) tip set is recorded, not lost.
        let guard1 = admit(&inflight, repo);
        assert!(
            matches!(inflight.try_begin(repo, vec![]), BeginOutcome::Coalesced),
            "while task #1 is in flight, push #2 to the same repo coalesces"
        );

        // Task #1 finishes normally: nothing pending (push #2 carried no tips), so
        // the empty-pending check removes the key in its critical section.
        assert!(
            matches!(guard1.finish_or_take_pending(), FinishOutcome::Finished(_)),
            "no pending tips — the task exits and releases the key"
        );
        assert_eq!(
            inflight.len(),
            0,
            "when the in-flight task ends its repo key is released — the set does not leak"
        );

        // A LATER push for the SAME repo is admitted again (processed, not skipped
        // forever). This is what coalesce->shed breaks: shed drops the job and no sweep
        // re-derives the missing copy, so the recovery copy is permanently lost.
        let guard2 = admit(&inflight, repo);
        // An errored task (guard dropped without finishing) still releases the key.
        drop(guard2);
        assert_eq!(inflight.len(), 0);

        // Durability across PANIC: a task that panics mid-walk must still release its
        // key (the still-armed guard's Drop runs on unwind), so one crashed walk never
        // permanently locks a repo out of future recovery copies. Coalesce real tips
        // first: the panic loses them (logged), and the loss must not corrupt the set.
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = admit(&inflight, repo);
            assert!(matches!(
                inflight.try_begin(repo, vec![("old1".to_string(), "new1".to_string())]),
                BeginOutcome::Coalesced
            ));
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
        // The next push is re-admitted, and the panicked task's pending tips did NOT
        // survive into it (they are lost-and-logged, recovered only by a later push).
        let guard3 = admit(&inflight, repo);
        assert!(
            matches!(guard3.finish_or_take_pending(), FinishOutcome::Finished(_)),
            "the pre-panic pending tips must not leak into the re-admitted task"
        );
    }

    /// Degenerate state: the first push on a cold/empty in-flight set always admits
    /// (never a false coalesce on an empty set).
    #[test]
    fn u4_first_push_on_a_cold_set_always_admits() {
        let inflight = crate::state::EncryptInflight::new();
        assert!(inflight.is_empty(), "cold set is empty");
        assert!(
            matches!(
                inflight.try_begin("owner/first", vec![]),
                crate::state::BeginOutcome::Admitted(_)
            ),
            "the first push on a cold in-flight set must admit (never falsely coalesce)"
        );
    }

    /// Unwrap an Admitted outcome (panic on Coalesced) — the u4/u5 suites' shorthand.
    fn admit(
        inflight: &crate::state::EncryptInflight,
        repo: &str,
    ) -> crate::state::EncryptInflightGuard {
        match inflight.try_begin(repo, vec![]) {
            crate::state::BeginOutcome::Admitted(g) => g,
            crate::state::BeginOutcome::Coalesced => panic!("expected {repo} to admit"),
        }
    }

    /// Model of the pre-fix / mutated code: no coalescing check, so every push spawns.
    /// Returns the count of tasks spawned (== the size of the unbounded outstanding set
    /// the fix prevents), used as the RED comparison in the bound test above.
    fn simulate_without_coalescing(pushes: usize) -> usize {
        (0..pushes).count()
    }

    // ---- #174 U5 (F5): a push that loses try_begin is REQUEUED, never dropped ----
    //
    // F5: the in-flight task pins only its own pre-spawn object-list snapshot, so a
    // push B arriving while task A is in flight used to be SKIPPED outright (the old
    // None arm) — B's pins and recovery copies were silently absent until an
    // unrelated later push re-walked the repo. U5 records B's (old, new) tip pairs
    // into the in-flight key's pending slot in the SAME critical section as the
    // presence check, and A's task loop-drains them before releasing the key.

    /// The F5 lost-update repro. Task A is in flight past its snapshot; push B
    /// coalesces carrying its tip pair; when A finishes its snapshot iteration the
    /// tracker must hand A exactly B's recorded work with the key retained — and only
    /// an empty pending check may remove the key. On pre-U5 code this is RED: the
    /// coalesce arm records B's work nowhere and there is no drain surface at all.
    #[test]
    fn u5_coalesced_push_work_is_drained_by_the_inflight_task() {
        use crate::state::{BeginOutcome, FinishOutcome, PendingWork};
        let inflight = crate::state::EncryptInflight::new();
        let repo = "did:key:z6MkF5LostUpdateCCCCCCCCCCCCCCCCCCCCCCCC/repo";

        // Push A admits; its spawned task is "in flight past its snapshot".
        let guard_a = match inflight.try_begin(repo, vec![]) {
            BeginOutcome::Admitted(g) => g,
            BeginOutcome::Coalesced => panic!("first push must admit"),
        };

        // Push B lands while A is in flight: coalesced, tip pair recorded.
        let b_pair = (
            "b0ldb0ldb0ldb0ldb0ldb0ldb0ldb0ldb0ldb0ld".to_string(),
            "bnewbnewbnewbnewbnewbnewbnewbnewbnewbnew".to_string(),
        );
        match inflight.try_begin(repo, vec![b_pair.clone()]) {
            BeginOutcome::Coalesced => {}
            BeginOutcome::Admitted(_) => panic!("push B must coalesce while A is in flight"),
        }

        // A finishes its snapshot iteration: it must be handed B's work (drained),
        // not exit — an exit here is exactly the F5 silent loss.
        match guard_a.finish_or_take_pending() {
            FinishOutcome::Pending(guard_a, work) => {
                assert_eq!(
                    work,
                    PendingWork::Tips(vec![b_pair]),
                    "A drains exactly B's recorded tip pair"
                );
                assert_eq!(inflight.len(), 1, "the key is retained while A iterates");
                // Nothing further pending: A now exits and releases the key.
                match guard_a.finish_or_take_pending() {
                    FinishOutcome::Finished(_) => {}
                    FinishOutcome::Pending(..) => panic!("no second batch was recorded"),
                }
                assert_eq!(
                    inflight.len(),
                    0,
                    "an empty pending check at task end releases the key"
                );
            }
            FinishOutcome::Finished(_) => panic!(
                "F5: B's coalesced work vanished — the in-flight task exited without draining it"
            ),
        }
    }

    /// Drain-vs-admit race, both orderings driven deterministically through the lock
    /// API (the check+merge and check+remove are each ONE critical section, so a push
    /// can only land on one side of A's final pending check — never inside it):
    /// before it, the push is merged and A drains it; after it, the key is gone and
    /// the push is admitted as a fresh task. Neither ordering loses the work. A
    /// check-then-record split (merge moved outside try_begin's critical section)
    /// turns ordering 1 RED: the work recorded after A's check is never drained.
    #[test]
    fn u5_drain_vs_admit_race_loses_no_work_in_either_ordering() {
        use crate::state::{BeginOutcome, FinishOutcome, PendingWork};
        let inflight = crate::state::EncryptInflight::new();
        let repo = "did:key:z6MkF5RaceOrderDDDDDDDDDDDDDDDDDDDDDDDDD/repo";
        let pair = ("cold".to_string(), "cnew".to_string());

        // Ordering 1: push C lands BEFORE A's final pending check → merged in
        // try_begin's critical section → A must drain it (key retained).
        let guard_a = admit(&inflight, repo);
        assert!(matches!(
            inflight.try_begin(repo, vec![pair.clone()]),
            BeginOutcome::Coalesced
        ));
        match guard_a.finish_or_take_pending() {
            FinishOutcome::Pending(g, work) => {
                assert_eq!(work, PendingWork::Tips(vec![pair.clone()]));
                assert!(matches!(
                    g.finish_or_take_pending(),
                    FinishOutcome::Finished(_)
                ));
            }
            FinishOutcome::Finished(_) => {
                panic!("a push merged before the final check must be drained, not lost")
            }
        }
        assert!(inflight.is_empty());

        // Ordering 2: push C lands AFTER A's final pending check removed the key →
        // it must be ADMITTED as a fresh task (its own snapshot covers its work).
        let guard_a = admit(&inflight, repo);
        assert!(matches!(
            guard_a.finish_or_take_pending(),
            FinishOutcome::Finished(_)
        ));
        match inflight.try_begin(repo, vec![pair]) {
            BeginOutcome::Admitted(g) => drop(g),
            BeginOutcome::Coalesced => panic!(
                "a push landing after the key was removed must admit a new task — a \
                 coalesce here records work no task will ever drain"
            ),
        }
    }

    /// Exit-vs-successor (the double-remove hazard). A's normal exit removes the key
    /// and disarms the guard in ONE critical section, and the disarmed guard is
    /// handed back — so its eventual Drop lands in the real remove→drop window. A
    /// successor task B admitted inside that window must keep ITS key when A's guard
    /// finally drops. With the disarm reverted (Drop removing unconditionally) this
    /// is RED: dropping A's guard deletes B's key and the third push falsely admits
    /// a second task for the repo.
    #[test]
    fn u5_disarmed_guard_drop_never_removes_a_successor_key() {
        use crate::state::{BeginOutcome, FinishOutcome};
        let inflight = crate::state::EncryptInflight::new();
        let repo = "did:key:z6MkF5DisarmEEEEEEEEEEEEEEEEEEEEEEEEEEEE/repo";

        // A admits and exits normally; HOLD the disarmed guard to keep the window open.
        let guard_a = admit(&inflight, repo);
        let disarmed = match guard_a.finish_or_take_pending() {
            FinishOutcome::Finished(g) => g,
            FinishOutcome::Pending(..) => panic!("nothing was pending"),
        };
        assert!(inflight.is_empty(), "A's exit released the key");

        // Successor B is admitted inside the remove→drop window.
        let guard_b = admit(&inflight, repo);
        assert_eq!(inflight.len(), 1);

        // A's disarmed guard now drops. B's key must SURVIVE: a third push still
        // coalesces against B's in-flight task.
        drop(disarmed);
        assert_eq!(
            inflight.len(),
            1,
            "dropping A's disarmed guard must not remove successor B's key"
        );
        assert!(
            matches!(inflight.try_begin(repo, vec![]), BeginOutcome::Coalesced),
            "B's task is still the (only) in-flight task — at-most-one-per-repo holds"
        );
        drop(guard_b);
        assert!(inflight.is_empty());
    }

    /// Pending overflow: past the 1024-pair bound the slot degrades to the FullScan
    /// marker (bounded memory under a hostile push burst); at exactly the bound it
    /// stays a Tips batch. The marker is an explicit variant, never an empty tip
    /// list — an empty-tips encoding would drain to an empty delta and pin nothing.
    #[test]
    fn u5_pending_overflow_degrades_to_full_scan_marker() {
        use crate::state::{BeginOutcome, FinishOutcome, PendingWork};
        let inflight = crate::state::EncryptInflight::new();
        let pair = |i: usize| (format!("old{i}"), format!("new{i}"));

        // At the bound: exactly 1024 pairs stay a Tips batch.
        let repo_at = "owner/at-bound";
        let g = admit(&inflight, repo_at);
        assert!(matches!(
            inflight.try_begin(repo_at, (0..1024).map(pair).collect()),
            BeginOutcome::Coalesced
        ));
        match g.finish_or_take_pending() {
            FinishOutcome::Pending(g, PendingWork::Tips(v)) => {
                assert_eq!(v.len(), 1024, "at the bound the pairs are kept verbatim");
                assert!(matches!(
                    g.finish_or_take_pending(),
                    FinishOutcome::Finished(_)
                ));
            }
            other => panic!(
                "expected a Tips batch at the bound, got {:?}",
                match other {
                    FinishOutcome::Pending(_, w) => Some(w),
                    FinishOutcome::Finished(_) => None,
                }
            ),
        }

        // Past the bound: the accumulated slot degrades to FullScan and later
        // merges are absorbed (still one bounded marker, not a growing list).
        let repo_over = "owner/over-bound";
        let g = admit(&inflight, repo_over);
        assert!(matches!(
            inflight.try_begin(repo_over, (0..1024).map(pair).collect()),
            BeginOutcome::Coalesced
        ));
        assert!(matches!(
            inflight.try_begin(repo_over, vec![pair(9999)]),
            BeginOutcome::Coalesced
        ));
        assert!(matches!(
            inflight.try_begin(repo_over, vec![pair(10000)]),
            BeginOutcome::Coalesced
        ));
        match g.finish_or_take_pending() {
            FinishOutcome::Pending(g, work) => {
                assert_eq!(
                    work,
                    PendingWork::FullScan,
                    "overflow degrades to the explicit FullScan marker"
                );
                assert!(matches!(
                    g.finish_or_take_pending(),
                    FinishOutcome::Finished(_)
                ));
            }
            FinishOutcome::Finished(_) => panic!("the overflowed pending work vanished"),
        }
    }

    // ---- u5 drain-pipeline fixtures: a real git repo + a DB repo row ----

    fn u5_git(dir: &std::path::Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
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

    fn u5_init_repo(dir: &std::path::Path) {
        u5_git(dir, &["init", "-q", "-b", "main"]);
        u5_git(dir, &["config", "user.email", "t@t"]);
        u5_git(dir, &["config", "user.name", "t"]);
    }

    /// Commit `name` (parent dirs created) with `body`; returns the commit sha.
    fn u5_commit_file(dir: &std::path::Path, name: &str, body: &str) -> String {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, body).unwrap();
        u5_git(dir, &["add", name]);
        u5_git(dir, &["commit", "-qm", &format!("add {name}")]);
        u5_git(dir, &["rev-parse", "HEAD"])
    }

    /// A drain-task context over the test state and an on-disk repo. Empty
    /// `ipfs_api`/`irys_url` keep the pin/anchor stages inert (no network).
    fn u5_ctx(
        state: &AppState,
        rec: &crate::db::RepoRecord,
        repo_path: std::path::PathBuf,
        git_bin: &str,
        sem: std::sync::Arc<tokio::sync::Semaphore>,
    ) -> EncryptTaskCtx {
        EncryptTaskCtx {
            ipfs_api: String::new(),
            repo_path,
            db: state.db.clone(),
            repo_id: rec.id.clone(),
            owner_did: rec.owner_did.clone(),
            repo_name: rec.name.clone(),
            irys_url: String::new(),
            http_client: std::sync::Arc::clone(&state.http_client),
            node_did: state.node_did.to_string(),
            node_keypair: std::sync::Arc::clone(&state.node_keypair),
            git_bin: git_bin.to_string(),
            git_timeout: std::time::Duration::from_secs(600),
            encrypt_sem: sem,
            pin_sem: std::sync::Arc::new(tokio::sync::Semaphore::new(64)),
        }
    }

    /// #174 U3: a coalesced drain that runs after the repo row was deleted and
    /// recreated under the same owner/name must resolve the LIVE row's id, not the
    /// id frozen into the task ctx at spawn. Encrypted-pin metadata written under
    /// the dead id is invisible to authorized readers on the live row.
    ///
    /// `resolve_drain_object_list` already re-fetches by owner/name and uses
    /// `record.id` for the visibility-rule read; this binds the same id to the
    /// encrypt write, which was still taking `ctx.repo_id`.
    #[sqlx::test]
    async fn u3_drain_resolves_the_refetched_repo_id_after_an_id_rotation(pool: sqlx::PgPool) {
        let raw = pool.clone();
        let state = crate::test_support::test_state(pool).await;
        let tmp = tempfile::TempDir::new().unwrap();
        u5_init_repo(tmp.path());
        let c1 = u5_commit_file(tmp.path(), "a.txt", "one\n");

        state
            .db
            .upsert_mirror_repo("z6u3rot", "r", "/u3-rotation", None, false)
            .await
            .unwrap();
        let before = state.db.get_repo("z6u3rot", "r").await.unwrap().unwrap();
        let ctx = u5_ctx(
            &state,
            &before,
            tmp.path().to_path_buf(),
            "git",
            std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
        );
        assert_eq!(ctx.repo_id, before.id, "ctx captures the spawn-time id");

        // Delete + recreate under the SAME owner/name. This is the rotation: a new
        // row id over the same on-disk bare repo.
        sqlx::query("DELETE FROM repos WHERE id = $1")
            .bind(&before.id)
            .execute(&raw)
            .await
            .unwrap();
        let after = crate::db::RepoRecord {
            id: Uuid::new_v4().to_string(),
            name: before.name.clone(),
            owner_did: before.owner_did.clone(),
            description: None,
            is_public: true,
            default_branch: "main".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            disk_path: before.disk_path.clone(),
            forked_from: None,
            machine_id: None,
        };
        state.db.create_repo(&after).await.unwrap();
        assert_ne!(after.id, before.id, "the recreate really did rotate the id");

        let (drain_id, _list, _rules, _pub) = resolve_drain_object_list(
            &ctx,
            crate::state::PendingWork::Tips(vec![(ZERO_SHA.to_string(), c1.clone())]),
        )
        .await
        .expect("a public repo drains to a pin list");

        assert_eq!(
            drain_id, after.id,
            "the drain must write its encrypted-pin metadata under the LIVE row id"
        );
        assert_ne!(
            drain_id, ctx.repo_id,
            "the spawn-time id is the deleted row; metadata written there is \
             unreachable from the live repo"
        );
    }

    /// The drain resolves a coalesced push's tip pair to exactly that push's
    /// introduced objects (delta semantics — the F5 observable: push B's pins are
    /// recorded by the drain, and pre-existing objects are not re-listed).
    #[sqlx::test]
    async fn u5_drain_resolves_coalesced_tips_to_their_objects(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;
        let tmp = tempfile::TempDir::new().unwrap();
        u5_init_repo(tmp.path());
        let c1 = u5_commit_file(tmp.path(), "a.txt", "one\n");
        let c2 = u5_commit_file(tmp.path(), "b.txt", "two\n");
        state
            .db
            .upsert_mirror_repo("z6u5delta", "d", "/unused", None, false)
            .await
            .unwrap();
        let rec = state.db.get_repo("z6u5delta", "d").await.unwrap().unwrap();
        let ctx = u5_ctx(
            &state,
            &rec,
            tmp.path().to_path_buf(),
            "git",
            std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
        );

        // Push B advanced main c1 -> c2 and lost try_begin; its pair was coalesced.
        let (_drain_id, list, _rules, is_public) = resolve_drain_object_list(
            &ctx,
            crate::state::PendingWork::Tips(vec![(c1.clone(), c2.clone())]),
        )
        .await
        .expect("a public repo drains to a pin list");
        assert!(is_public, "mirror rows are public");
        let got: std::collections::HashSet<String> = list.into_iter().collect();
        let new_blob = u5_git(tmp.path(), &["rev-parse", "HEAD:b.txt"]);
        let old_blob = u5_git(tmp.path(), &["rev-parse", &format!("{c1}:a.txt")]);
        assert!(
            got.contains(&c2) && got.contains(&new_blob),
            "B's commit and blob are in the drained pin list (the F5 fix)"
        );
        assert!(
            !got.contains(&c1) && !got.contains(&old_blob),
            "pre-existing objects are not re-listed (delta, not full scan)"
        );
    }

    /// The FullScan marker drains through the FLAGGED full-scan path to a NON-EMPTY
    /// candidate set. RED arm of the encoding: were the marker a plain empty-tips
    /// call, the deletion-only fast path would return an empty delta and the drain
    /// would pin nothing (the F5 silent loss resurfacing).
    #[sqlx::test]
    async fn u5_drain_full_scan_marker_yields_nonempty_candidates(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;
        let tmp = tempfile::TempDir::new().unwrap();
        u5_init_repo(tmp.path());
        let c1 = u5_commit_file(tmp.path(), "a.txt", "one\n");
        state
            .db
            .upsert_mirror_repo("z6u5full", "f", "/unused", None, false)
            .await
            .unwrap();
        let rec = state.db.get_repo("z6u5full", "f").await.unwrap().unwrap();
        let ctx = u5_ctx(
            &state,
            &rec,
            tmp.path().to_path_buf(),
            "git",
            std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
        );

        let (_drain_id, list, _rules, _pub) =
            resolve_drain_object_list(&ctx, crate::state::PendingWork::FullScan)
                .await
                .expect("a public repo drains to a pin list");
        let got: std::collections::HashSet<String> = list.into_iter().collect();
        assert!(
            !got.is_empty(),
            "the FullScan drain must enumerate the repo — an empty list means the \
             marker collapsed into the empty-tips fast path"
        );
        let blob = u5_git(tmp.path(), &["rev-parse", "HEAD:a.txt"]);
        assert!(
            got.contains(&c1) && got.contains(&blob),
            "the full-scan drain covers the repo's commit and blob"
        );
    }

    /// Rules tightened between the coalesced push and its drain are honored, fail
    /// closed: the drain re-fetches rules/is_public fresh, so (1) a newly-withheld
    /// blob is NOT pinned, and (2) a repo whose root became unreadable to the
    /// anonymous public drains to nothing at all.
    #[sqlx::test]
    async fn u5_drain_honors_rules_tightened_after_the_push(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;
        let tmp = tempfile::TempDir::new().unwrap();
        u5_init_repo(tmp.path());
        u5_commit_file(tmp.path(), "pub.txt", "public\n");
        let c2 = u5_commit_file(tmp.path(), "secret/hidden.txt", "sealed\n");
        state
            .db
            .upsert_mirror_repo("z6u5tight", "t", "/unused", None, false)
            .await
            .unwrap();
        let rec = state.db.get_repo("z6u5tight", "t").await.unwrap().unwrap();
        let ctx = u5_ctx(
            &state,
            &rec,
            tmp.path().to_path_buf(),
            "git",
            std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
        );
        let pending = || crate::state::PendingWork::Tips(vec![(ZERO_SHA.to_string(), c2.clone())]);

        // At push time the repo had no rules. TIGHTEN before the drain: /secret/**
        // becomes reader-gated. The drain must re-fetch and withhold the new blob.
        state
            .db
            .set_visibility_rule(
                &rec.id,
                "/secret/**",
                crate::db::VisibilityMode::B,
                &[READER_DID.to_string()],
                &rec.owner_did,
            )
            .await
            .unwrap();
        let (_drain_id, list, _rules, _pub) = resolve_drain_object_list(&ctx, pending())
            .await
            .expect("still announceable at root");
        let got: std::collections::HashSet<String> = list.into_iter().collect();
        let pub_blob = u5_git(tmp.path(), &["rev-parse", "HEAD:pub.txt"]);
        let secret_blob = u5_git(tmp.path(), &["rev-parse", "HEAD:secret/hidden.txt"]);
        assert!(
            got.contains(&pub_blob),
            "the still-public blob is pinned by the drain"
        );
        assert!(
            !got.contains(&secret_blob),
            "a blob withheld by a rule added AFTER the push must NOT be pinned by \
             the drain (fresh rules, fail closed)"
        );

        // Tighten further: root becomes reader-gated → not announceable to the
        // anonymous public → the drain pins nothing at all.
        state
            .db
            .set_visibility_rule(
                &rec.id,
                "/",
                crate::db::VisibilityMode::A,
                &[READER_DID.to_string()],
                &rec.owner_did,
            )
            .await
            .unwrap();
        assert!(
            resolve_drain_object_list(&ctx, pending()).await.is_none(),
            "a repo no longer announceable under current rules drains to nothing \
             (fail closed)"
        );
    }

    /// #174 F2 / KTD-3 re-derivation equivalence: the object set the Pinata worker
    /// re-derives from ONLY the ref tuples (`pinata_object_list_for_refs`, run once a
    /// pin slot frees) must equal exactly what the old retained `object_list` would
    /// have pinned — the inline-resolved delta, filtered by the withheld set. If the
    /// two differ, the memory fix changed what gets pinned; they must not.
    #[tokio::test]
    async fn f2_pinata_rederivation_equals_retained_object_list() {
        let tmp = tempfile::TempDir::new().unwrap();
        u5_init_repo(tmp.path());
        let c1 = u5_commit_file(tmp.path(), "a.txt", "one\n");
        let c2 = u5_commit_file(tmp.path(), "b.txt", "two\n");
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
        let timeout = std::time::Duration::from_secs(600);

        // What the OLD retained-list task WOULD have pinned: the inline pipeline the
        // receive-pack tail ran before moving `object_list` into the closure — the
        // delta for main c1 -> c2, filtered by the (empty) withheld set.
        let candidates = crate::git::push_delta::resolve_candidates_for_push(
            sem.clone(),
            tmp.path().to_path_buf(),
            vec![c2.clone()],
            vec![c1.clone()],
            "git".to_string(),
            timeout,
            false,
        )
        .await;
        assert!(
            !candidates.full_scan,
            "the c1 -> c2 push is a delta, not a full scan"
        );
        let retained: std::collections::HashSet<String> =
            crate::git::visibility_pack::replicable_objects(
                candidates.candidates,
                &std::collections::HashSet::new(),
            )
            .into_iter()
            .collect();

        // What the worker re-derives from only the (ref, old, new) tuples. Empty rules
        // + is_public => announceable, withheld = {} (the common Pinata case).
        let ref_updates = vec![("refs/heads/main".to_string(), c1.clone(), c2.clone())];
        let rederived: std::collections::HashSet<String> = pinata_object_list_for_refs(
            sem.clone(),
            tmp.path().to_path_buf(),
            &ref_updates,
            Some(Vec::new()),
            true,
            "z6MkPinataOwnerAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            "git".to_string(),
            timeout,
        )
        .await
        .1
        .into_iter()
        .collect();

        let new_blob = u5_git(tmp.path(), &["rev-parse", "HEAD:b.txt"]);
        assert!(
            retained.contains(&c2) && retained.contains(&new_blob),
            "the push introduced the new commit and blob"
        );
        assert_eq!(
            rederived, retained,
            "the worker's git rev-list re-derivation must yield exactly the object set \
             the retained list would have pinned — the memory fix must not change what pins"
        );
    }

    /// #174 F2 / KTD-3 reaped + deadline-bounded: the worker's re-derivation git children
    /// run through the same INV-22 bounded, process-group-reaped helpers the sibling scans
    /// use. On a git that hangs on both `rev-list` and `--batch-all-objects`,
    /// `pinata_object_list_for_refs` must RETURN within the watchdog budget (the group is
    /// SIGKILLed + reaped at the deadline), not block. A bare `Command::output()` here
    /// would hang past the ceiling (RED).
    #[cfg(unix)]
    #[tokio::test]
    async fn f2_pinata_rederivation_is_deadline_bounded_and_reaped() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().unwrap();
        // Empty rules => replication_withheld_set short-circuits (no git). The tip
        // peel (`cat-file -t`) reports a commit so the delta stage proceeds; rev-list
        // and the full-scan `cat-file --batch-all-objects` both hang (bounded 30s so a
        // broken test cannot leak a permanent orphan).
        let fake = dir.path().join("fakegit");
        std::fs::write(
            &fake,
            "#!/bin/sh\ncase \"$1\" in\n  \
             cat-file) case \"$*\" in *--batch-all-objects*) i=0; while [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done ;; *) echo commit ;; esac ;;\n  \
             rev-list) i=0; while [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done ;;\n  \
             *) : ;;\nesac\nexit 0\n",
        )
        .unwrap();
        let mut perm = std::fs::metadata(&fake).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&fake, perm).unwrap();
        let git_bin = fake.to_str().unwrap().to_string();

        let ref_updates = vec![(
            "refs/heads/main".to_string(),
            ZERO_SHA.to_string(),
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        )];
        let got = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            pinata_object_list_for_refs(
                std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
                dir.path().to_path_buf(),
                &ref_updates,
                Some(Vec::new()),
                true,
                "z6MkPinataOwnerAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                git_bin,
                std::time::Duration::from_millis(400),
            ),
        )
        .await
        .expect(
            "pinata_object_list_for_refs must return within the watchdog budget — a hang \
             means the re-derivation git is not deadline-bounded / group-reaped (RED)",
        );
        assert!(
            got.1.is_empty(),
            "a hung git yields nothing this push (the reconciliation sweep backstops)"
        );
    }

    /// Hot-repo drain at encrypt-pool size 1: the task loop holds NO task-level
    /// permit, so per-iteration helper acquires (withheld walk, candidate scan,
    /// recipients walk) each get the pool's single permit in turn and BOTH the
    /// snapshot iteration and the coalesced-drain iteration complete. RED if the
    /// loop takes a task-level permit: the first helper acquire nests over the
    /// same exhausted semaphore and the task parks forever.
    #[sqlx::test]
    async fn u5_hot_repo_drain_completes_at_pool_size_one(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;
        let tmp = tempfile::TempDir::new().unwrap();
        u5_init_repo(tmp.path());
        u5_commit_file(tmp.path(), "pub.txt", "public\n");
        let c2 = u5_commit_file(tmp.path(), "secret/hidden.txt", "sealed\n");
        state
            .db
            .upsert_mirror_repo("z6u5hot", "h", "/unused", None, false)
            .await
            .unwrap();
        let rec = state.db.get_repo("z6u5hot", "h").await.unwrap().unwrap();
        // A path-scoped rule so every gated walk actually runs (withheld walk on
        // the drain, recipients walk on both iterations). READER_DID carries no
        // resolvable key, so the encrypt stage plans no seal and stays offline.
        state
            .db
            .set_visibility_rule(
                &rec.id,
                "/secret/**",
                crate::db::VisibilityMode::B,
                &[READER_DID.to_string()],
                &rec.owner_did,
            )
            .await
            .unwrap();
        let rules = state.db.list_visibility_rules(&rec.id).await.unwrap();

        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let ctx = u5_ctx(&state, &rec, tmp.path().to_path_buf(), "git", sem);

        let inflight = crate::state::EncryptInflight::new();
        let guard = admit(&inflight, &rec.id);
        assert!(matches!(
            inflight.try_begin(&rec.id, vec![(ZERO_SHA.to_string(), c2)]),
            crate::state::BeginOutcome::Coalesced
        ));

        tokio::time::timeout(
            std::time::Duration::from_secs(60),
            run_encrypt_pin_task(ctx, guard, Vec::new(), Some(rules), true),
        )
        .await
        .expect(
            "the drain must complete at pool size 1 — a task-level permit would \
             deadlock the helper-internal acquires",
        );
        assert!(
            inflight.is_empty(),
            "the drained task released its repo key on exit"
        );
    }

    /// The task LOOP is load-bearing: work coalesced during the snapshot iteration
    /// is drained (its candidate scan runs git) before the task exits. RED under
    /// the drain-loop revert (task drops its guard after the snapshot without
    /// checking pending): the fake git never runs and the marker is absent.
    #[cfg(unix)]
    #[sqlx::test]
    async fn u5_task_drains_coalesced_work_before_exiting(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;
        let tmp = tempfile::TempDir::new().unwrap();
        let marker = tmp.path().join("git.ran");
        // The drain's candidate scan probes the tip type then walks: report a
        // commit tip and an empty rev-list, recording every invocation.
        let body = format!(
            "#!/bin/sh\necho ran >> \"{}\"\ncase \"$1\" in\n  cat-file) echo commit ;;\n  *) : ;;\nesac\nexit 0\n",
            marker.display()
        );
        let git_bin = write_fake_git(tmp.path(), &body);
        state
            .db
            .upsert_mirror_repo("z6u5loop", "l", "/unused", None, false)
            .await
            .unwrap();
        let rec = state.db.get_repo("z6u5loop", "l").await.unwrap().unwrap();
        let ctx = u5_ctx(
            &state,
            &rec,
            tmp.path().to_path_buf(),
            &git_bin,
            std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
        );

        let inflight = crate::state::EncryptInflight::new();
        let guard = admit(&inflight, &rec.id);
        // Push B coalesces mid-flight with a real (created-ref) tip pair.
        assert!(matches!(
            inflight.try_begin(
                &rec.id,
                vec![(
                    ZERO_SHA.to_string(),
                    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
                )]
            ),
            crate::state::BeginOutcome::Coalesced
        ));

        // Snapshot: empty object list, no rules — the snapshot iteration itself
        // spawns no git, so any git invocation below belongs to the DRAIN.
        run_encrypt_pin_task(ctx, guard, Vec::new(), None, true).await;
        assert!(
            marker.exists(),
            "the task must drain B's coalesced tips (candidate scan runs git) \
             before exiting — an absent marker is the F5 skip"
        );
        assert!(
            inflight.is_empty(),
            "the empty pending check at task end released the key"
        );
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

    // ── #174 U2 / F3: second same-repo push serialized until a disconnected first ──
    // push's git process GROUP is reaped (RepoWriteLease riding the disconnect reaper).

    /// `kill(pid, 0)` liveness probe (same-uid here, so EPERM never applies).
    #[cfg(unix)]
    fn f3_alive(pid: i32) -> bool {
        unsafe { libc::kill(pid, 0) == 0 }
    }

    /// F3 (P1, RED-before/GREEN-after): on a client disconnect DURING receive-pack the
    /// disconnected push's git group is torn down by KillGroupOnDrop's detached reaper
    /// (~4s TERM/grace/KILL/reap), while RepoWriteGuard::Drop releases the pg advisory
    /// lock at the disconnect INSTANT. Without the in-process write lease, a second
    /// same-node push then acquires the freed pg lock and mutates the shared local repo
    /// WHILE the first group is still writing — a torn snapshot. The lease is held by the
    /// write-path AdmissionGuard, which rides that reaper, so the second push must not run
    /// its receive-pack (mutate the repo) until the first group is reaped.
    ///
    /// The fake git labels the pushes by receive-pack arrival order (atomic mkdir): the
    /// first (push A) forks a SIGTERM-IGNORING descendant, records its pid, then hangs
    /// (so A can be dropped mid-transfer and its group survives the SIGTERM grace); the
    /// second (push B, a DIFFERENT source) records that its receive-pack ran — i.e. that
    /// B mutated the repo. The load-bearing invariant is strictly ordered, not
    /// time-windowed: B's marker must NEVER appear while A's descendant is still alive.
    ///
    /// Load-bearing: pre-fix (no lease) A's disconnect frees the pg lock, B's
    /// acquire_write succeeds within its ~1s retry, and B's receive-pack runs (marker
    /// appears) WHILE A's descendant is still alive — RED. With the lease the reaper
    /// holds it until the group is ESRCH-gone, so B's marker appears only AFTER — GREEN.
    #[cfg(unix)]
    #[sqlx::test]
    async fn f3_second_push_serialized_until_disconnected_group_reaped(pool: sqlx::PgPool) {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;

        let tmp = tempfile::TempDir::new().unwrap();
        let seq_a = tmp.path().join("seq_a"); // first receive-pack wins this mkdir = push A
        let descfile = tmp.path().join("desc.pid"); // A's SIGTERM-ignoring descendant pid
        let b_ran = tmp.path().join("b.ran"); // set when B's receive-pack runs (B mutates)
                                              // receive-pack: first invocation (A) forks a TERM-ignoring descendant (bounded
                                              // loop so a RED run leaks no permanent orphan), records its pid, and hangs in
                                              // `wait`; second (B) records that it ran. rev-parse feeds any tail probe.
        let body = format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
               receive-pack)\n\
                 cat >/dev/null 2>/dev/null\n\
                 if mkdir \"{seq}\" 2>/dev/null; then\n\
                   sh -c 'trap \"\" TERM; echo $$ > \"{desc}\"; i=0; while [ $i -lt 60 ]; do sleep 0.1; i=$((i+1)); done' &\n\
                   wait\n\
                 else\n\
                   echo 1 > \"{bran}\"\n\
                 fi ;;\n\
               rev-parse) echo deadbeef ;;\n\
               *) : ;;\n\
             esac\n\
             exit 0\n",
            seq = seq_a.display(),
            desc = descfile.display(),
            bran = b_ran.display(),
        );
        let git_bin = write_fake_git(tmp.path(), &body);
        // One repo; A and B push to it (same record.id -> same lease key). Non-path-scoped
        // + flush-only body -> no post-receive scans to muddy the observation.
        let state =
            f4_state_with_repo(pool.clone(), tmp.path(), &git_bin, "z6f3repo", "r1", false).await;
        let did = "did:key:z6MkF3PusherAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        // Push A: drive its handler future in slices until it reaches receive-pack and the
        // fake records its descendant pid (A now holds the lease and is hung).
        let mut fut_a = Box::pin(git_receive_pack(
            State(state.clone()),
            Path(("z6f3repo".to_string(), "r1".to_string())),
            Extension(crate::auth::AuthenticatedDid(did.to_string())),
            None,
            crate::rate_limit::PeerAddr(Some("203.0.113.81:5000".parse::<SocketAddr>().unwrap())),
            axum::http::HeaderMap::new(),
            axum::body::Bytes::from_static(b"0000"),
        ));
        let mut desc: Option<i32> = None;
        for _ in 0..1000 {
            let _ = tokio::time::timeout(std::time::Duration::from_millis(10), &mut fut_a).await;
            if let Some(p) = std::fs::read_to_string(&descfile)
                .ok()
                .and_then(|s| s.trim().parse::<i32>().ok())
            {
                desc = Some(p);
                break;
            }
        }
        let desc = desc.expect("push A must reach receive-pack and record its descendant pid");
        assert!(
            f3_alive(desc),
            "A's descendant must be alive before the disconnect"
        );

        // Push B: a DIFFERENT source, same repo. It blocks on the lease A holds.
        let state_b = state.clone();
        let handle_b = tokio::spawn(async move {
            git_receive_pack(
                State(state_b),
                Path(("z6f3repo".to_string(), "r1".to_string())),
                Extension(crate::auth::AuthenticatedDid(did.to_string())),
                None,
                crate::rate_limit::PeerAddr(Some(
                    "203.0.113.82:5000".parse::<SocketAddr>().unwrap(),
                )),
                axum::http::HeaderMap::new(),
                axum::body::Bytes::from_static(b"0000"),
            )
            .await
        });
        // Give B time to reach and block on the lease acquire.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            !b_ran.exists(),
            "B must not have mutated the repo while A legitimately holds the lease"
        );

        // Client disconnect on A: drop its future. RepoWriteGuard::Drop frees the pg lock
        // immediately; the write-path AdmissionGuard (carrying the lease's clone (a))
        // rides KillGroupOnDrop's detached reaper, which now tears down A's group.
        drop(fut_a);

        // Load-bearing ordering invariant: while A's descendant is still alive (group not
        // yet reaped), B must NOT have run its receive-pack. Poll until the descendant is
        // gone; every step it is alive, B's marker must be absent. Pre-fix, B's marker
        // appears here (RED); with the lease it can only appear after the reap (GREEN).
        let mut reaped = false;
        for _ in 0..800 {
            if !f3_alive(desc) {
                reaped = true;
                break;
            }
            assert!(
                !b_ran.exists(),
                "F3 RED: push B mutated the repo while push A's disconnected git group \
                 was still alive (descendant pid {desc}) — the second writer must be \
                 serialized until the first group is reaped"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        // Safety net so a RED run never leaks the orphan.
        unsafe {
            libc::kill(desc, libc::SIGKILL);
        }
        assert!(
            reaped,
            "A's disconnected group must be reaped within the teardown cap"
        );

        // GREEN tail: once the group is reaped the lease frees and B proceeds — its
        // receive-pack runs (marker appears) and it returns 200.
        let mut b_mutated = false;
        for _ in 0..1000 {
            if b_ran.exists() {
                b_mutated = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            b_mutated,
            "push B must proceed and mutate the repo once A's group is reaped"
        );
        let resp = tokio::time::timeout(std::time::Duration::from_secs(30), handle_b)
            .await
            .expect("push B must complete once the lease frees")
            .expect("push B task must not panic")
            .expect("push B must succeed");
        assert_eq!(resp.status(), 200, "push B lands 200 after serialization");
    }

    /// F3 clean-path no-regression: a clean push (no disconnect) releases the lease after
    /// the receive-pack group is reaped and the (success-only) Tigris upload in
    /// guard.release runs, so the per-repo lease entry is GC'd and a second same-repo
    /// push proceeds immediately. A lease that failed to free on the clean path would
    /// wedge every subsequent push to the repo.
    #[cfg(unix)]
    #[sqlx::test]
    async fn f3_clean_push_frees_lease_and_second_push_proceeds(pool: sqlx::PgPool) {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;

        let tmp = tempfile::TempDir::new().unwrap();
        // Clean receive-pack: drain stdin, exit 0. No hang, no descendant.
        let body = "#!/bin/sh\ncase \"$1\" in\n  receive-pack) cat >/dev/null 2>/dev/null ;;\n  rev-parse) echo deadbeef ;;\n  *) : ;;\nesac\nexit 0\n";
        let git_bin = write_fake_git(tmp.path(), body);
        let state =
            f4_state_with_repo(pool.clone(), tmp.path(), &git_bin, "z6f3clean", "c1", false).await;
        let did = "did:key:z6MkF3CleanPusherAAAAAAAAAAAAAAAAAAAAAAAA";

        let push = |st: AppState, peer: &'static str| async move {
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                git_receive_pack(
                    State(st),
                    Path(("z6f3clean".to_string(), "c1".to_string())),
                    Extension(crate::auth::AuthenticatedDid(did.to_string())),
                    None,
                    crate::rate_limit::PeerAddr(Some(peer.parse::<SocketAddr>().unwrap())),
                    axum::http::HeaderMap::new(),
                    axum::body::Bytes::from_static(b"0000"),
                ),
            )
            .await
            .expect("a clean push must not wedge on the lease")
            .expect("the push must succeed")
        };

        let a = push(state.clone(), "203.0.113.91:5000").await;
        assert_eq!(a.status(), 200, "clean push A lands 200");
        // The clean push freed its lease (both clones dropped) -> the entry GC'd.
        assert!(
            state.repo_write_leases.is_empty(),
            "a clean push must free the per-repo lease (Drop-frees-key) so it never wedges"
        );

        let b = push(state.clone(), "203.0.113.92:5000").await;
        assert_eq!(
            b.status(),
            200,
            "a second same-repo push proceeds after a clean first"
        );
        assert!(
            state.repo_write_leases.is_empty(),
            "the lease entry must be freed again after the second clean push"
        );
    }

    /// F3 DoS (P2, RED-before/GREEN-after): a second same-repo push that BLOCKS on the
    /// per-repo write lease must hold NO global write permit while it waits. The lease
    /// is a block-and-wait serializer, so a lease-blocked waiter can sit for up to
    /// steal_after (~a full git_service_timeout window). If it grabs a scarce global
    /// write-pool slot BEFORE blocking, a handful of hostile sources can stack same-repo
    /// pushes, pin every write slot on lease-waiters sending zero bytes, and shed 503 on
    /// every push to every OTHER repo node-wide. The fix acquires the lease BEFORE the
    /// two write permits, so a blocked waiter pins no slot.
    ///
    /// Load-bearing invariant: with the write pool sized to 2, push A holds the lease and
    /// is in-flight in receive-pack (1 permit held), and same-repo push B is blocked on
    /// the lease, `git_write_semaphore.available_permits()` must stay 1 (only A holds).
    /// Pre-fix B takes its permit BEFORE blocking on the lease, draining the pool to 0
    /// (RED). With the reorder B blocks before any permit, so the pool stays at 1 (GREEN).
    #[cfg(unix)]
    #[sqlx::test]
    async fn f3_lease_blocked_waiter_holds_no_write_permit(pool: sqlx::PgPool) {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;
        use std::sync::Arc;
        use tokio::sync::Semaphore;

        let tmp = tempfile::TempDir::new().unwrap();
        let seq_a = tmp.path().join("seq_a"); // first receive-pack wins this mkdir = push A
        let a_inpack = tmp.path().join("a.inpack"); // set when A reaches receive-pack (holds lease+permit)
        let b_ran = tmp.path().join("b.ran"); // set when B's receive-pack runs (B got past the lease)
                                              // receive-pack: first invocation (A) marks that it reached the pack and hangs in a
                                              // bounded loop (so a RED run leaks no permanent orphan); second (B) marks it ran.
        let body = format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
               receive-pack)\n\
                 cat >/dev/null 2>/dev/null\n\
                 if mkdir \"{seq}\" 2>/dev/null; then\n\
                   echo 1 > \"{ainp}\"\n\
                   i=0; while [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done\n\
                 else\n\
                   echo 1 > \"{bran}\"\n\
                 fi ;;\n\
               rev-parse) echo deadbeef ;;\n\
               *) : ;;\n\
             esac\n\
             exit 0\n",
            seq = seq_a.display(),
            ainp = a_inpack.display(),
            bran = b_ran.display(),
        );
        let git_bin = write_fake_git(tmp.path(), &body);
        let mut state =
            f4_state_with_repo(pool.clone(), tmp.path(), &git_bin, "z6f3dos", "d1", false).await;
        // Size the write pool to 2 so one in-flight holder (A) leaves exactly one slot
        // free, and a pool-holding waiter (B, pre-fix) would drain it to zero. Sizing to
        // 1 would 503 B on the pool before it could block on the lease, hiding the bug.
        state.git_write_semaphore = Arc::new(Semaphore::new(2));
        let did = "did:key:z6MkF3DosPusherAAAAAAAAAAAAAAAAAAAAAAAAAA";

        // Push A: drive its handler future in slices until it reaches receive-pack (it now
        // holds the lease and one write permit and is hung). available_permits() drops to 1.
        let mut fut_a = Box::pin(git_receive_pack(
            State(state.clone()),
            Path(("z6f3dos".to_string(), "d1".to_string())),
            Extension(crate::auth::AuthenticatedDid(did.to_string())),
            None,
            crate::rate_limit::PeerAddr(Some("203.0.113.71:5000".parse::<SocketAddr>().unwrap())),
            axum::http::HeaderMap::new(),
            axum::body::Bytes::from_static(b"0000"),
        ));
        for _ in 0..1000 {
            let _ = tokio::time::timeout(std::time::Duration::from_millis(10), &mut fut_a).await;
            if a_inpack.exists() {
                break;
            }
        }
        assert!(
            a_inpack.exists(),
            "push A must reach receive-pack and hold the lease"
        );
        assert_eq!(
            state.git_write_semaphore.available_permits(),
            1,
            "with the pool sized to 2, the single in-flight holder (A) leaves one slot free"
        );

        // Push B: a DIFFERENT source, same repo. It blocks on the lease A holds.
        let state_b = state.clone();
        let handle_b = tokio::spawn(async move {
            git_receive_pack(
                State(state_b),
                Path(("z6f3dos".to_string(), "d1".to_string())),
                Extension(crate::auth::AuthenticatedDid(did.to_string())),
                None,
                crate::rate_limit::PeerAddr(Some(
                    "203.0.113.72:5000".parse::<SocketAddr>().unwrap(),
                )),
                axum::http::HeaderMap::new(),
                axum::body::Bytes::from_static(b"0000"),
            )
            .await
        });

        // Load-bearing check: while B is a lease-blocked waiter the pool must stay at 1
        // (only A holds a permit). Poll the invariant across a full window; pre-fix B
        // grabs the last slot within ms and the pool falls to 0 (RED), post-fix it never
        // does (GREEN). A stable state, not a one-shot race: B stays blocked on the lease
        // (steal_after is far larger than this window) so once it settles the pool holds.
        for _ in 0..100 {
            assert_eq!(
                state.git_write_semaphore.available_permits(),
                1,
                "F3 DoS RED: a lease-blocked same-repo waiter took a global write permit \
                 while sending zero bytes, draining the pool — a blocked waiter must pin \
                 no write-pool slot"
            );
            assert!(
                !b_ran.exists(),
                "B must not have run receive-pack while A holds the lease"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        // Non-vacuous: B is genuinely parked on the lease, not returned early.
        assert!(
            !handle_b.is_finished(),
            "push B must still be blocked on the lease at this point"
        );

        // Client disconnect on A: drop its future. The write-path AdmissionGuard rides the
        // reaper, freeing the lease once A's group is reaped; B then proceeds.
        drop(fut_a);
        let resp = tokio::time::timeout(std::time::Duration::from_secs(30), handle_b)
            .await
            .expect("push B must complete once A's group is reaped and the lease frees")
            .expect("push B task must not panic")
            .expect("push B must succeed");
        assert_eq!(resp.status(), 200, "push B lands 200 after serialization");
        assert!(b_ran.exists(), "push B ran its receive-pack once unblocked");
    }

    /// Backstop for the F1 wait loops below. It is a HANG detector, never the thing an
    /// assertion rests on: every F1 conclusion is drawn from a state the loop actually
    /// observed (a returned shed, a second reference on the lease entry), so a loaded
    /// machine only spends more iterations getting there. It must stay comfortably under
    /// `F1_HOLD_SECS` so push A is still holding the lease when the loop gives up.
    #[cfg(unix)]
    const F1_BACKSTOP: std::time::Duration = std::time::Duration::from_secs(30);

    /// How long `f1_hanging_first_git`'s first receive-pack holds the lease. Bounded so a
    /// RED run leaks no permanent orphan, and well above the two sequential `F1_BACKSTOP`
    /// windows the discriminator can spend, so the hold never expires mid-observation on
    /// a loaded machine. The old bound was 10s, which is under the 19s the pair took on a
    /// contended box: push A's git would exit and free the lease mid-test.
    #[cfg(unix)]
    const F1_HOLD_SECS: usize = 150;

    /// Poll `cond` until it holds, yielding between checks so spawned handlers make
    /// progress. Returns false if `cap` elapses first. Callers assert on the state the
    /// loop settled into, not on the elapsed time.
    #[cfg(unix)]
    async fn f1_wait_for(cap: std::time::Duration, mut cond: impl FnMut() -> bool) -> bool {
        let deadline = std::time::Instant::now() + cap;
        loop {
            if cond() {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// Fake git for the U1 lease-park tests. The FIRST receive-pack invocation marks
    /// that it reached the pack and hangs in a BOUNDED loop (so a RED run leaks no
    /// permanent orphan); every later invocation marks that it got past the lease.
    /// Returns `(git_bin, a_inpack marker, later_ran marker)`.
    #[cfg(unix)]
    fn f1_hanging_first_git(
        tmp: &std::path::Path,
    ) -> (String, std::path::PathBuf, std::path::PathBuf) {
        let seq_a = tmp.join("f1_seq_a"); // first receive-pack wins this mkdir = push A
        let a_inpack = tmp.join("f1_a.inpack");
        let later_ran = tmp.join("f1_later.ran");
        let body = format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
               receive-pack)\n\
                 cat >/dev/null 2>/dev/null\n\
                 if mkdir \"{seq}\" 2>/dev/null; then\n\
                   echo 1 > \"{ainp}\"\n\
                   i=0; while [ $i -lt {hold} ]; do sleep 1; i=$((i+1)); done\n\
                 else\n\
                   echo 1 > \"{later}\"\n\
                 fi ;;\n\
               rev-parse) echo deadbeef ;;\n\
               *) : ;;\n\
             esac\n\
             exit 0\n",
            seq = seq_a.display(),
            ainp = a_inpack.display(),
            later = later_ran.display(),
            hold = F1_HOLD_SECS,
        );
        (write_fake_git(tmp, &body), a_inpack, later_ran)
    }

    /// Add a second repo to a state built by `f4_state_with_repo`, returning its DB id.
    /// The U1 tests need two repos in ONE state to show that shedding on a contended
    /// lease is confined to that repo.
    #[cfg(unix)]
    async fn f1_add_repo(state: &AppState, owner: &str, name: &str) -> String {
        state
            .db
            .upsert_mirror_repo(owner, name, &format!("/unused-{owner}-{name}"), None, false)
            .await
            .unwrap();
        let rec = state.db.get_repo(owner, name).await.unwrap().unwrap();
        state
            .repo_store
            .init(&rec.owner_did, &rec.name)
            .await
            .unwrap();
        rec.id
    }

    /// #174 U2: the write lease must register under the STABLE DISK IDENTITY
    /// (sanitized owner slug + repo name, what `RepoStore::local_path` and the pg
    /// advisory lock key on), not `record.id`.
    ///
    /// The row id rotates on delete+recreate under the same slug while the bare
    /// repo on disk is reused, so an id-keyed lease silently stops serializing
    /// across that rotation and lets two writers onto one `objects/` directory.
    /// Asserting on the key the holder actually registers under binds the
    /// production call site — a helper unit test alone would not.
    #[cfg(unix)]
    #[sqlx::test]
    async fn u2_lease_registers_under_the_disk_identity_not_the_row_id(pool: sqlx::PgPool) {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;

        let tmp = tempfile::TempDir::new().unwrap();
        let (git_bin, a_inpack, _later_ran) = f1_hanging_first_git(tmp.path());
        let state =
            f4_state_with_repo(pool.clone(), tmp.path(), &git_bin, "z6u2key", "k1", false).await;
        // Rotate the row to a UUID id first. f4_state_with_repo creates the repo
        // through the mirror path, whose id is literally `owner_short/name` and so
        // coincides with the identity key — which would leave this test unable to
        // tell the two keys apart. A UUID id is also the real shape of the bug: an
        // API-created repo, or any repo whose row was recreated under the same slug.
        let seeded = state.db.get_repo("z6u2key", "k1").await.unwrap().unwrap();
        let rotated_id = Uuid::new_v4().to_string();
        sqlx::query("UPDATE repos SET id = $1 WHERE id = $2")
            .bind(&rotated_id)
            .bind(&seeded.id)
            .execute(&pool)
            .await
            .unwrap();

        let rec = state.db.get_repo("z6u2key", "k1").await.unwrap().unwrap();
        assert_eq!(rec.id, rotated_id, "the row really did take the new id");
        let identity = crate::state::repo_identity_key(&rec.owner_did, &rec.name);
        assert_ne!(
            identity, rec.id,
            "the identity key must differ from the row id, or this test proves nothing"
        );

        let did = "did:key:z6MkU2KeyPusherAAAAAAAAAAAAAAAAAAAAAAAA";
        let peer: SocketAddr = "203.0.113.91:5000".parse().unwrap();
        let handle = tokio::spawn({
            let st = state.clone();
            let did = did.to_string();
            async move {
                git_receive_pack(
                    State(st),
                    Path(("z6u2key".to_string(), "k1".to_string())),
                    Extension(crate::auth::AuthenticatedDid(did)),
                    None,
                    crate::rate_limit::PeerAddr(Some(peer)),
                    axum::http::HeaderMap::new(),
                    axum::body::Bytes::from_static(b"0000"),
                )
                .await
            }
        });
        assert!(
            f1_wait_for(F1_BACKSTOP, || a_inpack.exists()).await,
            "the push never reached receive-pack within {F1_BACKSTOP:?}"
        );

        assert_eq!(
            state.repo_write_leases.refs_for(&identity),
            1,
            "the lease holder must be registered under the stable disk identity"
        );
        assert_eq!(
            state.repo_write_leases.refs_for(&rec.id),
            0,
            "and never under the rotating row id"
        );

        handle.abort();
    }

    /// #174 (RED-before/GREEN-after): the lease steal bound derived from
    /// `git_service_timeout_secs` must not overflow. Unchecked, `* 2 + 60` panics the push
    /// in a debug build and wraps to a short `Duration` in release, and a wrapped bound
    /// would let a waiter steal the lease out from under a live push. Drives the handler
    /// rather than the arithmetic, so the call-site wiring is what is under test.
    ///
    /// `GIT_SERVICE_TIMEOUT_SECS_MAX` means clap no longer admits a value this large, and
    /// the test keeps `u64::MAX` anyway rather than moving to the ceiling. Two reasons, and
    /// the second is the load-bearing one: `Config` is reachable by direct construction,
    /// which is how this test and every other one build it; and at the ceiling the
    /// arithmetic does not overflow, so a test pinned there would pass with the saturation
    /// removed and prove nothing about this line.
    #[cfg(unix)]
    #[sqlx::test]
    async fn push_survives_a_git_service_timeout_that_overflows_the_lease_bound(
        pool: sqlx::PgPool,
    ) {
        use axum::extract::{Path, State};
        use axum::response::IntoResponse;
        use axum::Extension;
        use std::net::SocketAddr;

        let tmp = tempfile::TempDir::new().unwrap();
        let git_bin = write_fake_git(
            tmp.path(),
            "#!/bin/sh\n\
             case \"$1\" in\n\
               receive-pack) cat > /dev/null 2>/dev/null ;;\n\
               rev-parse) echo deadbeef ;;\n\
               *) : ;;\n\
             esac\n\
             exit 0\n",
        );
        let mut state =
            f4_state_with_repo(pool.clone(), tmp.path(), &git_bin, "z6ovflow", "o1", false).await;
        // Every value above (u64::MAX - 60) / 2 overflows the derived bound; u64::MAX is
        // the top of that tail, and the value clap accepted before the ceiling landed.
        let mut cfg = (*state.config).clone();
        cfg.git_service_timeout_secs = u64::MAX;
        state.config = std::sync::Arc::new(cfg);

        let resp = git_receive_pack(
            State(state),
            Path(("z6ovflow".to_string(), "o1".to_string())),
            Extension(crate::auth::AuthenticatedDid(
                "did:key:z6MkOverflowPusherAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            )),
            None,
            crate::rate_limit::PeerAddr(Some("203.0.113.90:5000".parse::<SocketAddr>().unwrap())),
            axum::http::HeaderMap::new(),
            ref_update_body("1111111111111111111111111111111111111111"),
        )
        .await
        .expect("push must succeed under a maximal git_service_timeout_secs")
        .into_response();
        assert_eq!(
            resp.status(),
            200,
            "a maximal service timeout must disable the steal bound, not break the push"
        );
    }

    /// #174 U1 scenario 1 (RED-before/GREEN-after): parked pushes on one repo's write
    /// lease are BOUNDED. `git_receive_pack` takes `body: Bytes`, so axum has already
    /// buffered the whole pack (up to `max_pack_bytes`) before the handler runs, and the
    /// park runs to `lease_steal_after` = `git_service_timeout_secs * 2 + 60` = 1260s at
    /// defaults. An unbounded waiter set is therefore unbounded buffered memory held for
    /// 21 minutes. With the cap at K, a holder plus K live waiters means the next push
    /// sheds a 503 + Retry-After instead of joining the queue.
    ///
    /// Read as state, never as elapsed time: the shed is the returned `Overloaded`, and
    /// "the queue did not grow" is the waiter count the loop polls to. The bound is on
    /// LIVE WAITERS, so the holder is not counted; that is what keeps a leaked lease from
    /// wedging the repo (see `steal_on_leaked_lease_still_works_under_the_waiter_cap`).
    #[cfg(unix)]
    #[sqlx::test]
    async fn u1_push_past_the_lease_waiter_cap_sheds_with_503(pool: sqlx::PgPool) {
        use axum::extract::{Path, State};
        use axum::response::IntoResponse;
        use axum::Extension;
        use std::net::SocketAddr;

        let tmp = tempfile::TempDir::new().unwrap();
        let (git_bin, a_inpack, _later_ran) = f1_hanging_first_git(tmp.path());
        let mut state =
            f4_state_with_repo(pool.clone(), tmp.path(), &git_bin, "z6u1cap", "c1", false).await;
        // Cap of ONE live waiter, so a holder plus one parked push fills the repo's queue.
        state.repo_write_leases = crate::state::RepoWriteLeases::new(1);
        // The lease keys on the stable disk identity (#174 U2), not the row id.
        let repo_id = {
            let r = state.db.get_repo("z6u1cap", "c1").await.unwrap().unwrap();
            crate::state::repo_identity_key(&r.owner_did, &r.name)
        };
        let did = "did:key:z6MkU1CapPusherAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let push = |peer: SocketAddr| {
            let st = state.clone();
            let did = did.to_string();
            async move {
                git_receive_pack(
                    State(st),
                    Path(("z6u1cap".to_string(), "c1".to_string())),
                    Extension(crate::auth::AuthenticatedDid(did)),
                    None,
                    crate::rate_limit::PeerAddr(Some(peer)),
                    axum::http::HeaderMap::new(),
                    axum::body::Bytes::from_static(b"0000"),
                )
                .await
            }
        };

        // Push A holds the lease (its git hangs) until it is aborted below.
        let handle_a = tokio::spawn(push("203.0.113.81:5000".parse().unwrap()));
        assert!(
            f1_wait_for(F1_BACKSTOP, || a_inpack.exists()).await,
            "push A never reached receive-pack within {F1_BACKSTOP:?}"
        );
        assert_eq!(
            state.repo_write_leases.waiters_for(&repo_id),
            0,
            "the uncontended holder must spend no waiter budget"
        );

        // Push B fills the single waiter slot.
        let handle_b = tokio::spawn(push("203.0.113.82:5000".parse().unwrap()));
        assert!(
            f1_wait_for(F1_BACKSTOP, || state
                .repo_write_leases
                .waiters_for(&repo_id)
                == 1)
            .await,
            "push B never parked on the contended lease within {F1_BACKSTOP:?}"
        );

        // Push C is past the cap: it must be turned away, not queued.
        let c = tokio::time::timeout(F1_BACKSTOP, push("203.0.113.83:5000".parse().unwrap()))
            .await
            .expect("a push past the waiter cap must return, not park");
        assert!(
            matches!(c, Err(AppError::Overloaded(_))),
            "U1 RED: a push arriving past the repo's live-waiter cap joined the unbounded \
             park queue instead of shedding, holding its fully buffered pack for up to \
             steal_after (1260s at defaults); got {c:?}"
        );
        let resp = c.unwrap_err().into_response();
        assert_eq!(
            resp.status(),
            503,
            "the shed must be a 503, consistent with the other admission paths"
        );
        assert_eq!(
            resp.headers().get("retry-after").unwrap().to_str().unwrap(),
            "1",
            "the shed must advertise Retry-After"
        );
        assert_eq!(
            state.repo_write_leases.waiters_for(&repo_id),
            1,
            "the shed must not have joined the queue, and must leave no waiter residue"
        );
        assert_eq!(
            state.repo_write_leases.refs_for(&repo_id),
            2,
            "only the holder and the one real waiter may reference the entry after a shed"
        );

        handle_a.abort();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(60), handle_b).await;
    }

    /// #174 U1 scenario 2, THE REGRESSION GUARD for the rejected design. A source parked
    /// on repo A's lease must still be served on an UNCONTENDED repo B. The rejected fix
    /// bounded parked bodies by taking the per-source write permit ABOVE the lease, which
    /// makes a parked push spend that source's node-wide budget: the same pusher is then
    /// denied on every other repo, and (since `TrustedProxy` defaults to `None`, so every
    /// pusher behind a proxy or NAT resolves to one key) so is everyone else. Moving the
    /// per-caller permit back above the lease turns this red.
    ///
    /// The per-source cap is 2 here: the holder spends one, so a parked push spending the
    /// second is what denies repo B. Under the shipped ordering the parked push holds no
    /// permit at all and repo B is served.
    #[cfg(unix)]
    #[sqlx::test]
    async fn u1_a_source_parked_on_one_repo_is_still_served_on_another(pool: sqlx::PgPool) {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;

        let tmp = tempfile::TempDir::new().unwrap();
        let (git_bin, a_inpack, later_ran) = f1_hanging_first_git(tmp.path());
        let mut state =
            f4_state_with_repo(pool.clone(), tmp.path(), &git_bin, "z6u1two", "r1", false).await;
        state.git_write_per_caller = crate::rate_limit::PerCallerConcurrency::new(2, 100);
        let repo1 = {
            let r = state.db.get_repo("z6u1two", "r1").await.unwrap().unwrap();
            crate::state::repo_identity_key(&r.owner_did, &r.name)
        };
        f1_add_repo(&state, "z6u1two", "r2").await;
        let did = "did:key:z6MkU1TwoPusherAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let src: SocketAddr = "203.0.113.84:5000".parse().unwrap();
        let push = |repo: &'static str| {
            let st = state.clone();
            let did = did.to_string();
            async move {
                git_receive_pack(
                    State(st),
                    Path(("z6u1two".to_string(), repo.to_string())),
                    Extension(crate::auth::AuthenticatedDid(did)),
                    None,
                    crate::rate_limit::PeerAddr(Some(src)),
                    axum::http::HeaderMap::new(),
                    axum::body::Bytes::from_static(b"0000"),
                )
                .await
            }
        };

        // Push A (this source) holds repo r1's lease; push B (same source) parks on it.
        let handle_a = tokio::spawn(push("r1"));
        assert!(
            f1_wait_for(F1_BACKSTOP, || a_inpack.exists()).await,
            "push A never reached receive-pack within {F1_BACKSTOP:?}"
        );
        let handle_b = tokio::spawn(push("r1"));
        assert!(
            f1_wait_for(F1_BACKSTOP, || state.repo_write_leases.waiters_for(&repo1)
                == 1)
            .await,
            "push B never parked on r1's contended lease within {F1_BACKSTOP:?}"
        );

        // Push C: same source, DIFFERENT repo, uncontended. It must be served.
        let c = tokio::time::timeout(F1_BACKSTOP, push("r2"))
            .await
            .expect("a push to an uncontended repo must not park");
        let resp = c.unwrap_or_else(|e| {
            panic!(
                "U1 scenario 2 RED: a push to an UNCONTENDED repo was denied because the \
                 same source had a push parked on a DIFFERENT repo's lease. A parked push \
                 must hold no cross-repo admission budget; got {e:?}"
            )
        });
        assert_eq!(resp.status(), 200, "the uncontended repo's push lands 200");
        assert!(
            later_ran.exists(),
            "the uncontended repo's push must have run its receive-pack"
        );

        handle_a.abort();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(60), handle_b).await;
    }

    /// #174 U1 scenario 3, THE CROSS-TENANT GUARD. `GITLAWB_TRUSTED_PROXY` is unset by
    /// default (`TrustedProxy::None`), so behind an edge proxy, a NAT, or a CI pool every
    /// pusher resolves to the SAME source key. A push parked on one repo's lease must not
    /// shed a DIFFERENT pusher's push to a DIFFERENT repo. This is the shape that made
    /// the rejected design a cross-tenant denial rather than a self-inflicted one: with
    /// the per-source permit above the park, four parked pushes deny every push on the
    /// node for up to 1260s.
    ///
    /// Same one source IP for all three pushes (the collapsed-key shape), distinct pusher
    /// DIDs, per-source cap 2 so the holder plus a parked push would exhaust it.
    #[cfg(unix)]
    #[sqlx::test]
    async fn u1_parked_push_does_not_shed_another_pusher_behind_the_same_ip(pool: sqlx::PgPool) {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;

        let tmp = tempfile::TempDir::new().unwrap();
        let (git_bin, a_inpack, later_ran) = f1_hanging_first_git(tmp.path());
        let mut state =
            f4_state_with_repo(pool.clone(), tmp.path(), &git_bin, "z6u1nat", "n1", false).await;
        // The default proxy trust: the resolved key is the peer IP, which is the edge's.
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.git_write_per_caller = crate::rate_limit::PerCallerConcurrency::new(2, 100);
        let repo1 = {
            let r = state.db.get_repo("z6u1nat", "n1").await.unwrap().unwrap();
            crate::state::repo_identity_key(&r.owner_did, &r.name)
        };
        f1_add_repo(&state, "z6u1nat", "n2").await;
        // Every pusher arrives from the one edge IP, so they share a source key.
        let edge: SocketAddr = "203.0.113.85:5000".parse().unwrap();
        let push = |pusher: &'static str, repo: &'static str| {
            let st = state.clone();
            async move {
                git_receive_pack(
                    State(st),
                    Path(("z6u1nat".to_string(), repo.to_string())),
                    Extension(crate::auth::AuthenticatedDid(pusher.to_string())),
                    None,
                    crate::rate_limit::PeerAddr(Some(edge)),
                    axum::http::HeaderMap::new(),
                    axum::body::Bytes::from_static(b"0000"),
                )
                .await
            }
        };

        let handle_a = tokio::spawn(push(
            "did:key:z6MkU1NatPusherOneAAAAAAAAAAAAAAAAAAAAAA",
            "n1",
        ));
        assert!(
            f1_wait_for(F1_BACKSTOP, || a_inpack.exists()).await,
            "pusher one never reached receive-pack within {F1_BACKSTOP:?}"
        );
        let handle_b = tokio::spawn(push(
            "did:key:z6MkU1NatPusherTwoAAAAAAAAAAAAAAAAAAAAAA",
            "n1",
        ));
        assert!(
            f1_wait_for(F1_BACKSTOP, || state.repo_write_leases.waiters_for(&repo1)
                == 1)
            .await,
            "pusher two never parked on n1's contended lease within {F1_BACKSTOP:?}"
        );

        // A third, unrelated pusher behind the same edge IP, on a different repo.
        let c = tokio::time::timeout(
            F1_BACKSTOP,
            push("did:key:z6MkU1NatPusherThreeAAAAAAAAAAAAAAAAAA", "n2"),
        )
        .await
        .expect("an unrelated pusher's push to an uncontended repo must not park");
        let resp = c.unwrap_or_else(|e| {
            panic!(
                "U1 scenario 3 RED: one repo's parked push shed an UNRELATED pusher's push \
                 to a DIFFERENT repo, because every pusher behind the proxy shares one \
                 resolved source key. Contention on one repo must never deny another; \
                 got {e:?}"
            )
        });
        assert_eq!(resp.status(), 200, "the unrelated pusher lands 200");
        assert!(
            later_ran.exists(),
            "the unrelated pusher must have run its receive-pack"
        );

        handle_a.abort();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(60), handle_b).await;
    }

    /// #174 F1 (U1) key shape: the write sub-cap is keyed on the SOURCE, not the repo.
    /// A source at its cap is shed on EVERY repo (otherwise one source could hold four
    /// buffered bodies per repo, and the bound would be `repos x cap x max_pack_bytes`),
    /// while a different source is shed on none. Uncontended leases here: this pins the
    /// key's shape, not the acquisition order.
    #[sqlx::test]
    async fn f1_write_cap_key_is_per_source_not_per_repo(pool: sqlx::PgPool) {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;
        use std::sync::Arc;
        use tokio::sync::Semaphore;

        let mut state = crate::test_support::test_state(pool).await;
        state.git_write_semaphore = Arc::new(Semaphore::new(4));
        state.git_write_per_caller = crate::rate_limit::PerCallerConcurrency::new(1, 100);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        for name in ["k1", "k2"] {
            state
                .db
                .upsert_mirror_repo(
                    "z6f1key",
                    name,
                    &format!("/tmp/f1-key-{name}-nonexistent"),
                    None,
                    false,
                )
                .await
                .unwrap();
        }

        let did = "did:key:z6MkF1KeyPusherAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let capped: SocketAddr = "203.0.113.65:5000".parse().unwrap();
        let other: SocketAddr = "203.0.113.66:5000".parse().unwrap();
        let _slot = state
            .git_write_per_caller
            .try_acquire(&capped.ip().to_string())
            .expect("pin the capped source at its single write slot");

        let push = |peer: SocketAddr, repo: &'static str| {
            let st = state.clone();
            async move {
                git_receive_pack(
                    State(st),
                    Path(("z6f1key".to_string(), repo.to_string())),
                    Extension(crate::auth::AuthenticatedDid(did.to_string())),
                    None,
                    crate::rate_limit::PeerAddr(Some(peer)),
                    axum::http::HeaderMap::new(),
                    axum::body::Bytes::from_static(b"0000"),
                )
                .await
            }
        };

        for repo in ["k1", "k2"] {
            let r = push(capped, repo).await;
            assert!(
                matches!(r, Err(AppError::Overloaded(_))),
                "the capped source must shed on repo {repo} too: the sub-cap is per \
                 source, not per repo; got {r:?}"
            );
        }
        let r = push(other, "k2").await;
        assert!(
            !matches!(r, Err(AppError::Overloaded(_))),
            "a different source must not be shed on any repo while the capped source \
             holds its slot; got {r:?}"
        );
    }

    /// #174 F1 (U1) fallback: a caller with no resolvable source key (no trusted
    /// header, no peer address) takes no per-caller permit and is bounded by the global
    /// write pool only, exactly as before the move. `acquire_read_caller_permit`
    /// returns `Ok(None)` for a `None` key, so it must never 503 here.
    #[sqlx::test]
    async fn f1_write_cap_is_inert_without_a_resolvable_source_key(pool: sqlx::PgPool) {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::sync::Arc;
        use tokio::sync::Semaphore;

        let mut state = crate::test_support::test_state(pool).await;
        state.git_write_semaphore = Arc::new(Semaphore::new(4));
        state.git_write_per_caller = crate::rate_limit::PerCallerConcurrency::new(1, 1);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state
            .db
            .upsert_mirror_repo("z6f1none", "n1", "/tmp/f1-none-nonexistent", None, false)
            .await
            .unwrap();
        // Saturate the limiter's only key slot as well, so a request that DID resolve a
        // key would be shed. The keyless request must still pass.
        let _slot = state
            .git_write_per_caller
            .try_acquire("203.0.113.67")
            .expect("occupy the limiter's single key slot");

        let r = git_receive_pack(
            State(state.clone()),
            Path(("z6f1none".to_string(), "n1".to_string())),
            Extension(crate::auth::AuthenticatedDid(
                "did:key:z6MkF1NoKeyPusherAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            )),
            None,
            crate::rate_limit::PeerAddr(None),
            axum::http::HeaderMap::new(),
            axum::body::Bytes::from_static(b"0000"),
        )
        .await;
        assert!(
            !matches!(r, Err(AppError::Overloaded(_))),
            "a caller with no resolvable source key must fall back to the global write \
             pool only, never shed on the per-caller cap; got {r:?}"
        );
    }

    /// #174 F1 (U1) no-regression: moving the per-caller permit above the lease must
    /// not leak it. Two SEQUENTIAL clean pushes from the SAME source with the sub-cap
    /// set to 1 must both land 200; if the first push's permit outlived its request the
    /// second would 503, breaking every repeat pusher.
    #[cfg(unix)]
    #[sqlx::test]
    async fn f1_sequential_pushes_from_one_source_release_the_write_permit(pool: sqlx::PgPool) {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;

        let tmp = tempfile::TempDir::new().unwrap();
        let body = "#!/bin/sh\ncase \"$1\" in\n  receive-pack) cat >/dev/null 2>/dev/null ;;\n  rev-parse) echo deadbeef ;;\n  *) : ;;\nesac\nexit 0\n";
        let git_bin = write_fake_git(tmp.path(), body);
        let mut state =
            f4_state_with_repo(pool.clone(), tmp.path(), &git_bin, "z6f1seq", "s1", false).await;
        state.git_write_per_caller = crate::rate_limit::PerCallerConcurrency::new(1, 100);
        let did = "did:key:z6MkF1SeqPusherAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let src: SocketAddr = "203.0.113.68:5000".parse().unwrap();

        for attempt in 1..=2 {
            let resp = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                git_receive_pack(
                    State(state.clone()),
                    Path(("z6f1seq".to_string(), "s1".to_string())),
                    Extension(crate::auth::AuthenticatedDid(did.to_string())),
                    None,
                    crate::rate_limit::PeerAddr(Some(src)),
                    axum::http::HeaderMap::new(),
                    axum::body::Bytes::from_static(b"0000"),
                ),
            )
            .await
            .expect("a clean push must not wedge")
            .unwrap_or_else(|e| panic!("push {attempt} from the same source must succeed: {e:?}"));
            assert_eq!(resp.status(), 200, "clean push {attempt} lands 200");
        }
        assert_eq!(
            state.git_write_per_caller.tracked_keys(),
            0,
            "every per-source write permit must be released when its push completes"
        );
    }
    // ---- #174 F2a: the coalescing gate runs BEFORE the withheld walk ----
    //
    // These drive `post_receive_replication_tail` directly (the handler's detached
    // tail, extracted so the ordering the gate depends on is observable) over a REAL
    // git repo, with a logging git shim in front of the real binary. The shim's log
    // is the seam: `ls-tree` lines are withheld-walk children, and a line naming a
    // tip sha attributes a scan to the push that pushed it.

    /// A git shim that appends its argv to `log`, then delegates to the real git, so
    /// the walks stay real while every child is observable.
    #[cfg(unix)]
    fn f2a_logging_git(dir: &std::path::Path, log: &std::path::Path) -> String {
        write_fake_git(
            dir,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"{}\"\nexec git \"$@\"\n",
                log.display()
            ),
        )
    }

    fn f2a_log(log: &std::path::Path) -> String {
        std::fs::read_to_string(log).unwrap_or_default()
    }

    /// Withheld-walk children run so far. `ls-tree` is the walk's signature child
    /// (`blob_paths` lists every reachable commit's tree); the delta scan and the
    /// full-scan fallback use `rev-list` / `cat-file` instead.
    fn f2a_walks(log: &std::path::Path) -> usize {
        f2a_log(log)
            .lines()
            .filter(|l| l.starts_with("ls-tree"))
            .count()
    }

    /// A state whose git is the shim, plus a repo row (optionally path-scoped, so
    /// the withheld walk actually runs rather than taking the no-rule shortcut).
    /// The repo's on-disk path is passed to the tail directly, so no repo_store or
    /// receive-pack plumbing is involved.
    async fn f2a_state(
        pool: sqlx::PgPool,
        git_bin: &str,
        owner: &str,
        name: &str,
        path_scoped: bool,
    ) -> (AppState, crate::db::RepoRecord) {
        let mut state = crate::test_support::test_state(pool).await;
        state.git_bin = git_bin.to_string();
        state
            .db
            .upsert_mirror_repo(owner, name, "/unused", None, false)
            .await
            .unwrap();
        let rec = state.db.get_repo(owner, name).await.unwrap().unwrap();
        if path_scoped {
            state
                .db
                .set_visibility_rule(
                    &rec.id,
                    "/secret/**",
                    crate::db::VisibilityMode::B,
                    &["did:key:z6MkF2aReaderAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()],
                    &rec.owner_did,
                )
                .await
                .unwrap();
        }
        (state, rec)
    }

    fn f2a_update(ref_name: &str, new_sha: &str) -> Vec<RefUpdate> {
        vec![RefUpdate {
            old_sha: ZERO_SHA.to_string(),
            new_sha: new_sha.to_string(),
            ref_name: ref_name.to_string(),
        }]
    }

    const F2A_PUSHER: &str = "did:key:z6MkF2aPusherAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// Scenario 1 (the finding). A second rapid push to the same repo coalesces
    /// WITHOUT running the withheld walk. Asserted on the walk's git children, not
    /// on the `Coalesced` outcome: with `try_begin` below the walk (the pre-fix
    /// order) the second push still parks on the scan pool and re-walks, which is
    /// exactly the accumulation jatmn found.
    ///
    /// The pin pool's only permit is held for the whole test, so both pushes' pin
    /// tasks park before doing any git of their own: every `ls-tree` in the log is a
    /// tail walk.
    #[cfg(unix)]
    #[sqlx::test]
    async fn f2a_coalesced_push_does_not_run_the_withheld_walk(pool: sqlx::PgPool) {
        let repo = tempfile::TempDir::new().unwrap();
        let bin = tempfile::TempDir::new().unwrap();
        u5_init_repo(repo.path());
        let c1 = u5_commit_file(repo.path(), "a.txt", "one\n");
        let c2 = u5_commit_file(repo.path(), "secret/s.txt", "two\n");
        let log = bin.path().join("git.log");
        let git_bin = f2a_logging_git(bin.path(), &log);
        let (mut state, rec) = f2a_state(pool, &git_bin, "z6f2acoal", "c1", true).await;
        state.pin_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let _held = state.pin_semaphore.clone().acquire_owned().await.unwrap();

        post_receive_replication_tail(
            state.clone(),
            rec.clone(),
            f2a_update("refs/heads/main", &c2),
            repo.path().to_path_buf(),
            F2A_PUSHER.to_string(),
        )
        .await;
        let after_first = f2a_walks(&log);
        assert!(
            after_first >= 1,
            "the admitted push must have run the withheld walk; log:\n{}",
            f2a_log(&log)
        );
        assert_eq!(
            state.encrypt_inflight.len(),
            1,
            "the admitted push's task holds the repo key while it is parked on the pin pool"
        );

        post_receive_replication_tail(
            state.clone(),
            rec.clone(),
            f2a_update("refs/heads/second", &c1),
            repo.path().to_path_buf(),
            F2A_PUSHER.to_string(),
        )
        .await;

        assert_eq!(
            f2a_walks(&log),
            after_first,
            "a push that coalesces must not run the withheld walk at all; log:\n{}",
            f2a_log(&log)
        );
        assert_eq!(
            state
                .encrypt_inflight
                .pending_for(&crate::state::repo_identity_key(&rec.owner_did, &rec.name)),
            Some(crate::state::PendingWork::Tips(vec![(
                ZERO_SHA.to_string(),
                c1.clone()
            )])),
            "the coalesced push's tip pairs are queued for the in-flight task's drain"
        );
    }
    /// Poll `cond` until it holds, with a bound so a regression fails the test
    /// rather than hanging the suite.
    async fn f2a_wait_for(mut cond: impl FnMut() -> bool, what: &str) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !cond() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {what}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }

    /// A `rev-list --objects` line names the tips a DELTA scan was asked to resolve,
    /// so it attributes that scan to one push's tips. The withheld walk's own
    /// `rev-list --all` / `ls-tree` lines never carry a tip as an argument this way.
    fn f2a_delta_scanned(log: &std::path::Path, tip: &str) -> bool {
        f2a_log(log)
            .lines()
            .any(|l| l.starts_with("rev-list --objects") && l.contains(tip))
    }

    /// Scenario 2. The tip pairs a coalesced push queues are consumed by the
    /// in-flight task's drain, which is what makes coalescing lossless. Asserted on
    /// the drained WORK (the delta scan the drain runs for those tips), not on the
    /// key going empty: an armed guard's Drop empties the key too, so `is_empty`
    /// cannot tell a drain from a discard.
    ///
    /// The coalesced tips are injected through `try_begin` directly rather than by a
    /// second tail. A second tail would spawn its own Pinata worker, which re-derives
    /// from the SAME tips, and the two scans are indistinguishable in the git log; the
    /// tail-to-`try_begin` half is covered by scenario 1's pending-slot assertion.
    #[cfg(unix)]
    #[sqlx::test]
    async fn f2a_coalesced_tips_are_drained_by_the_inflight_task(pool: sqlx::PgPool) {
        let repo = tempfile::TempDir::new().unwrap();
        let bin = tempfile::TempDir::new().unwrap();
        u5_init_repo(repo.path());
        u5_commit_file(repo.path(), "a.txt", "one\n");
        let c2 = u5_commit_file(repo.path(), "secret/s.txt", "two\n");
        let log = bin.path().join("git.log");
        let git_bin = f2a_logging_git(bin.path(), &log);
        let (mut state, rec) = f2a_state(pool, &git_bin, "z6f2adrain", "d1", true).await;
        state.pin_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let held = state.pin_semaphore.clone().acquire_owned().await.unwrap();

        // Push A is admitted; its task then parks on the held pin pool, key retained.
        post_receive_replication_tail(
            state.clone(),
            rec.clone(),
            f2a_update("refs/heads/main", &c2),
            repo.path().to_path_buf(),
            F2A_PUSHER.to_string(),
        )
        .await;

        // A later push lands while A's task is in flight: it coalesces, and its tip
        // advances main to a commit no other push in this test names.
        let c3 = u5_commit_file(repo.path(), "b.txt", "three\n");
        assert!(
            matches!(
                state.encrypt_inflight.try_begin(
                    &crate::state::repo_identity_key(&rec.owner_did, &rec.name),
                    vec![(c2.clone(), c3.clone())],
                ),
                crate::state::BeginOutcome::Coalesced
            ),
            "a push arriving while a task is in flight must coalesce"
        );
        assert!(
            !f2a_delta_scanned(&log, &c3),
            "nothing has scanned the coalesced tip yet"
        );

        drop(held);
        f2a_wait_for(
            || f2a_delta_scanned(&log, &c3),
            "the in-flight task's drain to resolve the coalesced push's tips",
        )
        .await;
    }

    /// Scenario 3 (trap 4). A push coalesces WHILE the admitted push is walking, the
    /// admitted walk then FAILS, and the coalesced work is still drained. Moving
    /// `try_begin` above the walk opens this window, so the failed-walk arm must
    /// still spawn the task (with an empty snapshot) rather than let the guard go:
    /// dropping it discards the pending tips with a warn.
    ///
    /// The git shim fails the FIRST `rev-list --all` (the withheld walk's commit
    /// enumeration) after signalling that the walk has started and waiting for the
    /// test to inject the coalescing push, then behaves normally, so the drain that
    /// follows is a real one.
    #[cfg(unix)]
    #[sqlx::test]
    async fn f2a_walk_failure_still_drains_the_coalesced_work(pool: sqlx::PgPool) {
        let repo = tempfile::TempDir::new().unwrap();
        let bin = tempfile::TempDir::new().unwrap();
        u5_init_repo(repo.path());
        u5_commit_file(repo.path(), "a.txt", "one\n");
        let c2 = u5_commit_file(repo.path(), "secret/s.txt", "two\n");
        let c3 = u5_commit_file(repo.path(), "b.txt", "three\n");
        let log = bin.path().join("git.log");
        let started = bin.path().join("walk.started");
        let go = bin.path().join("walk.go");
        let once = bin.path().join("walk.once");
        let git_bin = write_fake_git(
            bin.path(),
            &format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$*\" >> \"{log}\"\n\
                 case \"$*\" in\n\
                   'rev-list --all'*)\n\
                     if [ ! -f \"{once}\" ]; then\n\
                       : > \"{once}\"\n\
                       : > \"{started}\"\n\
                       while [ ! -f \"{go}\" ]; do sleep 0.05; done\n\
                       exit 1\n\
                     fi ;;\n\
                 esac\n\
                 exec git \"$@\"\n",
                log = log.display(),
                once = once.display(),
                started = started.display(),
                go = go.display(),
            ),
        );
        let (state, rec) = f2a_state(pool, &git_bin, "z6f2afail", "f1", true).await;

        let tail = tokio::spawn(post_receive_replication_tail(
            state.clone(),
            rec.clone(),
            f2a_update("refs/heads/main", &c2),
            repo.path().to_path_buf(),
            F2A_PUSHER.to_string(),
        ));
        f2a_wait_for(|| started.exists(), "the admitted push's walk to start").await;

        // Mid-walk arrival: the key is already taken, so this push coalesces into the
        // slot the walking task owns. (With the gate back below the walk it would be
        // ADMITTED here instead, and this assertion is what catches that.)
        assert!(
            matches!(
                state.encrypt_inflight.try_begin(
                    &crate::state::repo_identity_key(&rec.owner_did, &rec.name),
                    vec![(c2.clone(), c3.clone())],
                ),
                crate::state::BeginOutcome::Coalesced
            ),
            "a push arriving mid-walk must coalesce, not start a second task"
        );
        std::fs::write(&go, b"").unwrap();
        tail.await.unwrap();

        f2a_wait_for(
            || f2a_delta_scanned(&log, &c3),
            "the failed walk's task to drain the coalesced push's tips",
        )
        .await;
    }

    /// Mount a Pinata upload endpoint that assigns every object the same CID, and
    /// point the state at it. Returns the server (kept alive by the caller) and CID.
    async fn f2a_pinata(state: &mut AppState) -> (mockito::ServerGuard, String) {
        let cid = "bafyf2acoalescedmapping".to_string();
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/")
            .with_status(200)
            .with_body(format!(r#"{{"data":{{"cid":"{cid}"}}}}"#))
            .expect_at_least(1)
            .create_async()
            .await;
        let mut cfg = (*state.config).clone();
        cfg.pinata_jwt = "f2a-test-jwt".to_string();
        cfg.pinata_upload_url = server.url();
        state.config = std::sync::Arc::new(cfg);
        (server, cid)
    }

    /// Poll the branch to CID table until the push's mapping lands (the Pinata
    /// worker is detached), bounded so a regression fails rather than hangs.
    async fn f2a_wait_for_branch_cid(
        db: &crate::db::Db,
        slug: &str,
        what: &str,
    ) -> Vec<crate::db::BranchCid> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            let rows = db.list_branch_cids(slug).await.unwrap();
            if !rows.is_empty() {
                return rows;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {what}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }

    fn f2a_slug(rec: &crate::db::RepoRecord) -> String {
        format!(
            "{}/{}",
            crate::db::normalize_owner_key(&rec.owner_did),
            rec.name
        )
    }

    /// Scenario 4 (traps 1 and 2). A coalesced push still does its own per-push work:
    /// it records a branch to CID mapping and broadcasts its own ref update. Both
    /// would be lost by returning early on `Coalesced`, and the mapping alone would be
    /// lost by leaving the Pinata gate on `withheld.is_some()` (a coalesced push never
    /// walks, so its `withheld` is None) while a test that only checked "the spawn
    /// ran" stayed green.
    #[cfg(unix)]
    #[sqlx::test]
    async fn f2a_coalesced_push_still_pins_and_announces(pool: sqlx::PgPool) {
        let repo = tempfile::TempDir::new().unwrap();
        let bin = tempfile::TempDir::new().unwrap();
        u5_init_repo(repo.path());
        let c1 = u5_commit_file(repo.path(), "a.txt", "one\n");
        let c2 = u5_commit_file(repo.path(), "secret/s.txt", "two\n");
        let log = bin.path().join("git.log");
        let git_bin = f2a_logging_git(bin.path(), &log);
        let (mut state, rec) = f2a_state(pool, &git_bin, "z6f2apin", "p1", true).await;
        let (_server, cid) = f2a_pinata(&mut state).await;
        let mut updates = state.ref_update_tx.subscribe();

        // A task for this repo is already in flight, so the push below coalesces.
        let _inflight = match state.encrypt_inflight.try_begin(
            &crate::state::repo_identity_key(&rec.owner_did, &rec.name),
            Vec::new(),
        ) {
            crate::state::BeginOutcome::Admitted(g) => g,
            crate::state::BeginOutcome::Coalesced => panic!("the first begin must admit"),
        };

        post_receive_replication_tail(
            state.clone(),
            rec.clone(),
            vec![RefUpdate {
                old_sha: c1.clone(),
                new_sha: c2.clone(),
                ref_name: "refs/heads/main".to_string(),
            }],
            repo.path().to_path_buf(),
            F2A_PUSHER.to_string(),
        )
        .await;

        let slug = f2a_slug(&rec);
        let mapped = f2a_wait_for_branch_cid(
            &state.db,
            &slug,
            "the coalesced push's branch to CID mapping",
        )
        .await;
        assert_eq!(
            mapped.len(),
            1,
            "one mapping, for the ref this push advanced"
        );
        assert_eq!(mapped[0].ref_name, "refs/heads/main");
        assert_eq!(mapped[0].sha, c2, "mapped to the tip this push landed");
        assert_eq!(mapped[0].cid, cid);

        let broadcast = updates
            .try_recv()
            .expect("a coalesced push still fires its own announce");
        assert_eq!(broadcast.new_sha, c2);
        assert_eq!(broadcast.ref_name, "refs/heads/main");
    }

    /// A push handler whose `release` parks at its pre-unlock point, so a test can
    /// drop the future from inside the cancellable post-receive window. Returns the
    /// state, the seeded record and the git-invocation log.
    ///
    /// Path-scoped on purpose: the tail's withheld walk is the observable, and
    /// without a path-scoped rule `replication_withheld_set` takes the no-walk
    /// shortcut and spawns no git at all.
    #[cfg(unix)]
    async fn p2_parked_release_state(
        pool: sqlx::PgPool,
        tmp: &std::path::Path,
        owner: &str,
        name: &str,
        git_body: Option<&str>,
    ) -> (AppState, std::path::PathBuf) {
        let log = tmp.join("git.log");
        let git_bin = match git_body {
            Some(body) => write_fake_git(tmp, body),
            None => f2a_logging_git(tmp, &log),
        };
        let repos_dir = tmp.join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();

        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.git_bin = git_bin;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        // Armed and never notified: every guard this store hands out parks in
        // `release` right before the advisory unlock, which is inside the window a
        // client disconnect can hit.
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool.clone())
            .with_pre_unlock_gate(std::sync::Arc::new(tokio::sync::Notify::new()));
        state
            .db
            .upsert_mirror_repo(owner, name, &format!("/unused-{owner}-{name}"), None, false)
            .await
            .unwrap();
        let rec = state.db.get_repo(owner, name).await.unwrap().unwrap();
        state
            .db
            .set_visibility_rule(
                &rec.id,
                "/secret/**",
                crate::db::VisibilityMode::B,
                &["did:key:z6MkP2TailReaderAAAAAAAAAAAAAAAAAAAAAA".to_string()],
                &rec.owner_did,
            )
            .await
            .unwrap();
        state
            .repo_store
            .init(&rec.owner_did, &rec.name)
            .await
            .unwrap();
        (state, log)
    }

    const P2_PUSHER: &str = "did:key:z6MkP2TailPusherAAAAAAAAAAAAAAAAAAAAAA";

    fn p2_push(
        state: &AppState,
        owner: &str,
        name: &str,
    ) -> impl std::future::Future<Output = Result<axum::response::Response>> {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;
        git_receive_pack(
            State(state.clone()),
            Path((owner.to_string(), name.to_string())),
            Extension(crate::auth::AuthenticatedDid(P2_PUSHER.to_string())),
            None,
            crate::rate_limit::PeerAddr(Some("203.0.113.90:5000".parse::<SocketAddr>().unwrap())),
            axum::http::HeaderMap::new(),
            axum::body::Bytes::from_static(b"0000"),
        )
    }

    fn p2_logged(log: &std::path::Path, prefix: &str) -> bool {
        f2a_log(log).lines().any(|l| l.starts_with(prefix))
    }

    /// #174 (jatmn P2, RED-before/GREEN-after): a client disconnect DURING
    /// `guard.release()` must not take the replication tail with it. On a
    /// successful push `release` awaits the Tigris upload and then the advisory
    /// unlock, both cancellation points, while the pack has already landed on disk.
    /// Spawning the tail below `release` means a disconnect in that window drops
    /// this push's pins, recovery copy and announce: the F2 dropped-tail class, one
    /// step earlier in the handler.
    ///
    /// Load-bearing: with the spawn below `release` the walk's `for-each-ref` never
    /// appears after the disconnect (RED). With it above, gated on
    /// `receive_result.is_ok()`, it does (GREEN).
    #[cfg(unix)]
    #[sqlx::test]
    async fn receive_pack_tail_survives_a_disconnect_during_release(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let (state, log) = p2_parked_release_state(pool, tmp.path(), "z6p2tail", "t1", None).await;

        let mut fut = Box::pin(p2_push(&state, "z6p2tail", "t1"));

        // Drive until receive-pack has run. Nothing between it and `release` awaits,
        // so a future that stops completing after that point is parked on the gate.
        let mut ran = false;
        for _ in 0..1000 {
            let step = tokio::time::timeout(std::time::Duration::from_millis(10), &mut fut).await;
            assert!(
                step.is_err(),
                "the handler must park inside release, not return"
            );
            if p2_logged(&log, "receive-pack") {
                ran = true;
                break;
            }
        }
        assert!(ran, "the push must reach receive-pack");
        // Settle into the parked state. Whether the tail's walk has already started
        // by now is immaterial: pre-fix no tail is ever spawned, because `release`
        // never returns, so the marker below can only come from a spawn above it.
        for _ in 0..5 {
            let _ = tokio::time::timeout(std::time::Duration::from_millis(10), &mut fut).await;
        }

        // The disconnect: drop the handler future while `release` is still awaiting.
        drop(fut);

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !p2_logged(&log, "for-each-ref") {
            assert!(
                std::time::Instant::now() < deadline,
                "RED: the pack landed but its replication tail never ran. A disconnect \
                 during guard.release() took the tail with the handler future — spawn it \
                 above release, gated on receive_result.is_ok()"
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }

        // Not asserted here: that the same disconnect leaves the session advisory
        // lock free. A handler-level "the next acquire_write succeeds" probe does not
        // discriminate. It still passes with the `Drop` backstop disabled, because the
        // guard's `PoolConnection` goes back to the pool when this future is dropped
        // and `#[sqlx::test]` builds the pool with `idle_timeout(1s)`, so the session
        // ends on its own a beat later and postgres frees the lock with no help from
        // the code under test. Measured with the backstop disabled: held at the drop,
        // free ~2s later, observed from a session outside the pool. `acquire_write`
        // retries for far longer than that, so it waits the release out and reports
        // success either way. `write_guard_release_cancelled_mid_unlock_frees_the_lock`
        // is the real proof: it probes from a connection held OUT of the pool, 400ms
        // after the drop, which is inside that window rather than past it.
    }

    /// The must-not direction of the same reorder. Moving the spawn above
    /// `release` moves it above the `?` that used to gate it, so the success check
    /// has to be explicit: a FAILED receive-pack must still spawn no tail, or a
    /// pusher who aborts a pack mid-transfer gets a half-applied repo pinned and
    /// announced on demand.
    #[cfg(unix)]
    #[sqlx::test]
    async fn receive_pack_failure_spawns_no_tail_even_when_the_client_disconnects(
        pool: sqlx::PgPool,
    ) {
        // receive-pack fails; everything else the handler or a tail might run is
        // logged, so any walk child would show up.
        let tmp = tempfile::TempDir::new().unwrap();
        let log = tmp.path().join("git.log");
        let body = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"{}\"\n\
             case \"$1\" in receive-pack) cat >/dev/null 2>/dev/null; exit 1 ;; esac\n\
             exec git \"$@\"\n",
            log.display()
        );
        let (state, log) =
            p2_parked_release_state(pool, tmp.path(), "z6p2fail", "t1", Some(&body)).await;

        let mut fut = Box::pin(p2_push(&state, "z6p2fail", "t1"));
        let mut ran = false;
        for _ in 0..1000 {
            let step = tokio::time::timeout(std::time::Duration::from_millis(10), &mut fut).await;
            if p2_logged(&log, "receive-pack") {
                ran = true;
                // A failed push still parks in `release` (the lock is freed on
                // failure too); drop it there, the same disconnect as above.
                assert!(
                    step.is_err(),
                    "the failed push must still park inside release"
                );
                break;
            }
        }
        assert!(ran, "the push must reach receive-pack");
        for _ in 0..5 {
            let _ = tokio::time::timeout(std::time::Duration::from_millis(10), &mut fut).await;
        }
        drop(fut);

        tokio::time::sleep(std::time::Duration::from_millis(750)).await;
        assert!(
            !p2_logged(&log, "for-each-ref"),
            "a failed receive-pack must spawn no replication tail: pinning and \
             announcing a half-applied repo is exactly what release(false) refuses \
             to upload"
        );
    }

    /// Scenario 5 (trap 3, fail-closed). On a repo whose withheld walk is failing, a
    /// coalesced push must not publish. Before the gate moved, every push on such a
    /// repo got `announce = false` from its own walk; a coalesced push has no walk, so
    /// the announce decision now comes from the Pinata worker's recomputation, which
    /// fails closed the same way. Asserted on the broadcast channel: nothing is sent.
    #[cfg(unix)]
    #[sqlx::test]
    async fn f2a_coalesced_push_on_a_failing_walk_does_not_publish(pool: sqlx::PgPool) {
        let repo = tempfile::TempDir::new().unwrap();
        let bin = tempfile::TempDir::new().unwrap();
        u5_init_repo(repo.path());
        let c1 = u5_commit_file(repo.path(), "a.txt", "one\n");
        let c2 = u5_commit_file(repo.path(), "secret/s.txt", "two\n");
        let log = bin.path().join("git.log");
        // Every withheld walk fails: the repo cannot be vetted, so it must neither
        // replicate nor announce.
        let git_bin = write_fake_git(
            bin.path(),
            &format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$*\" >> \"{log}\"\n\
                 case \"$*\" in 'rev-list --all'*) exit 1 ;; esac\n\
                 exec git \"$@\"\n",
                log = log.display(),
            ),
        );
        let (mut state, rec) = f2a_state(pool, &git_bin, "z6f2aclosed", "x1", true).await;
        let (_server, _cid) = f2a_pinata(&mut state).await;
        let mut updates = state.ref_update_tx.subscribe();

        let _inflight = match state.encrypt_inflight.try_begin(
            &crate::state::repo_identity_key(&rec.owner_did, &rec.name),
            Vec::new(),
        ) {
            crate::state::BeginOutcome::Admitted(g) => g,
            crate::state::BeginOutcome::Coalesced => panic!("the first begin must admit"),
        };

        post_receive_replication_tail(
            state.clone(),
            rec.clone(),
            vec![RefUpdate {
                old_sha: c1.clone(),
                new_sha: c2.clone(),
                ref_name: "refs/heads/main".to_string(),
            }],
            repo.path().to_path_buf(),
            F2A_PUSHER.to_string(),
        )
        .await;

        // The worker has reached its recomputation (and failed it) once the walk's
        // commit enumeration shows up in the log; give the rest of the task a settle.
        f2a_wait_for(
            || {
                f2a_log(&log)
                    .lines()
                    .any(|l| l.starts_with("rev-list --all"))
            },
            "the Pinata worker's fail-closed recomputation",
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        assert!(
            matches!(
                updates.try_recv(),
                Err(tokio::sync::broadcast::error::TryRecvError::Empty)
            ),
            "a push whose replication could not be vetted must not broadcast"
        );
        assert!(
            state
                .db
                .list_branch_cids(&f2a_slug(&rec))
                .await
                .unwrap()
                .is_empty(),
            "and it must pin nothing, so it maps no CID"
        );
    }

    /// Scenario 6. A repo the anonymous public cannot read at root takes no key, runs
    /// no walk, and spawns no git at all: the cheap predicate answers before anything
    /// is acquired, exactly as `replication_withheld_set`'s own early return did.
    #[cfg(unix)]
    #[sqlx::test]
    async fn f2a_private_repo_takes_no_key_and_runs_no_git(pool: sqlx::PgPool) {
        let repo = tempfile::TempDir::new().unwrap();
        let bin = tempfile::TempDir::new().unwrap();
        u5_init_repo(repo.path());
        let c1 = u5_commit_file(repo.path(), "a.txt", "one\n");
        let log = bin.path().join("git.log");
        let git_bin = f2a_logging_git(bin.path(), &log);
        let (state, mut rec) = f2a_state(pool, &git_bin, "z6f2apriv", "v1", false).await;
        rec.is_public = false;

        post_receive_replication_tail(
            state.clone(),
            rec.clone(),
            f2a_update("refs/heads/main", &c1),
            repo.path().to_path_buf(),
            F2A_PUSHER.to_string(),
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        assert!(
            state.encrypt_inflight.is_empty(),
            "a repo that replicates nothing must not take the coalescing key"
        );
        assert_eq!(
            f2a_log(&log),
            "",
            "and it must spawn no git: no walk, no candidate scan, no re-derivation"
        );
    }

    /// Scenario 7. The first push is unaffected: it is admitted, it runs the walk, and
    /// it still does the full per-push work (pin, mapping, announce).
    #[cfg(unix)]
    #[sqlx::test]
    async fn f2a_first_push_is_admitted_and_does_the_full_work(pool: sqlx::PgPool) {
        let repo = tempfile::TempDir::new().unwrap();
        let bin = tempfile::TempDir::new().unwrap();
        u5_init_repo(repo.path());
        let c1 = u5_commit_file(repo.path(), "a.txt", "one\n");
        let c2 = u5_commit_file(repo.path(), "secret/s.txt", "two\n");
        let log = bin.path().join("git.log");
        let git_bin = f2a_logging_git(bin.path(), &log);
        let (mut state, rec) = f2a_state(pool, &git_bin, "z6f2afirst", "f1", true).await;
        let (_server, cid) = f2a_pinata(&mut state).await;
        let mut updates = state.ref_update_tx.subscribe();

        post_receive_replication_tail(
            state.clone(),
            rec.clone(),
            vec![RefUpdate {
                old_sha: c1.clone(),
                new_sha: c2.clone(),
                ref_name: "refs/heads/main".to_string(),
            }],
            repo.path().to_path_buf(),
            F2A_PUSHER.to_string(),
        )
        .await;

        assert!(
            f2a_walks(&log) >= 1,
            "the admitted push runs the withheld walk itself; log:\n{}",
            f2a_log(&log)
        );
        let slug = f2a_slug(&rec);
        let mapped = f2a_wait_for_branch_cid(
            &state.db,
            &slug,
            "the admitted push's branch to CID mapping",
        )
        .await;
        assert_eq!(mapped[0].sha, c2);
        assert_eq!(mapped[0].cid, cid);
        let broadcast = updates
            .try_recv()
            .expect("the admitted push fires its announce");
        assert_eq!(broadcast.new_sha, c2);
    }

    // ---- #174 F2b: a failed OWN walk does not buy a pin permit and a second walk ----

    /// Withheld-walk commit-enumeration attempts so far. Each `replication_withheld_set`
    /// runs exactly one `rev-list --all`, so this counts the walks that were attempted
    /// (the `ls-tree` counter above cannot: a walk whose enumeration fails never gets
    /// to `ls-tree`).
    fn f2b_walk_attempts(log: &std::path::Path) -> usize {
        f2a_log(log)
            .lines()
            .filter(|l| l.starts_with("rev-list --all"))
            .count()
    }

    /// A NON-coalesced push whose own withheld walk failed must not take a global pin
    /// permit and must not re-run the same failing walk in the Pinata worker.
    ///
    /// The F2a change moved the Pinata gate from `withheld.is_some()` to the rules-only
    /// `announce_at_root`, which a coalesced push genuinely needs (it has no walk of its
    /// own). But it also let an ADMITTED push whose walk failed acquire `pin_semaphore`
    /// and re-derive `replication_withheld_set`, which fails the same way. With
    /// `max_concurrent_pin_tasks` defaulting to 8 and the pin pool DEFERRING rather than
    /// shedding, eight such pushes stall pins node-wide.
    ///
    /// Asserted on observable work, twice over, with the pin pool's only permit held for
    /// the whole first phase:
    ///  * the walk attempts while the permit is held. Two: the tail's own (which fails)
    ///    and the recovery task's recipients walk, which must NOT park on the pin pool
    ///    for its empty object list. The Pinata worker's is the third and must not exist.
    ///  * the walk attempts after the permit is released. Still two: nothing was left
    ///    waiting on the pin pool, which is the permit assertion.
    ///
    /// Load-bearing both ways. With the gate back on plain `announce_at_root` the Pinata
    /// worker parks on the held permit and then walks once it is freed (phase 2 sees 3).
    /// Without the empty-list guard on `pin_new_objects_gated` the recovery task parks
    /// too, so phase 1 sees 1.
    #[cfg(unix)]
    #[sqlx::test]
    async fn f2b_failed_own_walk_takes_no_pin_permit_and_runs_no_second_walk(pool: sqlx::PgPool) {
        let repo = tempfile::TempDir::new().unwrap();
        let bin = tempfile::TempDir::new().unwrap();
        u5_init_repo(repo.path());
        let c1 = u5_commit_file(repo.path(), "a.txt", "one\n");
        let c2 = u5_commit_file(repo.path(), "secret/s.txt", "two\n");
        let log = bin.path().join("git.log");
        // Every withheld walk fails, so this push can never be vetted.
        let git_bin = write_fake_git(
            bin.path(),
            &format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$*\" >> \"{log}\"\n\
                 case \"$*\" in 'rev-list --all'*) exit 1 ;; esac\n\
                 exec git \"$@\"\n",
                log = log.display(),
            ),
        );
        let (mut state, rec) = f2a_state(pool, &git_bin, "z6f2bfail", "w1", true).await;
        let (_server, _cid) = f2a_pinata(&mut state).await;
        // One pin permit, held: anything that reaches a pin-admission acquire parks
        // instead of running, which is what makes "took no permit" observable.
        state.pin_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let held = state.pin_semaphore.clone().acquire_owned().await.unwrap();

        // Nothing pre-takes the coalescing key, so this push is ADMITTED and runs its
        // own walk.
        post_receive_replication_tail(
            state.clone(),
            rec.clone(),
            vec![RefUpdate {
                old_sha: c1.clone(),
                new_sha: c2.clone(),
                ref_name: "refs/heads/main".to_string(),
            }],
            repo.path().to_path_buf(),
            F2A_PUSHER.to_string(),
        )
        .await;

        f2a_wait_for(
            || f2b_walk_attempts(&log) >= 2,
            "the tail's own walk and the recovery task's recipients walk",
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(
            f2b_walk_attempts(&log),
            2,
            "a failed own walk must not buy a third walk in the Pinata worker; log:\n{}",
            f2a_log(&log)
        );

        // Release pin admission. A task that had parked on it now wakes and walks;
        // nothing should have been parked.
        drop(held);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert_eq!(
            f2b_walk_attempts(&log),
            2,
            "nothing may be left waiting on the pin permit for a push that pins \
             nothing; log:\n{}",
            f2a_log(&log)
        );
        assert!(
            state
                .db
                .list_branch_cids(&f2a_slug(&rec))
                .await
                .unwrap()
                .is_empty(),
            "and the unvetted push still maps no CID"
        );
    }
}
