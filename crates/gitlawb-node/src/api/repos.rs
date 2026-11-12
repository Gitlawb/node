use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Json;
use bytes::Bytes;
use futures::{stream, StreamExt};
use std::collections::HashSet;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use crate::auth::{caller_authorized_to_push, AuthenticatedDid};
use crate::db::RepoRecord;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::git::{smart_http, store, visibility_pack};
use crate::state::AppState;
use crate::visibility::{visibility_check, withheld_globs, Decision};

/// The git all-zeros object id — the create/delete sentinel in a ref update.
const ZERO_SHA: &str = "0000000000000000000000000000000000000000";

const FEDERATED_PEER_CONCURRENCY: usize = 4;
const FEDERATED_PEER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const FEDERATED_AGGREGATE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
pub(crate) const MAX_FEDERATED_PEERS: usize = 200;
const MAX_FEDERATED_PEER_BYTES: usize = 512 * 1024;
const MAX_FEDERATED_PEER_REPOS: usize = 200;
const MAX_FEDERATED_REPOS: usize = 1_000;
const MAX_FEDERATED_REPO_JSON_BYTES: usize = 2 * 1024 * 1024;
// The aggregate byte budget counts serialized repo values and separators. Keep
// a fixed reserve for the response object's keys, counters, and closing bytes.
const FEDERATED_RESPONSE_OVERHEAD_BYTES: usize = 256;

/// The set of blob and withheld-subtree tree OIDs withheld from **anonymous**
/// replication for a repo, or `None` when the repo must not replicate at all
/// (private / mode A / undetermined, fail closed). This is the anonymous
/// replication gate: `caller` is hard-coded to `None` and there is intentionally
/// no caller parameter, which distinguishes it from the per-caller read-serve
/// projection in `git_upload_pack` (which passes the real caller). Both the push
/// pin path and the reconciliation sweep call this helper so the two cannot drift
/// on what is withheld. `rules` is the already-fetched visibility-rule snapshot
/// (callers fetch once and may reuse it, e.g. for encrypt-then-pin).
///
/// Returns `(announce, withheld)`: `announce` is whether the repo may be
/// announced/replicated to the anonymous public at all (also gates gossip and
/// Arweave anchoring downstream), and `withheld` is the anonymous withheld object
/// set (blobs and withheld-subtree trees) when announceable (`None` when not
/// announceable). A failed/panicked withheld walk fails closed on both axes:
/// `announce` is forced false and `withheld` is `None`, so an unvetted push
/// neither replicates objects nor announces. Returning both keeps the gate's
/// announce decision a single source rather than recomputing it at each call site.
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
        // root-only-rules cases), so skip the full withheld_object_oids walk and
        // withhold nothing. The predicate's safety-invariant test guards that
        // this short-circuit matches what the walk would have returned.
        Some(rules) if !visibility_pack::has_path_scoped_rule(&rules) => {
            Some(std::collections::HashSet::new())
        }
        // withheld_object_oids walks every ref with blocking `git ls-tree`; keep
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
                crate::git::visibility_pack::withheld_object_oids_bounded(
                    &disk_path, &git_bin, timeout, &rules, is_public, &owner_did, None,
                )
            })
            .await
            .map_err(|e| {
                tracing::warn!(err = %e, "withheld_object_oids task panicked; skipping replication")
            })
            .ok()
            .and_then(|r| {
                r.map_err(|e| {
                    tracing::warn!(err = %e, "withheld_object_oids failed; skipping replication")
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

/// The replicable object set for a full-scan pin fallback, failing closed (#99, #172).
/// The full-scan candidate set includes dangling objects the reachable-only
/// withheld set never classified, so compute the reachable visibility-allowed
/// blob set, the reachable visibility-allowed tree set, and the all-blob plus
/// all-tree universes off the async worker and keep only commits/tags plus
/// allowed blobs plus allowed trees. Any error in any walk (or a task panic)
/// pins nothing this push, mirroring the degraded-path shape of
/// `replication_withheld_set`.
///
/// Always walks (there is no no-git arm), so the whole blocking scan runs under
/// one `git_encrypt_semaphore` admission permit (#174 F4): see
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
        // One whole-scan deadline shared across every phase (#174 F4). A fresh
        // `Instant::now() + timeout` for a later phase let a large-but-successful
        // earlier phase plus a full later phase hold the scan permit ~Nx the
        // configured budget. Sharing the deadline caps total occupancy at ~1x:
        // each phase runs against the remaining budget, and if an earlier phase
        // consumes the budget a later one gets what is left and fails closed
        // (pins nothing) rather than over-holding, the safe direction. The cost
        // is honest: a genuinely large repo whose first phase nears the budget
        // under-pins this push rather than the previous silent ~2x hold; size the
        // budget so the blob walk, tree walk, and typed enumeration normally fit.
        let deadline = std::time::Instant::now() + timeout;
        let allowed = crate::git::visibility_pack::replicable_blob_set_bounded(
            &disk_path,
            &git_bin,
            deadline.saturating_duration_since(std::time::Instant::now()),
            &rules,
            is_public,
            &owner_did,
        )?;
        let allowed_trees = crate::git::visibility_pack::replicable_tree_set_bounded(
            &disk_path,
            &git_bin,
            deadline.saturating_duration_since(std::time::Instant::now()),
            &rules,
            is_public,
            &owner_did,
        )?;
        let (all_blobs, all_trees) =
            crate::git::push_delta::all_blob_and_tree_oids(&disk_path, &git_bin, deadline)?;
        Ok(crate::git::visibility_pack::replicable_objects_fail_closed(
            candidates,
            &allowed,
            &all_blobs,
            &allowed_trees,
            &all_trees,
        ))
    })
    .await
    .map_err(|e| {
        tracing::warn!(err = %e, "fail-closed object walk task panicked; pinning nothing this push")
    })
    .ok()
    .and_then(|r| {
        r.map_err(|e| {
            tracing::warn!(err = %e, "fail-closed object walk failed; pinning nothing this push")
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

/// Validate a repository name at the create/fork write paths. The charset is
/// restricted, and the length is bounded so every cursor the server emits
/// parses back: `repo_cursor` embeds the name in a base64(JSON) cursor that
/// `parse_repo_cursor` rejects over 4096 bytes (#465 4th round).
///
/// This is the API-side validator, and it deliberately differs from the
/// stricter disk-side `validate_repo_name` in `git/repo_store.rs`: this one
/// admits names the store rejects (empty, leading `-`, non-ASCII
/// alphanumeric) and rejects `.`, which the store allows. The divergence
/// predates this bound (#412 owns the fork half), so a store-rejected name
/// still fails later at `repo_store.init` after the proof is spent. Do not
/// "fix" the divergence here; the length bound below is the one that keeps
/// emitted cursors parseable, and it is shared via `MAX_REPO_NAME_LEN` so the
/// two validators cannot drift apart on length.
fn validate_repo_name(name: &str) -> Result<()> {
    // Sanitize name: alphanumeric, hyphens, underscores only
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AppError::BadRequest(
            "repo name must contain only alphanumeric characters, hyphens, and underscores".into(),
        ));
    }
    // Byte length, not char count: the cursor budget is measured in bytes.
    if name.len() > crate::db::MAX_REPO_NAME_LEN {
        return Err(AppError::BadRequest(format!(
            "repo name must be at most {} bytes",
            crate::db::MAX_REPO_NAME_LEN
        )));
    }
    Ok(())
}

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

    validate_repo_name(&req.name)?;

    // default_branch is caller-supplied and becomes a PR's target_branch when the
    // PR omits one, which is interpolated into a git revision argument. Validate
    // it as a ref so it cannot begin with '-' and inject a git option downstream.
    crate::api::validate_git_ref_with_git(&state.git_bin, &req.default_branch)
        .map_err(crate::api::map_git_ref_validation_error)?;

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
    // Strip at most one ".git" suffix — shared with the UCAN push matcher
    // (`canonical_repo_name`), so a delegation and a remote URL name a
    // repository the same way. At-most-once matters: a repo literally named
    // "foo.git" is addressed as "foo.git.git".
    let name = gitlawb_core::ucan::push::canonical_repo_name(repo);
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

    // For receive-pack (push), read the latest from Tigris so the client sees
    // the same refs that acquire_write() will operate on. A NON-MUTATING
    // snapshot, not `acquire_fresh`: the advertisement runs WITHOUT the advisory
    // lock, and acquire_fresh downloads and publishes into the live repo path
    // (removing the existing directory and renaming the extract into place), so
    // an unlocked advertisement could delete or swap the directory under a
    // concurrent guarded write. In the worst ordering the guarded write has
    // finished but `release` has not compressed the tree, and the guarded
    // release uploads the replaced old tree with its still-valid ETag and
    // reports success, losing the accepted write. The snapshot unpacks into a
    // throwaway temp dir that is served from and then removed.
    //
    // Bound the acquire under `git_acquire_timeout_secs`: the concurrency permit is
    // already held above, and `git_service_timeout_secs` only starts once git spawns,
    // so an un-deadlined acquire (a hung Tigris HEAD/GET here) pins the permit until
    // the pool drains (#174 P1-2). On expiry the handler-local `_permit`/`_caller_permit`
    // drop on the early return (the AdmissionGuard is not built until after acquire),
    // so the shed frees the slot; return a bounded 503.
    let acquire_deadline = std::time::Duration::from_secs(state.config.git_acquire_timeout_secs);
    let acquire_fut = async {
        let res = if service == "git-receive-pack" {
            state
                .repo_store
                .read_snapshot(&record.owner_did, &record.name)
                .await
                .map(|s| (s.path().to_path_buf(), Some(s)))
        } else {
            state
                .repo_store
                .acquire(&record.owner_did, &record.name)
                .await
                .map(|p| (p, None))
        };
        res.map_err(|e| {
            if is_expected_transient_acquire_failure(&e) {
                tracing::warn!(repo = %name, service = %service, err = %e, "repo acquire failed");
            } else {
                tracing::error!(repo = %name, service = %service, err = %e, "repo acquire failed");
            }
            // This closure bypasses the `From<anyhow::Error>` chain, so a typed
            // refusal would otherwise be stringified into a 500 `git_error`. Route
            // just that one case through `From` and leave every other failure on
            // exactly today's behavior: this call site also serves the read path via
            // `acquire`, whose error vocabulary is out of scope here.
            if e.is::<crate::git::repo_store::RepoUnavailable>() {
                AppError::from(e)
            } else {
                AppError::Git(e.to_string())
            }
        })
    };
    // The snapshot (if any) is kept alive for the whole handler scope below: its
    // Drop removes the temp dir it was unpacked into, so dropping it here would
    // delete the directory `info_refs` is about to serve from.
    let (disk_path, _snapshot_keepalive) = tokio::time::timeout(acquire_deadline, acquire_fut)
        .await
        .map_err(|_elapsed| {
            tracing::warn!(repo = %name, service = %service, "repo acquire timed out; shedding with 503");
            AppError::Overloaded("git service acquisition timed out, retry shortly".into())
        })??;

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

/// Test-only entry point: build an [`EncryptTaskCtx`] from a test `AppState` (with
/// an overridable `ipfs_api` for a mock Kubo server and an explicit `disk_path` for
/// the fixture repo) and run the real drain task. Keeps `EncryptTaskCtx` and
/// `run_encrypt_pin_task` private to this module.
///
/// `owner_did` and `repo_name` must name the real seeded row: the drain re-fetches
/// the record by owner/name every lap, so a blank name resolves `Gone` and every
/// lap would pin nothing.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_encrypt_pin_task_for_test(
    state: &AppState,
    guard: crate::state::EncryptInflightGuard,
    disk_path: std::path::PathBuf,
    repo_id: String,
    owner_did: String,
    repo_name: String,
    ipfs_api: String,
    snapshot_objects: Vec<String>,
    snapshot_rules: Option<Vec<crate::db::VisibilityRule>>,
    snapshot_is_public: bool,
) {
    let ctx = EncryptTaskCtx {
        ipfs_api,
        repo_path: disk_path,
        db: state.db.clone(),
        repo_id,
        owner_did,
        repo_name,
        irys_url: String::new(),
        http_client: std::sync::Arc::clone(&state.http_client),
        node_did: state.node_did.to_string(),
        node_keypair: std::sync::Arc::clone(&state.node_keypair),
        git_bin: state.git_bin.clone(),
        git_timeout: std::time::Duration::from_secs(state.config.git_service_timeout_secs),
        encrypt_sem: state.git_encrypt_semaphore.clone(),
        pin_sem: state.pin_semaphore.clone(),
    };
    run_encrypt_pin_task(
        ctx,
        guard,
        snapshot_objects,
        snapshot_rules,
        snapshot_is_public,
    )
    .await;
}

/// Test-only fault-injection seam for the drain re-reads in
/// `resolve_drain_object_list`. The behavior worth testing lives on the `Err` arm of
/// the two re-reads, which a real Postgres pool will not produce on demand, so the two
/// reads go through the wrappers below and consult this table first. Keyed by `repo_id`
/// (a fresh uuid per test) so tests running in parallel in one process cannot see each
/// other's injections, and it also records the ATTEMPT counts the retry-bound
/// assertions key on.
#[cfg(test)]
pub(crate) mod drain_faults {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    #[derive(Default, Clone, Copy, Debug)]
    pub(crate) struct Counters {
        pub(crate) repo_read_failures_left: usize,
        pub(crate) rules_read_failures_left: usize,
        pub(crate) repo_read_attempts: usize,
        pub(crate) rules_read_attempts: usize,
        pub(crate) reread_exhausted: bool,
        pub(crate) outcome_commit_failures_left: usize,
        pub(crate) outcome_commit_attempts: usize,
    }

    fn table() -> &'static Mutex<HashMap<String, Counters>> {
        static TABLE: OnceLock<Mutex<HashMap<String, Counters>>> = OnceLock::new();
        TABLE.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// Make the next `repo_read_failures` repo re-reads and the next
    /// `rules_read_failures` rule re-reads for `repo_id` return `Err`, then succeed.
    pub(crate) fn inject(repo_id: &str, repo_read_failures: usize, rules_read_failures: usize) {
        table().lock().unwrap().insert(
            repo_id.to_string(),
            Counters {
                repo_read_failures_left: repo_read_failures,
                rules_read_failures_left: rules_read_failures,
                ..Default::default()
            },
        );
    }

    /// Observed attempt counts (and remaining injections) for `repo_id`.
    pub(crate) fn counters(repo_id: &str) -> Counters {
        table()
            .lock()
            .unwrap()
            .get(repo_id)
            .copied()
            .unwrap_or_default()
    }

    /// Whether the drain re-read loop exhausted its retry budget for `repo_id`.
    pub(crate) fn reread_exhausted(repo_id: &str) -> bool {
        table()
            .lock()
            .unwrap()
            .get(repo_id)
            .map(|c| c.reread_exhausted)
            .unwrap_or(false)
    }

    pub(crate) fn mark_reread_exhausted(repo_id: &str) {
        table()
            .lock()
            .unwrap()
            .entry(repo_id.to_string())
            .or_default()
            .reread_exhausted = true;
    }

    /// Production-path hook: count one repo re-read attempt, return whether it must fail.
    pub(crate) fn take_repo_read(repo_id: &str) -> bool {
        let mut map = table().lock().unwrap();
        let c = map.entry(repo_id.to_string()).or_default();
        c.repo_read_attempts += 1;
        if c.repo_read_failures_left > 0 {
            c.repo_read_failures_left -= 1;
            return true;
        }
        false
    }

    /// Production-path hook: count one rules re-read attempt, return whether it must fail.
    pub(crate) fn take_rules_read(repo_id: &str) -> bool {
        let mut map = table().lock().unwrap();
        let c = map.entry(repo_id.to_string()).or_default();
        c.rules_read_attempts += 1;
        if c.rules_read_failures_left > 0 {
            c.rules_read_failures_left -= 1;
            return true;
        }
        false
    }

    /// Test path: arm `n` injected failures for the request-level outcome
    /// commit (`commit_request_outcomes_atomically`) on `repo_id`.
    pub(crate) fn arm_outcome_commit(repo_id: &str, n: usize) {
        table()
            .lock()
            .unwrap()
            .entry(repo_id.to_string())
            .or_default()
            .outcome_commit_failures_left = n;
    }

    /// Production-path hook: count one outcome-commit attempt, return whether
    /// it must fail.
    pub(crate) fn take_outcome_commit(repo_id: &str) -> bool {
        let mut map = table().lock().unwrap();
        let c = map.entry(repo_id.to_string()).or_default();
        c.outcome_commit_attempts += 1;
        if c.outcome_commit_failures_left > 0 {
            c.outcome_commit_failures_left -= 1;
            return true;
        }
        false
    }
}

/// The drain's repo re-read, behind the test-only fault seam above.
async fn drain_get_repo(ctx: &EncryptTaskCtx) -> anyhow::Result<Option<RepoRecord>> {
    #[cfg(test)]
    if drain_faults::take_repo_read(&ctx.repo_id) {
        return Err(anyhow::anyhow!("injected repo re-read failure"));
    }
    ctx.db.get_repo(&ctx.owner_did, &ctx.repo_name).await
}

/// The drain's visibility-rule re-read, behind the test-only fault seam above.
async fn drain_list_rules(
    ctx: &EncryptTaskCtx,
    record_id: &str,
) -> anyhow::Result<Vec<crate::db::VisibilityRule>> {
    #[cfg(test)]
    if drain_faults::take_rules_read(&ctx.repo_id) {
        return Err(anyhow::anyhow!("injected visibility-rule re-read failure"));
    }
    ctx.db.list_visibility_rules(record_id).await
}

/// The request-level outcome commit, behind the test-only fault seam above.
/// A forced failure exercises the carve-out where `outcome_commit_ok=false`
/// still returns 200 and defers effects to startup reconcile.
#[allow(clippy::too_many_arguments)]
async fn commit_request_outcomes_seamed(
    state: &AppState,
    _record_id: &str,
    request_id: &str,
    ok_names: &[&str],
    ng_names: &[&str],
    uncertain_names: &[&str],
    unpack_failed: bool,
    exit_ok: bool,
    parsed_json_opt: Option<&serde_json::Value>,
    accepted_ordinal: Option<i32>,
    rejected_reason: Option<&str>,
    terminal_no_effects: bool,
) -> anyhow::Result<()> {
    #[cfg(test)]
    if drain_faults::take_outcome_commit(_record_id) {
        return Err(anyhow::anyhow!("injected outcome-commit failure"));
    }
    state
        .db
        .commit_request_outcomes_atomically(
            request_id,
            ok_names,
            ng_names,
            uncertain_names,
            unpack_failed,
            exit_ok,
            parsed_json_opt,
            accepted_ordinal,
            rejected_reason,
            terminal_no_effects,
        )
        .await
}

/// Attempts allowed for the drain re-read before the lap gives up. The coalesced
/// push's work is already out of the pending slot (`finish_or_take_pending` took it
/// in the same critical section that kept the key), and there is no reconciliation
/// sweep to re-derive it: a transient read error must be RETRIED here or that push's
/// pin/encrypt pass is gone. The bound keeps a sustained outage from spinning
/// forever; on exhaustion the work is still lost (the pre-existing residual), but
/// the give-up is logged at ERROR so it is observable instead of silent.
const DRAIN_REREAD_MAX_ATTEMPTS: usize = 3;

/// Backoff before the next re-read attempt. Doubles per attempt.
const DRAIN_REREAD_BACKOFF: std::time::Duration = std::time::Duration::from_millis(50);

/// The outcome of the drain's fresh state re-read, keeping the three cases distinct
/// that a single `Err => None` collapses into one: a usable refresh, a repo that
/// genuinely no longer exists (terminal, and NOT a retry), and a transient read
/// failure (retryable).
enum DrainRefresh {
    State {
        /// Boxed only to keep the enum small: `RepoRecord` dwarfs the other two
        /// variants, which carry nothing (clippy::large_enum_variant).
        record: Box<RepoRecord>,
        rules: Vec<crate::db::VisibilityRule>,
    },
    Gone,
    Failed,
}

/// Re-read repo state for a drain lap, retrying transient read errors.
///
/// Both reads are retryable and neither may be read as an absence: an `Err` from the
/// repo row is not "the repo is gone", and an `Err` from the rule list is not "this
/// repo has no rules" (`.ok()` made those indistinguishable, and a `None` rule set
/// makes `replication_withheld_set` return `None`, which skips the entire lap). Only
/// `Ok(None)` on the repo row is a terminal absence, and it consumes no retry budget.
///
/// The whole `RepoRecord` comes back, not just its rules and flags: the caller writes
/// against `record.id` from this FRESH re-fetch, never `ctx.repo_id` frozen at spawn.
async fn drain_refresh_state(ctx: &EncryptTaskCtx) -> DrainRefresh {
    let mut backoff = DRAIN_REREAD_BACKOFF;
    for attempt in 1..=DRAIN_REREAD_MAX_ATTEMPTS {
        let record = match drain_get_repo(ctx).await {
            Ok(Some(rec)) => Box::new(rec),
            Ok(None) => return DrainRefresh::Gone,
            Err(e) => {
                tracing::warn!(
                    repo = %ctx.repo_id, err = %e, attempt,
                    "coalesced drain: repo re-read failed; retrying"
                );
                tokio::time::sleep(backoff).await;
                backoff *= 2;
                continue;
            }
        };
        // record.id, never the spawn-time ctx.repo_id: the record above is re-fetched
        // fresh by owner/name, and a delete+re-create between spawn and drain gives
        // the row a NEW id - rules read against the stale id come back empty and
        // would fail open for the new row.
        match drain_list_rules(ctx, &record.id).await {
            Ok(rules) => return DrainRefresh::State { record, rules },
            Err(e) => {
                tracing::warn!(
                    repo = %ctx.repo_id, err = %e, attempt,
                    "coalesced drain: visibility-rule re-read failed; retrying"
                );
                tokio::time::sleep(backoff).await;
                backoff *= 2;
            }
        }
    }
    tracing::error!(
        repo = %ctx.repo_id,
        attempts = DRAIN_REREAD_MAX_ATTEMPTS,
        "coalesced drain: re-read failed on every attempt; the coalesced push's \
         pin/encrypt pass is dropped (no reconciliation sweep re-derives it)"
    );
    #[cfg(test)]
    drain_faults::mark_reread_exhausted(&ctx.repo_id);
    DrainRefresh::Failed
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
    // Both re-reads are bounded-retried: a transient blip must not discard the
    // coalesced push's work (`finish_or_take_pending` already took it out of the
    // pending slot and no sweep re-derives it). The rules come back from the same
    // refresh, read against the FRESH record.id, never the spawn-time ctx.repo_id.
    let (record, rules_opt) = match drain_refresh_state(ctx).await {
        DrainRefresh::State { record, rules } => (*record, Some(rules)),
        DrainRefresh::Gone => {
            tracing::warn!(
                repo = %ctx.repo_id,
                "coalesced drain: repo record is gone; dropping the pending work"
            );
            return None;
        }
        DrainRefresh::Failed => {
            tracing::warn!(
                repo = %ctx.repo_id,
                "coalesced drain: repo re-fetch failed; pinning nothing (fail closed)"
            );
            return None;
        }
    };
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
// Nine because the merge of #173 and #174 landed both sets of arguments on one
// signature: #174's pin-admission permit plus #173's git seam and pin provenance.
// Each is a distinct value the pin loop needs and none is derivable from another, so
// a wrapper struct here would only rename the same nine fields.
//
// `batch_budget` is the ninth and is passed rather than read from the constant so the
// permit-release regression can drive a short budget. Hardcoding `PIN_BATCH_BUDGET`
// here made that test cost 120s of wall clock, and the only cheaper shapes were
// vacuous: a lock released before the budget returns at the same time whether or not
// the loop is bounded, which proves nothing. Production passes the constant.
#[allow(clippy::too_many_arguments)]
async fn pin_new_objects_gated(
    pin_sem: &Arc<tokio::sync::Semaphore>,
    ipfs_api: &str,
    repo_path: &std::path::Path,
    git_bin: &str,
    git_timeout: std::time::Duration,
    object_list: Vec<String>,
    db: &Arc<crate::db::Db>,
    repo_id: &str,
    batch_budget: std::time::Duration,
) -> crate::ipfs_pin::PinBatchOutcome {
    // Nothing to pin: answer before taking a permit (#174 F2b). The permit bounds how
    // many pin loops run concurrently, and an empty list does no pinning, so parking
    // here would spend a global pin slot on no work. The pool DEFERS rather
    // than sheds, so those calls stall pins for every other repo. Empty is the normal
    // shape for a push whose walk failed or that may replicate nothing.
    if object_list.is_empty() {
        return crate::ipfs_pin::PinBatchOutcome {
            confirmed: Vec::new(),
            last_attempted: None,
        };
    }
    let _permit = pin_sem
        .clone()
        .acquire_owned()
        .await
        .expect("pin_semaphore is never closed");
    crate::ipfs_pin::pin_new_objects(
        ipfs_api,
        repo_path,
        git_bin,
        git_timeout,
        object_list,
        db,
        repo_id,
        batch_budget,
        None,
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
        // The literal, not `ctx.git_bin`: that knob is the WALK binary, and tests point
        // it at a fake that answers `rev-list` and friends. Routing the pin path's
        // `cat-file` read through it would ask that fake to impersonate cat-file too.
        // Same choice, for the same reason, as `api/ipfs`'s bounded call sites. The
        // parameter stays so the seam is still drivable from a test.
        "git",
        ctx.git_timeout,
        object_list,
        &ctx.db,
        // The drain's repo id, never `ctx.repo_id` frozen at spawn (#174 U3): pin
        // provenance must name the row the reader will resolve against.
        repo_id,
        crate::ipfs_pin::PIN_BATCH_BUDGET,
    )
    .await;
    if !pinned.confirmed.is_empty() {
        tracing::info!(count = pinned.confirmed.len(), "pinned git objects to IPFS");
        for (sha, cid) in &pinned.confirmed {
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
                // The real git, not `ctx.git_bin`: tests point that at a fake
                // walk git, and the seal reads must run the real one.
                "git",
                crate::ipfs_pin::PIN_BATCH_BUDGET,
                &recipients,
                // Push path: recipients derived at admission under a write lease,
                // no sweep-style snapshot to fence (see PolicyFence's doc).
                None,
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

/// Map an `acquire_write` failure to the right `AppError`. An exhausted repo write-lock
/// POOL is a capacity signal, not a broken repo, so it sheds 503 + Retry-After the same
/// way the admission caps around it do; it used to fall into the generic git 500, which
/// tells the client nothing about retrying (#173 F1). Lock contention and a refused
/// under-lock refresh are transient and map to fixed-body 503s via [`RepoBusy`] and
/// [`RepoUnavailable`]; only genuine untyped git failures stay on the 500 path.
///
/// Shared with every `acquire_write` caller (`receive-pack`, `api/issues.rs`,
/// `api/pulls.rs`) so the write-acquisition contract cannot drift between routes.
pub(crate) fn acquire_write_app_error(err: &anyhow::Error, repo: &str) -> AppError {
    if err
        .downcast_ref::<crate::git::repo_store::LockPoolBusy>()
        .is_some()
    {
        tracing::warn!(repo = %repo, err = %err, "write-lock pool exhausted; shedding with 503");
        AppError::Overloaded("git write locks at capacity, retry shortly".into())
    } else if is_expected_transient_acquire_failure(err) {
        tracing::warn!(repo = %repo, err = %err, "acquire_write failed");
        if err
            .downcast_ref::<crate::git::repo_store::RepoBusy>()
            .is_some()
        {
            AppError::RepoBusy
        } else {
            AppError::RepoUnavailable
        }
    } else {
        tracing::error!(repo = %repo, err = %err, "acquire_write failed");
        AppError::Git(err.to_string())
    }
}

/// Map an error from a `smart_http` git service call to the right `AppError`:
/// [`smart_http::GitServiceTimeout`] to 504, a malformed client request to 400,
/// anything else to a 500 git error. Pure (no logging) so it is unit-testable;
/// callers add their own tracing.
/// Acquire failures that are ordinary and transient: lock contention
/// ([`RepoBusy`]) and an under-lock refresh that could not reach object storage
/// ([`RepoUnavailable`]). Both already log at their raise site and both map to a
/// retryable 503, so the handler layer logs them at warn rather than paging.
/// Best-effort, like the database startup classifier: anything this cannot
/// recognize counts as NOT transient and keeps its error-level log.
///
/// [`RepoBusy`]: crate::git::repo_store::RepoBusy
/// [`RepoUnavailable`]: crate::git::repo_store::RepoUnavailable
fn is_expected_transient_acquire_failure(err: &anyhow::Error) -> bool {
    err.downcast_ref::<crate::git::repo_store::RepoBusy>()
        .is_some()
        || err
            .downcast_ref::<crate::git::repo_store::RepoUnavailable>()
            .is_some()
}

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
        // One message for every refusal. It must not say whether a delegation was
        // presented, was expired, or named another repository: varying it would turn
        // the denial into an oracle for which capabilities exist. It only has to be
        // TRUE in all of those cases, which the previous owner-only wording no
        // longer was once a delegation could authorize a push.
        _ => Some(AppError::Forbidden(
            "push rejected — you must be the repo owner, or hold a valid \
             owner-issued git/push delegation for this repository \
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

/// Post-git disposition: one tested gate deciding replication/Tigris,
/// metrics/inline effects, and HTTP 200 after `git receive-pack` returns.
///
/// Policy 2 carve-out (documented in the PR body): `spawn_tail` and
/// `release_ok` follow in-memory report knowledge (`exit_ok &&
/// any_ref_ok`) even when the outcome commit failed, because F2
/// disconnect safety requires the tail before `release`, the tail is
/// read-only on disk, and announces carry `cert_id: None`. Durable
/// accounting (`run_effects`: push events, certs, webhooks) instead
/// waits for the outcome commit, else startup reconcile (Option B
/// attended-restart contract).
///
/// Storage/replication split for capability-free pushes: a zero
/// `report-status` with git exit ok may still have landed refs, and the
/// shared Tigris copy must stay fresh — otherwise the next write's
/// `acquire_write` download replaces the local repo with the stale
/// archive, erasing the acknowledged landing (and its marker) before
/// startup reconcile can prove it. So `release_ok` also covers exit-ok
/// pushes with no report (`report_absent`), while `spawn_tail` stays
/// proven-refs-only: uploading the post-push disk state is always safe,
/// announcing unproven refs is not. The deferred tail for late-proved
/// refs runs from the drain (see `tail_owed_after_proof`).
#[derive(Debug, PartialEq, Eq)]
struct PostGitDisposition {
    spawn_tail: bool,
    release_ok: bool,
    run_effects: bool,
}

fn post_git_disposition(
    exit_ok: bool,
    any_ref_ok: bool,
    outcome_commit_ok: bool,
    report_absent: bool,
) -> PostGitDisposition {
    let landed = exit_ok && any_ref_ok;
    PostGitDisposition {
        spawn_tail: landed,
        release_ok: exit_ok && (any_ref_ok || report_absent),
        run_effects: landed && outcome_commit_ok,
    }
}

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

    // The reader gate applies to the write path too, and the POST cannot lean
    // on info/refs having checked it: a caller can skip the advertisement and
    // hit this route directly. Without the check here a delegate (or any signed
    // caller with a valid signature) could write to a private repo it cannot
    // read, which is precisely the "delegates must also be readers" rule the
    // advertisement already enforces.
    let rules = state.db.list_visibility_rules(&record.id).await?;
    if visibility_check(
        &rules,
        record.is_public,
        &record.owner_did,
        Some(auth.0.as_str()),
        "/",
    ) == Decision::Deny
    {
        tracing::debug!(repo = %name, caller = %auth.0, "receive-pack denied by visibility");
        return Err(AppError::RepoNotFound(format!("{owner}/{name}")));
    }

    // Parse ref updates from pkt-line body before handing to git. The count
    // cap and duplicate-refusal live inside `parse_ref_updates`, so both fire
    // before any per-request materialization, gate, or durable write below.
    let ref_updates = parse_ref_updates(&body)?;
    tracing::debug!(
        ref_count = ref_updates.len(),
        "parsed ref updates from pack"
    );
    // ── Owner-only push enforcement (on by default; GITLAWB_ENFORCE_OWNER_PUSH) ──
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
    // Uses the same verified identity as the owner-push gate above, but a STRICTER
    // predicate: owner-only, deliberately not `caller_authorized_to_push`.
    //
    // A delegate can therefore clear the gate above and still be refused here. That
    // is the intended policy, not an oversight: a protected branch is the owner's
    // explicit marker that even routine writes should stop, so a `git/push`
    // delegation must not silently override it. Widening this to accept a
    // delegation would make every existing protection weaker the moment the owner
    // issues any capability.
    //
    // `delegated_push_is_still_refused_on_a_protected_branch` pins this.
    for update in &ref_updates {
        // Strip refs/heads/ prefix to get plain branch name
        let branch = update
            .ref_name
            .strip_prefix("refs/heads/")
            .unwrap_or(&update.ref_name);
        if !crate::api::did_matches(&auth.0, &record.owner_did) {
            // A non-owner (delegated pusher included) must fail closed when the
            // protection lookup errors: treating Err as unprotected lets a
            // protected branch be pushed through a database hiccup.
            match state.db.is_branch_protected(&record.id, branch).await {
                Ok(true) => {
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
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(
                        branch = %branch,
                        pusher = %auth.0,
                        err = %e,
                        "branch protection lookup failed; refusing non-owner push"
                    );
                    return Err(AppError::Internal(anyhow::anyhow!(
                        "failed to check branch protection: {e}"
                    )));
                }
            }
        }
    }

    // ── Internal-namespace push gate ────────────────────────────────
    // `refs/gitlawb/*` carries node-managed metadata (request markers as
    // blobs under `requests/`, issue JSON blobs under `issues/`). A pusher
    // must never write there: an attacker-controlled ref pointing at a blob
    // or tree is skipped by `rev-list --all` yet still served, bypassing
    // the fail-closed under-withhold check. Refuse before intent is
    // written so a denied push leaves no rows behind.
    if let Some(bad) = ref_updates
        .iter()
        .map(|u| u.ref_name.as_str())
        .find(|r| ref_is_internal_namespace(r))
    {
        tracing::warn!(
            repo = %name,
            ref_name = %bad,
            "refusing push into internal refs/gitlawb/ namespace"
        );
        return Err(AppError::Forbidden(
            "pushing to refs/gitlawb/* is not allowed".into(),
        ));
    }

    // #26 Split PR 1: durable intent for this push, written BEFORE the
    // per-repo lease, admission permits, and the receive_pack call. Holding
    // no lease and no admission permit across the DB transaction means a
    // stalled statement cannot exhaust the push admission pool while the git
    // resource the permit meters is idle. Bounded by a 30s timeout that
    // refuses the push without running Git on incomplete intent; atomic
    // parent+children so a refused pre-Git request cannot strand a
    // payload-only parent.
    let signature_header = headers
        .get("signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let signature_input = headers
        .get("signature-input")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let content_digest = headers
        .get("content-digest")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let request_id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let request_bytes_hash = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&body);
        h.finalize().to_vec()
    };
    let req_row = crate::db::ReceivePackRequest {
        id: request_id.clone(),
        repo_id: record.id.clone(),
        pusher_did: auth.0.to_string(),
        node_did: state.node_did.to_string(),
        request_bytes: Vec::new(),
        request_bytes_hash,
        state: crate::db::request_state::RECEIVED.to_string(),
        git_exit_ok: None,
        parsed_report: None,
        accepted_ordinal: None,
        attempt_count: 0,
        last_error: None,
        next_attempt_at: None,
        created_at: now.clone(),
        completed_at: None,
        signature_header: Some(signature_header.clone()),
        signature_input: Some(signature_input.clone()),
        content_digest: Some(content_digest.clone()),
    };
    let db_timeout = std::time::Duration::from_secs(30);
    // Arm the drop-guard BEFORE the insert resolves: on timeout the
    // cancellation may land after the commit did, stranding a `received`
    // aggregate the early return below would otherwise leave behind. The
    // refuse is a no-op on an id that never committed.
    let _intent_guard = IntentDropGuard::new(state.db.clone(), request_id.clone());
    let db_result = tokio::time::timeout(
        db_timeout,
        state.db.insert_receive_pack_request_with_children(
            &req_row,
            &record.id,
            &state.node_did.to_string(),
            auth.0.as_str(),
            &ref_updates,
            &signature_header,
            &signature_input,
            &content_digest,
        ),
    )
    .await;
    // Both timeout expiry and DB error refuse the push before any lease or
    // permit is held, so admission capacity is never pinned by this write.
    // The insert is one transaction: timeout cancellation rolls back rather
    // than leaving a partially committed intent. `db_result` is
    // `Result<Result<..>, Elapsed>`: the outer `Err` is the timeout, the
    // inner `Err` is a real insert failure — both must refuse without
    // running git, or refs land with no request rows and nothing to
    // reconcile them.
    match db_result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            tracing::error!(
                err = %e,
                repo = %name,
                "failed to persist durable post-receive intent; refusing push"
            );
            return Err(AppError::Overloaded(
                "durable intent write failed, retry shortly".into(),
            ));
        }
        Err(_) => {
            tracing::error!(
                repo = %name,
                "durable intent write timed out; refusing push"
            );
            return Err(AppError::Overloaded(
                "durable intent write failed, retry shortly".into(),
            ));
        }
    }
    // Empty command stream (`0000` flush, no ref updates): no child can ever
    // consume the proof, and the no-report outcome below terminalizes the
    // parent without an accepted child that could ack it — leaving a
    // terminal aggregate the retention gate holds forever. Ack up front:
    // with zero children there are no effects to complete, so the proof is
    // vacuously durable. (The ACK gate itself is untouched: any request
    // that may have landed refs still waits for the drain's ack.)
    if ref_updates.is_empty() {
        if let Err(e) = state.db.ack_request_proof(&request_id).await {
            tracing::warn!(
                err = %e,
                request_id = %request_id,
                repo = %name,
                "empty push: proof ack failed; retention will hold the aggregate"
            );
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
    // Drop-guard: armed above (before the insert resolved) so the
    // insert-timeout cancellation window is covered too. Explicit refusals
    // below still call `refuse_receive_pack_before_git` inline for a
    // synchronous terminal state; the guard is the backstop for drops.
    let lease = match state
        .repo_write_leases
        .acquire(&repo_key, lease_steal_after)
        .await
    {
        Some(l) => l,
        None => {
            tracing::warn!(
                repo = %name,
                "repo write-lease waiter cap reached; shedding with 503"
            );
            if let Err(e) = state
                .db
                .refuse_receive_pack_before_git(&request_id, "repo write-lease waiter cap reached")
                .await
            {
                tracing::warn!(err = %e, request_id = %request_id, "pre-git refusal cleanup failed");
            }
            return Err(AppError::Overloaded(
                "repo is busy with another push, retry shortly".into(),
            ));
        }
    };

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
    // pool via many slow pushes. The push rate limiter bounds arrival RATE, not in-flight
    // concurrency, so this cap is what bounds occupancy. Owner enforcement is on by
    // default now, but it is not what makes this cap load-bearing: an operator may turn it
    // off for a rolling upgrade, and even with it on a single owner can open many
    // concurrent slow pushes to their own repo.
    // Keyed on the resolved source IP, NEVER the signed DID (a DID farm defeats
    // a DID key); no resolvable key -> global write pool only. Then the global write permit:
    // pushes draw from the dedicated WRITE pool, separate from reads, and it is held for the
    // whole op (moved into the AdmissionGuard below).
    let caller_key = read_caller_key(&headers, peer, state.push_limiter_trust);
    let _caller_permit = match acquire_read_caller_permit(
        &state.git_write_per_caller,
        caller_key.as_deref(),
        name,
        "receive-pack",
    ) {
        Ok(p) => p,
        Err(e) => {
            if let Err(ce) = state
                .db
                .refuse_receive_pack_before_git(&request_id, "admission per-source cap reached")
                .await
            {
                tracing::warn!(err = %ce, request_id = %request_id, "pre-git refusal cleanup failed");
            }
            return Err(e);
        }
    };
    let _permit = match git_permit(&state.git_write_semaphore) {
        Ok(p) => p,
        Err(e) => {
            if let Err(ce) = state
                .db
                .refuse_receive_pack_before_git(&request_id, "git write pool saturated")
                .await
            {
                tracing::warn!(err = %ce, request_id = %request_id, "pre-git refusal cleanup failed");
            }
            return Err(e);
        }
    };

    // Intent row and its digest comment live above (pre-lease): durable intent
    // is minimal — only the digest is consumed by recovery (marker
    // correlation). The raw pack is never replayed by this split, so it is
    // not copied into the shared database.
    tracing::debug!(repo = %name, "acquiring write lock");
    // Bound the write acquire under `git_acquire_timeout_secs`. acquire_write's
    // advisory-lock loop already caps at ~60s, but its per-iteration
    // `pg_try_advisory_lock().fetch_one(&pool)` can block indefinitely on a hung /
    // exhausted Postgres pool (so the 60-count never advances) — and the write permit
    // is held the whole time, draining the pool (#174 P1-2). The outer
    // `tokio::time::timeout` cancels a mid-sleep/mid-`fetch_one` future, so it bounds
    // both the loop and a hung iteration. Cancelling here is only safe because
    // acquire_write holds its advisory lock on a connection from a pool whose
    // `after_release` hook unlocks (#173): the dropped future used to leave the lock
    // held with no guard alive to release it, wedging later pushes to that repo. The
    // permit is a handler local here (moved into the AdmissionGuard only after this),
    // so the early return on timeout drops it and frees the slot; shed a bounded 503.
    let acquire_deadline = std::time::Duration::from_secs(state.config.git_acquire_timeout_secs);
    let acquire_raw = tokio::time::timeout(
        acquire_deadline,
        state
            .repo_store
            .acquire_write(&record.owner_did, &record.name),
    )
    .await;
    let mut guard = match acquire_raw {
        Err(_) => {
            tracing::warn!(repo = %name, "acquire_write timed out; shedding with 503");
            if let Err(e) = state
                .db
                .refuse_receive_pack_before_git(&request_id, "acquire_write timed out")
                .await
            {
                tracing::warn!(err = %e, request_id = %request_id, "pre-git refusal cleanup failed");
            }
            return Err(AppError::Overloaded(
                "git service acquisition timed out, retry shortly".into(),
            ));
        }
        Ok(Err(e)) => {
            if let Err(ce) = state
                .db
                .refuse_receive_pack_before_git(&request_id, "acquire_write failed")
                .await
            {
                tracing::warn!(err = %ce, request_id = %request_id, "pre-git refusal cleanup failed");
            }
            return Err(acquire_write_app_error(&e, name));
        }
        Ok(Ok(g)) => g,
    };
    let disk_path = guard.path().to_path_buf();
    tracing::debug!(repo = %name, path = %disk_path.display(), "running git receive-pack");
    let body_len = body.len();
    let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);
    // Recovery upgrade invariant (best-effort): before the first
    // durable intent or marker relies on reflogs/hidden refs,
    // idempotently enable them for new and upgraded repos. Failures
    // are non-fatal here — refusing the push would break fake-git
    // harnesses and non-repo disk paths in tests, and production
    // reconcile already fails closed (leaves rows prepared for
    // attended recovery) when a reflog is missing. A failed upgrade
    // only degrades automatic recovery to attended recovery.
    // Bounded through the configured git binary: the unbounded
    // synchronous variant would run several `git config` children with
    // no timeout while holding both admission permits, the lease, and
    // the repo write lock.
    if let Err(e) = crate::git::store::verify_recovery_prereqs_bounded(
        &state.git_bin,
        &disk_path,
        std::time::Duration::from_secs(10),
    )
    .await
    {
        tracing::warn!(err = %e, repo = %name, "recovery prereqs unavailable; proceeding with degraded automatic recovery");
    }
    // Move both admission permits into the guard so they release only after the spawned
    // receive-pack process group is reaped, on complete/timeout/disconnect — not the
    // instant a disconnect drops this future while the detached reaper runs (#174 P1-a).
    // The handler keeps no copy. This is independent of the write-lock `guard.release`
    // below: admission tracks the git process lifetime, the write lock tracks the repo.
    //
    // The WRITE LOCK rides the same seam (#173 F2). `guard.release(..)` below is only
    // reached if `receive_pack` returns, so on a client disconnect the guard would drop
    // with the future and the lock pool's `after_release` hook would free the advisory
    // lock immediately, while `KillGroupOnDrop`'s detached reaper is still giving the
    // group its ~2s SIGTERM grace. A second push admitted in that window puts two
    // `git receive-pack` groups on one repo, which is exactly what the timeout path
    // reaps to prevent ("a caller releasing a write lock can't race them"). Sharing the
    // guard rather than moving it outright is what lets the SUCCESS path still reclaim
    // it for the Tigris upload: the copy retained here can only DELAY release, never
    // perform it early, because the handler reaches the take below only after
    // `receive_pack` has returned (group reaped or disarmed). On the disconnect path
    // this copy dies with the future and the reaper's copy is last, so the lock frees
    // after the reap with no upload, which is the release(success = false) semantics an
    // interrupted push must have.
    // THE SPLIT (#285 U3). Settling the tree and freeing the advisory lock do not
    // have to happen at the same moment, and only the unlock has to wait for the
    // reaper. The guard below is shared, so on a disconnect its last copy is the
    // one riding `KillGroupOnDrop`, and a settlement done from `RepoWriteGuard::drop`
    // would therefore land only after the process group is torn down. `acquire`
    // takes no advisory lock on its way to the live tree, so a read inside that
    // window would be served refs no publish ever confirmed. Holding the
    // settlement in THIS future puts the marker on disk at the disconnect instant,
    // while the reaper still holds the lock. The success path disarms it below,
    // after `release` has classified the tree itself.
    let mut settlement = guard.take_settlement();
    let guard = std::sync::Arc::new(std::sync::Mutex::new(Some(guard)));
    // Clone (a) of the write lease rides this AdmissionGuard: on a client disconnect the
    // guard moves into KillGroupOnDrop's detached reaper, so the lease frees only after
    // the receive-pack group is reaped — NOT at the disconnect instant (which is exactly
    // when RepoWriteGuard::Drop frees the pg lock). Tying the lease to RepoWriteGuard
    // instead would drop it at disconnect and reopen the F3 race.
    let admission = smart_http::AdmissionGuard::new(_permit, _caller_permit)
        .with_hold(std::sync::Arc::clone(&guard))
        .with_lease(lease.clone());

    // Marker hiding was verified above by `verify_recovery_prereqs`,
    // which is warn-and-proceed (not a push refusal): on failure the
    // marker is still written and reconcile quarantines on a missing
    // or mismatched marker. Compute the value and write the per-request
    // marker through the bounded runners using the configured git binary:
    // both hold admission permits, the lease, and the write lock, so an
    // unbounded `hash-object` could pin them all on a hung child.
    match crate::git::store::marker_value_for_bounded(
        &state.git_bin,
        &disk_path,
        &req_row.request_bytes_hash,
        std::time::Duration::from_secs(10),
    )
    .await
    {
        Ok(marker_value) => {
            if let Err(e) = crate::git::store::write_marker_bounded(
                &state.git_bin,
                &disk_path,
                &request_id,
                &marker_value,
                std::time::Duration::from_secs(10),
            )
            .await
            {
                tracing::warn!(
                    err = %e,
                    request_id = %request_id,
                    repo = %name,
                    "bounded marker write failed; reconcile will quarantine this request"
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                err = %e,
                request_id = %request_id,
                repo = %name,
                "marker value computation failed; reconcile will quarantine this request"
            );
        }
    }

    // P1 (reviewer-1/2 round 3): use receive_pack_raw to get the raw
    // stdout (which contains the report-status with per-ref ok/ng
    // results) and the process exit status. This allows us to:
    // 1. Parse per-ref results to distinguish proven rejections from
    //    uncertain outcomes on error.
    // 2. On success, write effects and then DELETE outbox rows so they
    //    don't replay on restart.
    //
    // The reflog action is best-effort binding (receive-pack writes a
    // fixed `push` message and ignores GIT_REFLOG_ACTION); causality
    // still relies on marker + tuple/timestamp + history guards. Marker
    // namespace hiding was verified above by `verify_recovery_prereqs`.
    let reflog_action = format!("gitlawb-request:{request_id}");
    // Phase-flip the drop-guard: git is about to start, so a dropped future
    // from here forward is a mid-git disconnect (not a pre-git shed). The
    // guard then marks children uncertain and terminalizes the parent, which
    // the mark_uncertain path below cannot do on a drop — it never runs, and
    // the detached reaper does process teardown only, no DB writes.
    _intent_guard.notify_git_started();
    let (receive_raw, exit_ok) = match smart_http::receive_pack_raw_with_reflog(
        &state.git_bin,
        &disk_path,
        body,
        git_timeout,
        Some(admission),
        Some(&reflog_action),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            // Timeout or spawn failure — the git process group was
            // torn down. Mark all prepared rows as uncertain so the
            // reconcile step can check them against disk at startup.
            if let Err(ce) = state
                .db
                .mark_pending_ref_transitions_uncertain(&request_id)
                .await
            {
                tracing::warn!(
                    err = %ce,
                    request_id = %request_id,
                    repo = %name,
                    "failed to mark pending ref transitions uncertain after receive-pack error"
                );
            }
            let app = git_service_app_error(&e);
            match &app {
                AppError::Timeout(_) => tracing::warn!(repo = %name, "git receive-pack timed out"),
                AppError::BadRequest(msg) => {
                    tracing::warn!(repo = %name, err = %msg, "git receive-pack: bad client request")
                }
                _ => tracing::error!(repo = %name, err = %e, "git receive-pack failed"),
            }
            return Err(app);
        }
    };

    // P1 (reviewer-1/2 round 4): complete the per-ref outcome
    // model. The previous `all_refs_ok` ignored `unpack_ok` and
    // treated an absent report as success, then ran the durable
    // effects loop unconditionally. A mixed push where one ref is
    // rejected still issued a signed certificate, an anchor job, a
    // push event, a trust-score bump, and a webhook for the rejected
    // ref. Git can report `unpack ok / ng refs/heads/main` on a
    // zero exit (a non-fast-forward, a hook denial), and that path
    // is exactly the one the previous logic missed.
    //
    // Build the set of ref names that the report-status proves
    // landed. Every ref update the handler intended to land gets a
    // fate:
    //   - in `ok_set`           → row goes to `applied`, effects fire
    //   - in `report` but ng    → row goes to `cancelled`, no effects
    //   - not in `report` at all → row goes to `uncertain` for reconcile
    //
    // If `unpack_ok == false`, no ref could have landed — all rows
    // become `cancelled` and no effects fire for any ref.
    //
    // If the report is unparseable (client did not request
    // report-status, or framing was malformed), every row becomes
    // `uncertain` so the on-disk reflog proof can sort out which
    // ones actually landed at the next startup.
    let report = smart_http::parse_report_status(&receive_raw);

    // (unpack_ok, all_in_report_ok, ok_set, request_failed).
    //
    // Outcome authority: only a complete Git report or request-bound
    // disk evidence may move a child to `applied`; process exit alone
    // never does. An absent report is indeterminate regardless of exit
    // status — a capability-free client can omit `report-status` and
    // Git then returns no per-ref results even for rejected commands.
    // The branches below synthesize nothing as success; unreported
    // refs become `uncertain` for reconcile, which must prove landing
    // before any push event, certificate, anchor, or webhook.
    let (unpack_ok, all_in_report_ok, ok_set, request_failed) = match &report {
        Some((unpack_ok, ref_results)) => {
            let ok_set: std::collections::HashSet<&str> = ref_results
                .iter()
                .filter(|(_, ok)| *ok)
                .map(|(name, _)| name.as_str())
                .collect();
            let all_in_report_ok = ref_results.iter().all(|(_, ok)| *ok);
            (*unpack_ok, all_in_report_ok, ok_set, !exit_ok)
        }
        None => {
            // No report: indeterminate regardless of exit status. Every
            // declared ref is `uncertain` for reconcile.
            let ok_set: std::collections::HashSet<&str> = std::collections::HashSet::new();
            (false, true, ok_set, !exit_ok)
        }
    };

    // Per-ref outcome, committed atomically with the parent request
    // row in one transaction (see
    // `commit_request_outcomes_atomically`). The previous code flipped
    // children and stamped the parent in separate writes, so a crash
    // between them left applied children attached to a `received`
    // parent the drain never schedules. The normalized `parsed_report`
    // is the accepted-ref authority when present; the no-report path
    // stores no report and moves the parent to `rejected_at_git` for
    // fail-closed reconcile, and the executor's null-report fallback
    // covers reconciled/legacy rows (not just backward compatibility).
    let pending_ref_names: Vec<&str> = ref_updates.iter().map(|u| u.ref_name.as_str()).collect();

    // #26 Split PR 1: the push event id is keyed on
    // `(request_id, accepted_ordinal)`. The `accepted_ordinal` is
    // the ordinal (in `ref_updates`) of the FIRST ref the report
    // proves landed; the v30 migration's `ordinal` column carries
    // the position. No `first_ref_name` rewrite is needed because
    // the identity is on the request, not on a mutable per-ref
    // column. Compute it once here so the per-ref effects loop can
    // stamp the request row at the right moment. Unpack failure
    // clears it below: no ref landed, so no ordinal is accepted.
    let mut accepted_ordinal: Option<i32> = ref_updates
        .iter()
        .position(|u| ok_set.contains(u.ref_name.as_str()))
        .map(|i| i as i32);
    if !unpack_ok {
        accepted_ordinal = None;
    }

    // Build the atomic outcome inputs.
    #[allow(clippy::type_complexity)]
    let (
        unpack_failed,
        ok_names,
        ng_names,
        uncertain_names,
        parsed_json_opt,
        rejected_reason,
        terminal_no_effects,
    ): (
        bool,
        Vec<&str>,
        Vec<&str>,
        Vec<&str>,
        Option<serde_json::Value>,
        Option<String>,
        bool,
    ) = match &report {
        None => {
            // No report-status: indeterminate regardless of exit status.
            // Process success is not per-ref success — a capability-free
            // client can omit `report-status` and Git then emits zero
            // result bytes even for rejected commands. Every declared ref
            // stays `uncertain`; reconcile must prove landing on disk
            // before any push event, certificate, anchor, or webhook.
            // The client still receives the Git response; only durable
            // effects are deferred. This arm runs FIRST: with no report the
            // `unpack_ok` flag below is meaningless, and routing here through
            // the unpack-failure arm would mislabel the aggregate and persist
            // a false `git_exit_ok`.
            (
                false,
                Vec::new(),
                Vec::new(),
                pending_ref_names.clone(),
                None,
                Some(crate::durable_outbox::NO_REPORT_AWAITING_EVIDENCE.to_string()),
                false,
            )
        }
        Some(parsed) if !unpack_ok => {
            // Unpack failure proves no ref landed, regardless of per-ref
            // `ok` bits or process exit. The report is present here (absence
            // is handled above), so its ref list is authoritative: cancel
            // every child, clear any accepted ordinal, and terminalize with
            // no effects so the executor can never outrun the cancelled rows.
            let parsed_json = serde_json::json!({
                "unpack_ok": false,
                "ref_results": parsed.1.iter().map(|(n, _)| serde_json::json!({
                    "ref_name": n,
                    "ok": false,
                })).collect::<Vec<_>>(),
            });
            (
                true,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Some(parsed_json),
                None,
                true,
            )
        }
        Some(parsed) => {
            // Report present with unpack ok (absence is handled in the first
            // arm): per-ref fates from the authoritative report.
            let mut ok_names: Vec<&str> = Vec::new();
            let mut ng_names: Vec<&str> = Vec::new();
            let mut unmentioned: Vec<&str> = Vec::new();
            let reported: std::collections::HashSet<&str> =
                parsed.1.iter().map(|(n, _)| n.as_str()).collect();
            for name in &pending_ref_names {
                if !reported.contains(name) {
                    unmentioned.push(*name);
                } else if ok_set.contains(name) {
                    ok_names.push(*name);
                } else {
                    ng_names.push(*name);
                }
            }
            // Syntactic completeness (flush) is enforced in
            // `strip_sideband`; command-set completeness is enforced here:
            // a parsed report that omits declared refs is not
            // authoritative. Persist the whole request as indeterminate so
            // reconciliation produces a fresh normalized outcome before
            // anything is retired. Otherwise a partial prefix would commit
            // one ok child as applied, leave siblings uncertain, and the
            // executor would delete the unresolved evidence on completion.
            if !unmentioned.is_empty() {
                tracing::warn!(
                    request_id = %request_id,
                    repo = %name,
                    unmentioned = ?unmentioned,
                    "report-status omits declared refs; persisting as indeterminate"
                );
                (
                    false,
                    Vec::new(),
                    Vec::new(),
                    pending_ref_names.clone(),
                    None,
                    Some("incomplete report-status: omitted declared refs".to_string()),
                    false,
                )
            } else {
                if !ng_names.is_empty() {
                    tracing::warn!(
                        request_id = %request_id,
                        repo = %name,
                        rejected_refs = ?ng_names,
                        "git report-status: some refs rejected; durable effects will skip them"
                    );
                }
                let parsed_json = serde_json::json!({
                    "unpack_ok": parsed.0,
                    "ref_results": parsed.1.iter().map(|(n, ok)| serde_json::json!({
                        "ref_name": n,
                        "ok": ok,
                    })).collect::<Vec<_>>(),
                });
                // All refs rejected with exit zero: terminal with no
                // effects. The startup drain must have nothing executable
                // to revisit and retention must be able to purge.
                let terminal = ok_names.is_empty() && !pending_ref_names.is_empty();
                (
                    false,
                    ok_names,
                    ng_names,
                    unmentioned,
                    Some(parsed_json),
                    None,
                    terminal,
                )
            }
        }
    };

    // Bounded synchronous retry for post-git outcome commit. After git has landed
    // refs we cannot 503 (refs are already durable), but leaving the parent in
    // `received` hides it from the claim-gated due worker, which only matches
    // `outcomes_committed` / `effects_pending`. Retry up to 3x with short
    // backoff; on persistent failure the push still returns 200 (git did
    // land), metrics/effects are skipped inline, and durable effects wait for
    // the next process restart, when startup reconcile promotes disk-proved
    // children and the aggregate. This attended-restart window is by design:
    // refs are safe on disk, never silently dropped, just not yet accounted.
    //
    // Stash the computed fates on the drop-guard first: a drop during the
    // retries (or anywhere later while the guard is armed) then commits these
    // fates via the guard's bounded retry instead of a context-free blanket
    // `uncertain` — git-proven rejections land `cancelled`, not `uncertain`.
    _intent_guard.set_fates(ComputedFates {
        ok_names: ok_names.iter().map(|s| s.to_string()).collect(),
        ng_names: ng_names.iter().map(|s| s.to_string()).collect(),
        uncertain_names: uncertain_names.iter().map(|s| s.to_string()).collect(),
        unpack_failed,
        git_exit_ok: exit_ok,
        parsed_json: parsed_json_opt.clone(),
        accepted_ordinal,
        rejected_reason: rejected_reason.clone(),
        terminal_no_effects,
    });
    let mut delay_ms = 20;
    let outcome_commit_ok = loop {
        match commit_request_outcomes_seamed(
            &state,
            &record.id,
            &request_id,
            &ok_names,
            &ng_names,
            &uncertain_names,
            unpack_failed,
            exit_ok,
            parsed_json_opt.as_ref(),
            accepted_ordinal,
            rejected_reason.as_deref(),
            terminal_no_effects,
        )
        .await
        {
            Ok(()) => break true,
            Err(e) if delay_ms < 500 => {
                tracing::warn!(
                    err = %e,
                    request_id = %request_id,
                    repo = %name,
                    delay_ms,
                    "commit_request_outcomes_atomically failed; retrying"
                );
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                delay_ms = delay_ms.saturating_mul(5).min(500);
            }
            Err(e) => {
                tracing::warn!(
                    err = %e,
                    request_id = %request_id,
                    repo = %name,
                    "commit_request_outcomes_atomically failed after retries; \
                     effects deferred to startup reconcile (parent stays received \
                     unless the still-armed guard terminalizes it on scope exit, \
                     which startup reconcile recovers the same way)"
                );
                break false;
            }
        }
    };

    // A resolved outcome commit leaves no `received` parent behind, so drops
    // from here on need no guard cleanup — disarm to avoid a wasteful spawned
    // txn per push. On persistent commit failure the guard stays in its
    // git-started phase: a later drop still terminalizes the aggregate for
    // startup reconcile instead of stranding it.
    if outcome_commit_ok {
        _intent_guard.disarm();
    }

    // On non-zero exit, return an error to the caller. The outbox
    // rows have already been handled above (per-ref fates applied).
    // The client-visible body does NOT include wire-supplied ref
    // names — ref names can carry control bytes and the previous
    // `format!("refs rejected: {rejected:?}")` embedded them in a
    // 500 response. Server-side the names are logged above.
    if request_failed {
        let reclaimed = guard
            .lock()
            .expect("repo write-lock mutex poisoned")
            .take()
            .expect("the write lock is only taken here, and only once");
        let _ = reclaimed.release(false).await;
        drop(lease);

        let body_msg = if !unpack_ok {
            "git-receive-pack failed: unpack failed"
        } else if !all_in_report_ok {
            "git-receive-pack failed: refs rejected"
        } else {
            "git-receive-pack failed"
        };
        return Err(AppError::Git(body_msg.to_string()));
    }

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
    let push_succeeded = exit_ok;
    let publish_durability = PublishDurabilitySlot::new();
    // P1 (reviewer-1/2 round 4): the durable effects only fire for
    // refs the report-status proves landed. The previous code ran
    // them unconditionally once past the `!exit_ok` return, so a
    // `unpack ok / ng refs/heads/main` zero-exit push still signed
    // a cert and queued an anchor for the rejected ref.
    //
    // `push_succeeded` is the request-level signal for the
    // replication tail and the lock release. `any_ref_ok` is the
    // request-scoped effects gate (push event, trust score,
    // metrics): at least one ref must have landed for those to be
    // meaningful. Both derive from the committed child state
    // (`ok_names`, already unpack-gated to empty on unpack failure),
    // never from the raw `ok_set`, so an `unpack_ok: false` report
    // listing `ok: true` bits cannot reach effects or the tail.
    let any_ref_ok = unpack_ok && !ok_names.is_empty();
    // Single post-git disposition gate: replication/Tigris, metrics, and
    // inline effects all derive from one struct so Option B
    // attended-restart cannot disagree with itself across blocks.
    // Policy 2 carve-out (see PR body): replication/Tigris runs on
    // in-memory report knowledge even when the outcome commit failed,
    // because F2 disconnect safety requires the tail before `release`,
    // the tail is read-only on disk, and announces carry `cert_id: None`.
    // Durable accounting instead waits for startup reconcile.
    //
    // MUTATION (RED): gating `spawn_tail`/`release_ok` on
    // `outcome_commit_ok` breaks `post_git_disposition_replication_carve_out`.
    let disposition =
        post_git_disposition(exit_ok, any_ref_ok, outcome_commit_ok, report.is_none());

    // One replication tail per push, on the proven-landed ref set the
    // disposition selected. When a release ordering is armed below, the
    // tail spawns there carrying the durability slot; otherwise it fires
    // here for the carve-out path (replication on in-memory knowledge).
    let landed_refs: Vec<RefUpdate> = if disposition.spawn_tail {
        accepted_ref_updates(&ok_set, &ref_updates)
    } else {
        Vec::new()
    };
    // The stored-head and poll-feed writes are durable accounting, so they
    // do not run here: `apply_request_effects` below writes them from the
    // request's accepted transition rows, after the publish verdict, under
    // the same proof rules every other durable effect obeys. Writing them
    // pre-release would leave rows claiming a landing a refused publish
    // then deleted, and a landing reconcile proves only later would emit
    // nothing at all.
    if disposition.spawn_tail && !push_succeeded && !landed_refs.is_empty() {
        tokio::spawn(post_receive_replication_tail(
            state.clone(),
            record.clone(),
            landed_refs.clone(),
            disk_path.clone(),
            auth.0.to_string(),
            None,
        ));
    }

    // Always release the advisory lock — even on error — to prevent stale locks
    // from blocking subsequent pushes. Only upload to Tigris when the push
    // succeeded; uploading a half-applied repo would propagate corruption.
    // Reclaim the write lock from the shared cell (#173 F2). This is only reachable
    // once `receive_pack` has returned, so the admission guard's copy can only ever
    // DELAY release, never perform it early; on the disconnect path this line is not
    // reached at all and the reaper's copy is last.
    let reclaimed = guard
        .lock()
        .expect("repo write-lock mutex poisoned")
        .take()
        .expect("the write lock is only taken here, and only once");
    if push_succeeded {
        // Arm on the guard's OWN publish stage, so a disconnect anywhere in
        // `release` is classified by how far the publish actually got rather
        // than by the mere fact that release was entered.
        publish_durability.arm_for_release(reclaimed.publish_stage());
        if disposition.spawn_tail && !landed_refs.is_empty() {
            tokio::spawn(post_receive_replication_tail(
                state.clone(),
                record.clone(),
                landed_refs,
                disk_path.clone(),
                auth.0.to_string(),
                Some(publish_durability.arc()),
            ));
        }
    }
    // Short-circuit on a refused publish BEFORE anything downstream observes
    // the push. The pack is on local disk but not in object storage, so
    // touching the repo, recording the push, bumping trust, issuing ref
    // certificates or answering 200 would all be reporting a write no other
    // node can read.
    let outcome = reclaimed.release(disposition.release_ok).await;
    // `release` classified the tree on whatever outcome it reached, so this
    // future's copy of the settlement must not classify it a second time: a
    // definite refusal has already deleted the tree and cleared its marker.
    if let Some(settlement) = settlement.as_mut() {
        settlement.disarm();
    }
    if push_succeeded {
        publish_durability.record(outcome).await;
    }
    outcome.into_result()?;
    // Clean path: clone (a) already dropped inside run_git_service when the receive-pack
    // group was reaped; clone (b) held here spanned the success-only Tigris upload that
    // ran inside release() above. Drop it now so a second same-repo push proceeds the
    // moment this write is durable, rather than at end of the (longer) handler tail. On
    // the disconnect path this line is never reached: clone (a) rides the reaper (F3).
    drop(lease);

    // Unless refs landed AND the outcome was durably committed, return 200
    // with the receive-pack body and run no durable effects (no push event,
    // no trust score, no metrics, no webhooks, no certs, no anchor jobs).
    // Refs the commit resolved were flipped to `cancelled` / `uncertain`
    // above and reconcile will not promote them; on commit failure children
    // stay `prepared` until the guard's scope-exit drop commits the stashed
    // fates or marks them `uncertain`, and reconcile resolves either outcome.
    if !disposition.run_effects {
        return axum::response::Response::builder()
            .status(axum::http::StatusCode::OK)
            .header("Content-Type", "application/x-git-receive-pack-result")
            .header("Cache-Control", "no-cache")
            .body(axum::body::Body::from(receive_raw))
            .map_err(|e| AppError::Internal(anyhow::anyhow!("failed to build response: {e}")));
    }

    // #26 Split PR 1 step 3 — the per-ref effects fan-out moved into
    // `apply_request_effects`. The live handler and the recovery
    // drain call the same function, so the live and recovery paths
    // produce identical artifact ids and the request row's
    // `accepted_ordinal` is the single source of truth for the push
    // event identity. A `Retry` outcome here means one or more
    // per-ref effects failed transiently; the request is left in
    // `effects_pending` for the drain to pick up on the next
    // startup. A `Nothing` outcome means the request had no
    // accepted ref (the disposition gate above would have caught
    // that case via `run_effects`, so this is defensive).
    let _ = state.db.touch_repo(&record.id).await;
    crate::metrics::record_push(&record.id);
    crate::metrics::observe_pack_size(body_len as f64);

    // Claim ownership before inline effects: a background worker may
    // concurrently list this just-committed row as due. Loser skips;
    // the owner executes. Lease is recoverable on crash.
    match state
        .db
        .try_claim_due_request(&request_id, 300, &Utc::now().to_rfc3339())
        .await
    {
        Ok(true) => {}
        _ => {
            return axum::response::Response::builder()
                .status(axum::http::StatusCode::OK)
                .header("Content-Type", "application/x-git-receive-pack-result")
                .header("Cache-Control", "no-cache")
                .body(axum::body::Body::from(receive_raw))
                .map_err(|e| AppError::Internal(anyhow::anyhow!("failed to build response: {e}")));
        }
    }

    match crate::durable_outbox::apply_request_effects(&state, &request_id).await {
        Ok(crate::durable_outbox::EffectsOutcome::Done) => {
            if let Err(e) = state.db.mark_request_complete(&request_id).await {
                tracing::warn!(
                    err = %e,
                    request_id = %request_id,
                    repo = %name,
                    "live path: mark_request_complete failed; drain will pick up"
                );
            }
        }
        Ok(crate::durable_outbox::EffectsOutcome::Nothing) => {
            // No accepted ref (defensive — `any_ref_ok` gates the
            // call site, so this branch is unreachable in practice).
            // Mark complete so the drain skips the request.
            if let Err(e) = state.db.mark_request_complete(&request_id).await {
                tracing::warn!(
                    err = %e,
                    request_id = %request_id,
                    repo = %name,
                    "live path: mark_request_complete (Nothing) failed"
                );
            }
        }
        Ok(crate::durable_outbox::EffectsOutcome::Retry { last_error }) => {
            // Centralized policy: exponential backoff, attempt_count increment,
            // and quarantine all live in one place — routing through the same helper
            // as the drain so both executors advance retry state identically.
            if let Err(e) = crate::durable_outbox::schedule_request_retry_or_quarantine(
                &state,
                &request_id,
                &last_error,
            )
            .await
            {
                tracing::warn!(
                    err = %e,
                    request_id = %request_id,
                    repo = %name,
                    "live path: schedule retry failed; drain will pick up"
                );
            }
        }
        Ok(crate::durable_outbox::EffectsOutcome::AwaitingSiblings) => {
            // Siblings unresolved: completion waits for startup reconcile,
            // not for a failed effect. Route nowhere near retry accounting
            // — incrementing attempts here would quarantine a request that
            // is only waiting. The aggregate stays `outcomes_committed`,
            // re-checkable once the claim lease lapses, so the drain
            // re-checks it and reconcile resolves it.
            //
            // Accepted residual, stated honestly: this arm is unreachable
            // through the current outcome builder — `run_effects` requires a
            // non-empty committed ok-set, and a successful commit leaves no
            // `prepared`/`uncertain` sibling behind (every prepared child is
            // flipped; unmentioned refs force the indeterminate path, which
            // does not run effects). The arm exists for symmetry with the
            // drain consumer, so a future builder change that CAN produce
            // live siblings waits instead of misrouting to quarantine. Its
            // presence (not behavior) is pinned in inv22_gates; deleting it
            // must be a conscious edit, not drift.
            tracing::debug!(
                request_id = %request_id,
                repo = %name,
                "live path: siblings unresolved, waiting for reconcile (no retry accounting)"
            );
        }
        Err(e) => {
            // Execution errors must advance retry accounting so the request
            // is not frozen behind the 300s claim lease with attempt_count
            // stuck. Route through the same helper as the drain.
            tracing::error!(
                err = %e,
                request_id = %request_id,
                repo = %name,
                "live path: apply_request_effects returned Err; scheduling retry"
            );
            let msg = format!("executor error: {e}");
            if let Err(sched_err) = crate::durable_outbox::schedule_request_retry_or_quarantine(
                &state,
                &request_id,
                &msg,
            )
            .await
            {
                tracing::warn!(
                    err = %sched_err,
                    request_id = %request_id,
                    repo = %name,
                    "live path: schedule retry (Err arm) failed"
                );
            }
        }
    }

    axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header("Content-Type", "application/x-git-receive-pack-result")
        .header("Cache-Control", "no-cache")
        .body(axum::body::Body::from(receive_raw))
        .map_err(|e| AppError::Internal(anyhow::anyhow!("failed to build response: {e}")))
}

/// Records the release-side publish outcome for the detached post-receive tail.
///
/// The subtle case is the one this type exists for: the handler future is
/// DROPPED, so `release` never returns and `record` is never called. The slot
/// then has to classify an attempt whose outcome nobody will ever report, and
/// the only honest source for that is the publish STAGE — how far the attempt
/// had actually got when it was abandoned.
///
/// Tracking "release started" instead was the defect. `release` awaits a blocking
/// compression before the conditional PUT is constructed, so a cancellation
/// there is a definite "no publication was attempted", yet every cancellation
/// after the flag was set recorded `UploadUnknowable` — which the tail accepted,
/// and then went on to do IPFS, Pinata, P2P, GraphQL, Arweave and peer work for
/// refs that existed only in a rejected local write.
struct PublishDurabilitySlot {
    inner: Arc<std::sync::Mutex<Option<crate::git::repo_store::ReleaseOutcome>>>,
    recorded: std::sync::atomic::AtomicBool,
    /// The stage of the release this slot is armed for. `None` until the release
    /// is about to be awaited, which is what makes a drop before that point leave
    /// the slot empty and the tail fail closed.
    stage: std::sync::Mutex<Option<Arc<crate::git::publish::PublishStageCell>>>,
}

impl PublishDurabilitySlot {
    fn new() -> Self {
        Self {
            inner: Arc::new(std::sync::Mutex::new(None)),
            recorded: std::sync::atomic::AtomicBool::new(false),
            stage: std::sync::Mutex::new(None),
        }
    }

    /// Arm the slot against the guard's publish stage, immediately before the
    /// release is awaited.
    fn arm_for_release(&self, stage: Arc<crate::git::publish::PublishStageCell>) {
        *self.stage.lock().expect("publish stage slot poisoned") = Some(stage);
    }

    fn arc(&self) -> Arc<std::sync::Mutex<Option<crate::git::repo_store::ReleaseOutcome>>> {
        Arc::clone(&self.inner)
    }

    async fn record(&self, outcome: crate::git::repo_store::ReleaseOutcome) {
        *self
            .inner
            .lock()
            .expect("publish durability mutex poisoned") = Some(outcome);
        self.recorded
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Drop for PublishDurabilitySlot {
    fn drop(&mut self) {
        if self.recorded.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let Some(stage) = self
            .stage
            .lock()
            .expect("publish stage slot poisoned")
            .clone()
        else {
            // Dropped before the release was even armed. Leave the slot empty so
            // the tail fails closed on the wait below.
            return;
        };
        use crate::git::publish::PublishStage;
        use crate::git::repo_store::ReleaseOutcome;
        let outcome = match stage.get() {
            // The store answered. Cancellation after that point loses the
            // handler's response, not the write, so the tail may run.
            //
            // `NoBackend` joins it: with no object storage configured there is
            // no publication to confirm and the pack on local disk is the
            // durable copy, which is exactly what `ReleaseOutcome::Released`
            // already means for a release that had nothing to upload.
            PublishStage::Published { .. } | PublishStage::NoBackend => ReleaseOutcome::Released,
            // THE FINDING. Compression was still running, so the conditional PUT
            // was never constructed and no publication was ever attempted. This
            // is a definite refusal, not an unknowable one, and the tail must
            // skip every replication effect.
            PublishStage::Idle | PublishStage::PreparingArchive | PublishStage::Refused => {
                ReleaseOutcome::UploadFailed
            }
            // Genuinely in flight. Nothing here can reconcile it — a `Drop` impl
            // cannot await a HEAD — so it stays unknowable, which the tail refuses
            // because it requires `Released`. The write is still on local disk and
            // the next writer's under-lock refresh resolves it.
            PublishStage::PutDispatched { .. } | PublishStage::Ambiguous { .. } => {
                ReleaseOutcome::UploadUnknowable
            }
        };
        let mut slot = self
            .inner
            .lock()
            .expect("publish durability mutex poisoned");
        if slot.is_none() {
            *slot = Some(outcome);
        }
    }
}

/// May the detached replication tail run?
///
/// ONLY on `Released`, which is the outcome that means the store acknowledged
/// this attempt (directly, or through the release-side reconciliation that
/// matched the attempt id against what the store holds). `UploadUnknowable` used
/// to pass here, which let the tail pin, announce and publish refs whose archive
/// may never have landed; an unresolved dispatch has to be reconciled to this
/// attempt's own generation before it counts as confirmation, and the place that
/// can do it is `release`, not this predicate.
async fn publish_durability_confirmed(
    slot: &Option<Arc<std::sync::Mutex<Option<crate::git::repo_store::ReleaseOutcome>>>>,
    wait: std::time::Duration,
) -> bool {
    let Some(slot) = slot else {
        return true;
    };
    let confirmed = |outcome: Option<crate::git::repo_store::ReleaseOutcome>| {
        matches!(
            outcome,
            Some(crate::git::repo_store::ReleaseOutcome::Released)
        )
    };
    let start = std::time::Instant::now();
    loop {
        let outcome = *slot.lock().expect("publish durability mutex poisoned");
        if outcome.is_some() {
            return confirmed(outcome);
        }
        if start.elapsed() >= wait {
            // No outcome within the release-side transfer bound plus slack. Fail
            // closed when the slot is still empty; an abandoned handler installs
            // its stage's verdict via PublishDurabilitySlot::drop, so the tail
            // resolves promptly rather than waiting out the full bound.
            return confirmed(*slot.lock().expect("publish durability mutex poisoned"));
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// Chunk size for the batched post-receive writers below: bounded per
/// statement while every accepted ref still lands.
pub(crate) const PUSH_WRITE_CHUNK: usize = 256;

/// The declared refs the report's ok set proves landed — never the declared
/// set alone, and never a ref the report did not accept. The caller passes the
/// `ok_set` already derived for the outcome commit, so the set that feeds the
/// head update and the push-event write is exactly the set that marked each
/// ref `applied`; a report that cannot be parsed yields an empty set upstream
/// and nothing here invents landing for it.
fn accepted_ref_updates<S>(
    ok_refs: &std::collections::HashSet<S>,
    declared: &[RefUpdate],
) -> Vec<RefUpdate>
where
    S: std::borrow::Borrow<str> + Eq + std::hash::Hash,
{
    declared
        .iter()
        .filter(|u| ok_refs.contains(u.ref_name.as_str()))
        .cloned()
        .collect()
}

/// The branch a `refs/heads/<branch>` ref names; `None` for anything else, so a
/// tag push can never move a PR's stored head.
fn branch_from_ref(ref_name: &str) -> Option<&str> {
    ref_name
        .strip_prefix("refs/heads/")
        .filter(|branch| !branch.is_empty())
}

/// The `(branch, tip)` pairs a proven landing still leaves at its ref's
/// current target.
///
/// Each candidate is checked against the ref on disk, not applied blindly:
/// the effect executor that calls this runs after the repository write
/// lock is released, so a later push may already have moved the branch
/// past this landing. Writing a superseded tip would pin the rollup to a
/// commit the branch has moved past, and a stale non-NULL head is not
/// self-healing — `set_pr_head_if_absent` only fills absent heads. A
/// check that fails (moved past, deleted, or unreadable because the repo
/// is not on this node's disk) skips the write rather than inventing a
/// head: the newest proven landing's own pass covers the update, and the
/// read-side fallback fills an absent head from `repo_push_events`.
///
/// A repo that is not on this node's disk at all yields no candidates: the
/// drain replays effects for pushes whose objects live only in cold storage,
/// and a missing repo dir is that case, not a failure the pass should retry.
/// `read_ref` errors inside a repo that IS present (the `git` subprocess
/// itself failed) propagate: the caller treats them as transient and retries
/// the effect.
pub(crate) fn heads_still_at_tip(
    disk_path: &std::path::Path,
    updates: &[RefUpdate],
) -> anyhow::Result<Vec<(String, String)>> {
    if !disk_path.is_dir() {
        return Ok(Vec::new());
    }
    let mut heads = Vec::new();
    for update in updates {
        // A deletion carries an all-zero new SHA. Storing it would hand the
        // rollup a target that resolves to no commit, so leave the last real
        // head standing.
        if update.new_sha == ZERO_SHA {
            continue;
        }
        let Some(branch) = branch_from_ref(&update.ref_name) else {
            continue;
        };
        if crate::git::store::read_ref(disk_path, &update.ref_name)?.as_deref()
            == Some(update.new_sha.as_str())
        {
            heads.push((branch.to_string(), update.new_sha.clone()));
        }
    }
    Ok(heads)
}

/// Point every open pull request fed by this push at the branch's new tip.
///
/// `heads` is the `(branch, tip)` set the caller has already proven still
/// sits at each ref's target (see [`heads_still_at_tip`]); this function
/// writes what it is given and never resolves refs itself.
///
/// One UPDATE per chunk of branches, keyed on (repo, source branch, open): no
/// per-PR probing, no repo listing, and the cost grows with neither the
/// number of open pull requests nor, per statement, the number of refs
/// pushed. The error propagates: the effect executor turns it into a
/// `Retry`, so a transient failure waits for the next pass rather than
/// silently freezing a stale head — a stale head is not self-healing, since
/// `set_pr_head_if_absent` only fills NULL heads.
pub(crate) async fn update_open_pr_heads(
    db: &crate::db::Db,
    repo_id: &str,
    heads: &[(String, String)],
) -> anyhow::Result<()> {
    let mut dedup: Vec<(String, String)> = Vec::new();
    // Position of each branch already in `dedup`, so the merge below is a
    // lookup rather than a scan. Last write wins, as the per-ref loop this
    // replaced did: a `VALUES` join over duplicate branches would pick a row
    // arbitrarily, and an arbitrary head is worse than a deterministic one.
    let mut at: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for (branch, sha) in heads {
        match at.get(branch.as_str()) {
            Some(&i) => dedup[i].1 = sha.clone(),
            None => {
                at.insert(branch, dedup.len());
                dedup.push((branch.clone(), sha.clone()));
            }
        }
    }

    // Chunked for the same reason the push events are: bounded per statement,
    // and every branch git accepted still gets its head moved.
    for chunk in dedup.chunks(PUSH_WRITE_CHUNK) {
        db.set_open_pr_heads_batch(repo_id, chunk)
            .await
            .map_err(|e| {
                let rows = chunk
                    .iter()
                    .map(|(branch, sha)| format!("{branch}@{sha}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                anyhow::anyhow!("stored-head update failed for {repo_id} ({rows}): {e}")
            })?;
    }
    Ok(())
}

/// Write the catch-up poll row for each proven landing.
///
/// The events derive from the request's accepted transition rows — the
/// durable record of what landed — not from the live handler's in-memory
/// parse, so the live path and the recovery drain record the same rows.
/// `id` is deterministic on `(request_id, ordinal)`: a recovery replay
/// inserts the same id and the `ON CONFLICT` collapses it to a no-op
/// instead of delivering one landing to pollers twice.
///
/// `created_at` prefers the transition's own `applied_at` — the moment the
/// landing was durably committed — over this pass's run time, so an event
/// the drain writes stamps when the push landed, not when the node
/// restarted. It is display metadata, not the ordering key: the cursor
/// pages on the database-assigned `seq`.
///
/// The error propagates: the effect executor turns it into a `Retry`, so a
/// transient failure waits for the next pass rather than dropping a row the
/// poll surface can never re-derive.
pub(crate) async fn record_push_events(
    db: &crate::db::Db,
    request_id: &str,
    children: &[&crate::db::PendingRefTransition],
) -> anyhow::Result<()> {
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let events: Vec<crate::db::RepoPushEvent> = children
        .iter()
        // A deletion carries an all-zero new SHA. Recording it would hand a
        // poller a target that resolves to no commit.
        .filter(|c| c.new_sha != ZERO_SHA)
        .map(|c| crate::db::RepoPushEvent {
            id: crate::db::repo_push_event_id_for(request_id, c.ordinal),
            // Ignored on insert; the database assigns the ordering key.
            seq: 0,
            repo_id: c.repo_id.clone(),
            ref_name: c.ref_name.clone(),
            after_sha: c.new_sha.clone(),
            created_at: c.applied_at.clone().unwrap_or_else(|| now.clone()),
        })
        .collect();

    // One statement per chunk, never one per ref: a per-ref loop would put a
    // database round trip for every ref on the effect pass, and a single
    // unbounded statement would let the pusher choose its parameter count.
    // One request is one repo, so the first row names it for the error below.
    let repo_id = events.first().map(|e| e.repo_id.as_str()).unwrap_or("");
    for chunk in events.chunks(PUSH_WRITE_CHUNK) {
        db.insert_repo_push_events(chunk).await.map_err(|e| {
            let rows = chunk
                .iter()
                .map(|ev| format!("{}@{}", ev.ref_name, ev.after_sha))
                .collect::<Vec<_>>()
                .join(" ");
            anyhow::anyhow!("push-event write failed for {repo_id} ({rows}): {e}")
        })?;
    }
    Ok(())
}

/// The detached post-receive replication tail (#174 F2): everything a landed push
/// still owes after its git response has been returned: the replication decision,
/// the per-repo-coalesced pin/encrypt task, and this push's own Pinata + announce
/// task. Split out of `git_receive_pack` so the ordering the coalescing gate depends
/// on is directly testable; the handler spawns it and returns.
/// Deferred-replication entry: the drain spawns this for aggregates that
/// complete without ever having a live tail (capability-free pushes whose
/// landing reconcile proved). `pub(crate)` so the drain can call it; the
/// live handler is the other caller.
pub(crate) async fn post_receive_replication_tail(
    state: AppState,
    record: RepoRecord,
    ref_updates: Vec<RefUpdate>,
    disk_path: std::path::PathBuf,
    did: String,
    publish_durability: Option<
        Arc<std::sync::Mutex<Option<crate::git::repo_store::ReleaseOutcome>>>,
    >,
) {
    let durability_wait = std::time::Duration::from_secs(
        state
            .config
            .lock_held_transfer_timeout_secs
            .saturating_add(5),
    );
    if !publish_durability_confirmed(&publish_durability, durability_wait).await {
        tracing::warn!(
            repo = %record.id,
            "skipping post-receive tail: publish durability was not confirmed"
        );
        return;
    }

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
                        pinata_git_timeout,
                        object_list,
                        &db_clone,
                        &repo_id,
                        crate::ipfs_pin::PIN_BATCH_BUDGET,
                        // Push path: no sweep-style batch snapshot to fence (see
                        // PolicyFence's doc).
                        None,
                    )
                    .await,
                )
            } else {
                (
                    false,
                    crate::ipfs_pin::PinBatchOutcome {
                        confirmed: Vec::new(),
                        last_attempted: None,
                    },
                )
            };

            if !pinned.confirmed.is_empty() {
                tracing::info!(
                    count = pinned.confirmed.len(),
                    "pinned git objects to Pinata"
                );
            }

            // Build sha→cid map from durably recorded pins only: an
            // unconfirmed provider upload must not drive branch/gossip CID
            // state for a row the resolver cannot serve.
            let cid_map: std::collections::HashMap<String, String> =
                pinned.confirmed.into_iter().collect();

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
                            v: crate::p2p::CURRENT_REF_UPDATE_VERSION,
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
                            sig: None,
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
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &repo, caller, "/").await?;

    // Build the filter from the canonical stored slug, NOT from the raw path
    // segments. `branch_cids.repo` is written as
    // `{normalize_owner_key(owner_did)}/{name}` (the push path builds the same
    // slug before calling `upsert_branch_cid`), and
    // `get_repo` resolves both `did:key:zX` and bare `zX` to the same record, so
    // a request in the full-DID form authorizes and then matches zero rows,
    // returning an empty page with a 200.
    let repo_slug = format!(
        "{}/{}",
        crate::db::normalize_owner_key(&record.owner_did),
        record.name
    );
    let refs = state.db.list_branch_cids(&repo_slug).await?;

    Ok(Json(
        serde_json::json!({ "refs": refs, "count": refs.len() }),
    ))
}

struct FederatedPeerRepos {
    node_url: String,
    node_did: String,
    repos: Vec<serde_json::Value>,
    truncated: bool,
}

struct FederatedPeerPage {
    repos: Vec<serde_json::Value>,
    truncated: bool,
}

struct BoundedFederatedPeerRows(Vec<serde_json::Value>, bool);

impl<'de> serde::Deserialize<'de> for BoundedFederatedPeerRows {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct RowsVisitor;

        impl<'de> serde::de::Visitor<'de> for RowsVisitor {
            type Value = BoundedFederatedPeerRows;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a bounded array of repository objects")
            }

            fn visit_seq<A>(self, mut rows: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut repos = Vec::with_capacity(MAX_FEDERATED_PEER_REPOS);
                while repos.len() < MAX_FEDERATED_PEER_REPOS {
                    let Some(repo) = rows.next_element::<serde_json::Value>()? else {
                        return Ok(BoundedFederatedPeerRows(repos, false));
                    };
                    if !repo.is_object() {
                        return Err(<A::Error as serde::de::Error>::custom(
                            "peer repository row is not an object",
                        ));
                    }
                    repos.push(repo);
                }
                let mut truncated = false;
                while rows.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    truncated = true;
                }
                Ok(BoundedFederatedPeerRows(repos, truncated))
            }
        }

        deserializer.deserialize_seq(RowsVisitor)
    }
}

struct FederatedRepoBudget {
    repos: Vec<serde_json::Value>,
    json_bytes: usize,
    max_repos: usize,
    max_json_bytes: usize,
    truncated: bool,
}

impl FederatedRepoBudget {
    fn new(capacity: usize, max_repos: usize, max_json_bytes: usize) -> Self {
        Self {
            repos: Vec::with_capacity(capacity.min(max_repos)),
            json_bytes: FEDERATED_RESPONSE_OVERHEAD_BYTES,
            max_repos,
            max_json_bytes,
            truncated: false,
        }
    }

    fn push(&mut self, repo: serde_json::Value) -> bool {
        if self.is_saturated() {
            self.truncated = true;
            return false;
        }
        let Ok(repo_bytes) = serde_json::to_vec(&repo) else {
            return true;
        };
        let charged = repo_bytes.len().saturating_add(1);
        if self.json_bytes.saturating_add(charged) > self.max_json_bytes {
            self.truncated = true;
            return false;
        }
        self.json_bytes += charged;
        self.repos.push(repo);
        true
    }

    fn is_saturated(&self) -> bool {
        self.repos.len() >= self.max_repos || self.json_bytes >= self.max_json_bytes
    }
}

async fn fetch_federated_peer_repos(
    client: &reqwest::Client,
    url: &str,
) -> Option<FederatedPeerPage> {
    let mut response = client.get(url).send().await.ok()?;
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|len| len > MAX_FEDERATED_PEER_BYTES as u64)
    {
        return None;
    }
    let total = response
        .headers()
        .get("x-total-count")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok());

    let capacity = response
        .content_length()
        .and_then(|len| usize::try_from(len).ok())
        .unwrap_or(0)
        .min(MAX_FEDERATED_PEER_BYTES);
    let mut body = Vec::with_capacity(capacity);
    while let Some(chunk) = response.chunk().await.ok()? {
        if body.len().saturating_add(chunk.len()) > MAX_FEDERATED_PEER_BYTES {
            return None;
        }
        body.extend_from_slice(&chunk);
    }

    let BoundedFederatedPeerRows(repos, overflow) = serde_json::from_slice(&body).ok()?;
    let truncated = overflow || total.is_some_and(|total| total > repos.len() as u64);
    Some(FederatedPeerPage { repos, truncated })
}

fn enrich_federated_repo(
    mut repo: serde_json::Value,
    node_url: &str,
    node_did: &str,
) -> Option<serde_json::Value> {
    let object = repo.as_object_mut()?;
    object.insert(
        "node_url".to_string(),
        serde_json::Value::String(node_url.to_string()),
    );
    object.insert(
        "node_did".to_string(),
        serde_json::Value::String(node_did.to_string()),
    );
    object.insert("local".to_string(), serde_json::Value::Bool(false));
    Some(repo)
}

async fn collect_federated_fetches<I, F>(fetches: I, aggregate: &mut FederatedRepoBudget) -> usize
where
    I: IntoIterator<Item = F>,
    F: Future<Output = Option<FederatedPeerRepos>>,
{
    let mut responses = stream::iter(fetches).buffer_unordered(FEDERATED_PEER_CONCURRENCY);
    let mut nodes_queried = 0;

    let deadline = tokio::time::Instant::now() + FEDERATED_AGGREGATE_DEADLINE;
    loop {
        let response = match tokio::time::timeout_at(deadline, responses.next()).await {
            Ok(Some(response)) => response,
            Ok(None) => break,
            Err(_) => {
                aggregate.truncated = true;
                tracing::warn!("federated aggregation deadline exceeded");
                break;
            }
        };
        let Some(response) = response else {
            aggregate.truncated = true;
            tracing::warn!("federated peer fetch failed or exceeded its response limits");
            continue;
        };
        nodes_queried += 1;
        aggregate.truncated |= response.truncated;
        for repo in response.repos {
            let Some(repo) = enrich_federated_repo(repo, &response.node_url, &response.node_did)
            else {
                continue;
            };
            if !aggregate.push(repo) || aggregate.is_saturated() {
                aggregate.truncated = true;
                return nodes_queried;
            }
        }
    }

    nodes_queried
}

/// GET /api/v1/repos/federated
///
/// Query all known peers for their public repos and return a merged view of
/// the network. Each repo includes a `node_url` and `node_did` indicating
/// which node hosts it. Peer work is bounded by `FEDERATED_AGGREGATE_DEADLINE`
/// and `MAX_FEDERATED_PEERS`; omitted
/// results set `truncated`. The route admits 12 requests per minute per client IP.
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

    let mut aggregate = FederatedRepoBudget::new(
        local_repos.len(),
        MAX_FEDERATED_REPOS,
        MAX_FEDERATED_REPO_JSON_BYTES,
    );
    for (r, count) in &local_repos {
        let Ok(mut repo) = serde_json::to_value(to_response(r, &state, *count)) else {
            continue;
        };
        repo["node_url"] = serde_json::Value::String(local_node_url.clone());
        repo["node_did"] = serde_json::Value::String(local_node_did.clone());
        repo["local"] = serde_json::Value::Bool(true);
        if !aggregate.push(repo) || aggregate.is_saturated() {
            aggregate.truncated = true;
            break;
        }
    }

    // Keep peer work bounded even when the table contains many reachable rows.
    // Dropping the buffered stream at the aggregate ceiling cancels its in-flight
    // request futures and leaves the remaining iterator entries unpolled.
    // One extra row detects omitted peers without materializing the full table.
    let mut peers = state
        .db
        .list_federation_peers(MAX_FEDERATED_PEERS as i64 + 1)
        .await?;
    aggregate.truncated |= peers.len() > MAX_FEDERATED_PEERS;
    peers.truncate(MAX_FEDERATED_PEERS);
    let fetches: Vec<_> = peers
        .into_iter()
        .filter(|p| p.last_ping_ok && !p.http_url.is_empty())
        .map(|peer| {
            let client = Arc::clone(&state.http_client);
            let url = format!(
                "{}/api/v1/repos?limit={MAX_FEDERATED_PEER_REPOS}&offset=0",
                peer.http_url.trim_end_matches('/')
            );
            let peer_did = peer.did.clone();
            let peer_url = peer.http_url.clone();
            async move {
                tokio::time::timeout(
                    FEDERATED_PEER_TIMEOUT,
                    fetch_federated_peer_repos(&client, &url),
                )
                .await
                .ok()
                .flatten()
                .map(|page| FederatedPeerRepos {
                    node_url: peer_url,
                    node_did: peer_did,
                    repos: page.repos,
                    truncated: page.truncated,
                })
            }
        })
        .collect();

    let peer_nodes_queried = if aggregate.is_saturated() {
        0
    } else {
        collect_federated_fetches(fetches, &mut aggregate).await
    };

    let count = aggregate.repos.len();
    let truncated = aggregate.truncated;
    Ok(Json(serde_json::json!({
        "repos": aggregate.repos,
        "count": count,
        "nodes_queried": 1 + peer_nodes_queried,
        "truncated": truncated,
    })))
}

// ── Fork ──────────────────────────────────────────────────────────────────

/// Removes a fork's local mirror clone on every exit until disarmed after the
/// database row commits — but ONLY while that clone still belongs to the attempt
/// the guard was built for.
///
/// The bare `remove_dir_all` this replaces authorized itself with the path alone.
/// Two attempts at the same logical fork share one path, so a failed attempt
/// unwinding late could remove the directory a successor had already published
/// and inserted a row for.
struct ForkCloneGuard {
    path: Option<PathBuf>,
    attempt: crate::git::publish::PublishAttemptId,
}

const FORK_CREATE_CONFIRM_ATTEMPTS: u32 = 5;

/// Who owns the logical fork name once `create_repo` has reported an error.
///
/// The distinction the previous `Option<RepoRecord>` could not draw is between
/// "my insert committed" and "somebody's insert committed". Only the first
/// entitles this request to answer 201 with that row, and only the third
/// entitles it to compensate.
enum ForkRowConfirmation {
    /// THIS attempt's row is present: the insert committed and the error was a
    /// transport-level report of a successful write.
    Ours(Box<crate::db::RepoRecord>),
    /// A different attempt owns the name. This request's archive, disk path and
    /// fork provenance do not belong to that row, so it must not be returned,
    /// and that attempt's resources must not be compensated.
    Foreign,
    /// Nothing owns the name.
    Absent,
}

/// After `create_repo` fails, re-read the row with bounded retries so a
/// transport-level error does not skip archive compensation when the insert never
/// landed, and so a successful insert is not mistaken for a failure.
///
/// Keyed on `record_id` FIRST. Owner/name identifies a namespace, not an attempt:
/// a concurrent ordinary create, a mirror registration or a retry can insert a
/// different row under the same logical name, and treating that as proof of our
/// own commit returned 201 carrying somebody else's row.
async fn confirm_fork_repo_row(
    db: &crate::db::Db,
    record_id: &str,
    owner_short: &str,
    fork_name: &str,
) -> anyhow::Result<ForkRowConfirmation> {
    let mut delay = std::time::Duration::from_millis(25);
    for attempt in 0..FORK_CREATE_CONFIRM_ATTEMPTS {
        let looked_up = async {
            if let Some(ours) = db.get_repo_by_id(record_id).await? {
                return Ok::<_, anyhow::Error>(ForkRowConfirmation::Ours(Box::new(ours)));
            }
            Ok(match db.get_repo(owner_short, fork_name).await? {
                Some(_) => ForkRowConfirmation::Foreign,
                None => ForkRowConfirmation::Absent,
            })
        }
        .await;
        match looked_up {
            Ok(confirmation) => return Ok(confirmation),
            Err(e) if attempt + 1 < FORK_CREATE_CONFIRM_ATTEMPTS => {
                tracing::warn!(
                    fork = %fork_name,
                    attempt,
                    err = %e,
                    "fork create_repo confirmation lookup failed — retrying"
                );
                tokio::time::sleep(delay).await;
                delay = delay
                    .saturating_mul(2)
                    .min(std::time::Duration::from_secs(1));
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!("loop returns on every attempt")
}

/// When the confirmation lookup stays unavailable after bounded retries, keep
/// retrying in the background and compensate only after establishing that no row
/// exists for this fork name.
///
/// The `None` observation is still racy on its own — a successor can commit
/// between the read and the deletions, and did, which let recovery for a failed
/// fork erase a succeeding attempt's repository. What makes it safe is that the
/// compensation it calls is now conditional on the object and the directory still
/// carrying THIS attempt's identity, so a successor that commits at any point
/// after the read keeps both.
#[allow(clippy::too_many_arguments)]
async fn schedule_fork_create_recovery(
    db: std::sync::Arc<crate::db::Db>,
    repo_store: crate::git::repo_store::RepoStore,
    record_id: String,
    owner_short: String,
    fork_name: String,
    owner_did: String,
    disk_path: std::path::PathBuf,
    attempt: crate::git::publish::PublishAttemptId,
) {
    let mut delay = std::time::Duration::from_millis(250);
    for n in 0..12 {
        match confirm_fork_repo_row(&db, &record_id, &owner_short, &fork_name).await {
            Ok(ForkRowConfirmation::Ours(_)) => {
                tracing::info!(
                    fork = %fork_name,
                    attempt = n,
                    "fork create_repo recovery found this attempt's row — no compensation"
                );
                return;
            }
            Ok(ForkRowConfirmation::Foreign) => {
                tracing::info!(
                    fork = %fork_name,
                    attempt = n,
                    "fork create_repo recovery found another attempt's row under this name — \
                     compensating only what this attempt still owns"
                );
                repo_store
                    .compensate_fork_archive(&owner_did, &fork_name, disk_path.as_path(), &attempt)
                    .await;
                return;
            }
            Ok(ForkRowConfirmation::Absent) => {
                tracing::warn!(
                    fork = %fork_name,
                    attempt = n,
                    "fork create_repo recovery confirmed no row — compensating orphan archive"
                );
                repo_store
                    .compensate_fork_archive(&owner_did, &fork_name, disk_path.as_path(), &attempt)
                    .await;
                return;
            }
            Err(e) if n + 1 < 12 => {
                tracing::warn!(
                    fork = %fork_name,
                    attempt = n,
                    err = %e,
                    "fork create_repo recovery lookup failed — retrying"
                );
                tokio::time::sleep(delay).await;
                delay = delay
                    .saturating_mul(2)
                    .min(std::time::Duration::from_secs(30));
            }
            Err(e) => {
                tracing::error!(
                    fork = %fork_name,
                    err = %e,
                    "fork create_repo recovery gave up — orphan archive may remain until operator cleanup"
                );
                return;
            }
        }
    }
}

impl ForkCloneGuard {
    fn new(
        path: crate::git::repo_store::ValidatedRepoDiskPath,
        attempt: crate::git::publish::PublishAttemptId,
    ) -> Self {
        let path = path.into_path_buf();
        // Stamp the directory before anything can fail, so every later cleanup
        // (this guard's Drop, the handler's compensation, the background
        // recovery) has an ownership answer to consult.
        crate::git::repo_store::claim_fork_disk_path(&path, &attempt);
        Self {
            path: Some(path),
            attempt,
        }
    }

    fn path(&self) -> &std::path::Path {
        self.path
            .as_deref()
            .expect("fork clone guard disarmed while still in use")
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for ForkCloneGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            crate::git::repo_store::remove_fork_clone_if_ours(
                &path,
                &self.attempt,
                "fork attempt cleanup",
            );
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ForkRepoRequest {
    pub name: Option<String>, // defaults to source repo name
}

/// POST /api/v1/repos/:owner/:repo/fork
/// Argv for the fork's mirror clone, with `--` before the first positional (#374).
///
/// Both positionals here are server-derived paths rather than caller-supplied
/// URLs, so this is defence in depth rather than a reachable injection. It is
/// still the same argv contract as the other clone sites, and it is extracted for
/// the same reason: so the delimiter's placement is pinned by a test instead of
/// resting on review.
fn fork_clone_args<'a>(source: &'a str, dest: &'a str) -> [&'a str; 5] {
    ["clone", "--mirror", "--", source, dest]
}

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

    validate_repo_name(&fork_name)?;

    // Same barrier every other repo-creation route goes through. The character
    // allowlist above is vacuously true on an empty name, and `repo_disk_path`
    // is a raw join, so without this a `{"name":""}` fork lands a row with an
    // empty name at `<repos_dir>/<owner_slug>/.git`. Closed #272 fixed this
    // class on the sync route and never scoped fork.
    //
    // It runs with the other admissibility checks, above the proof spend and the
    // source acquire, because the header comment promises that a fork rejected
    // for a bad name never burns a valid proof. The two name rules are kept
    // separate on purpose: neither is a subset of the other, since the allowlist
    // above rejects a dot (`v1.2.3`) that `validate_repo_name` accepts, and
    // accepts a non-ASCII alphanumeric that it rejects.
    let disk_path = crate::git::repo_store::validated_repo_disk_path(
        &state.config.repos_dir,
        &forker_did,
        &fork_name,
    )
    .map_err(|e| AppError::BadRequest(e.to_string()))?;

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

    // Clone the source repo as a mirror
    let output = std::process::Command::new("git")
        .args(fork_clone_args(
            source_path.to_str().unwrap_or(""),
            disk_path.to_str().unwrap_or(""),
        ))
        .output()
        .map_err(|e| AppError::Git(format!("git clone --mirror failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::Git(format!(
            "git clone --mirror failed: {stderr}"
        )));
    }

    // ONE identity for the whole workflow: the DB row id this request will
    // insert is also the attempt id stamped into the object's metadata and onto
    // the disk clone. That is what lets confirmation ask "is my row there" rather
    // than "is a row there", and lets every cleanup ask "is this still mine"
    // rather than "does this name resolve".
    let record_id = Uuid::new_v4().to_string();
    let attempt = crate::git::publish::PublishAttemptId::from_owned(record_id.clone());

    let mut clone_guard = ForkCloneGuard::new(disk_path.clone(), attempt.clone());

    // Upload fork to Tigris. Create-only: a refused precondition means an orphan
    // archive already sits under this key (a failed create_repo or another
    // writer), and proceeding would create a DB record whose archive is shadowed
    // by bytes that are not this fork. Refuse rather than accept a fork other
    // nodes would fetch as unrelated content. The clone guard removes the local
    // mirror on every DEFINITE upload failure path.
    if let Err(e) = state
        .repo_store
        .release_after_write(&forker_did, &fork_name, &attempt)
        .await
    {
        match e {
            crate::git::tigris::UploadError::PreconditionLost { status } => {
                // One reconciliation before refusing: an SDK-level retry, or a
                // duplicated dispatch, can land THIS attempt's bytes and then see
                // the create-only fence refuse the second copy. The stored object
                // carrying our own attempt id says the publish succeeded, and
                // refusing it would fence the fork name behind our own work.
                match state
                    .repo_store
                    .fork_attempt_landed(&forker_did, &fork_name, &attempt)
                    .await
                {
                    Ok(true) => {
                        tracing::info!(
                            fork = %fork_name,
                            status,
                            "fork create-only PUT was refused but the stored archive is this \
                             attempt's own — continuing"
                        );
                    }
                    Ok(false) => {
                        tracing::warn!(
                            forker = %forker_did,
                            fork = %fork_name,
                            status,
                            "fork refused: an archive already exists under the fork's key"
                        );
                        return Err(AppError::RepoExists(fork_name.clone()));
                    }
                    // The store could not be asked whether the stored archive is ours,
                    // so "not ours" is not an answer we have. Reporting a permanent name
                    // conflict from a transient store failure sends the client away from
                    // a name that may well be free; refuse retryably instead.
                    //
                    // The clone guard is deliberately NOT disarmed here. Unlike the
                    // ambiguous arm below, a lost precondition proves this attempt's PUT
                    // was refused, so the local clone protects nothing the store does not
                    // already hold. Keeping it would wedge the fork name: the retry this
                    // 503 invites re-clones into the same destination and fails because
                    // it exists, and the leftover carries a dead attempt's stamp that no
                    // cleanup will ever claim. Let Drop remove it.
                    Err(e) => {
                        tracing::warn!(
                            forker = %forker_did,
                            fork = %fork_name,
                            status,
                            err = %e,
                            "fork refused retryably: the store could not be asked whether the \
                             archive under the fork's key is this attempt's own"
                        );
                        return Err(AppError::RepoUnavailable);
                    }
                }
            }
            crate::git::tigris::UploadError::NotPublished(other) => {
                // Proven not to have committed. Dropping the clone (on the
                // guard's Drop) is safe, and the fork name is left free.
                return Err(AppError::Git(format!("fork upload failed: {other:#}")));
            }
            crate::git::tigris::UploadError::Ambiguous { source, .. } => {
                // THE DURABLE FAILURE MODE. The create-only PUT can commit and
                // the response can still be lost or unparseable. Compensating
                // that as a definite failure dropped the only local clone and
                // skipped the DB insert, and every retry then saw the orphan
                // object and returned RepoExists — the fork name unusable until
                // an operator intervened.
                //
                // Ask the store instead. The attempt id travelled with the bytes,
                // so "did MY write land" is answerable even when "did my request
                // succeed" is not.
                match state
                    .repo_store
                    .fork_attempt_landed(&forker_did, &fork_name, &attempt)
                    .await
                {
                    Ok(true) => {
                        tracing::warn!(
                            fork = %fork_name,
                            err = %source,
                            "fork upload lost its response but the stored archive is this \
                             attempt's own — recovering the committed publish"
                        );
                    }
                    // Not (yet) ours, or unreachable. The request may still be in
                    // flight, so nothing here may be destroyed: keep the clone,
                    // keep whatever is stored, and refuse retryably. Disarming the
                    // guard is what preserves the only local copy.
                    Ok(false) | Err(_) => {
                        clone_guard.disarm();
                        tracing::warn!(
                            forker = %forker_did,
                            fork = %fork_name,
                            err = %source,
                            "fork upload outcome is unknowable — leaving the clone and any \
                             stored object in place for reconciliation rather than \
                             compensating a write that may have landed"
                        );
                        return Err(AppError::RepoUnavailable);
                    }
                }
            }
        }
    }

    let now = Utc::now();
    let record = crate::db::RepoRecord {
        id: record_id.clone(),
        name: fork_name.clone(),
        owner_did: forker_did.clone(),
        description: source.description.clone(),
        is_public: source.is_public,
        default_branch: source.default_branch.clone(),
        created_at: now,
        updated_at: now,
        disk_path: clone_guard.path().to_string_lossy().to_string(),
        forked_from: Some(source.id.clone()),
        machine_id: state.machine_id.clone(),
    };

    if let Err(e) = state.db.create_repo(&record).await {
        match confirm_fork_repo_row(&state.db, &record_id, forker_short, &fork_name).await {
            Ok(ForkRowConfirmation::Ours(committed)) => {
                clone_guard.disarm();
                tracing::warn!(
                    fork = %fork_name,
                    forker = %forker_did,
                    "fork create_repo returned an error but THIS attempt's row is present — treating as success"
                );
                return Ok((
                    StatusCode::CREATED,
                    Json(to_response(&committed, &state, 0)),
                ));
            }
            Ok(ForkRowConfirmation::Foreign) => {
                // A concurrent create, mirror registration or retry owns the
                // name. Returning its row would hand this caller a repository
                // whose archive, disk path and fork provenance are not the ones
                // this request produced. Refuse, and compensate only what this
                // attempt still owns — the guard and `compensate_fork_archive`
                // both check ownership, so the successor's object and directory
                // survive.
                tracing::warn!(
                    fork = %fork_name,
                    forker = %forker_did,
                    "fork create_repo lost the name to another attempt — refusing rather than \
                     claiming its row"
                );
                clone_guard.disarm();
                state
                    .repo_store
                    .compensate_fork_archive(&forker_did, &fork_name, disk_path.as_path(), &attempt)
                    .await;
                return Err(AppError::RepoExists(fork_name.clone()));
            }
            Ok(ForkRowConfirmation::Absent) => {
                clone_guard.disarm();
                state
                    .repo_store
                    .compensate_fork_archive(&forker_did, &fork_name, disk_path.as_path(), &attempt)
                    .await;
                return Err(e.into());
            }
            Err(lookup_err) => {
                clone_guard.disarm();
                let db = std::sync::Arc::clone(&state.db);
                let repo_store = state.repo_store.clone();
                let owner_short = forker_short.to_string();
                let fork_name_cl = fork_name.clone();
                let owner_did = forker_did.clone();
                let disk_path_cl = disk_path.as_path().to_path_buf();
                let record_id_cl = record_id.clone();
                let attempt_cl = attempt.clone();
                tokio::spawn(async move {
                    schedule_fork_create_recovery(
                        db,
                        repo_store,
                        record_id_cl,
                        owner_short,
                        fork_name_cl,
                        owner_did,
                        disk_path_cl,
                        attempt_cl,
                    )
                    .await;
                });
                tracing::warn!(
                    fork = %fork_name,
                    create_err = %e,
                    lookup_err = %lookup_err,
                    "fork create_repo failed and confirmation lookup stayed unavailable — scheduled recovery"
                );
                return Err(AppError::RepoUnavailable);
            }
        }
    }

    clone_guard.disarm();
    // The row is committed: this directory is now the repository, not an
    // attempt's staging area, and nothing may ever compensate it away.
    crate::git::repo_store::release_fork_disk_claim(disk_path.as_path());

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

// ── Drop guard for stranded intents ──────────────────────────────────────

/// Phase-aware drop-guard that terminalizes a durable intent when the handler
/// future is dropped. Two uncovered spans need two cleanups:
/// - Dropped before git starts (lease park, `acquire_write`, prereq checks,
///   marker write, or a commit landing inside the insert-timeout cancellation
///   window): no git evidence can exist, so refuse the aggregate outright —
///   parent to `rejected_at_git`, `prepared` children to `cancelled`.
/// - Dropped after git starts (the whole `receive_pack` await and the outcome
///   commit): git may have landed refs, so commit the stashed fates when the
///   report was already parsed (proven rejections go `cancelled`, unknowns
///   `uncertain`); with no fates, mark `prepared` children `uncertain` and
///   terminalize the parent, mirroring the `receive_pack` Err arm for a
///   drop that can never reach it. Startup reconcile still promotes proved
///   children of a `rejected_at_git` parent.
///
/// Arm before the intent insert resolves (the refuse is a no-op on an
/// uncommitted id), move to git-started immediately before awaiting
/// `receive_pack`, stash computed fates once the report is parsed, and disarm
/// once the outcome commit resolves. A sync Drop cannot await, so cleanup is
/// spawned like `KillGroupOnDrop` and `RepoWriteGuard` do: prefer the current
/// runtime handle, and with no runtime (off-runtime drop, process teardown)
/// log loudly instead of panicking on a bare `tokio::spawn`. The spawned
/// cleanup retries with backoff until the aggregate leaves `received`
/// (see `retry_guard_cleanup`): a single shot can lose the race the early
/// arming was meant to close.
struct IntentDropGuard {
    db: std::sync::Arc<crate::db::Db>,
    request_id: String,
    phase: std::sync::Arc<std::sync::atomic::AtomicU8>,
    fates: std::sync::Arc<std::sync::Mutex<Option<ComputedFates>>>,
}

const INTENT_PHASE_PRE_GIT: u8 = 0;
const INTENT_PHASE_GIT_STARTED: u8 = 1;
const INTENT_PHASE_DONE: u8 = 2;

impl IntentDropGuard {
    fn new(db: std::sync::Arc<crate::db::Db>, request_id: String) -> Self {
        Self {
            db,
            request_id,
            phase: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(INTENT_PHASE_PRE_GIT)),
            fates: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Stash the computed outcome fates once git's report is parsed, so a
    /// later drop commits fates instead of a blanket `uncertain`.
    fn set_fates(&self, fates: ComputedFates) {
        if let Ok(mut slot) = self.fates.lock() {
            *slot = Some(fates);
        }
    }

    /// Call immediately before awaiting `receive_pack`: from here a drop is a
    /// mid-git disconnect, not a pre-git shed.
    fn notify_git_started(&self) {
        self.phase.store(
            INTENT_PHASE_GIT_STARTED,
            std::sync::atomic::Ordering::Release,
        );
    }

    fn disarm(&self) {
        self.phase
            .store(INTENT_PHASE_DONE, std::sync::atomic::Ordering::Release);
    }
}

/// Owned per-ref outcome fates computed from git's report-status, stashed on
/// the drop-guard so a post-git drop commits them instead of a context-free
/// blanket `uncertain`. A guard that only knows "git started" would flip even
/// git-proven rejections to `uncertain`, which reconcile can never resolve
/// (a rejected ref never lands, so no proof can exist) — they would linger
/// until an operator path. With fates, rejections go straight to `cancelled`
/// (terminal, purgeable) and only genuinely unknown refs stay `uncertain`.
#[derive(Clone)]
struct ComputedFates {
    ok_names: Vec<String>,
    ng_names: Vec<String>,
    uncertain_names: Vec<String>,
    unpack_failed: bool,
    git_exit_ok: bool,
    parsed_json: Option<serde_json::Value>,
    accepted_ordinal: Option<i32>,
    rejected_reason: Option<String>,
    terminal_no_effects: bool,
}

/// Spawned drop-guard cleanup with bounded retry. A single shot can evaluate
/// the `state = 'received'` gate before a racing commit lands (the
/// insert-timeout cancellation window) or hit a transient DB error — either
/// strands permanently since nothing re-drives it. Retry with short backoff
/// until a live aggregate leaves `received`; a missing row retries until the
/// budget expires instead, since it may be an insert whose commit has not
/// landed yet. The budget covers the 30s intent-insert lifetime, so a commit
/// landing inside the cancellation window is always observed.
///
/// Each attempt is bounded 10s like the sibling cleanups: a lock-blocked
/// `commit_request_outcomes_atomically` (awaited bare, unbounded inside) must
/// not park the spawned task and its pool connection past the budget — the
/// case the bound exists for. The existing warn arm retries inside the budget.
async fn retry_guard_cleanup(
    db: &std::sync::Arc<crate::db::Db>,
    request_id: &str,
    post_git: bool,
    fates: Option<ComputedFates>,
) {
    retry_guard_cleanup_with_budget(
        db,
        request_id,
        post_git,
        fates,
        std::time::Duration::from_secs(30),
    )
    .await
}

/// Budget-parameterized core of [`retry_guard_cleanup`]; the wrapper above
/// supplies the production 30s, tests supply milliseconds.
async fn retry_guard_cleanup_with_budget(
    db: &std::sync::Arc<crate::db::Db>,
    request_id: &str,
    post_git: bool,
    fates: Option<ComputedFates>,
    budget: std::time::Duration,
) {
    const ATTEMPT_CAP: std::time::Duration = std::time::Duration::from_secs(10);
    let start = std::time::Instant::now();
    let mut delay = std::time::Duration::from_millis(100);
    loop {
        if start.elapsed() >= budget {
            tracing::warn!(
                request_id = %request_id,
                "drop-guard cleanup budget exhausted with aggregate still uncommitted/received"
            );
            return;
        }
        // Every DB round is bounded, and each bound is clamped to the
        // remaining budget: a fixed 10s attempt (or an unbounded state
        // read) could otherwise overshoot the budget by a whole window,
        // parking the spawned task and its pool connection past it.
        let slice = std::cmp::min(ATTEMPT_CAP, budget - start.elapsed());
        enum Check {
            Missing,
            Terminal,
            Received,
            Unknown,
        }
        let check = match tokio::time::timeout(slice, db.get_receive_pack_request(request_id)).await
        {
            Err(_) => {
                tracing::warn!(
                    request_id = %request_id,
                    "drop-guard state check timed out; retrying within budget"
                );
                Check::Unknown
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    err = %e,
                    request_id = %request_id,
                    "drop-guard state check failed; retrying within budget"
                );
                Check::Unknown
            }
            Ok(Ok(None)) => Check::Missing,
            Ok(Ok(Some(req))) if req.state != crate::db::request_state::RECEIVED => Check::Terminal,
            Ok(Ok(Some(_))) => Check::Received,
        };
        match check {
            Check::Terminal => return,
            // Missing (uncommitted or purged) and Unknown (failed read):
            // only the budget decides; a missing row may be an insert
            // whose commit has not landed yet.
            Check::Missing | Check::Unknown => {}
            Check::Received => {
                let remaining = budget.saturating_sub(start.elapsed());
                if remaining.is_zero() {
                    tracing::warn!(
                        request_id = %request_id,
                        "drop-guard cleanup budget exhausted with aggregate still received"
                    );
                    return;
                }
                let run = async {
                    if post_git {
                        match &fates {
                            Some(f) if !(f.terminal_no_effects && f.parsed_json.is_none()) => {
                                let ok: Vec<&str> = f.ok_names.iter().map(String::as_str).collect();
                                let ng: Vec<&str> = f.ng_names.iter().map(String::as_str).collect();
                                let un: Vec<&str> =
                                    f.uncertain_names.iter().map(String::as_str).collect();
                                db.commit_request_outcomes_atomically(
                                    request_id,
                                    &ok,
                                    &ng,
                                    &un,
                                    f.unpack_failed,
                                    f.git_exit_ok,
                                    f.parsed_json.as_ref(),
                                    f.accepted_ordinal,
                                    f.rejected_reason.as_deref(),
                                    f.terminal_no_effects,
                                )
                                .await
                            }
                            _ => db.mark_receive_pack_interrupted(request_id).await,
                        }
                    } else {
                        db.refuse_receive_pack_before_git(
                            request_id,
                            "handler dropped before git started",
                        )
                        .await
                    }
                };
                match tokio::time::timeout(std::cmp::min(ATTEMPT_CAP, remaining), run).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        tracing::warn!(
                            err = %e,
                            request_id = %request_id,
                            "drop-guard cleanup attempt failed; retrying within budget"
                        );
                    }
                    Err(_) => {
                        tracing::warn!(
                            request_id = %request_id,
                            "drop-guard cleanup attempt timed out; retrying within budget"
                        );
                    }
                }
            }
        }
        if start.elapsed() + delay > budget {
            tracing::warn!(
                request_id = %request_id,
                "drop-guard cleanup budget exhausted with aggregate still uncommitted/received"
            );
            return;
        }
        tokio::time::sleep(delay).await;
        delay = std::cmp::min(delay * 2, std::time::Duration::from_secs(5));
    }
}

impl Drop for IntentDropGuard {
    fn drop(&mut self) {
        let phase = self.phase.load(std::sync::atomic::Ordering::Acquire);
        if phase == INTENT_PHASE_DONE {
            return;
        }
        let db = self.db.clone();
        let request_id = self.request_id.clone();
        let post_git = phase == INTENT_PHASE_GIT_STARTED;
        let fates = self.fates.lock().ok().and_then(|mut slot| slot.take());
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    retry_guard_cleanup(&db, &request_id, post_git, fates).await;
                });
            }
            Err(_) => {
                tracing::warn!(
                    request_id = %request_id,
                    phase,
                    "intent drop-guard fired off-runtime; cannot spawn cleanup, intent may strand"
                );
            }
        }
    }
}

// ── Pkt-line parsing ──────────────────────────────────────────────────────

/// True for refnames inside the node-managed namespace: the `refs/gitlawb/`
/// subtree plus the bare `refs/gitlawb` name (no trailing slash), which
/// `starts_with("refs/gitlawb/")` alone misses and which lands on repos with
/// no internal refs yet. Extracted so the gate predicate is unit-testable;
/// the handler denies any push naming such a ref before intent is written.
fn ref_is_internal_namespace(ref_name: &str) -> bool {
    ref_name == "refs/gitlawb" || ref_name.starts_with("refs/gitlawb/")
}

/// Maximum ref commands accepted in one receive-pack body.
///
/// Every accepted entry costs a per-ref branch-protection SELECT plus a
/// durable child row that rides the aggregate into reconcile/quarantine scans
/// until retention. One body (`max_pack_bytes` allows gigabytes, ~24M command
/// lines) could otherwise turn a single request into tens of thousands of
/// pre-lease DB operations, an unbounded durable row set for one signer, and
/// an equally unbounded `Vec<RefUpdate>` of three-String entries — so the cap
/// fires inside the parse loop, bounding the allocation too, not just the
/// downstream work. Sized well above a legitimate mirror push (branches + tags
/// of any realistic repo) while keeping the worst-case pre-intent work at ~8k
/// indexed SELECTs and ~8k child rows — comfortably inside the 30s
/// intent-write guard. A repo needing to move more than this in one push
/// pushes in batches. Pinned from both sides by
/// `receive_pack_refuses_a_ref_update_count_over_the_cap` (over the cap is
/// refused) and `receive_pack_admits_a_ref_update_count_at_the_cap` (exactly
/// at the cap is not).
const MAX_REF_UPDATES: usize = 8192;

/// `Clone` so `git_receive_pack` can hand the parsed updates to the detached
/// replication tail at the durability boundary while the certificate and webhook
/// loops below still iterate their own copy (#174 U5).
#[derive(Clone, Debug)]
pub struct RefUpdate {
    pub(crate) old_sha: String,
    pub(crate) new_sha: String,
    pub(crate) ref_name: String,
}

/// A git object id is 40 hex chars; length alone is not enough, since a peer
/// can send 40 arbitrary bytes (#398).
pub(crate) fn is_hex_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parse git receive-pack pkt-line ref updates from the request body.
/// Format per line: `<40-hex-old> <40-hex-new> <refname>[NUL capabilities]\n`
///
/// Returns `Err` if any command line in the ref-update section is not valid
/// UTF-8. Silently skipping non-UTF-8 lines would allow a pusher to plant
/// refs/gitlawb/* refs (bytes ≥ 0x80 are accepted by git but invisible to
/// the namespace gate and visibility_pack exemption), so the whole push must
/// be refused instead.
///
/// Two more refusals/adjustments happen here so a hostile body is bounded
/// before it is materialized, not after:
/// - Past [`MAX_REF_UPDATES`] command lines the push is refused
///   (`BadRequest`), counting every valid line — a body up to `max_pack_bytes`
///   holds ~24M lines, and building three Strings per entry for all of them
///   before checking would make the cap a post-parse bound only.
/// - Identical commands in one push are dropped: they would derive the same
///   deterministic intent child id, and `pending_ref_transitions` has no
///   `ON CONFLICT`, so the duplicate would fail the whole intent transaction
///   and answer a permanent shape as a retryable `Overloaded`. Git processes
///   the second occurrence of a command as the same no-op anyway.
///
/// Pinned by `receive_pack_refuses_a_ref_update_count_over_the_cap`,
/// `receive_pack_admits_a_ref_update_count_at_the_cap`, and
/// `receive_pack_dedupes_identical_ref_commands_before_intent`.
fn parse_ref_updates(body: &[u8]) -> Result<Vec<RefUpdate>> {
    let mut updates = Vec::new();
    let mut commands = 0usize;
    let mut seen: HashSet<(String, String, String)> = HashSet::new();
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

        // Non-UTF-8 ref-update lines must be refused, not skipped. Git accepts
        // refnames with bytes ≥ 0x80 (e.g. \xff-prefixed), so a skipped line
        // bypasses the refs/gitlawb namespace gate below and lands a blob ref
        // that is invisible to parse_ref_updates yet still served by
        // visibility_pack. Reject the entire push so no such ref reaches git.
        let line = match std::str::from_utf8(data) {
            Ok(s) => s,
            Err(_) => {
                return Err(AppError::BadRequest(
                    "ref-update line is not valid UTF-8; push refused".into(),
                ))
            }
        };

        // Strip capabilities (after NUL) and trailing newline
        let line = line
            .split('\0')
            .next()
            .unwrap_or(line)
            .trim_end_matches('\n');

        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() == 3 && is_hex_sha(parts[0]) && is_hex_sha(parts[1]) {
            commands += 1;
            if commands > MAX_REF_UPDATES {
                return Err(AppError::BadRequest(format!(
                    "too many ref updates in one push: more than {MAX_REF_UPDATES}"
                )));
            }
            let candidate = RefUpdate {
                old_sha: parts[0].to_ascii_lowercase(),
                new_sha: parts[1].to_ascii_lowercase(),
                ref_name: parts[2].to_string(),
            };
            if seen.insert((
                candidate.ref_name.clone(),
                candidate.old_sha.clone(),
                candidate.new_sha.clone(),
            )) {
                updates.push(candidate);
            }
        }
    }

    Ok(updates)
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

    /// #374: the fork path builds its own `git clone --mirror` argv. Driven
    /// through real git so a missing or misplaced `--` fails, matching the
    /// coverage on the `gl clone`, `gl mirror`, and sync sinks.
    #[test]
    fn fork_clone_never_parses_the_source_as_a_git_option() {
        let td = tempfile::TempDir::new().unwrap();
        let dest = td.path().join("fork.git");
        let injected = "--upload-pack=false";

        let out = std::process::Command::new("git")
            .env("LC_ALL", "C")
            .args(fork_clone_args(injected, dest.to_str().unwrap()))
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);

        assert!(!out.status.success(), "an option-shaped source must fail");
        assert!(
            stderr.contains(&format!("repository '{injected}'")),
            "git must name the source as the repository, not consume it as an option: {stderr}"
        );
    }

    use crate::auth::caller_authorized_to_push;
    use crate::error::AppError;
    use gitlawb_core::identity::Keypair;

    const OWNER_DID: &str = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
    const OWNER_SHORT: &str = "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
    const STRANGER_DID: &str = "did:key:z6Mkffonly5tranger0000000000000000000000000000000";

    use crate::git::publish::{PublishAttemptId, PublishStage, PublishStageCell};
    use crate::git::repo_store::ReleaseOutcome;

    /// A slot armed against a stage cell the test drives directly, which is the
    /// only way to reach the abandoned-handler arms without a live push.
    fn armed_slot(stage: PublishStage) -> (PublishDurabilitySlot, Arc<PublishStageCell>) {
        let cell = Arc::new(PublishStageCell::new());
        cell.set(stage);
        let slot = PublishDurabilitySlot::new();
        slot.arm_for_release(Arc::clone(&cell));
        (slot, cell)
    }

    /// P1 FINDING 1, at the type level. A handler cancelled while the archive is
    /// still being compressed has NOT attempted publication: the conditional PUT
    /// is not constructed until compression returns. Recording that as
    /// `UploadUnknowable` is what let the detached tail do IPFS, Pinata, P2P,
    /// GraphQL, Arweave and peer work for refs that exist only in a local write
    /// the store never saw.
    #[test]
    fn slot_drop_during_compression_records_a_definite_non_publication() {
        let (slot, _cell) = armed_slot(PublishStage::PreparingArchive);
        let arc = slot.arc();
        drop(slot);
        assert_eq!(
            *arc.lock().expect("publish durability mutex poisoned"),
            Some(ReleaseOutcome::UploadFailed),
            "a cancellation before the PUT was dispatched must be recorded as a definite \
             non-publication, not as unknowable durability"
        );
    }

    /// The other side of the same boundary: once the request is on the wire, the
    /// outcome genuinely is unknowable, and a `Drop` impl cannot await a HEAD to
    /// resolve it. Unknowable is honest here — and the tail refuses it anyway,
    /// because the tail requires `Released`.
    #[test]
    fn slot_drop_after_dispatch_records_unknowable() {
        let (slot, _cell) = armed_slot(PublishStage::PutDispatched {
            attempt: PublishAttemptId::new(),
        });
        let arc = slot.arc();
        drop(slot);
        assert_eq!(
            *arc.lock().expect("publish durability mutex poisoned"),
            Some(ReleaseOutcome::UploadUnknowable),
            "a dispatched PUT may still commit, so the drop must not claim it definitely failed"
        );
    }

    /// A disconnect AFTER the store acknowledged the publish loses the response,
    /// not the write. The tail must still run: this is the case the stage model
    /// gains over the old flag, which could only ever say "unknowable" here.
    #[test]
    fn slot_drop_after_the_store_acknowledged_records_released() {
        let (slot, _cell) = armed_slot(PublishStage::Published {
            attempt: PublishAttemptId::new(),
            etag: Some("\"e1\"".to_string()),
        });
        let arc = slot.arc();
        drop(slot);
        assert_eq!(
            *arc.lock().expect("publish durability mutex poisoned"),
            Some(ReleaseOutcome::Released),
            "a confirmed publish is durable regardless of what happened to the handler"
        );
    }

    /// A node with no object storage configured has nothing to publish, so the
    /// pack on local disk IS the durable copy and a disconnect must not withhold
    /// the tail. Distinct from `Idle`, where a publish was possible and never
    /// started; collapsing the two turns every Tigris-less deployment's pushes
    /// into un-replicated ones.
    #[test]
    fn slot_drop_with_no_storage_backend_records_released() {
        let (slot, _cell) = armed_slot(PublishStage::NoBackend);
        let arc = slot.arc();
        drop(slot);
        assert_eq!(
            *arc.lock().expect("publish durability mutex poisoned"),
            Some(ReleaseOutcome::Released),
            "with no backend there is no publication to confirm, so the tail must run"
        );
    }

    #[test]
    fn publish_durability_slot_drop_leaves_empty_before_release_starts() {
        let slot = PublishDurabilitySlot::new();
        let arc = slot.arc();
        drop(slot);
        assert_eq!(
            *arc.lock().expect("publish durability mutex poisoned"),
            None,
            "dropping before release starts must not synthesize durability for the tail"
        );
    }

    #[test]
    fn publish_durability_slot_drop_waits_for_contended_mutex() {
        let (slot, _cell) = armed_slot(PublishStage::PutDispatched {
            attempt: PublishAttemptId::new(),
        });
        let arc = slot.arc();
        let holder = {
            let arc = Arc::clone(&arc);
            std::thread::spawn(move || {
                let _guard = arc.lock().expect("publish durability mutex poisoned");
                std::thread::sleep(std::time::Duration::from_millis(100));
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(10));
        drop(slot);
        holder.join().expect("mutex holder thread");
        let outcome = *arc.lock().expect("publish durability mutex poisoned");
        assert_eq!(
            outcome,
            Some(ReleaseOutcome::UploadUnknowable),
            "drop must block until it can install its verdict, not give up on try_lock"
        );
    }

    /// The tail must resolve promptly on an abandoned handler rather than wait
    /// out the whole transfer bound — it just resolves to a REFUSAL now.
    #[tokio::test]
    async fn publish_durability_confirmed_refuses_quickly_after_unrecorded_slot_drop() {
        let start = std::time::Instant::now();
        let (slot, _cell) = armed_slot(PublishStage::PreparingArchive);
        let arc = slot.arc();
        drop(slot);
        let confirmed =
            publish_durability_confirmed(&Some(arc), std::time::Duration::from_millis(50)).await;
        assert!(
            !confirmed,
            "a cancellation before dispatch must not admit the replication tail"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_millis(200),
            "the tail must not wait out the full transfer bound once the slot carries a verdict"
        );
    }

    #[tokio::test]
    async fn publish_durability_confirmed_fails_closed_when_release_never_records() {
        let slot = Arc::new(std::sync::Mutex::new(None));
        let confirmed =
            publish_durability_confirmed(&Some(slot), std::time::Duration::from_millis(30)).await;
        assert!(
            !confirmed,
            "an empty slot after the bounded wait must not admit the tail; only an installed \
             Released outcome may"
        );
    }

    /// P1 FINDING 1, at the gate. The tail replicates to IPFS, Pinata, P2P,
    /// GraphQL, Arweave and peers, all of which publish refs to other nodes. Only
    /// a CONFIRMED publish may license that. `UploadUnknowable` used to pass here,
    /// which is what carried an unattempted (and an unreconciled) write into the
    /// network.
    #[tokio::test]
    async fn publish_durability_confirmed_accepts_only_released() {
        let slot = Arc::new(std::sync::Mutex::new(Some(ReleaseOutcome::Released)));
        assert!(
            publish_durability_confirmed(&Some(slot), std::time::Duration::from_millis(5)).await
        );

        for refused in [
            ReleaseOutcome::UploadUnknowable,
            ReleaseOutcome::UploadFailed,
            ReleaseOutcome::Fenced,
        ] {
            let slot = Arc::new(std::sync::Mutex::new(Some(refused)));
            assert!(
                !publish_durability_confirmed(&Some(slot), std::time::Duration::from_millis(5))
                    .await,
                "{refused:?} is not a confirmed publish and must not admit the tail"
            );
        }
    }

    #[sqlx::test]
    async fn federated_peer_query_is_bounded(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool.clone()).await;
        sqlx::query("INSERT INTO peers (did, http_url, last_ping_ok, announced_at) SELECT 'peer-' || n, 'https://example.com', TRUE, '2026-01-01T00:00:00Z' FROM generate_series(1, $1) n")
            .bind(MAX_FEDERATED_PEERS as i64 + 5)
            .execute(&pool).await.unwrap();
        let peers = state.db.list_federation_peers(i64::MAX).await.unwrap();
        assert_eq!(peers.len(), MAX_FEDERATED_PEERS + 1);
        assert_eq!(state.db.list_federation_peers(2).await.unwrap().len(), 2);
        assert!(state.db.list_federation_peers(0).await.unwrap().is_empty());
    }

    #[sqlx::test]
    async fn federated_route_brakes_repeated_anonymous_requests(pool: sqlx::PgPool) {
        use tower::ServiceExt;
        let mut state = crate::test_support::test_state(pool).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.federated_rate_limiter =
            crate::rate_limit::RateLimiter::new_bounded(1, std::time::Duration::from_secs(60), 10);
        let router = crate::server::build_router(state);
        for n in 0..2 {
            let mut request = axum::http::Request::builder()
                .uri("/api/v1/repos/federated")
                .body(axum::body::Body::empty())
                .unwrap();
            request.extensions_mut().insert(axum::extract::ConnectInfo(
                "203.0.113.42:5000".parse::<std::net::SocketAddr>().unwrap(),
            ));
            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                if n == 0 {
                    StatusCode::OK
                } else {
                    StatusCode::TOO_MANY_REQUESTS
                }
            );
        }
    }

    #[test]
    fn fork_clone_guard_removes_its_own_mirror_on_drop() {
        let root = tempfile::TempDir::new().unwrap();
        let validated = crate::git::repo_store::validated_repo_disk_path(
            root.path(),
            "did:key:testfork",
            "fork",
        )
        .expect("test fork path must validate");
        std::fs::create_dir_all(validated.as_path()).unwrap();
        {
            let _guard = ForkCloneGuard::new(validated.clone(), PublishAttemptId::new());
            assert!(validated.exists());
        }
        assert!(
            !validated.exists(),
            "dropping the fork clone guard must remove the mirror directory it stamped"
        );
    }

    /// P1 FINDING 3, the filesystem half. Two attempts at one logical fork share
    /// a disk path. A late-unwinding attempt must not remove the directory a
    /// SUCCESSOR now owns — the successor has already published its archive and
    /// returned 201 for it.
    #[test]
    fn fork_clone_guard_leaves_a_successors_mirror_alone() {
        let root = tempfile::TempDir::new().unwrap();
        let validated = crate::git::repo_store::validated_repo_disk_path(
            root.path(),
            "did:key:testfork",
            "fork",
        )
        .expect("test fork path must validate");
        std::fs::create_dir_all(validated.as_path()).unwrap();

        let loser = ForkCloneGuard::new(validated.clone(), PublishAttemptId::new());
        // The successor claims the path while the loser is still unwinding.
        let successor = PublishAttemptId::new();
        crate::git::repo_store::claim_fork_disk_path(validated.as_path(), &successor);

        drop(loser);
        assert!(
            validated.exists(),
            "a failed attempt must not delete the directory a successor now owns"
        );
    }

    #[tokio::test]
    async fn federated_route_uses_the_state_owned_bucket_before_database_access() {
        use tower::ServiceExt;
        let mut state = crate::test_support::test_state_lazy();
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.federated_rate_limiter =
            crate::rate_limit::RateLimiter::new_bounded(1, std::time::Duration::from_secs(60), 10);
        assert!(state.federated_rate_limiter.check("203.0.113.42").await);
        // Both routers must use the same exhausted bucket from AppState.
        for router in [
            crate::server::build_router(state.clone()),
            crate::server::build_router(state),
        ] {
            let mut request = axum::http::Request::builder()
                .uri("/api/v1/repos/federated")
                .body(axum::body::Body::empty())
                .unwrap();
            request.extensions_mut().insert(axum::extract::ConnectInfo(
                "203.0.113.42:5000".parse::<std::net::SocketAddr>().unwrap(),
            ));
            let response =
                tokio::time::timeout(std::time::Duration::from_secs(1), router.oneshot(request))
                    .await
                    .expect("the exhausted bucket must reject before accessing the lazy database")
                    .unwrap();
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }

    #[tokio::test]
    async fn federated_aggregate_deadline_returns_partial_results() {
        let mut budget = FederatedRepoBudget::new(0, 1000, MAX_FEDERATED_REPO_JSON_BYTES);
        let fetches =
            (0..8).map(|_| async { std::future::pending::<Option<FederatedPeerRepos>>().await });
        let nodes = tokio::time::timeout(
            FEDERATED_AGGREGATE_DEADLINE + std::time::Duration::from_secs(2),
            collect_federated_fetches(fetches, &mut budget),
        )
        .await
        .expect("the aggregate must stop before the caller deadline");
        assert_eq!(nodes, 0);
        assert!(budget.truncated);
    }

    #[tokio::test]
    async fn federated_peer_response_enforces_byte_and_row_ceilings() {
        let mut row_server = mockito::Server::new_async().await;
        let row_body =
            serde_json::to_string(&vec![serde_json::json!({}); MAX_FEDERATED_PEER_REPOS + 1])
                .unwrap();
        let row_mock = row_server
            .mock("GET", "/api/v1/repos")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(row_body)
            .expect(1)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let page =
            fetch_federated_peer_repos(&client, &format!("{}/api/v1/repos", row_server.url()))
                .await
                .unwrap();
        assert_eq!(page.repos.len(), MAX_FEDERATED_PEER_REPOS);
        assert!(page.truncated);
        row_mock.assert_async().await;

        let byte_body = serde_json::to_string(&vec![serde_json::json!({
            "description": "x".repeat(MAX_FEDERATED_PEER_BYTES)
        })])
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let byte_server = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 1_024];
            let _ = socket.read(&mut request).await.unwrap();
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                         transfer-encoding: chunked\r\nconnection: close\r\n\r\n{:x}\r\n",
                        byte_body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let _ = socket.write_all(byte_body.as_bytes()).await;
            let _ = socket.write_all(b"\r\n0\r\n\r\n").await;
        });

        assert!(
            fetch_federated_peer_repos(&client, &format!("http://{address}/api/v1/repos"))
                .await
                .is_none(),
            "a chunked peer body above the byte ceiling must be omitted without Content-Length"
        );
        byte_server.await.unwrap();
    }

    #[tokio::test]
    async fn federated_peer_total_count_prevents_false_complete_page() {
        let mut server = mockito::Server::new_async().await;
        let body = serde_json::to_string(
            &(0..MAX_FEDERATED_PEER_REPOS)
                .map(|id| serde_json::json!({ "id": id }))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let page_mock = server
            .mock("GET", "/api/v1/repos")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_header("x-total-count", &(MAX_FEDERATED_PEER_REPOS + 1).to_string())
            .with_body(body)
            .expect(1)
            .create_async()
            .await;

        let page = fetch_federated_peer_repos(
            &reqwest::Client::new(),
            &format!("{}/api/v1/repos", server.url()),
        )
        .await
        .expect("the capped peer page is otherwise valid");
        page_mock.assert_async().await;
        assert_eq!(page.repos.len(), MAX_FEDERATED_PEER_REPOS);
        assert!(page.truncated, "the peer total proves another row exists");

        let mut aggregate = FederatedRepoBudget::new(300, 300, MAX_FEDERATED_REPO_JSON_BYTES);
        let nodes = collect_federated_fetches(
            [std::future::ready(Some(FederatedPeerRepos {
                node_url: server.url(),
                node_did: "did:key:peer".to_string(),
                repos: page.repos,
                truncated: page.truncated,
            }))],
            &mut aggregate,
        )
        .await;
        assert_eq!(nodes, 1);
        assert_eq!(aggregate.repos.len(), MAX_FEDERATED_PEER_REPOS);
        assert!(
            aggregate.truncated,
            "the aggregate must not report the paged peer as complete"
        );

        let mut malformed_server = mockito::Server::new_async().await;
        let malformed_mock = malformed_server
            .mock("GET", "/api/v1/repos")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_header("x-total-count", "not-a-count")
            .with_body("[{}]")
            .expect(1)
            .create_async()
            .await;
        let malformed = fetch_federated_peer_repos(
            &reqwest::Client::new(),
            &format!("{}/api/v1/repos", malformed_server.url()),
        )
        .await
        .expect("a malformed optional total must not discard a bounded page");
        malformed_mock.assert_async().await;
        assert!(!malformed.truncated);
        assert_eq!(malformed.repos.len(), 1);
    }

    #[test]
    fn federated_aggregate_stays_inside_row_and_serialized_byte_budgets() {
        let mut rows = FederatedRepoBudget::new(3, 2, 4_096);
        assert!(rows.push(serde_json::json!({ "name": "one" })));
        assert!(rows.push(serde_json::json!({ "name": "two" })));
        assert!(rows.is_saturated());
        assert!(!rows.push(serde_json::json!({ "name": "three" })));
        assert_eq!(rows.repos.len(), 2);
        assert!(rows.truncated);

        let max_bytes = 600;
        let mut bytes = FederatedRepoBudget::new(8, 8, max_bytes);
        while bytes.push(serde_json::json!({ "description": "x".repeat(100) })) {}
        let count = bytes.repos.len();
        let truncated = bytes.truncated;
        let response = serde_json::json!({
            "repos": bytes.repos,
            "count": count,
            "nodes_queried": 1,
            "truncated": truncated,
        });
        assert!(serde_json::to_vec(&response).unwrap().len() <= max_bytes);
        assert!(response["truncated"].as_bool().unwrap());
    }

    struct ActiveFetch {
        active: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Drop for ActiveFetch {
        fn drop(&mut self) {
            self.active
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn federated_collection_bounds_concurrency_and_cancels_at_aggregate_limit() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(AtomicUsize::new(0));
        let mut senders = Vec::new();
        let mut fetches = Vec::new();

        for i in 0..10 {
            let (tx, rx) = tokio::sync::oneshot::channel();
            senders.push(Some(tx));
            let active = Arc::clone(&active);
            let max_active = Arc::clone(&max_active);
            let started = Arc::clone(&started);
            fetches.push(async move {
                started.fetch_add(1, Ordering::SeqCst);
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                max_active.fetch_max(current, Ordering::SeqCst);
                let _active = ActiveFetch { active };
                rx.await.ok()?;
                Some(FederatedPeerRepos {
                    node_url: format!("https://peer-{i}.example"),
                    node_did: format!("did:key:peer-{i}"),
                    repos: vec![serde_json::json!({ "id": i })],
                    truncated: false,
                })
            });
        }

        let task = tokio::spawn(async move {
            let mut aggregate = FederatedRepoBudget::new(1, 1, usize::MAX);
            let nodes = collect_federated_fetches(fetches, &mut aggregate).await;
            (aggregate, nodes)
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while started.load(Ordering::SeqCst) < FEDERATED_PEER_CONCURRENCY {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the bounded fetch window should fill");

        assert_eq!(started.load(Ordering::SeqCst), FEDERATED_PEER_CONCURRENCY);
        assert_eq!(active.load(Ordering::SeqCst), FEDERATED_PEER_CONCURRENCY);
        assert_eq!(
            max_active.load(Ordering::SeqCst),
            FEDERATED_PEER_CONCURRENCY
        );

        senders[0].take().unwrap().send(()).unwrap();
        let (aggregate, nodes) = tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("the aggregate ceiling should stop collection")
            .unwrap();

        assert_eq!(nodes, 1);
        assert_eq!(aggregate.repos.len(), 1);
        assert!(aggregate.truncated);
        assert_eq!(started.load(Ordering::SeqCst), FEDERATED_PEER_CONCURRENCY);
        assert_eq!(
            active.load(Ordering::SeqCst),
            0,
            "in-flight fetches must be dropped"
        );
    }

    async fn json_body(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        serde_json::from_slice(&bytes).expect("json body")
    }

    fn federated_request() -> axum::http::Request<axum::body::Body> {
        let mut request = axum::http::Request::builder()
            .uri("/api/v1/repos/federated")
            .body(axum::body::Body::empty())
            .unwrap();
        request.extensions_mut().insert(axum::extract::ConnectInfo(
            "203.0.113.42:5000".parse::<std::net::SocketAddr>().unwrap(),
        ));
        request
    }

    /// Pins the federated response contract end to end: the envelope fields
    /// (`count`, `nodes_queried`, `truncated`) and the per-repo annotations
    /// (`node_url`, `node_did`, `local`) are asserted on an actual HTTP 200
    /// body driven through `build_router`, not on a self-constructed value.
    /// The seeded repo is deliberately owned by a DID other than the node:
    /// the envelope must carry the node's DID, so a regression that reports
    /// the owner DID instead would fail the `node_did` assertion.
    #[sqlx::test]
    async fn federated_route_envelope_annotates_repos_on_real_200_body(pool: sqlx::PgPool) {
        use tower::ServiceExt;

        let state = crate::test_support::test_state(pool).await;
        let node_did = state.node_did.to_string();
        state
            .db
            .create_repo(&repo_owned_by("did:key:z6MkEnvelopeOwnerNotTheNode"))
            .await
            .expect("seed local repo");

        let router = crate::server::build_router(state);
        let response = router.oneshot(federated_request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;

        assert_eq!(body["count"].as_u64(), Some(1));
        assert_eq!(
            body["nodes_queried"].as_u64(),
            Some(1),
            "no peers seeded, only the local node was queried"
        );
        assert_eq!(body["truncated"].as_bool(), Some(false));
        let repo = &body["repos"][0];
        assert_eq!(repo["name"].as_str(), Some("demo"));
        assert_eq!(repo["local"].as_bool(), Some(true));
        assert_eq!(repo["node_did"].as_str(), Some(node_did.as_str()));
        assert!(
            repo["node_url"].as_str().is_some_and(|u| !u.is_empty()),
            "local repos must carry the node's URL, got {repo}"
        );
    }

    /// `truncated` must be observable on the wire when the peer table holds
    /// more rows than `MAX_FEDERATED_PEERS`. Every seeded peer points at the
    /// same reachable stub returning `[]`, so no fetch can fail and no peer
    /// page can report truncation: the count bound is the only reason the
    /// body says `truncated`. The `nodes_queried` assertion pins the fetch
    /// side: every peer inside the bound is queried, and dropping the count
    /// bound would report `truncated: false`.
    #[sqlx::test]
    async fn federated_route_reports_truncated_when_peer_table_overflows(pool: sqlx::PgPool) {
        use tower::ServiceExt;

        let mut peer_server = mockito::Server::new_async().await;
        let peer_mock = peer_server
            .mock("GET", "/api/v1/repos")
            .match_query(mockito::Matcher::Exact(format!(
                "limit={MAX_FEDERATED_PEER_REPOS}&offset=0"
            )))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("[]")
            .expect(MAX_FEDERATED_PEERS)
            .create_async()
            .await;

        let state = crate::test_support::test_state(pool.clone()).await;
        sqlx::query("INSERT INTO peers (did, http_url, last_ping_ok, announced_at) SELECT 'peer-' || n, $1, TRUE, '2026-01-01T00:00:00Z' FROM generate_series(1, $2) n")
            .bind(peer_server.url())
            .bind(MAX_FEDERATED_PEERS as i64 + 2)
            .execute(&pool)
            .await
            .unwrap();

        let router = crate::server::build_router(state);
        let response = router.oneshot(federated_request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(
            body["truncated"].as_bool(),
            Some(true),
            "more peers than the bound must surface as truncated"
        );
        assert_eq!(
            body["nodes_queried"].as_u64(),
            Some(1 + MAX_FEDERATED_PEERS as u64),
            "the stub is reachable, so every peer inside the bound is queried"
        );
        peer_mock.assert_async().await;
    }

    /// A single unreachable peer must still flip `truncated` on the wire via
    /// the failed-fetch path, even though the peer table stays under the
    /// bound. Guards the `aggregate.truncated = true` on fetch failure.
    #[sqlx::test]
    async fn federated_route_reports_truncated_when_peer_fetch_fails(pool: sqlx::PgPool) {
        use tower::ServiceExt;

        let state = crate::test_support::test_state(pool.clone()).await;
        sqlx::query("INSERT INTO peers (did, http_url, last_ping_ok, announced_at) VALUES ('did:key:deadpeer', 'http://127.0.0.1:1/', TRUE, '2026-01-01T00:00:00Z')")
            .execute(&pool)
            .await
            .unwrap();

        let router = crate::server::build_router(state);
        let response = router.oneshot(federated_request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(
            body["truncated"].as_bool(),
            Some(true),
            "a failed peer fetch must surface as truncated"
        );
        assert_eq!(body["nodes_queried"].as_u64(), Some(1));
    }

    /// Peer repos must carry `node_url`, `node_did` and `local: false` on the
    /// real response body. Guards `enrich_federated_repo`: dropping an
    /// annotation there must turn this red.
    #[sqlx::test]
    async fn federated_route_annotates_peer_repos_on_real_200_body(pool: sqlx::PgPool) {
        use tower::ServiceExt;

        let mut peer_server = mockito::Server::new_async().await;
        let peer_mock = peer_server
            .mock("GET", "/api/v1/repos")
            // Pin the outbound peer query parameters: production must request
            // the bounded page. Dropping the parameters stops matching this
            // mock, so the peer fetch fails and the body reports
            // `truncated: true` instead of `false` below.
            .match_query(mockito::Matcher::Exact(format!(
                "limit={MAX_FEDERATED_PEER_REPOS}&offset=0"
            )))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"[{"id": "peer-repo-1", "name": "from-peer"}]"#)
            .expect(1)
            .create_async()
            .await;

        let state = crate::test_support::test_state(pool.clone()).await;
        sqlx::query("INSERT INTO peers (did, http_url, last_ping_ok, announced_at) VALUES ('did:key:peer1', $1, TRUE, '2026-01-01T00:00:00Z')")
            .bind(peer_server.url())
            .execute(&pool)
            .await
            .unwrap();

        let router = crate::server::build_router(state);
        let response = router.oneshot(federated_request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["truncated"].as_bool(), Some(false));
        assert_eq!(body["nodes_queried"].as_u64(), Some(2));
        let repo = body["repos"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"].as_str() == Some("peer-repo-1"))
            .expect("peer repo present in federated body");
        assert_eq!(repo["node_url"].as_str(), Some(peer_server.url().as_str()));
        assert_eq!(repo["node_did"].as_str(), Some("did:key:peer1"));
        assert_eq!(repo["local"].as_bool(), Some(false));
        peer_mock.assert_async().await;
    }

    #[test]
    fn repo_name_validation_rejects_bad_charset_and_overlong_names() {
        assert!(validate_repo_name("ok-name_123").is_ok());
        assert!(validate_repo_name(&"a".repeat(crate::db::MAX_REPO_NAME_LEN)).is_ok());
        // The bound is in bytes: the cursor budget is measured in bytes.
        let overlong = "a".repeat(crate::db::MAX_REPO_NAME_LEN + 1);
        let err = validate_repo_name(&overlong).unwrap_err();
        assert!(
            matches!(err, AppError::BadRequest(_)),
            "overlong name must be a 400, got: {err:?}"
        );
        assert!(validate_repo_name("bad name!").is_err());
        // Empty names were already admissible before the length bound; the
        // bound does not change that.
        assert!(validate_repo_name("").is_ok());
    }

    #[tokio::test]
    async fn create_repo_rejects_overlong_name_through_handler() {
        // Pins the wiring: `create_repo` must call `validate_repo_name`
        // before any database access. The lazy state never connects, so
        // deleting the call site would let the handler proceed to `get_repo`
        // and fail with a connection error instead of BadRequest.
        let state = crate::test_support::test_state_lazy();
        let overlong = "a".repeat(crate::db::MAX_REPO_NAME_LEN + 1);
        let err = create_repo(
            State(state),
            Extension(AuthenticatedDid(OWNER_DID.to_owned())),
            axum::http::HeaderMap::new(),
            Json(CreateRepoRequest {
                name: overlong,
                description: None,
                is_public: true,
                default_branch: "main".into(),
            }),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AppError::BadRequest(ref msg) if msg.contains("at most")),
            "overlong name through create_repo must be a 400, got: {err:?}"
        );
    }

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

    // #398: a peer-supplied pkt-line whose 40-byte "SHA" fields carry non-hex
    // content must be dropped, not forwarded into RefUpdate events, branch_cid
    // rows, and sync-notify JSON as a canonical-looking identifier.
    #[test]
    fn parse_ref_updates_requires_hex_shas() {
        let sha_a = "a".repeat(40);
        let sha_b = "b".repeat(40);
        let pkt = |old: &str, new: &str, refname: &str| {
            let line = format!("{old} {new} {refname}");
            format!("{:04x}{}0000", line.len() + 4, line).into_bytes()
        };

        // Valid 40-hex old + new -> accepted.
        let updates = parse_ref_updates(&pkt(&sha_a, &sha_b, "refs/heads/main")).unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].old_sha, sha_a);
        assert_eq!(updates[0].new_sha, sha_b);
        assert_eq!(updates[0].ref_name, "refs/heads/main");

        // 40-byte non-hex fields -> dropped.
        let junk = "Z".repeat(40);
        assert!(parse_ref_updates(&pkt(&junk, &sha_b, "refs/heads/main"))
            .unwrap()
            .is_empty());
        assert!(parse_ref_updates(&pkt(&sha_a, &junk, "refs/heads/main"))
            .unwrap()
            .is_empty());

        // Wrong lengths -> dropped.
        assert!(
            parse_ref_updates(&pkt(&"a".repeat(39), &sha_b, "refs/heads/main"))
                .unwrap()
                .is_empty()
        );
        assert!(
            parse_ref_updates(&pkt(&sha_a, &"b".repeat(41), "refs/heads/main"))
                .unwrap()
                .is_empty()
        );

        // A bad line among good ones drops only the bad line.
        let sha_c = "c".repeat(40);
        let bad = pkt(&junk, &sha_b, "refs/heads/bad");
        let good = pkt(&sha_a, &sha_c, "refs/heads/good");
        let mut mixed = bad[..bad.len() - 4].to_vec(); // strip trailing flush
        mixed.extend_from_slice(&good);
        let updates = parse_ref_updates(&mixed).unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].ref_name, "refs/heads/good");
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

    #[test]
    fn is_expected_transient_matches_both_typed_refusals() {
        // The real raise shape wraps the marker in a `.context()` layer naming the
        // owner slug and repo, so the downcast has to survive that wrapping.
        let busy = anyhow::Error::new(crate::git::repo_store::RepoBusy)
            .context("another write is in progress for alice/demo");
        assert!(is_expected_transient_acquire_failure(&busy));

        let unavailable = anyhow::Error::new(crate::git::repo_store::RepoUnavailable)
            .context("could not read the archive HEAD for alice/demo");
        assert!(is_expected_transient_acquire_failure(&unavailable));
    }

    #[test]
    fn is_expected_transient_rejects_unrelated_failures() {
        // Anything the classifier cannot recognize keeps paging at error level.
        let other = anyhow::anyhow!("disk on fire");
        assert!(!is_expected_transient_acquire_failure(&other));
    }

    #[test]
    fn acquire_write_app_error_maps_transient_markers_to_retryable_503() {
        let busy = anyhow::Error::new(crate::git::repo_store::RepoBusy)
            .context("another write is in progress for alice/demo");
        assert!(matches!(
            acquire_write_app_error(&busy, "demo"),
            AppError::RepoBusy
        ));

        let unavailable = anyhow::Error::new(crate::git::repo_store::RepoUnavailable)
            .context("could not read the archive HEAD for alice/demo");
        assert!(matches!(
            acquire_write_app_error(&unavailable, "demo"),
            AppError::RepoUnavailable
        ));

        let pool = anyhow::Error::new(crate::git::repo_store::LockPoolBusy);
        assert!(matches!(
            acquire_write_app_error(&pool, "demo"),
            AppError::Overloaded(_)
        ));

        let other = anyhow::anyhow!("disk on fire");
        assert!(matches!(
            acquire_write_app_error(&other, "demo"),
            AppError::Git(_)
        ));
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
            // Finite: a write capability that never lapses is refused, since there
            // is no revocation path to withdraw a leaked one.
            Some(chrono::Utc::now() + chrono::Duration::hours(1)),
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

    /// Policy 2 carve-out: replication/Tigris follows landed report
    /// knowledge even when the outcome commit failed, while durable
    /// accounting waits. MUTATION (RED): gating `spawn_tail` or
    /// `release_ok` on `outcome_commit_ok` breaks the carve-out row.
    #[test]
    fn post_git_disposition_replication_carve_out() {
        // Happy path: everything runs.
        assert_eq!(
            post_git_disposition(true, true, true, false),
            PostGitDisposition {
                spawn_tail: true,
                release_ok: true,
                run_effects: true
            },
        );
        // Commit failure defers accounting but NOT replication/Tigris.
        assert_eq!(
            post_git_disposition(true, true, false, false),
            PostGitDisposition {
                spawn_tail: true,
                release_ok: true,
                run_effects: false
            },
        );
        // No landed refs with a report: nothing runs anywhere.
        assert_eq!(
            post_git_disposition(true, false, true, false),
            PostGitDisposition {
                spawn_tail: false,
                release_ok: false,
                run_effects: false
            },
        );
        // Failed git: nothing runs anywhere, report or not.
        assert_eq!(
            post_git_disposition(false, false, false, false),
            PostGitDisposition {
                spawn_tail: false,
                release_ok: false,
                run_effects: false
            },
        );
        assert_eq!(
            post_git_disposition(false, false, true, true),
            PostGitDisposition {
                spawn_tail: false,
                release_ok: false,
                run_effects: false
            },
        );
        // No report with exit ok: refs may have landed, so the shared
        // copy is refreshed (no stale-download erasure) but nothing is
        // announced and no effects run until reconcile proves the landing.
        // MUTATION (RED): dropping `report_absent` from `release_ok`
        // reintroduces the stale-Tigris erasure of acknowledged pushes.
        assert_eq!(
            post_git_disposition(true, false, true, true),
            PostGitDisposition {
                spawn_tail: false,
                release_ok: true,
                run_effects: false
            },
        );
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

    /// #172: first-push delta (empty old tips, `full_scan == false`) must drop the
    /// withheld-subtree tree. The withheld set comes from `replication_withheld_set`,
    /// the production wrapper all three delta call sites already use.
    #[tokio::test]
    async fn first_push_delta_drops_withheld_subtree_tree() {
        use std::process::Command;
        use std::time::Duration;

        let td = tempfile::TempDir::new().unwrap();
        let work = td.path().join("work");
        let bare = td.path().join("bare.git");
        let run = |args: &[&str], dir: &std::path::Path| {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(dir)
                    .status()
                    .unwrap()
                    .success(),
                "git {args:?} failed"
            );
        };
        std::fs::create_dir_all(work.join("public")).unwrap();
        std::fs::create_dir_all(work.join("secret")).unwrap();
        std::fs::write(work.join("public/a.txt"), b"public bytes\n").unwrap();
        std::fs::write(work.join("secret/b.txt"), b"TOP SECRET\n").unwrap();
        run(&["init", "-q"], &work);
        run(&["config", "user.email", "t@t"], &work);
        run(&["config", "user.name", "t"], &work);
        run(&["add", "."], &work);
        run(&["commit", "-qm", "init"], &work);
        run(
            &[
                "clone",
                "-q",
                "--bare",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            td.path(),
        );
        let oid = |rev: &str| {
            let out = Command::new("git")
                .args(["rev-parse", rev])
                .current_dir(&bare)
                .output()
                .unwrap();
            assert!(out.status.success(), "rev-parse {rev}");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let head = oid("HEAD");
        let root_tree = oid("HEAD^{tree}");
        let public_tree = oid("HEAD:public");
        let public_blob = oid("HEAD:public/a.txt");
        let secret_tree = oid("HEAD:secret");
        let secret_blob = oid("HEAD:secret/b.txt");

        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(64));
        let pin_set = crate::git::push_delta::resolve_candidates_for_push(
            sem.clone(),
            bare.clone(),
            vec![head.clone()],
            vec![],
            "git".into(),
            Duration::from_secs(600),
            false,
        )
        .await;
        assert!(
            !pin_set.full_scan,
            "a first push of a commit tip must take the delta path, not full-scan"
        );
        assert!(
            pin_set.candidates.contains(&secret_tree) && pin_set.candidates.contains(&secret_blob),
            "precondition: the first-push delta includes the withheld tree and blob, \
             so a later drop is a filter hit, not a missing-candidate skip"
        );

        let (_announce, withheld) = replication_withheld_set(
            sem,
            Some(vec![vis_rule("/secret/**", &[])]),
            OWNER_DID,
            true,
            bare,
            "git".into(),
            Duration::from_secs(600),
        )
        .await;
        let withheld = withheld
            .expect("announceable public repo with a path-scoped rule must yield a withheld set");
        let replicable =
            crate::git::visibility_pack::replicable_objects(pin_set.candidates, &withheld);
        assert!(
            replicable.contains(&head) && replicable.contains(&root_tree),
            "commit and root tree still replicate"
        );
        assert!(
            replicable.contains(&public_tree) && replicable.contains(&public_blob),
            "public tree and blob still replicate"
        );
        assert!(
            !replicable.contains(&secret_tree),
            "withheld-subtree tree must not survive the first-push delta pin set (#172)"
        );
        assert!(
            !replicable.contains(&secret_blob),
            "withheld blob still drops"
        );
    }

    /// #172: full-scan fallback drops a withheld-subtree tree and a dangling tree,
    /// keeping the commit, root tree, public tree, and public blob.
    #[tokio::test]
    async fn full_scan_drops_withheld_and_dangling_trees() {
        use std::io::Write;
        use std::process::Command;
        use std::time::Duration;

        let td = tempfile::TempDir::new().unwrap();
        let work = td.path().join("work");
        let bare = td.path().join("bare.git");
        let run = |args: &[&str], dir: &std::path::Path| {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(dir)
                    .status()
                    .unwrap()
                    .success(),
                "git {args:?} failed"
            );
        };
        std::fs::create_dir_all(work.join("public")).unwrap();
        std::fs::create_dir_all(work.join("secret")).unwrap();
        std::fs::write(work.join("public/a.txt"), b"public bytes\n").unwrap();
        std::fs::write(work.join("secret/b.txt"), b"TOP SECRET\n").unwrap();
        run(&["init", "-q"], &work);
        run(&["config", "user.email", "t@t"], &work);
        run(&["config", "user.name", "t"], &work);
        run(&["add", "."], &work);
        run(&["commit", "-qm", "init"], &work);
        run(
            &[
                "clone",
                "-q",
                "--bare",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            td.path(),
        );
        let oid = |rev: &str| {
            let out = Command::new("git")
                .args(["rev-parse", rev])
                .current_dir(&bare)
                .output()
                .unwrap();
            assert!(out.status.success(), "rev-parse {rev}");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let head = oid("HEAD");
        let root_tree = oid("HEAD^{tree}");
        let public_tree = oid("HEAD:public");
        let public_blob = oid("HEAD:public/a.txt");
        let secret_tree = oid("HEAD:secret");
        let secret_blob = oid("HEAD:secret/b.txt");

        let mut child = Command::new("git")
            .args(["mktree"])
            .current_dir(&bare)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        writeln!(
            child.stdin.as_mut().unwrap(),
            "100644 blob {secret_blob}\tdangling-only-unreferenced.txt"
        )
        .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "git mktree");
        let dangling_tree = String::from_utf8_lossy(&out.stdout).trim().to_string();

        let deadline = std::time::Instant::now() + Duration::from_secs(600);
        let candidates = crate::git::push_delta::list_all_objects(&bare, "git", deadline).unwrap();
        assert!(
            candidates.contains(&dangling_tree),
            "precondition: dangling tree is in the full-scan universe"
        );
        assert!(
            candidates.contains(&secret_tree) && candidates.contains(&secret_blob),
            "precondition: full-scan universe includes the withheld tree and blob"
        );

        let replicable = fail_closed_full_scan_objects(
            std::sync::Arc::new(tokio::sync::Semaphore::new(64)),
            bare,
            vec![vis_rule("/secret/**", &[])],
            true,
            OWNER_DID.to_string(),
            candidates,
            "git".into(),
            Duration::from_secs(600),
        )
        .await;
        assert!(replicable.contains(&head), "HEAD commit kept");
        // The root tree is dropped too under the structural gate: its bytes
        // name the withheld subtree's OID, so pinning it to public IPFS leaks
        // that subtree's existence (the same leak class as the subtree).
        assert!(
            !replicable.contains(&root_tree),
            "root tree naming a withheld subtree drops under the structural gate"
        );
        assert!(replicable.contains(&public_tree), "public tree kept");
        assert!(replicable.contains(&public_blob), "public blob kept");
        assert!(
            !replicable.contains(&secret_tree),
            "withheld-subtree tree dropped on full-scan (#172)"
        );
        assert!(
            !replicable.contains(&secret_blob),
            "withheld blob dropped on full-scan"
        );
        assert!(
            !replicable.contains(&dangling_tree),
            "dangling tree dropped on full-scan (#172, #99 geometry for trees)"
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
        //
        // #218 review round 8 P1 (fixture, not production): the `for-each-ref` arm
        // must answer in the COLUMN SHAPE `blob_paths` phase 2 asks for
        // (`%(objectname) %(objecttype)`, plus the peeled `%(*objectname)
        // %(*objecttype)` pair when the tip is a tag), not a ref NAME. A single
        // bare token made the phase-2 parse fail closed, so the walk returned an
        // error and the request surfaced as a generic 500 — which silently
        // repurposed this test from "the filtered serve shares the deadline" into
        // "the walk errors", losing the #174 guard while looking merely red. A
        // commit tip peels to nothing, so two columns is the whole line here; the
        // 1.2s walk cost stays on `ls-tree` so walk and serve remain independently
        // attributable.
        let body = format!(
            "#!/bin/sh\ncase \"$1\" in\n  \
             for-each-ref) echo {commit} commit ;;\n  \
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
            "Decentralized npm for agents on Twigpine",
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
            Some("Decentralized npm for agents on Twigpine"),
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

    // ── Stored pull-request head maintenance on push ──────────────────────

    const PR_SHA_OLD: &str = "1111111111111111111111111111111111111111";
    const PR_SHA_NEW: &str = "2222222222222222222222222222222222222222";

    async fn pr_head_db(pool: sqlx::PgPool) -> crate::db::Db {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        db
    }

    /// An open PR on `feature` in `repo_id`, with no stored head yet.
    async fn seed_open_pr(db: &crate::db::Db, repo_id: &str, number: i64, source_branch: &str) {
        let now = chrono::Utc::now().to_rfc3339();
        db.create_pr(&crate::db::PullRequest {
            id: uuid::Uuid::new_v4().to_string(),
            repo_id: repo_id.to_string(),
            number,
            title: "t".into(),
            body: None,
            author_did: "did:key:zAuthor".into(),
            source_branch: source_branch.into(),
            target_branch: "main".into(),
            status: "open".into(),
            merged_by_did: None,
            merged_at: None,
            head_commit: None,
            created_at: now.clone(),
            updated_at: now,
        })
        .await
        .unwrap();
    }

    fn ref_update(ref_name: &str, old_sha: &str, new_sha: &str) -> RefUpdate {
        RefUpdate {
            old_sha: old_sha.into(),
            new_sha: new_sha.into(),
            ref_name: ref_name.into(),
        }
    }

    /// One `(branch, tip)` pair in the shape `heads_still_at_tip` returns and
    /// `update_open_pr_heads` consumes: the bare branch name, not the full ref.
    fn head_pair(branch: &str, sha: &str) -> (String, String) {
        (branch.to_string(), sha.to_string())
    }

    async fn head_of(db: &crate::db::Db, repo_id: &str, number: i64) -> Option<String> {
        db.get_pr(repo_id, number)
            .await
            .unwrap()
            .unwrap()
            .head_commit
    }

    /// The push path sees `refs/heads/feature`; `source_branch` stores
    /// `feature`. Pin the mapping directly, because a WHERE clause comparing
    /// the full ref against the bare name matches nothing and would make the
    /// whole update a silent no-op that still reads green everywhere else.
    #[test]
    fn branch_from_ref_strips_only_branch_refs() {
        assert_eq!(branch_from_ref("refs/heads/feature"), Some("feature"));
        assert_eq!(
            branch_from_ref("refs/heads/release/1.x"),
            Some("release/1.x")
        );
        // A tag push must not move a PR whose source branch shares the name.
        assert_eq!(branch_from_ref("refs/tags/feature"), None);
        assert_eq!(branch_from_ref("refs/notes/commits"), None);
        assert_eq!(branch_from_ref("feature"), None);
        assert_eq!(branch_from_ref("refs/heads/"), None);
    }

    /// Scenario 1: a push to a PR's source branch moves that PR's stored head.
    #[sqlx::test]
    async fn push_to_source_branch_moves_the_open_pr_head(pool: sqlx::PgPool) {
        let db = pr_head_db(pool).await;
        seed_open_pr(&db, "repo-1", 1, "feature").await;

        update_open_pr_heads(&db, "repo-1", &[head_pair("feature", PR_SHA_NEW)])
            .await
            .unwrap();

        assert_eq!(
            head_of(&db, "repo-1", 1).await,
            Some(PR_SHA_NEW.to_string())
        );
    }

    /// Scenario 2: a push to a different branch of the same repo changes
    /// nothing.
    #[sqlx::test]
    async fn push_to_unrelated_branch_leaves_the_pr_head_unchanged(pool: sqlx::PgPool) {
        let db = pr_head_db(pool).await;
        seed_open_pr(&db, "repo-1", 1, "feature").await;
        db.set_open_pr_heads("repo-1", "feature", PR_SHA_OLD)
            .await
            .unwrap();

        update_open_pr_heads(&db, "repo-1", &[head_pair("main", PR_SHA_NEW)])
            .await
            .unwrap();

        assert_eq!(
            head_of(&db, "repo-1", 1).await,
            Some(PR_SHA_OLD.to_string()),
            "a push to main must not move a PR whose source is `feature`"
        );
    }

    /// Scenario 3: after the PR is closed, further pushes to the same branch
    /// leave the frozen head alone.
    #[sqlx::test]
    async fn push_after_close_does_not_move_the_frozen_head(pool: sqlx::PgPool) {
        let db = pr_head_db(pool).await;
        seed_open_pr(&db, "repo-1", 1, "feature").await;
        db.set_open_pr_heads("repo-1", "feature", PR_SHA_OLD)
            .await
            .unwrap();
        let pr = db.get_pr("repo-1", 1).await.unwrap().unwrap();
        db.close_pr(&pr.id, None).await.unwrap();

        update_open_pr_heads(&db, "repo-1", &[head_pair("feature", PR_SHA_NEW)])
            .await
            .unwrap();

        assert_eq!(
            head_of(&db, "repo-1", 1).await,
            Some(PR_SHA_OLD.to_string()),
            "a closed PR keeps the head it froze at"
        );
    }

    /// Scenario 5: a force-push is a non-fast-forward ref update, so the stored
    /// head must follow it. The rollup target is the branch head, not the
    /// newest commit, and the discarded SHA must stop being the target.
    #[sqlx::test]
    async fn force_push_moves_the_pr_head_to_the_new_sha(pool: sqlx::PgPool) {
        let db = pr_head_db(pool).await;
        seed_open_pr(&db, "repo-1", 1, "feature").await;
        db.set_open_pr_heads("repo-1", "feature", PR_SHA_OLD)
            .await
            .unwrap();

        // Non-fast-forward: old_sha is the discarded tip, new_sha is unrelated.
        let rewritten = "3333333333333333333333333333333333333333";
        update_open_pr_heads(&db, "repo-1", &[head_pair("feature", rewritten)])
            .await
            .unwrap();

        assert_eq!(
            head_of(&db, "repo-1", 1).await,
            Some(rewritten.to_string()),
            "the rewritten tip becomes the rollup target"
        );
    }

    /// A same-named branch in two repos is an ordinary shape, and a missing
    /// repo predicate would be invisible to every single-repo assertion.
    #[sqlx::test]
    async fn push_does_not_move_a_same_named_branch_in_another_repo(pool: sqlx::PgPool) {
        let db = pr_head_db(pool).await;
        seed_open_pr(&db, "repo-1", 1, "feature").await;
        seed_open_pr(&db, "repo-2", 1, "feature").await;

        update_open_pr_heads(&db, "repo-1", &[head_pair("feature", PR_SHA_NEW)])
            .await
            .unwrap();

        assert_eq!(
            head_of(&db, "repo-1", 1).await,
            Some(PR_SHA_NEW.to_string())
        );
        assert_eq!(
            head_of(&db, "repo-2", 1).await,
            None,
            "the other repo's PR on the same branch name must be untouched"
        );
    }

    /// A bare repo at a tempdir whose named ref points at a real commit, for
    /// `heads_still_at_tip` tests: `git update-ref` requires the target to
    /// resolve, and a branch ref must point at a commit, so an empty tree is
    /// committed first. Returns the directory (kept alive by the caller) and
    /// the tip's real SHA.
    fn bare_repo_with_ref(ref_name: &str, message: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::TempDir::new().unwrap();
        let run = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .args(args)
                .current_dir(dir.path())
                .env("GIT_AUTHOR_NAME", "test")
                .env("GIT_AUTHOR_EMAIL", "test@example.com")
                .env("GIT_COMMITTER_NAME", "test")
                .env("GIT_COMMITTER_EMAIL", "test@example.com")
                .output()
                .expect("git runs");
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            out
        };
        run(&["init", "-q", "--bare", "."]);
        let mut child = std::process::Command::new("git")
            .args(["mktree"])
            .current_dir(dir.path())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("git mktree spawns");
        drop(child.stdin.take());
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "git mktree failed");
        let tree = String::from_utf8(out.stdout).unwrap().trim().to_string();
        let out = run(&["commit-tree", &tree, "-m", message]);
        let sha = String::from_utf8(out.stdout).unwrap().trim().to_string();
        run(&["update-ref", ref_name, &sha]);
        (dir, sha)
    }

    /// A landing that still sits at the branch's tip yields the head pair.
    #[test]
    fn heads_still_at_tip_returns_the_current_landing() {
        let (dir, sha) = bare_repo_with_ref("refs/heads/feature", "tip object");
        let heads = heads_still_at_tip(
            dir.path(),
            &[ref_update("refs/heads/feature", PR_SHA_OLD, &sha)],
        )
        .unwrap();
        assert_eq!(heads, vec![("feature".to_string(), sha)]);
    }

    /// The convergence property the tip check exists for: a push whose effect
    /// runs after a newer landing moved the branch must not write its stale
    /// tip, or the stored head — which is not self-healing — pins the rollup
    /// to a commit the branch has moved past.
    #[test]
    fn heads_still_at_tip_skips_a_landing_the_branch_moved_past() {
        let (dir, _sha) = bare_repo_with_ref("refs/heads/feature", "newer tip");
        let heads = heads_still_at_tip(
            dir.path(),
            &[ref_update("refs/heads/feature", PR_SHA_OLD, PR_SHA_NEW)],
        )
        .unwrap();
        assert!(
            heads.is_empty(),
            "a landing the branch has moved past yields no head write"
        );
    }

    /// A tag push carries a ref name whose last segment can equal a branch
    /// name. It is not a branch update and must not produce a head pair, even
    /// when the tag's tip matches the pushed SHA.
    #[test]
    fn heads_still_at_tip_skips_a_same_named_tag() {
        let (dir, sha) = bare_repo_with_ref("refs/tags/feature", "tag tip");
        let heads = heads_still_at_tip(
            dir.path(),
            &[ref_update("refs/tags/feature", PR_SHA_OLD, &sha)],
        )
        .unwrap();
        assert!(heads.is_empty(), "a tag tip must not yield a branch head");
    }

    /// Deleting the source branch is a ref update whose new SHA is all zeros,
    /// and a push to a branch that no longer exists resolves to nothing.
    /// Writing either as a head would hand the rollup a target no commit
    /// resolves to.
    #[test]
    fn heads_still_at_tip_skips_deletions_and_absent_refs() {
        let dir = tempfile::TempDir::new().unwrap();
        let out = std::process::Command::new("git")
            .args(["init", "-q", "--bare", "."])
            .current_dir(dir.path())
            .output()
            .expect("git runs");
        assert!(out.status.success(), "git init failed");

        let heads = heads_still_at_tip(
            dir.path(),
            &[
                ref_update("refs/heads/feature", PR_SHA_OLD, ZERO_SHA),
                ref_update("refs/heads/gone", PR_SHA_OLD, PR_SHA_NEW),
            ],
        )
        .unwrap();
        assert!(
            heads.is_empty(),
            "a deletion and an absent ref both yield no head write"
        );
    }

    /// The scenario tests above drive `update_open_pr_heads` directly, because a
    /// full receive-pack POST needs a real pack. That proves the mechanism and
    /// says nothing about the sink: delete the call from the effect bundle and
    /// every one of them still passes while no push ever moves a head again.
    /// Pin the wiring by source, the way the authz guards in `api/mod.rs` do.
    ///
    /// The pin lands on `run_effect_bundle` in `durable_outbox.rs`, not on the
    /// handler: the stored-head and poll-feed writes are durable accounting, so
    /// they run inside the effect executor — gated on the publish verdict on
    /// the live path and on reconcile's proof on the drain path — fed by the
    /// request's ACCEPTED transition rows, never a live parse.
    #[test]
    fn the_effect_bundle_actually_calls_the_head_update() {
        let src = include_str!("../durable_outbox.rs");
        let body = crate::test_support::scrape_source_region(
            src,
            Some("fn run_effect_bundle("),
            Some("\n}"),
        )
        .expect("run_effect_bundle not found (renamed or removed?)");

        assert!(
            body.contains("heads_still_at_tip("),
            "the stored-head update must go through the tip check: the effect \
             executor runs after the repo write lock is released, so only a \
             landing that still sits at the branch's current target may move a \
             pull request's head — an unchecked write can pin the rollup to a \
             commit a newer push already replaced"
        );
        assert!(
            body.contains("update_open_pr_heads("),
            "the effect bundle must feed the accepted transitions to the \
             stored-head update; without that call every head-maintenance test \
             here passes against a helper nothing invokes"
        );
        assert!(
            body.contains("record_push_events("),
            "the effect bundle must feed the accepted transitions to the \
             push-event recorder, or the catch-up poll surface is fed by nothing"
        );
    }

    /// The handler must not write the status surfaces itself — the publish
    /// verdict has not happened yet at the only place it could — and the
    /// executor that owns those writes must run only after it.
    ///
    /// Pre-release rows would outlive a refused publish, claiming a landing
    /// the node then deleted; effects that ran before the verdict would have
    /// the same problem. The ordering pin is therefore negative on the handler
    /// (no direct calls, ever) and positional on the executor's call site:
    /// `apply_request_effects` sits after `outcome.into_result()?`, so a
    /// refused publish returns before any durable accounting runs.
    #[test]
    fn the_status_surface_writes_wait_for_the_publish_verdict() {
        let src = include_str!("repos.rs");
        let body = crate::test_support::scrape_source_region(
            src,
            Some("fn git_receive_pack("),
            Some("\n}"),
        )
        .expect("git_receive_pack not found (renamed or removed?)");

        assert!(
            !body.contains("update_open_pr_heads(") && !body.contains("record_push_events("),
            "the handler must not write heads or push events directly: anything \
             written before release outlives a refused publish and claims a \
             landing that never happened; the writes belong to the effect \
             executor, which the drain replays identically"
        );
        let release = body
            .find("outcome.into_result()?")
            .expect("the publish verdict must still be in the push handler");
        let effects = body
            .find("apply_request_effects(&state, &request_id)")
            .expect("the effect executor must still be called from the push handler");
        assert!(
            effects > release,
            "durable effects must run after the publish verdict; a refusal \
             returns at into_result and must never reach them"
        );
    }

    /// A multi-ref push is one request. Every branch in it that has an open PR
    /// must be updated, not just the first — the same collapse-to-first bug the
    /// ref-certificate loop above already had to fix.
    #[sqlx::test]
    async fn a_multi_ref_push_updates_every_matching_pr(pool: sqlx::PgPool) {
        let db = pr_head_db(pool).await;
        seed_open_pr(&db, "repo-1", 1, "feature").await;
        seed_open_pr(&db, "repo-1", 2, "second").await;

        let other = "4444444444444444444444444444444444444444";
        update_open_pr_heads(
            &db,
            "repo-1",
            &[head_pair("feature", PR_SHA_NEW), head_pair("second", other)],
        )
        .await
        .unwrap();

        assert_eq!(
            head_of(&db, "repo-1", 1).await,
            Some(PR_SHA_NEW.to_string())
        );
        assert_eq!(head_of(&db, "repo-1", 2).await, Some(other.to_string()));
    }

    // ── Push-path fan-out: bounded work, not one round trip per ref ───────

    /// Statements executed on the push write path since the last call. The
    /// counter is thread-local, so it measures this test alone with no
    /// cross-test serialization to remember to take.
    fn statements_since_last_check() -> usize {
        crate::db::take_push_write_statements()
    }

    /// A `tracing` sink for the current thread, so "the drop is logged" is a
    /// property the test observes rather than one it takes on trust. The
    /// subscriber is installed for the lifetime of the returned value and
    /// captures whatever this thread emits while it lives.
    struct LogCapture {
        buf: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        _guard: tracing::subscriber::DefaultGuard,
    }

    #[derive(Clone)]
    struct LogSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for LogSink {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log buffer").extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
        type Writer = LogSink;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    impl LogCapture {
        fn contents(&self) -> String {
            String::from_utf8_lossy(&self.buf.lock().expect("log buffer")).into_owned()
        }
    }

    fn capture_logs() -> LogCapture {
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(LogSink(buf.clone()))
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .finish();
        LogCapture {
            buf,
            _guard: tracing::subscriber::set_default(subscriber),
        }
    }

    /// The same push as the accepted transition rows `run_effect_bundle` feeds
    /// the event recorder: one applied child per ref, ordinal in push order.
    fn many_pending_children(repo_id: &str, n: usize) -> Vec<crate::db::PendingRefTransition> {
        (0..n)
            .map(|i| {
                crate::test_support::pending_child(
                    "req-fan",
                    repo_id,
                    &format!("refs/heads/b{i}"),
                    PR_SHA_OLD,
                    &sha_for(i),
                    i as i32,
                )
            })
            .collect()
    }

    /// The same push as the `(branch, tip)` pairs `update_open_pr_heads`
    /// consumes after `heads_still_at_tip` has filtered it.
    fn many_head_pairs(n: usize) -> Vec<(String, String)> {
        (0..n)
            .map(|i| head_pair(&format!("b{i}"), &sha_for(i)))
            .collect()
    }

    fn sha_for(i: usize) -> String {
        format!("{:040x}", i + 1)
    }

    /// The cost of a push must not grow with the number of refs in it. Both
    /// writers on the receive-pack path used to issue one sequential round trip
    /// per ref, so a push of many refs multiplied database latency onto the
    /// user's `git push` response.
    ///
    /// This asserts on the WORK, not on the rows: a per-ref loop and a batched
    /// statement leave byte-identical rows behind, so a row-count assertion
    /// passes against either and proves nothing about the thing that was wrong.
    #[sqlx::test]
    async fn a_multi_ref_push_costs_one_statement_per_writer(pool: sqlx::PgPool) {
        let db = pr_head_db(pool).await;
        seed_open_pr(&db, "repo-fan", 1, "b0").await;
        seed_open_pr(&db, "repo-fan", 2, "b3").await;
        let children = many_pending_children("repo-fan", 8);
        let child_refs: Vec<_> = children.iter().collect();
        let pairs = many_head_pairs(8);

        statements_since_last_check();
        record_push_events(&db, "req-fan", &child_refs)
            .await
            .unwrap();
        assert_eq!(
            statements_since_last_check(),
            1,
            "recording an 8-ref push must be one multi-row insert, not one round \
             trip per ref"
        );

        update_open_pr_heads(&db, "repo-fan", &pairs).await.unwrap();
        assert_eq!(
            statements_since_last_check(),
            1,
            "moving the stored heads for an 8-ref push must be one statement"
        );

        // And the batching did not cost correctness: every row still landed, and
        // both open pull requests still followed their own branch.
        let rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM repo_push_events WHERE repo_id = 'repo-fan'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(rows, 8, "every ref must still be recorded");
        assert_eq!(head_of(&db, "repo-fan", 1).await, Some(sha_for(0)));
        assert_eq!(head_of(&db, "repo-fan", 2).await, Some(sha_for(3)));
    }

    // ── receive-pack report-status ────────────────────────────────────────
    //
    // These drive `accepted_ref_updates`, which is the consumer of the parser
    // ported from PR #384; testing through it covers both without duplicating
    // the parser's own test surface in `git/smart_http.rs`.

    /// One pkt-line: four lowercase hex length digits (covering themselves)
    /// followed by the payload.
    fn pkt(payload: &str) -> String {
        format!("{:04x}{}", payload.len() + 4, payload)
    }

    /// The report as receive-pack writes it when the client did NOT ask for
    /// `side-band-64k`: bare pkt-lines, no channel byte.
    fn plain_report(lines: &[&str]) -> Vec<u8> {
        let mut out = String::new();
        for line in lines {
            out.push_str(&pkt(&format!("{line}\n")));
        }
        out.push_str("0000");
        out.into_bytes()
    }

    /// The report as receive-pack actually writes it for a `git push` over
    /// smart HTTP, which negotiates `side-band-64k`.
    ///
    /// The framing here is not invented: it is the byte layout captured from
    /// `git receive-pack` 2.50.1 refusing one ref of a two-ref push. The report
    /// is DOUBLE wrapped — an outer pkt-line carrying a band byte, whose
    /// payload is itself a pkt-line stream — and a band-2 packet carrying the
    /// hook's stderr sits ahead of it. A parser that peels only the outer layer
    /// sees `000eunpack ok` as its first line, fails to match, and answers
    /// "cannot tell" for every push it exists to classify.
    fn sideband_report(stderr: &str, lines: &[&str]) -> Vec<u8> {
        let mut out = String::new();
        if !stderr.is_empty() {
            out.push_str(&pkt(&format!("\x02{stderr}\n")));
        }
        let mut inner = String::new();
        for line in lines {
            inner.push_str(&pkt(&format!("{line}\n")));
        }
        inner.push_str("0000");
        out.push_str(&pkt(&format!("\x01{inner}")));
        out.push_str("0000");
        out.into_bytes()
    }

    fn names(updates: &[RefUpdate]) -> Vec<&str> {
        updates.iter().map(|u| u.ref_name.as_str()).collect()
    }

    /// The ok-name set the handler derives from a parsed report — what `ok_set`
    /// holds at the production call site of `accepted_ref_updates`. An
    /// unparseable report yields an empty set, exactly as the handler's match
    /// arm produces, and a report whose refs were all refused has no ok names
    /// in it.
    fn ok_set_of(report: &[u8]) -> std::collections::HashSet<String> {
        match smart_http::parse_report_status(report) {
            Some((_, results)) => results
                .iter()
                .filter(|(_, ok)| *ok)
                .map(|(name, _)| name.clone())
                .collect(),
            None => std::collections::HashSet::new(),
        }
    }

    fn two_ref_push() -> Vec<RefUpdate> {
        vec![
            ref_update("refs/heads/main", PR_SHA_OLD, PR_SHA_NEW),
            ref_update("refs/heads/third", ZERO_SHA, PR_SHA_NEW),
        ]
    }

    /// A ref receive-pack answered `ng` is not applied, and nothing keyed on the
    /// push may treat it as though it were.
    ///
    /// receive-pack exits ZERO here. The pack unpacked, one ref moved, and the
    /// other was refused as a non-fast-forward — a per-ref verdict carried only
    /// in the `ng` pkt-line of a response the handler used to forward without
    /// reading. Every side effect derived from the REQUEST therefore fired for
    /// the refused ref too: the pull request on that branch had its stored head
    /// moved to a commit this node does not have, and the poll surface handed
    /// subscribers a SHA that resolves to nothing.
    #[test]
    fn only_the_refs_receive_pack_accepted_survive() {
        let declared = two_ref_push();
        let report = sideband_report(
            "error: denying non-fast-forward refs/heads/main (you should pull first)",
            &[
                "unpack ok",
                "ng refs/heads/main non-fast-forward",
                "ok refs/heads/third",
            ],
        );

        assert_eq!(
            names(&accepted_ref_updates(&ok_set_of(&report), &declared)),
            vec!["refs/heads/third"],
            "a refused ref must not reach the writes that publish a branch tip"
        );

        // The control: the same push with both refs taken keeps both, so what
        // the filter removes is the rejection and not simply the second ref.
        let all_ok = sideband_report(
            "",
            &["unpack ok", "ok refs/heads/main", "ok refs/heads/third"],
        );
        assert_eq!(
            names(&accepted_ref_updates(&ok_set_of(&all_ok), &declared)),
            vec!["refs/heads/main", "refs/heads/third"],
            "an accepted push must keep every ref it declared"
        );
    }

    /// `unpack fail` means the pack never landed, so no ref could have moved,
    /// whatever else the report goes on to say.
    #[test]
    fn an_unpack_failure_accepts_nothing() {
        let declared = two_ref_push();
        let report = plain_report(&["unpack fail", "ng refs/heads/main unpacker error"]);
        assert!(
            accepted_ref_updates(&ok_set_of(&report), &declared).is_empty(),
            "nothing lands when the pack itself did not unpack"
        );
    }

    /// The non-sideband framing parses too — a client that did not negotiate
    /// `side-band-64k` still gets its refs classified.
    #[test]
    fn the_plain_pkt_line_report_is_read_as_well_as_the_sideband_one() {
        let declared = two_ref_push();
        let report = plain_report(&[
            "unpack ok",
            "ng refs/heads/main non-fast-forward",
            "ok refs/heads/third",
        ]);
        assert_eq!(
            names(&accepted_ref_updates(&ok_set_of(&report), &declared)),
            vec!["refs/heads/third"]
        );
    }

    /// No report at all is INCONCLUSIVE, and inconclusive proves no ref.
    ///
    /// A client that never requested `report-status` is told nothing about
    /// individual refs, and neither is a reader of a truncated response. Nothing
    /// can distinguish "landed but unreported" from "refused", so the ok set is
    /// empty and these writes record nothing: recording the declared set would
    /// publish SHAs git may have refused. The unproven refs are not lost — the
    /// outcome rows stay `uncertain` and startup reconcile owns proving what
    /// actually landed from the on-disk reflog.
    #[test]
    fn an_unreadable_report_proves_no_ref_landed() {
        let declared = two_ref_push();
        for (label, report) in [
            ("empty", Vec::new()),
            ("flush only", b"0000".to_vec()),
            (
                "not a report",
                b"random bytes that are not pkt-lines".to_vec(),
            ),
            ("truncated", b"0057\x01000eunpack o".to_vec()),
        ] {
            assert!(
                accepted_ref_updates(&ok_set_of(&report), &declared).is_empty(),
                "a {label} report proves nothing, and unproven must not be                  recorded as landed"
            );
        }
    }

    /// A receive-pack request body carrying `n` well-formed ref-update lines.
    fn ref_update_request(n: usize) -> Vec<u8> {
        let mut out = String::new();
        for i in 0..n {
            out.push_str(&pkt(&format!(
                "{PR_SHA_OLD} {} refs/heads/b{i}\n",
                sha_for(i)
            )));
        }
        out.push_str("0000");
        out.into_bytes()
    }

    /// The parser REFUSES at the cap instead of scanning and allocating the whole
    /// request and being refused afterwards. Git routes raise the body
    /// limit to GITLAWB_MAX_PACK_BYTES — 2 GB by default — so the count check
    /// lives inside `parse_ref_updates`'s command loop, which returns the 400
    /// the first command past the cap rather than at the end of whatever the
    /// client sent.
    #[test]
    fn the_ref_parser_refuses_past_the_bound_instead_of_scanning_the_whole_body() {
        let err = parse_ref_updates(&ref_update_request(MAX_REF_UPDATES * 3))
            .expect_err("a body over the cap must be refused");
        assert!(
            err.to_string().contains(&MAX_REF_UPDATES.to_string()),
            "the refusal must name the limit the client has to get under, got: {err}"
        );

        let at = parse_ref_updates(&ref_update_request(MAX_REF_UPDATES))
            .expect("a push exactly at the cap parses in full");
        assert_eq!(
            at.len(),
            MAX_REF_UPDATES,
            "a push exactly at the cap must be parsed in full"
        );
    }

    /// The bound is only worth anything ahead of the accept. It runs before the
    /// per-ref branch-protection queries and before the repository is acquired
    /// and receive-pack is run, so an oversized push costs one parse and is
    /// refused, rather than being applied and then reported on.
    #[test]
    fn the_ref_bound_runs_before_git_accepts_the_push() {
        let src = include_str!("repos.rs");
        let body = crate::test_support::scrape_source_region(
            src,
            Some("fn git_receive_pack("),
            Some("\n}"),
        )
        .expect("git_receive_pack not found (renamed or removed?)");

        let bound = body
            .find("parse_ref_updates(&body)")
            .expect("the receive-pack handler must parse (and cap) the declared refs");
        let protection = body
            .find("is_branch_protected(")
            .expect("branch protection loop not found (renamed or removed?)");
        let accept = body
            .find("smart_http::receive_pack_raw_with_reflog(")
            .expect("receive_pack call not found (renamed or removed?)");

        assert!(
            bound < protection && bound < accept,
            "the ref bound must precede the per-ref protection queries and the \
             receive-pack call; a bound applied after git has accepted the refs \
             is a report, not a refusal"
        );
    }

    /// A push bigger than one chunk still records EVERY ref, and a pull request
    /// whose source branch sits past the chunk boundary still gets its head
    /// moved.
    ///
    /// This is the case truncation lost. receive-pack has already accepted every
    /// ref by the time these writers run, so a ref dropped here is a ref git told
    /// the client it took: the pull request keeps a stale `head_commit` forever
    /// and no push event is ever produced for it. A `tracing::warn!` is not a
    /// remedy for that, which is why the bound is now a chunk size and not a cap.
    #[sqlx::test]
    async fn a_push_past_the_chunk_boundary_records_every_ref_and_moves_its_pr_head(
        pool: sqlx::PgPool,
    ) {
        let db = pr_head_db(pool).await;
        let over = PUSH_WRITE_CHUNK + 7;
        // One pull request inside the first chunk and one past the boundary. The
        // second is the one a truncating fan-out abandoned.
        let past = PUSH_WRITE_CHUNK + 3;
        seed_open_pr(&db, "repo-chunk", 1, "b0").await;
        seed_open_pr(&db, "repo-chunk", 2, &format!("b{past}")).await;
        let children = many_pending_children("repo-chunk", over);
        let child_refs: Vec<_> = children.iter().collect();
        let pairs = many_head_pairs(over);

        let logs = capture_logs();
        record_push_events(&db, "req-fan", &child_refs)
            .await
            .unwrap();
        update_open_pr_heads(&db, "repo-chunk", &pairs)
            .await
            .unwrap();
        let logged = logs.contents();

        let rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM repo_push_events WHERE repo_id = 'repo-chunk'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(
            rows as usize, over,
            "every accepted ref must be recorded; git already took all {over}"
        );
        assert_eq!(
            head_of(&db, "repo-chunk", 1).await,
            Some(sha_for(0)),
            "the pull request inside the first chunk follows its branch"
        );
        assert_eq!(
            head_of(&db, "repo-chunk", 2).await,
            Some(sha_for(past)),
            "the pull request whose branch sits past the chunk boundary must \
             follow its branch too, or its rollup points at a commit the push \
             already replaced"
        );
        assert!(
            !logged.contains("truncated"),
            "nothing is dropped, so nothing is truncated, got: {logged}"
        );
    }

    /// Every ref is written, and the cost stays bounded per statement: the work
    /// is chunked, so the count is one statement per chunk and never one per ref.
    ///
    /// Asserted on the WORK, not the rows: a per-ref loop leaves byte-identical
    /// rows behind, so only the counter can tell the two apart. The two halves
    /// are what make the property real together: the test above says nothing is
    /// lost, this one says nothing is unbounded.
    #[sqlx::test]
    async fn a_push_past_the_chunk_boundary_costs_one_statement_per_chunk(pool: sqlx::PgPool) {
        let db = pr_head_db(pool).await;
        let over = PUSH_WRITE_CHUNK + 7;
        let chunks = over.div_ceil(PUSH_WRITE_CHUNK);
        assert_eq!(chunks, 2, "the fixture must actually cross the boundary");
        let children = many_pending_children("repo-chunk-cost", over);
        let child_refs: Vec<_> = children.iter().collect();
        let pairs = many_head_pairs(over);

        statements_since_last_check();
        record_push_events(&db, "req-fan", &child_refs)
            .await
            .unwrap();
        assert_eq!(
            statements_since_last_check(),
            chunks,
            "recording a {over}-ref push must be {chunks} multi-row inserts, not \
             one round trip per ref"
        );

        update_open_pr_heads(&db, "repo-chunk-cost", &pairs)
            .await
            .unwrap();
        assert_eq!(
            statements_since_last_check(),
            chunks,
            "moving the stored heads for a {over}-ref push must be {chunks} \
             statements"
        );
    }

    /// A chunk the database refuses propagates as an error: the caller is the
    /// effect executor, which turns it into a `Retry` for the next pass, so a
    /// failed write waits to be redone rather than being dropped behind a log
    /// line — a hole in the catch-up surface no later poll would ever ask about.
    ///
    /// The error carries the repo, the refs and the SHAs, because a request
    /// parked for retry or quarantined is only repairable when the failure
    /// names what it was trying to write.
    #[sqlx::test]
    async fn a_chunk_that_cannot_be_written_returns_an_error_naming_the_rows(pool: sqlx::PgPool) {
        let db = pr_head_db(pool).await;
        // The table is gone, so the write fails the way a real outage would.
        sqlx::query("DROP TABLE repo_push_events")
            .execute(db.pool())
            .await
            .unwrap();

        let children = many_pending_children("repo-lost", 2);
        let child_refs: Vec<_> = children.iter().collect();
        let err = record_push_events(&db, "req-lost", &child_refs)
            .await
            .expect_err("a write that cannot land must surface as an error");

        let msg = format!("{err}");
        assert!(
            msg.contains("repo-lost") && msg.contains("refs/heads/b0") && msg.contains(&sha_for(0)),
            "the error must name the repo, the refs and the SHAs that could not \
             be written, or the parked request is not repairable by hand; got: {msg}"
        );
    }

    /// The boundary itself: a push of exactly one chunk is one statement per
    /// writer, with no empty second chunk behind it.
    #[sqlx::test]
    async fn a_push_of_exactly_one_chunk_is_one_statement_per_writer(pool: sqlx::PgPool) {
        let db = pr_head_db(pool).await;
        let children = many_pending_children("repo-atchunk", PUSH_WRITE_CHUNK);
        let child_refs: Vec<_> = children.iter().collect();
        let pairs = many_head_pairs(PUSH_WRITE_CHUNK);

        statements_since_last_check();
        record_push_events(&db, "req-fan", &child_refs)
            .await
            .unwrap();
        assert_eq!(
            statements_since_last_check(),
            1,
            "a push of exactly one chunk must not issue a second statement"
        );
        update_open_pr_heads(&db, "repo-atchunk", &pairs)
            .await
            .unwrap();
        assert_eq!(statements_since_last_check(), 1);

        let rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM repo_push_events WHERE repo_id = 'repo-atchunk'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(
            rows as usize, PUSH_WRITE_CHUNK,
            "a push of exactly one chunk keeps every ref"
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
    /// pool with many slow pushes (the cap keys on source IP, not the DID, so it holds
    /// whether or not owner enforcement is on — and it can be turned off for a rolling
    /// upgrade). Global write pool has capacity; the source is pre-held at its single
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

        // Owner of the `rp4` row, so the push reaches the per-source write cap instead
        // of stopping at the owner-push gate (on by default). `did_matches` collapses
        // the `did:key:` prefix against the bare stored owner.
        let did = "did:key:z6rp4wr";
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

        // Owner of the seeded rows, so the push reaches `acquire_write` instead of
        // stopping at the owner-push gate (on by default). `did_matches` collapses the
        // `did:key:` prefix against the bare `owner` above.
        let did = "did:key:z6acqdead";
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

    /// A handler refusal after intent insert leaves a terminal aggregate, not
    /// a strand. Same stall as the deadline test above, but the push carries
    /// a real ref command, so intent has children: after the 503 the parent
    /// must be `rejected_at_git` with `completed_at` (purge-eligible), every
    /// child `cancelled` (never promotable, no tuple poisoning), and the
    /// proof acked (no purge block). Deleting any inline refuse call strands
    /// `received` + `prepared` and turns these red. The inline refuse is
    /// synchronous, so no sleep/poll is needed — unlike the drop-guard path.
    #[sqlx::test]
    async fn receive_pack_refusal_terminalizes_intent_aggregate(pool: sqlx::PgPool) {
        use crate::git::repo_store::advisory_lock_key;
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;

        let owner = "z6refuseagg";
        let name = "ra1";
        let owner_slug = owner.replace([':', '/'], "_");
        let lock_key = advisory_lock_key(&owner_slug, name);

        let mut state = crate::test_support::test_state(pool.clone()).await;
        let mut cfg = (*state.config).clone();
        cfg.git_acquire_timeout_secs = 2;
        cfg.git_service_timeout_secs = 600;
        state.config = std::sync::Arc::new(cfg);
        state
            .db
            .upsert_mirror_repo(owner, name, "/tmp/z6refuseagg-ra1", None, false)
            .await
            .unwrap();
        let repo_id = state
            .db
            .get_repo(owner, name)
            .await
            .unwrap()
            .expect("mirror row exists")
            .id;

        // Stall acquire_write on a second pooled connection.
        let mut lock_conn = pool.acquire().await.expect("second connection");
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(lock_key)
            .execute(&mut *lock_conn)
            .await
            .expect("hold the advisory lock");

        let did = "did:key:z6refuseagg";
        let peer: SocketAddr = "203.0.113.91:5000".parse().unwrap();
        let result = git_receive_pack(
            State(state.clone()),
            Path((owner.to_string(), name.to_string())),
            Extension(crate::auth::AuthenticatedDid(did.to_string())),
            None,
            crate::rate_limit::PeerAddr(Some(peer)),
            axum::http::HeaderMap::new(),
            ref_update_body("1111111111111111111111111111111111111111"),
        )
        .await;
        assert!(
            matches!(result, Err(AppError::Overloaded(_))),
            "stalled acquire_write must shed with Overloaded/503; got {result:?}"
        );

        // Exactly one aggregate for this push, terminal on both levels.
        let (req_id, req_state, completed_at): (String, String, Option<String>) = sqlx::query_as(
            "SELECT id, state, completed_at FROM receive_pack_requests WHERE repo_id = $1",
        )
        .bind(&repo_id)
        .fetch_one(state.db.pool())
        .await
        .expect("one intent aggregate per refused push");
        assert_eq!(
            req_state,
            crate::db::request_state::REJECTED_AT_GIT,
            "refused parent is terminal"
        );
        assert!(
            completed_at.is_some(),
            "refused parent carries completed_at so retention can purge it"
        );
        let children = state
            .db
            .list_pending_ref_transitions_for_request(&req_id)
            .await
            .unwrap();
        assert_eq!(children.len(), 1, "the ref command produced one child");
        assert_eq!(
            children[0].state,
            crate::db::pending_state::CANCELLED,
            "refused child is cancelled, never prepared"
        );
        let proof = state
            .db
            .get_request_proof(&req_id)
            .await
            .unwrap()
            .expect("proof row exists");
        assert!(
            proof.acked_at.is_some(),
            "refused proof is acked so purge is not blocked"
        );

        sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(lock_key)
            .execute(&mut *lock_conn)
            .await
            .expect("release the advisory lock");
    }

    #[cfg(unix)]
    fn pid_alive(pid: i32) -> bool {
        // SAFETY: kill(2) with signal 0 only probes; it takes integers and borrows no
        // Rust memory.
        unsafe { libc::kill(pid, 0) == 0 }
    }

    /// SIGKILL the recorded pids if the test unwinds, so a RED run leaks no orphan.
    #[cfg(unix)]
    struct KillOnPanic(Vec<i32>);
    #[cfg(unix)]
    impl Drop for KillOnPanic {
        fn drop(&mut self) {
            for pid in &self.0 {
                // SAFETY: as above.
                unsafe {
                    libc::kill(*pid, libc::SIGKILL);
                }
            }
        }
    }

    /// Is the repo write lock takeable from an INDEPENDENT session right now? Session
    /// advisory locks are re-entrant within their own session, so this must not run on
    /// any connection the code under test might be using.
    #[cfg(unix)]
    async fn write_lock_is_takeable(pool: &sqlx::PgPool, key: i64) -> bool {
        let mut probe = pool.acquire().await.expect("probe connection");
        let taken: (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
            .bind(key)
            .fetch_one(&mut *probe)
            .await
            .expect("probe try-lock");
        if taken.0 {
            sqlx::query("SELECT pg_advisory_unlock($1)")
                .bind(key)
                .execute(&mut *probe)
                .await
                .expect("probe unlock");
        }
        taken.0
    }

    /// #173 F2 (RED-before/GREEN-after): on a CLIENT DISCONNECT the repo write lock must
    /// stay held until the receive-pack process group is confirmed reaped.
    ///
    /// The handler's `guard.release(..)` line is only reached if `receive_pack` returns.
    /// When the request future is dropped mid-push the guard drops instead, and (since
    /// #173 U1 gave the lock pool an `after_release` hook) that FREES the advisory lock
    /// immediately, while `KillGroupOnDrop`'s detached reaper is still giving the group
    /// its ~2s SIGTERM grace. A second `acquire_write` admitted inside that window puts
    /// two `git receive-pack` groups on one repo. `smart_http.rs` states the invariant
    /// the other way round on the timeout path: "a caller releasing a write lock can't
    /// race them".
    ///
    /// Real seam, not a stand-in: the production `git_receive_pack` handler, a fake git
    /// whose descendant IGNORES SIGTERM (so the group genuinely survives the grace and
    /// the window is ~2s wide, not a scheduling artifact), and the lock probed from an
    /// independent session. RED before the fix: the lock is takeable while the group is
    /// still alive. GREEN after: takeable only once the group is gone.
    #[cfg(unix)]
    #[sqlx::test]
    async fn receive_pack_disconnect_holds_the_write_lock_until_the_group_is_reaped(
        pool: sqlx::PgPool,
    ) {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;

        let owner = "z6disc";
        let name = "dc1";
        let repos_dir = tempfile::TempDir::new().unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let descfile = tmp.path().join("desc.pid");
        // The leader dies on the group SIGTERM; its descendant traps SIGTERM and loops
        // (bounded at ~30s so a RED run leaks nothing permanent), so the group is only
        // gone once the reaper escalates to SIGKILL. The descendant inherits the stdout
        // pipe, which keeps drive_git_child's read_to_end pending until we drop.
        let body = format!(
            "#!/bin/sh\n\
             sh -c 'trap \"\" TERM; echo $$ > \"{}\"; i=0; while [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done' &\n\
             wait\n",
            descfile.display()
        );
        let git_bin = write_fake_git(tmp.path(), &body);

        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.git_bin = git_bin;
        state.repo_store = crate::git::repo_store::RepoStore::new(
            repos_dir.path().to_path_buf(),
            None,
            crate::git::repo_store::build_lock_pool(&pool, 4, std::time::Duration::from_secs(5)),
            std::time::Duration::from_secs(300),
        );
        let mut cfg = (*state.config).clone();
        // Long enough that the git-service timeout is never what ends this push; the
        // disconnect is.
        cfg.git_service_timeout_secs = 600;
        // Lock-path test, not owner-push authorization: pin off so the default-on gate
        // does not reject the proof DID before receive-pack runs.
        cfg.enforce_owner_push = false;
        state.config = std::sync::Arc::new(cfg);
        state
            .db
            .upsert_mirror_repo(owner, name, "/tmp/z6disc-dc1", None, false)
            .await
            .unwrap();

        // The mirror row stores the short owner as owner_did, so the slug is the owner.
        // Import the production derivation rather than hand-copying it: a local copy
        // silently diverged when the key moved to SHA-256 (#210).
        use crate::git::repo_store::advisory_lock_key;
        let key = advisory_lock_key(&owner.replace([':', '/'], "_"), name);
        // Probe from a pool that is NOT the store's lock pool and NOT the harness pool.
        let probe = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect_lazy_with((*pool.connect_options()).clone());

        assert!(
            write_lock_is_takeable(&probe, key).await,
            "the write lock must be free before the push"
        );

        // Drive the handler a slice at a time until the fake git's SIGTERM-ignoring
        // descendant records its pid, i.e. receive-pack is genuinely running under the
        // write lock. `Ok(_)` means the handler returned early; stop polling then, since
        // re-polling a completed future panics.
        //
        // Retried on a miss for the same reason `smart_http`'s disconnect tests retry:
        // under `cargo test` fork-storm load a freshly written fake `git` can transiently
        // fail to exec (ETXTBSY, a concurrent worker forked while its write fd was open),
        // which leaves no pid. A losing attempt's future is dropped, which reaps whatever
        // spawned and releases its write lock, so retries do not leak. The winning
        // attempt's future is kept PENDING: dropping it below is the disconnect under test.
        const SPAWN_ATTEMPTS: u64 = 12;
        let (fut, desc) = {
            let mut attempt = 0u64;
            loop {
                attempt += 1;
                let _ = std::fs::remove_file(&descfile);
                let mut fut = Box::pin(git_receive_pack(
                    State(state.clone()),
                    Path((owner.to_string(), name.to_string())),
                    Extension(crate::auth::AuthenticatedDid("did:key:z6disc".to_string())),
                    None,
                    crate::rate_limit::PeerAddr(Some(
                        "203.0.113.81:5000".parse::<SocketAddr>().unwrap(),
                    )),
                    axum::http::HeaderMap::new(),
                    axum::body::Bytes::from_static(b"0000"),
                ));
                let mut found: Option<i32> = None;
                for _ in 0..500 {
                    let finished =
                        tokio::time::timeout(std::time::Duration::from_millis(10), &mut fut)
                            .await
                            .is_ok();
                    if let Some(p) = std::fs::read_to_string(&descfile)
                        .ok()
                        .and_then(|s| s.trim().parse::<i32>().ok())
                    {
                        found = Some(p);
                        break;
                    }
                    if finished {
                        break;
                    }
                }
                match found {
                    Some(p) => break (fut, p),
                    None => {
                        drop(fut);
                        assert!(
                            attempt < SPAWN_ATTEMPTS,
                            "the push never reached receive-pack after {SPAWN_ATTEMPTS} \
                             attempts (persistent failure, not a transient runner miss)"
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(100 * attempt)).await;
                    }
                }
            }
        };
        let _cleanup = KillOnPanic(vec![desc]);
        assert!(
            pid_alive(desc),
            "the receive-pack group must be running before the disconnect"
        );
        assert!(
            !write_lock_is_takeable(&probe, key).await,
            "the write lock must be held while receive-pack runs"
        );

        // Client disconnect: drop the request future mid-receive-pack.
        drop(fut);

        let mut takeable_while_group_alive = false;
        let mut freed_after_reap = false;
        for _ in 0..800 {
            let takeable = write_lock_is_takeable(&probe, key).await;
            let group_alive = pid_alive(desc);
            if takeable && group_alive {
                takeable_while_group_alive = true;
            }
            if takeable && !group_alive {
                freed_after_reap = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        // Clean up regardless so a RED run leaves no orphan behind.
        // SAFETY: kill(2) takes integers only.
        unsafe {
            libc::kill(desc, libc::SIGKILL);
        }
        assert!(
            !takeable_while_group_alive,
            "the repo write lock was takeable while a receive-pack group was still alive \
             on that repo: a second push can enter and two git receive-pack groups run \
             against one repo (#173 F2)"
        );
        assert!(
            freed_after_reap,
            "the write lock must be released once the disconnected push's group is reaped"
        );
        // The other half of the disconnect invariant, and the reason the guard rides the
        // reaper rather than being released there: an interrupted push must not publish a
        // half-applied repo. The guard is gone by now (the lock above only frees when it
        // is), so the upload site has had its whole chance to be reached. The positive
        // control is `receive_pack_success_reclaims_and_releases_the_write_lock`, which
        // observes the same counter at 1: without it, a zero here would pass on any build
        // where an upload is simply impossible.
        assert_eq!(
            state.repo_store.tigris_upload_site_reached(),
            0,
            "a push interrupted by a client disconnect must not reach the Tigris upload \
             site: publishing a half-applied repo propagates it to every node that later \
             downloads it (#173 F2)"
        );
    }

    /// #173 F2, the other half: carrying the write lock through the admission seam must
    /// NOT cost the success path its `release(true)`. A push that completes normally has
    /// to reclaim the lock and release it explicitly (that is what performs the Tigris
    /// upload), synchronously, not leave it to the pool's `after_release` net. The lock
    /// is probed immediately after the handler returns, with no polling, so a fix that
    /// only ever dropped the guard would fail here.
    #[cfg(unix)]
    #[sqlx::test]
    async fn receive_pack_success_reclaims_and_releases_the_write_lock(pool: sqlx::PgPool) {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;

        let owner = "z6succ";
        let name = "sc1";
        let repos_dir = tempfile::TempDir::new().unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        // A receive-pack that succeeds. It DRAINS stdin first: exiting while the handler
        // is still writing the request body would EPIPE that write, which
        // `drive_git_child` surfaces as an error after a successful exit status, making
        // the push fail for a reason that has nothing to do with the lock under test.
        // It emits a single-framed report-status (unpack ok + ok main) so the
        // outcome authority (report, not process exit) marks the ref applied.
        let git_bin = write_fake_git(
            tmp.path(),
            "#!/bin/sh\ncat >/dev/null\nprintf '0022\\001unpack ok\\nok refs/heads/main\\n0000'\nexit 0\n",
        );

        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.git_bin = git_bin;
        state.repo_store = crate::git::repo_store::RepoStore::new(
            repos_dir.path().to_path_buf(),
            None,
            crate::git::repo_store::build_lock_pool(&pool, 4, std::time::Duration::from_secs(5)),
            std::time::Duration::from_secs(300),
        );
        let mut cfg = (*state.config).clone();
        cfg.enforce_owner_push = false;
        state.config = std::sync::Arc::new(cfg);
        state
            .db
            .upsert_mirror_repo(owner, name, "/tmp/z6succ-sc1", None, false)
            .await
            .unwrap();

        use crate::git::repo_store::advisory_lock_key;
        let key = advisory_lock_key(&owner.replace([':', '/'], "_"), name);
        let probe = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect_lazy_with((*pool.connect_options()).clone());

        // Retried ONLY on the ETXTBSY exec race a freshly written fake `git` hits under
        // fork-storm load (a concurrent test worker forked while its write fd was open).
        // Narrow on purpose: any other failure still fails the assertion below loudly.
        const SPAWN_ATTEMPTS: u64 = 12;
        let mut result = None;
        for attempt in 1..=SPAWN_ATTEMPTS {
            let outcome = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                git_receive_pack(
                    State(state.clone()),
                    Path((owner.to_string(), name.to_string())),
                    Extension(crate::auth::AuthenticatedDid("did:key:z6succ".to_string())),
                    None,
                    crate::rate_limit::PeerAddr(Some(
                        "203.0.113.83:5000".parse::<SocketAddr>().unwrap(),
                    )),
                    axum::http::HeaderMap::new(),
                    // Request-level gate defines success as
                    // `exit_ok && any_ref_ok`: a bare `0000` flush
                    // carries no ref command, so `ok_set` is empty
                    // and the push correctly skips the Tigris upload.
                    // Send one accepted ref so this positive control
                    // exercises the upload path.
                    ref_update_body("1111111111111111111111111111111111111111"),
                ),
            )
            .await
            .expect("the push must return");
            let exec_race =
                matches!(&outcome, Err(AppError::Git(m)) if m.contains("Text file busy"));
            if exec_race && attempt < SPAWN_ATTEMPTS {
                tokio::time::sleep(std::time::Duration::from_millis(100 * attempt)).await;
                continue;
            }
            result = Some(outcome);
            break;
        }
        let result = result.expect("one attempt must have produced an outcome");
        assert!(
            result.is_ok(),
            "the fake receive-pack succeeds, so the handler must too; got {result:?}"
        );

        // No polling: `release` unlocks on the connection that took the lock, so the
        // lock is free the instant the handler returns. Falling back to the async
        // `after_release` net would not satisfy this.
        assert!(
            write_lock_is_takeable(&probe, key).await,
            "a completed push must reclaim its write lock and release it synchronously"
        );
        // POSITIVE CONTROL for the disconnect case's "no upload" assertion. A push that
        // completed does reach the Tigris upload site, exactly once, so the zero the
        // disconnect test observes is a real difference between the two paths rather than
        // an artifact of tests running with no Tigris client configured. Exactly once,
        // not at least once: a retried exec race releases with success = false and must
        // not count.
        assert_eq!(
            state.repo_store.tigris_upload_site_reached(),
            1,
            "a completed push must reach the Tigris upload site once"
        );
    }

    /// Durable intent is wired at the handler boundary: a successful
    /// receive-pack leaves a request row, exactly one child carrying the
    /// pusher DID, and a versioned proof record.
    /// MUTATION (RED): wrapping the
    /// `insert_receive_pack_request_with_children` call in `if false`
    /// leaves zero rows and this test fails.
    #[cfg(unix)]
    #[sqlx::test]
    async fn receive_pack_success_persists_durable_intent_rows(pool: sqlx::PgPool) {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;

        let owner = "z6intent";
        let name = "in1";
        let repos_dir = tempfile::TempDir::new().unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let git_bin = write_fake_git(
            tmp.path(),
            "#!/bin/sh\ncat >/dev/null\nprintf '0022\\001unpack ok\\nok refs/heads/main\\n0000'\nexit 0\n",
        );

        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.git_bin = git_bin;
        state.repo_store = crate::git::repo_store::RepoStore::new(
            repos_dir.path().to_path_buf(),
            None,
            crate::git::repo_store::build_lock_pool(&pool, 4, std::time::Duration::from_secs(5)),
            std::time::Duration::from_secs(5),
        );
        let mut cfg = (*state.config).clone();
        cfg.enforce_owner_push = false;
        state.config = std::sync::Arc::new(cfg);
        state
            .db
            .upsert_mirror_repo(owner, name, "/tmp/z6intent-in1", None, false)
            .await
            .unwrap();

        let pusher = "did:key:z6MkIntentProofDidAAAAAAAAAAAAAAAAAA";
        let resp = git_receive_pack(
            State(state.clone()),
            Path((owner.to_string(), name.to_string())),
            Extension(crate::auth::AuthenticatedDid(pusher.to_string())),
            None,
            crate::rate_limit::PeerAddr(Some("203.0.113.84:5000".parse::<SocketAddr>().unwrap())),
            axum::http::HeaderMap::new(),
            ref_update_body("5555555555555555555555555555555555555555"),
        )
        .await
        .expect("push must succeed");
        assert_eq!(resp.status(), 200, "push must succeed");

        let repo_id = state.db.get_repo(owner, name).await.unwrap().unwrap().id;
        let (reqs,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::BIGINT FROM receive_pack_requests WHERE repo_id = $1 AND pusher_did = $2",
        )
        .bind(&repo_id)
        .bind(pusher)
        .fetch_one(state.db.pool())
        .await
        .unwrap();
        assert_eq!(
            reqs, 1,
            "exactly one durable request row per successful push"
        );
        let (kids,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::BIGINT FROM pending_ref_transitions WHERE repo_id = $1 AND pusher_did = $2",
        )
        .bind(&repo_id)
        .bind(pusher)
        .fetch_one(state.db.pool())
        .await
        .unwrap();
        // Live success applies inline and deletes accepted children after
        // effects, so zero-or-one (deleted after Done) is accepted; the
        // request + proof rows are the load-bearing evidence the insert
        // creates. A disabled insert leaves all three at zero.
        assert!(
            kids <= 1,
            "at most one child row survives live completion; got {kids}"
        );
        let (proofs,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::BIGINT FROM request_proofs WHERE repo_id = $1 AND pusher_did = $2",
        )
        .bind(&repo_id)
        .bind(pusher)
        .fetch_one(state.db.pool())
        .await
        .unwrap();
        assert_eq!(proofs, 1, "exactly one versioned proof record per intent");
    }

    /// #173 F1 (RED-before/GREEN-after): an exhausted repo write-lock POOL is a capacity
    /// signal, so the push must shed 503 + Retry-After (Overloaded) like every other
    /// admission path here, not report a 500 git error. Both directions: the shed with
    /// the single lock-pool connection occupied by a guard on a DIFFERENT repo (so this
    /// is pool capacity, not advisory-lock contention), and the must-not case once that
    /// connection is back. Before the fix `acquire_write`'s checkout failure fell into
    /// the generic `AppError::Git` arm (500, no Retry-After).
    #[sqlx::test]
    async fn receive_pack_lock_pool_exhaustion_sheds_503_not_500(pool: sqlx::PgPool) {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;

        let owner = "z6lockpool";
        let name = "lp1";
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let mut cfg = (*state.config).clone();
        cfg.enforce_owner_push = false;
        state.config = std::sync::Arc::new(cfg);
        // One lock-pool connection, short checkout timeout so the exhaustion surfaces
        // promptly rather than at the handler's own acquire deadline.
        state.repo_store = crate::git::repo_store::RepoStore::new(
            std::path::PathBuf::from("/tmp/gitlawb-lockpool-shed"),
            None,
            crate::git::repo_store::build_lock_pool(&pool, 1, std::time::Duration::from_secs(1)),
            std::time::Duration::from_secs(300),
        );
        state
            .db
            .upsert_mirror_repo(owner, name, "/tmp/z6lockpool-lp1", None, false)
            .await
            .unwrap();

        let did = "did:key:z6lockpool";
        let peer: SocketAddr = "203.0.113.71:5000".parse().unwrap();

        // Occupy the only lock-pool connection with a write on an UNRELATED repo.
        let held = state
            .repo_store
            .acquire_write(owner, "other-repo")
            .await
            .expect("the first write takes the only lock-pool connection");

        let shed = git_receive_pack(
            State(state.clone()),
            Path((owner.to_string(), name.to_string())),
            Extension(crate::auth::AuthenticatedDid(did.to_string())),
            None,
            crate::rate_limit::PeerAddr(Some(peer)),
            axum::http::HeaderMap::new(),
            axum::body::Bytes::from_static(b"0000"),
        )
        .await;
        assert!(
            matches!(shed, Err(AppError::Overloaded(_))),
            "an exhausted lock pool must shed 503 + Retry-After, not a 500 git error; \
             got {shed:?}"
        );

        // MUST-NOT: with the pool free again, the push is not shed as capacity (it fails
        // later on the nonexistent on-disk repo, which is a git error, not Overloaded).
        let _ = held.release(false).await;
        let admitted = git_receive_pack(
            State(state.clone()),
            Path((owner.to_string(), name.to_string())),
            Extension(crate::auth::AuthenticatedDid(did.to_string())),
            None,
            crate::rate_limit::PeerAddr(Some("203.0.113.72:5000".parse().unwrap())),
            axum::http::HeaderMap::new(),
            axum::body::Bytes::from_static(b"0000"),
        )
        .await;
        assert!(
            !matches!(admitted, Err(AppError::Overloaded(_))),
            "with the lock pool free, a push must not be shed as capacity; got {admitted:?}"
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
        let body = "#!/bin/sh\ncase \"$1\" in\n  rev-parse) echo deadbeef ;;\n  rev-list) echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ;;\n  ls-tree) case \"$*\" in *-rzt*) : ;; *) sleep 1.5 ;; esac ;;\n  cat-file) case \"$*\" in *--batch-all-objects*) sleep 1.5 ;; *) : ;; esac ;;\n  *) : ;;\nesac\nexit 0\n";
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

    /// #172 / #174 F4 sibling: a successful blob walk that nearly exhausts the
    /// shared budget must leave the tree allowed-set walk only the remainder, so
    /// the scan pins nothing. Distinguishes `ls-tree -rzt` (tree) from `ls-tree -rz`
    /// (blob). Load-bearing together with a fresh timeout on both the tree walk and
    /// the typed enumeration: those two later phases completing independently would
    /// keep the non-blob non-tree candidate.
    #[cfg(unix)]
    #[tokio::test]
    async fn full_scan_shares_one_deadline_with_tree_allowed_set_walk() {
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::sync::Semaphore;

        let tmp = tempfile::TempDir::new().unwrap();
        // Blob ls-tree -rz sleeps 1.5s; tree ls-tree -rzt sleeps 1.5s; cat-file is
        // instant. With a 2s whole-scan budget the tree walk is reaped.
        let body = "#!/bin/sh\ncase \"$1\" in\n  rev-parse) echo deadbeef ;;\n  rev-list) echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ;;\n  ls-tree) case \"$*\" in *-rzt*) sleep 1.5 ;; *) sleep 1.5 ;; esac ;;\n  cat-file) : ;;\n  *) : ;;\nesac\nexit 0\n";
        let git_bin = write_fake_git(tmp.path(), body);
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
            "a large-but-successful blob walk must leave the tree allowed-set walk only \
             the SHARED remainder, so it reaps and the scan fails closed; got {objs:?}"
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
            pin_new_objects_gated(
                &pin_sem,
                "",
                tmp.path(),
                "git",
                std::time::Duration::from_secs(30),
                objects.clone(),
                &db,
                "repo-gated-a",
                crate::ipfs_pin::PIN_BATCH_BUDGET,
            ),
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
            pin_new_objects_gated(
                &pin_sem,
                "",
                tmp.path(),
                "git",
                std::time::Duration::from_secs(30),
                objects,
                &db,
                "repo-gated-b",
                crate::ipfs_pin::PIN_BATCH_BUDGET,
            ),
        )
        .await
        .expect("the pin loop completes once admission frees");
        assert!(out.confirmed.is_empty(), "an empty ipfs_api pins nothing");
    }

    /// #173 F3, at the layer that actually owns the permit. `pin_new_objects_gated`
    /// holds the global `pin_semaphore` across the whole `ipfs_pin::pin_new_objects`
    /// call, so a DB call inside that loop with no deadline parked a global pin slot
    /// for as long as the query was stuck; once every slot was so held, post-push
    /// replication stopped for every repo on the node. With the loop's DB calls
    /// bounded by the batch deadline the call returns at ~the batch budget and the
    /// permit comes back, even though the table is still locked.
    ///
    /// The endpoint is a LIVE mockito server, not the `""` the sibling test above
    /// uses. `ipfs_pin::pin_new_objects` returns an empty outcome immediately on an
    /// empty `ipfs_api`, so an empty-string copy would never reach `is_pinned`, never touch
    /// the locked table, and pass identically with the bound deleted. The mock is at
    /// `.expect(0)` because a stalled pinned-status check must not fall through to an
    /// add.
    ///
    /// The budget is passed in (1500ms) rather than read from `PIN_BATCH_BUDGET`.
    /// Before that seam existed this test cost 120s of wall clock, because the bound
    /// it asserts IS the batch budget and the gate hardcoded the production constant.
    /// 1500ms is deliberately above `PIN_READ_FLOOR` (1100ms): below the floor
    /// `batch_budget_gate` breaks the loop as its first statement, so the run would
    /// never reach a DB call and would pass with the bound deleted.
    #[sqlx::test]
    async fn pin_new_objects_gated_frees_permit_after_stalled_db(pool: sqlx::PgPool) {
        use std::sync::Arc;
        use tokio::sync::Semaphore;

        let state = crate::test_support::test_state(pool.clone()).await;
        let db = state.db.clone();
        let tmp = tempfile::TempDir::new().unwrap();
        let pin_sem = Arc::new(Semaphore::new(1));

        let mut server = mockito::Server::new_async().await;
        let add = server
            .mock("POST", mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"{"Hash":"bafkreifjjcie6lypi6ny7amxnfftagclbuxndqonfipmb64f2km2devei4"}"#)
            .expect(0)
            .create_async()
            .await;

        // `ACCESS EXCLUSIVE` conflicts with the `ACCESS SHARE` every SELECT needs, so
        // `is_pinned` blocks at lock acquisition regardless of row count. Held for the
        // whole call: a lock released early would let the pre-fix bare await finish too,
        // and the test would prove nothing.
        let mut lock = pool.acquire().await.unwrap();
        sqlx::raw_sql("BEGIN; LOCK TABLE pinned_cids IN ACCESS EXCLUSIVE MODE;")
            .execute(&mut *lock)
            .await
            .unwrap();

        let objects = vec!["0123456789abcdef0123456789abcdef01234567".to_string()];
        let out = tokio::time::timeout(
            std::time::Duration::from_secs(150),
            pin_new_objects_gated(
                &pin_sem,
                &server.url(),
                tmp.path(),
                "git",
                std::time::Duration::from_secs(30),
                objects,
                &db,
                "repo-gated-stalled-db",
                std::time::Duration::from_millis(1500),
            ),
        )
        .await
        .expect(
            "a stalled DB must cost the pin loop its batch budget, not the lock's \
             lifetime: an unbounded await inside the loop holds this permit past every \
             budget",
        );

        assert!(
            out.confirmed.is_empty(),
            "a stalled pinned-status check pins nothing"
        );
        assert_eq!(
            pin_sem.available_permits(),
            1,
            "the global pin permit must be back once the bounded loop returns"
        );
        add.assert_async().await;

        sqlx::raw_sql("ROLLBACK").execute(&mut *lock).await.unwrap();
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
            pin_new_objects_gated(
                &pin_sem,
                "",
                tmp.path(),
                "git",
                std::time::Duration::from_secs(30),
                vec![],
                &db,
                "repo-gated-empty",
                crate::ipfs_pin::PIN_BATCH_BUDGET,
            ),
        )
        .await
        .expect("an empty object list must not wait on pin admission (#174 F2b)");
        assert!(out.confirmed.is_empty(), "and it pins nothing");
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
    #[cfg(unix)]
    fn ref_update_body(new_sha: &str) -> axum::body::Bytes {
        let line = format!("{ZERO_SHA} {new_sha} refs/heads/main");
        axum::body::Bytes::from(format!("{:04x}{}0000", line.len() + 4, line))
    }

    /// Build a receive-pack body carrying `count` distinct ref-update commands,
    /// framed like [`ref_update_body`] (one pkt-line each, then the flush).
    fn ref_update_body_many(count: usize) -> axum::body::Bytes {
        let mut s = String::new();
        for i in 0..count {
            let line = format!("{ZERO_SHA} {:040x} refs/heads/branch-{i}", i + 1);
            s.push_str(&format!("{:04x}{}", line.len() + 4, line));
        }
        s.push_str("0000");
        axum::body::Bytes::from(s)
    }

    /// Build a receive-pack body from explicit `(new_sha, refname)` commands
    /// in the given order — duplicates allowed — one pkt-line each, then flush.
    fn ref_update_body_cmds(cmds: &[(&str, &str)]) -> axum::body::Bytes {
        let mut s = String::new();
        for (new_sha, refname) in cmds {
            let line = format!("{ZERO_SHA} {new_sha} {refname}");
            s.push_str(&format!("{:04x}{}", line.len() + 4, line));
        }
        s.push_str("0000");
        axum::body::Bytes::from(s)
    }

    // The ref-count cap refuses inside `parse_ref_updates`, so the refusal
    // fires BEFORE the owner-push and branch-protection gates, BEFORE any
    // entry beyond the cap is materialized, and BEFORE the durable intent
    // insert: one oversized body cannot become thousands of per-ref
    // `is_branch_protected` SELECTs or a durable row set that rides
    // reconcile/quarantine scans until retention. The signer here is NOT the
    // owner, so if the cap were removed — or moved below the owner gate — the
    // answer would become Forbidden instead: pinning both the refusal and its
    // placement. Goes RED without `MAX_REF_UPDATES`.
    #[sqlx::test]
    async fn receive_pack_refuses_a_ref_update_count_over_the_cap(pool: sqlx::PgPool) {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;

        let owner = "z6refcapowner";
        let name = "rc1";
        let state =
            crate::test_support::test_state_with(pool.clone(), |cfg| cfg.enforce_owner_push = true)
                .await;
        state
            .db
            .upsert_mirror_repo(owner, name, "/tmp/z6refcapowner-rc1", None, false)
            .await
            .unwrap();
        let repo_id = state
            .db
            .get_repo(owner, name)
            .await
            .unwrap()
            .expect("mirror row exists")
            .id;

        let pusher = "did:key:z6refcapother";
        let peer: SocketAddr = "203.0.113.92:5000".parse().unwrap();
        let result = git_receive_pack(
            State(state.clone()),
            Path((owner.to_string(), name.to_string())),
            Extension(crate::auth::AuthenticatedDid(pusher.to_string())),
            None,
            crate::rate_limit::PeerAddr(Some(peer)),
            axum::http::HeaderMap::new(),
            ref_update_body_many(MAX_REF_UPDATES + 1),
        )
        .await;
        match result {
            Err(AppError::BadRequest(msg)) => assert!(
                msg.contains("too many ref updates"),
                "the refusal names the cap; got: {msg}"
            ),
            Err(other) => panic!("over-cap push must refuse with BadRequest/400; got {other:?}"),
            Ok(_) => panic!("over-cap push must refuse, not serve"),
        }

        // No rows at all: the refusal precedes the durable intent insert, so
        // nothing rides retention, reconcile, or quarantine scans.
        let (req_count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM receive_pack_requests WHERE repo_id = $1")
                .bind(&repo_id)
                .fetch_one(state.db.pool())
                .await
                .unwrap();
        assert_eq!(req_count, 0, "no intent aggregate for a refused push");
        let (child_count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM pending_ref_transitions WHERE repo_id = $1")
                .bind(&repo_id)
                .fetch_one(state.db.pool())
                .await
                .unwrap();
        assert_eq!(child_count, 0, "no child rows for a refused push");
    }

    // Boundary pin for the in-loop cap: EXACTLY MAX_REF_UPDATES commands is a
    // legal push that must pass the cap and fall through to the next gate —
    // here the owner gate (non-owner signer, enforcement on), which answers
    // Forbidden. The over-cap test alone cannot catch an off-by-one: both `>`
    // and `>=` refuse MAX+1, but only `>` lets MAX through, so this test goes
    // RED the moment the boundary starts rejecting a legal at-cap push
    // (e.g. a `>=` slip or counting the flush line as a command).
    #[sqlx::test]
    async fn receive_pack_admits_a_ref_update_count_at_the_cap(pool: sqlx::PgPool) {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;

        let owner = "z6refcapowner";
        let name = "rc-boundary";
        let state =
            crate::test_support::test_state_with(pool.clone(), |cfg| cfg.enforce_owner_push = true)
                .await;
        state
            .db
            .upsert_mirror_repo(owner, name, "/tmp/z6refcapowner-boundary", None, false)
            .await
            .unwrap();
        let repo_id = state
            .db
            .get_repo(owner, name)
            .await
            .unwrap()
            .expect("mirror row exists")
            .id;

        let pusher = "did:key:z6refcapother";
        let peer: SocketAddr = "203.0.113.93:5000".parse().unwrap();
        let result = git_receive_pack(
            State(state.clone()),
            Path((owner.to_string(), name.to_string())),
            Extension(crate::auth::AuthenticatedDid(pusher.to_string())),
            None,
            crate::rate_limit::PeerAddr(Some(peer)),
            axum::http::HeaderMap::new(),
            ref_update_body_many(MAX_REF_UPDATES),
        )
        .await;
        match result {
            Err(AppError::Forbidden(msg)) => assert!(
                !msg.contains("too many ref updates"),
                "an at-cap push must reach the owner gate, not the cap; got: {msg}"
            ),
            Err(other) => panic!(
                "an at-cap push must pass the cap and refuse at the owner gate; got {other:?}"
            ),
            Ok(_) => panic!("a non-owner at-cap push must still refuse at the owner gate"),
        }
        let (req_count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM receive_pack_requests WHERE repo_id = $1")
                .bind(&repo_id)
                .fetch_one(state.db.pool())
                .await
                .unwrap();
        assert_eq!(req_count, 0, "the owner gate precedes the intent insert");
    }

    // Two identical command lines in one push derive the same deterministic
    // intent child id (`pending_ref_transition` + request id + ref + old + new)
    // and the `pending_ref_transitions` INSERT has no `ON CONFLICT`, so without
    // dedupe the whole intent transaction dies on the duplicate: the handler
    // answers `Overloaded` — a retryable status for a shape that can never
    // succeed — and ZERO rows survive (nothing for reconcile). With the
    // parse-level dedupe this A,B,A body inserts two children, stalls at the
    // lease like the refusal harness, and terminalizes normally. Goes RED
    // (`fetch_one` finds no aggregate) without the dedupe.
    #[sqlx::test]
    async fn receive_pack_dedupes_identical_ref_commands_before_intent(pool: sqlx::PgPool) {
        use crate::git::repo_store::advisory_lock_key;
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;

        let owner = "z6dupintent";
        let name = "di1";
        let owner_slug = owner.replace([':', '/'], "_");
        let lock_key = advisory_lock_key(&owner_slug, name);

        let mut state = crate::test_support::test_state(pool.clone()).await;
        let mut cfg = (*state.config).clone();
        cfg.git_acquire_timeout_secs = 2;
        cfg.git_service_timeout_secs = 600;
        state.config = std::sync::Arc::new(cfg);
        state
            .db
            .upsert_mirror_repo(owner, name, "/tmp/z6dupintent-di1", None, false)
            .await
            .unwrap();
        let repo_id = state
            .db
            .get_repo(owner, name)
            .await
            .unwrap()
            .expect("mirror row exists")
            .id;

        // Stall acquire_write on a second pooled connection so the push stops
        // after the intent insert; the rows below are what the insert wrote.
        let mut lock_conn = pool.acquire().await.expect("second connection");
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(lock_key)
            .execute(&mut *lock_conn)
            .await
            .expect("hold the advisory lock");

        let did = "did:key:z6dupintent";
        let peer: SocketAddr = "203.0.113.94:5000".parse().unwrap();
        let sha_a = "1111111111111111111111111111111111111111";
        let sha_b = "2222222222222222222222222222222222222222";
        let result = git_receive_pack(
            State(state.clone()),
            Path((owner.to_string(), name.to_string())),
            Extension(crate::auth::AuthenticatedDid(did.to_string())),
            None,
            crate::rate_limit::PeerAddr(Some(peer)),
            axum::http::HeaderMap::new(),
            ref_update_body_cmds(&[
                (sha_a, "refs/heads/main"),
                (sha_b, "refs/heads/other"),
                (sha_a, "refs/heads/main"), // identical to line 1, non-adjacent
            ]),
        )
        .await;
        assert!(
            matches!(result, Err(AppError::Overloaded(_))),
            "stalled acquire_write must shed with Overloaded/503; got {result:?}"
        );

        let (req_id,): (String,) =
            sqlx::query_as("SELECT id FROM receive_pack_requests WHERE repo_id = $1")
                .bind(&repo_id)
                .fetch_one(state.db.pool())
                .await
                .expect("the intent aggregate exists: the duplicate must not kill the insert txn");
        let children = state
            .db
            .list_pending_ref_transitions_for_request(&req_id)
            .await
            .unwrap();
        assert_eq!(
            children.len(),
            2,
            "three command lines dedupe to two children — the repeated main command \
             is one child, not a PK collision"
        );

        sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(lock_key)
            .execute(&mut *lock_conn)
            .await
            .expect("release the advisory lock");
    }

    /// Absent report-status with exit zero is indeterminate, not proof.
    /// A capability-free client omits `report-status`; Git then emits zero
    /// result bytes even for rejected commands. The handler must leave every
    /// child `uncertain`, keep the parent out of `outcomes_committed`, and
    /// emit no push event, certificate, anchor, or webhook.
    #[cfg(unix)]
    #[sqlx::test]
    async fn absent_report_with_exit_zero_defers_effects_until_evidence(pool: sqlx::PgPool) {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;

        let tmp = tempfile::TempDir::new().unwrap();
        // Fake emits zero result bytes with exit zero: the exact
        // capability-free boundary.
        let git_bin = write_fake_git(tmp.path(), "#!/bin/sh\ncat >/dev/null\nexit 0\n");
        let mut state = f4_state_with_repo(
            pool.clone(),
            tmp.path(),
            &git_bin,
            "z6noreport",
            "n1",
            false,
        )
        .await;
        let mut cfg = (*state.config).clone();
        cfg.enforce_owner_push = false;
        state.config = std::sync::Arc::new(cfg);

        let peer: SocketAddr = "203.0.113.99:5000".parse().unwrap();
        let resp = git_receive_pack(
            State(state.clone()),
            Path(("z6noreport".to_string(), "n1".to_string())),
            Extension(crate::auth::AuthenticatedDid(
                "did:key:z6noreport".to_string(),
            )),
            None,
            crate::rate_limit::PeerAddr(Some(peer)),
            axum::http::HeaderMap::new(),
            ref_update_body("3333333333333333333333333333333333333333"),
        )
        .await
        .expect("capability-free push still receives the Git response");
        assert_eq!(
            resp.status(),
            200,
            "client is not rejected; effects are deferred"
        );

        // No child may be applied on exit-status alone.
        let applied = state
            .db
            .list_pending_ref_transitions_applied(100)
            .await
            .unwrap();
        assert!(
            applied.is_empty(),
            "absent report must not mark any child applied"
        );
        // No executable parent: nothing for the drain to effect.
        let due = state.db.list_receive_pack_requests_due(100).await.unwrap();
        assert!(
            due.is_empty(),
            "indeterminate request must not become executable without disk evidence"
        );
        // The aggregate must read as indeterminate, not unpack-failed: the
        // documented no-report reason and the TRUE git exit (0 here), so
        // operators see "await disk evidence" instead of a false unpack
        // failure flag. Routing the absent report through the unpack arm
        // persists "unpack failed without parseable report" + FALSE.
        let repo_id = state
            .db
            .get_repo("z6noreport", "n1")
            .await
            .unwrap()
            .expect("repo exists")
            .id;
        let (req_state, last_error, git_exit_ok): (String, Option<String>, Option<bool>) =
            sqlx::query_as(
                "SELECT state, last_error, git_exit_ok FROM receive_pack_requests WHERE repo_id = $1",
            )
            .bind(&repo_id)
            .fetch_one(state.db.pool())
            .await
            .unwrap();
        assert_eq!(
            req_state,
            crate::db::request_state::REJECTED_AT_GIT,
            "indeterminate parent waits in rejected_at_git for reconcile"
        );
        assert_eq!(
            last_error.as_deref(),
            Some(crate::durable_outbox::NO_REPORT_AWAITING_EVIDENCE),
            "parent carries the indeterminate reason, not an unpack-failure label"
        );
        assert_eq!(
            git_exit_ok,
            Some(true),
            "parent records the true git exit (0), not a false unpack failure"
        );
        // Storage durability: git exited ok, so the shared copy is refreshed
        // even with no proven refs — otherwise the next Tigris-backed write
        // restores a stale archive over the landed refs (and their marker)
        // before reconcile can prove the landing. The upload-site counter
        // records reaching the upload decision (tests run tigris: None).
        assert_eq!(
            state.repo_store.tigris_upload_site_reached(),
            1,
            "exit-ok push must reach the Tigris upload site with or without a report"
        );
    }

    /// A valid empty (`0000`, no commands) push terminalizes with its proof
    /// acked, so retention can purge it: no child can ever consume the
    /// proof, and the no-report outcome has no accepted child to ack it.
    /// Without the up-front ack the terminal parent fails the ACK gate
    /// forever. Backdates `completed_at` past retention and proves the
    /// purge deletes the aggregate.
    #[cfg(unix)]
    #[sqlx::test]
    async fn empty_receive_pack_acks_proof_for_retention(pool: sqlx::PgPool) {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;

        let tmp = tempfile::TempDir::new().unwrap();
        let git_bin = write_fake_git(tmp.path(), "#!/bin/sh\ncat >/dev/null\nexit 0\n");
        let mut state =
            f4_state_with_repo(pool.clone(), tmp.path(), &git_bin, "z6empty", "e1", false).await;
        let mut cfg = (*state.config).clone();
        cfg.enforce_owner_push = false;
        state.config = std::sync::Arc::new(cfg);

        let peer: SocketAddr = "203.0.113.97:5000".parse().unwrap();
        let resp = git_receive_pack(
            State(state.clone()),
            Path(("z6empty".to_string(), "e1".to_string())),
            Extension(crate::auth::AuthenticatedDid("did:key:z6empty".to_string())),
            None,
            crate::rate_limit::PeerAddr(Some(peer)),
            axum::http::HeaderMap::new(),
            axum::body::Bytes::from_static(b"0000"),
        )
        .await
        .expect("empty push receives the Git response");
        assert_eq!(resp.status(), 200);

        let repo_id = state
            .db
            .get_repo("z6empty", "e1")
            .await
            .unwrap()
            .expect("repo exists")
            .id;
        let (req_id, req_state): (String, String) =
            sqlx::query_as("SELECT id, state FROM receive_pack_requests WHERE repo_id = $1")
                .bind(&repo_id)
                .fetch_one(state.db.pool())
                .await
                .unwrap();
        assert_eq!(
            req_state,
            crate::db::request_state::REJECTED_AT_GIT,
            "empty push terminalizes without effects"
        );
        let proof = state
            .db
            .get_request_proof(&req_id)
            .await
            .unwrap()
            .expect("proof row exists");
        assert!(
            proof.acked_at.is_some(),
            "empty push acks its proof up front (no child ever could)"
        );

        // Age past retention: the aggregate must purge.
        let old = (chrono::Utc::now() - chrono::Duration::days(8)).to_rfc3339();
        sqlx::query("UPDATE receive_pack_requests SET completed_at = $1 WHERE id = $2")
            .bind(&old)
            .bind(&req_id)
            .execute(state.db.pool())
            .await
            .unwrap();
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(7)).to_rfc3339();
        let purged = state
            .db
            .purge_completed_receive_pack_requests_returning(&cutoff, 100)
            .await
            .unwrap();
        assert!(
            purged.iter().any(|(id, _)| id == &req_id),
            "empty terminal aggregate is purge-eligible, got {purged:?}"
        );
    }

    /// `unpack_ok: false` with a per-ref `ok: true` bit and exit zero must
    /// emit zero effects. The unpack gate clears the accepted set and
    /// terminalizes; children are cancelled, never applied.
    #[cfg(unix)]
    #[sqlx::test]
    async fn unpack_failure_with_ok_bit_emits_no_effects(pool: sqlx::PgPool) {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;

        let tmp = tempfile::TempDir::new().unwrap();
        // Single-framed report claiming unpack failure yet ok:true.
        let payload = "\x01unpack fail\nok refs/heads/main\n";
        let report = format!("{:04x}{payload}0000", payload.len() + 4);
        let git_bin = write_fake_git(
            tmp.path(),
            &format!("#!/bin/sh\ncat >/dev/null\nprintf '{report}'\nexit 0\n"),
        );
        let mut state =
            f4_state_with_repo(pool.clone(), tmp.path(), &git_bin, "z6unpack", "u1", false).await;
        let mut cfg = (*state.config).clone();
        cfg.enforce_owner_push = false;
        state.config = std::sync::Arc::new(cfg);

        let peer: SocketAddr = "203.0.113.98:5000".parse().unwrap();
        let before_certs = state
            .db
            .list_ref_certificates(
                &state
                    .db
                    .get_repo("z6unpack", "u1")
                    .await
                    .unwrap()
                    .unwrap()
                    .id,
                100,
            )
            .await
            .unwrap()
            .len();
        let resp = git_receive_pack(
            State(state.clone()),
            Path(("z6unpack".to_string(), "u1".to_string())),
            Extension(crate::auth::AuthenticatedDid(
                "did:key:z6unpack".to_string(),
            )),
            None,
            crate::rate_limit::PeerAddr(Some(peer)),
            axum::http::HeaderMap::new(),
            ref_update_body("4444444444444444444444444444444444444444"),
        )
        .await
        .expect("unpack-failed push still receives the Git response");
        assert_eq!(resp.status(), 200);
        let applied = state
            .db
            .list_pending_ref_transitions_applied(100)
            .await
            .unwrap();
        assert!(applied.is_empty(), "unpack failure applies no child");
        let after_certs = state
            .db
            .list_ref_certificates(
                &state
                    .db
                    .get_repo("z6unpack", "u1")
                    .await
                    .unwrap()
                    .unwrap()
                    .id,
                100,
            )
            .await
            .unwrap()
            .len();
        assert_eq!(
            before_certs, after_certs,
            "unpack failure issues no certificate"
        );
        let due = state.db.list_receive_pack_requests_due(100).await.unwrap();
        assert!(
            due.is_empty(),
            "unpack failure terminalizes with nothing executable"
        );
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
        // receive-pack succeeds instantly with a report-status (unpack ok
        // + ok main) so the report authority marks refs applied; every
        // candidate-scan git op (cat-file / rev-list / ls-tree) holds an
        // atomic mkdir lock for 150ms — a second scan process alive at
        // the same instant records an overlap.
        let body = format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
               receive-pack) cat > /dev/null 2>/dev/null; printf '0022\\001unpack ok\\nok refs/heads/main\\n0000' ;;\n\
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

        let new_sha = "1111111111111111111111111111111111111111";
        // The two repos have different owners, and owner-only push is on by default,
        // so each push signs as the owner of the repo it targets. The subject here is
        // the scan pool serializing two concurrent bursts, not authorization.
        let push = |owner: &'static str, name: &'static str, peer: &'static str| {
            let state = state.clone();
            tokio::spawn(async move {
                git_receive_pack(
                    State(state),
                    Path((owner.to_string(), name.to_string())),
                    Extension(crate::auth::AuthenticatedDid(format!("did:key:{owner}"))),
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
                    "did:key:z6f4fast".to_string(),
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
                    "did:key:z6f4park".to_string(),
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
        let did = "did:key:z6f3repo";

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
        let did = "did:key:z6f3clean";

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
        let did = "did:key:z6f3dos";

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

        let did = "did:key:z6u2key";
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
                "did:key:z6ovflow".to_string(),
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
        let did = "did:key:z6u1cap";
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
        let did = "did:key:z6u1two";
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
    /// Same one source IP for all three pushes (the collapsed-key shape), per-source
    /// cap 2 so the holder plus a parked push would exhaust it. A and B are the owner
    /// of `n1`; C is a second tenant, `z6u1nat2`, pushing to its own `n2` — owner-only
    /// push means a tenant is identified by the repo it may write, not by an arbitrary
    /// DID, and the cap keys on the resolved peer address rather than either.
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
        // n2 belongs to a DIFFERENT owner, so the third push is a genuinely different
        // tenant — which is what this test is named for. Owner-only push forces each
        // push to sign as the owner of the repo it targets, so the tenants are
        // distinguished by which repo they push to rather than by an arbitrary DID.
        f1_add_repo(&state, "z6u1nat2", "n2").await;
        // Every pusher arrives from the one edge IP, so they share a source key: the
        // per-source cap keys on the resolved peer address and never on the DID, which
        // is exactly the property under test.
        let edge: SocketAddr = "203.0.113.85:5000".parse().unwrap();
        let push = |owner: &'static str, repo: &'static str| {
            let st = state.clone();
            async move {
                git_receive_pack(
                    State(st),
                    Path((owner.to_string(), repo.to_string())),
                    Extension(crate::auth::AuthenticatedDid(format!("did:key:{owner}"))),
                    None,
                    crate::rate_limit::PeerAddr(Some(edge)),
                    axum::http::HeaderMap::new(),
                    axum::body::Bytes::from_static(b"0000"),
                )
                .await
            }
        };

        let handle_a = tokio::spawn(push("z6u1nat", "n1"));
        assert!(
            f1_wait_for(F1_BACKSTOP, || a_inpack.exists()).await,
            "pusher one never reached receive-pack within {F1_BACKSTOP:?}"
        );
        let handle_b = tokio::spawn(push("z6u1nat", "n1"));
        assert!(
            f1_wait_for(F1_BACKSTOP, || state.repo_write_leases.waiters_for(&repo1)
                == 1)
            .await,
            "pusher two never parked on n1's contended lease within {F1_BACKSTOP:?}"
        );

        // A third pusher — a different tenant — behind the same edge IP, on its own repo.
        let c = tokio::time::timeout(F1_BACKSTOP, push("z6u1nat2", "n2"))
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

        // The pusher must be the repos' owner: this test is about the write-cap key's
        // shape, so the push has to reach the cap rather than stop at the owner-push
        // gate, which is on by default. `did_matches` collapses the `did:key:` prefix,
        // so this is the same identity as the bare `z6f1key` the rows are owned by.
        let did = "did:key:z6f1key";
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
        // Positive, for the same reason as `f1_write_cap_is_inert_without_a_resolvable
        // _source_key`: `!matches!(.., Overloaded)` is satisfied by a Forbidden, so a
        // gate that started rejecting this pusher would leave the test green and inert.
        assert!(
            matches!(r, Err(AppError::Git(_))),
            "a different source must not be shed on any repo while the capped source \
             holds its slot, and must reach git; got {r:?}"
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
                "did:key:z6f1none".to_string(),
            )),
            None,
            crate::rate_limit::PeerAddr(None),
            axum::http::HeaderMap::new(),
            axum::body::Bytes::from_static(b"0000"),
        )
        .await;
        // Assert the POSITIVE outcome, not the absence of one error. Reaching git on
        // the missing on-disk repo is proof the request cleared BOTH the owner gate
        // and the per-caller cap. The previous shape — `!matches!(r, Overloaded)` —
        // was satisfied by any other error, so when owner-only push began rejecting
        // this pusher the test kept reporting ok while measuring nothing.
        assert!(
            matches!(r, Err(AppError::Git(_))),
            "a caller with no resolvable source key must fall back to the global write \
             pool only, never shed on the per-caller cap, and must reach git; got {r:?}"
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
        let did = "did:key:z6f1seq";
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

    #[cfg(unix)]
    fn f2a_log(log: &std::path::Path) -> String {
        std::fs::read_to_string(log).unwrap_or_default()
    }

    /// Withheld-walk children run so far. `ls-tree` is the walk's signature child
    /// (`blob_paths` lists every reachable commit's tree); the delta scan and the
    /// full-scan fallback use `rev-list` / `cat-file` instead.
    #[cfg(unix)]
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
    #[cfg(unix)]
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

    #[cfg(unix)]
    fn f2a_update(ref_name: &str, new_sha: &str) -> Vec<RefUpdate> {
        vec![RefUpdate {
            old_sha: ZERO_SHA.to_string(),
            new_sha: new_sha.to_string(),
            ref_name: ref_name.to_string(),
        }]
    }

    #[cfg(unix)]
    const F2A_PUSHER: &str = "did:key:z6MkF2aPusherAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// When publish durability is fenced, the tail must not run walks or take
    /// coalescing keys before returning.
    #[cfg(unix)]
    #[sqlx::test]
    async fn post_receive_tail_skips_all_work_when_publish_fenced(pool: sqlx::PgPool) {
        let repo = tempfile::TempDir::new().unwrap();
        let bin = tempfile::TempDir::new().unwrap();
        let log = bin.path().join("git.log");
        let git_bin = f2a_logging_git(bin.path(), &log);
        u5_init_repo(repo.path());
        let c1 = u5_commit_file(repo.path(), "a.txt", "one\n");
        let (state, rec) = f2a_state(pool, &git_bin, "z6f2afence", "fence-repo", false).await;
        let slot = Arc::new(std::sync::Mutex::new(Some(
            crate::git::repo_store::ReleaseOutcome::Fenced,
        )));
        post_receive_replication_tail(
            state.clone(),
            rec,
            f2a_update("refs/heads/main", &c1),
            repo.path().to_path_buf(),
            F2A_PUSHER.to_string(),
            Some(slot),
        )
        .await;
        assert_eq!(
            f2a_walks(&log),
            0,
            "a fenced publish must not run the replication walk; log:\n{}",
            f2a_log(&log)
        );
        assert_eq!(
            state.encrypt_inflight.len(),
            0,
            "a fenced publish must not take the per-repo coalescing key"
        );
    }

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
            None,
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
            None,
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
    #[cfg(unix)]
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
    #[cfg(unix)]
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
            None,
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
            None,
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
    #[cfg(unix)]
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
    #[cfg(unix)]
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

    #[cfg(unix)]
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
            None,
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
            // Default shim: fake `receive-pack` success with a report-status
            // (unpack ok + ok main) while logging every invocation and
            // delegating all other git commands to real git.
            None => {
                let body = format!(
                    "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"{}\"\n\
                     case \"$1\" in receive-pack) cat >/dev/null 2>/dev/null; printf '0022\\001unpack ok\\nok refs/heads/main\\n0000'; exit 0 ;; esac\n\
                     exec git \"$@\"\n",
                    log.display()
                );
                write_fake_git(tmp, &body)
            }
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

    // No shared pusher constant: the two P2 tests own different repos (`z6p2tail`
    // and `z6p2fail`), and owner-only push is on by default, so the identity has to
    // follow the repo each push targets rather than being fixed for both.

    #[cfg(unix)]
    fn p2_push(
        state: &AppState,
        owner: &str,
        name: &str,
    ) -> impl std::future::Future<Output = Result<axum::response::Response>> {
        use axum::extract::{Path, State};
        use axum::Extension;
        use std::net::SocketAddr;
        // One accepted ref: the request-level gate (`exit_ok &&
        // any_ref_ok`) needs a landed ref to spawn the replication
        // tail and reach the Tigris upload; a bare `0000` flush is
        // correctly a no-op.
        let line = format!("{ZERO_SHA} 1111111111111111111111111111111111111111 refs/heads/main");
        let body = axum::body::Bytes::from(format!("{:04x}{}0000", line.len() + 4, line));
        git_receive_pack(
            State(state.clone()),
            Path((owner.to_string(), name.to_string())),
            Extension(crate::auth::AuthenticatedDid(format!("did:key:{owner}"))),
            None,
            crate::rate_limit::PeerAddr(Some("203.0.113.90:5000".parse::<SocketAddr>().unwrap())),
            axum::http::HeaderMap::new(),
            body,
        )
    }

    #[cfg(unix)]
    fn p2_logged(log: &std::path::Path, prefix: &str) -> bool {
        f2a_log(log).lines().any(|l| l.starts_with(prefix))
    }

    /// A persistent `commit_request_outcomes_atomically` failure must not fail
    /// the push: the request-level gate (`outcome_commit_ok=false`) defers all
    /// durable effects to startup reconcile while the handler still answers
    /// 200, releases the write lock, and leaves the parent in `received` for
    /// the due worker. Asserted at the handler boundary, not the pure fn:
    /// removing the `run_effects` gate would land a push event, cert, and
    /// webhook row and turn this red.
    #[cfg(unix)]
    #[sqlx::test]
    async fn outcome_commit_failure_returns_200_and_defers_effects(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let log = tmp.path().join("git.log");
        let git_bin = write_fake_git(
            tmp.path(),
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"{}\"\n\
                 case \"$1\" in receive-pack) cat >/dev/null 2>/dev/null; printf '0022\\001unpack ok\\nok refs/heads/main\\n0000'; exit 0 ;; esac\n\
                 exec git \"$@\"\n",
                log.display()
            ),
        );
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();

        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.git_bin = git_bin;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        // Real (non-parked) store: release resolves and the tail gets its
        // publish-durability confirmation, so nothing parks.
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool.clone());
        let owner = "z6ocommit";
        let name = "t1";
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

        // Enough injected failures to exhaust the retry budget (delay_ms
        // 20 -> 100 -> 500, then break false).
        drain_faults::arm_outcome_commit(&rec.id, 4);

        let resp = p2_push(&state, owner, name)
            .await
            .expect("the push must return, not park");
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "a persistent outcome-commit failure defers effects; it does not fail the push"
        );

        // The tail still spawns on a landed push: its `for-each-ref` walk
        // appears in the git log after the handler returns.
        let mut walked = false;
        for _ in 0..100 {
            if p2_logged(&log, "for-each-ref") {
                walked = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            walked,
            "the replication tail must still run on a landed push"
        );

        // No durable effects were written: the gate deferred them all.
        let push_events: i64 = sqlx::query_scalar("SELECT count(*) FROM push_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        let certs: i64 = sqlx::query_scalar("SELECT count(*) FROM ref_certificates")
            .fetch_one(&pool)
            .await
            .unwrap();
        let hooks: i64 = sqlx::query_scalar("SELECT count(*) FROM webhook_deliveries")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!((push_events, certs, hooks), (0, 0, 0));

        // The parent never reaches a terminal state: it stays in a
        // reconcile-recoverable phase (`received` while the commit is
        // still armed, or `outcomes_committed`/`effects_pending` once the
        // still-armed intent guard terminalizes it on scope exit).
        let parent_state: String = sqlx::query_scalar("SELECT state FROM receive_pack_requests")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(
            ["received", "outcomes_committed", "effects_pending"].contains(&parent_state.as_str()),
            "a failed outcome commit must leave the parent recoverable, got: {parent_state}"
        );
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
    ///
    /// Round-3 P1: a successful receive-pack followed by a disconnect during
    /// `guard.release()` must still see its replication tail run. The tail is
    /// spawned above `release` (gated on `receive_result.is_ok()`), and the marker
    /// polls for `rev-list` (the new tail's primary walk command) — the previous
    /// `for-each-ref` marker is dead because commit 91d0578 removed the last
    /// tail-path use of that command (it lived in `assert_all_refs_are_commits`,
    /// which is now gone). The new marker points at a real command the tail still
    /// executes, so a future reorder that drops the tail will be caught.
    ///
    /// Load-bearing: with the spawn below `release` the walk's `rev-list` never
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

        // Round-3 P1: marker is `rev-list`, not `for-each-ref` — the
        // tail's primary walk is `git rev-list --objects --all` (the
        // same call as `smart_http::rev_list_keep`); a successful
        // re-key on the cloned path emits it from the post-receive
        // tail. Polling for `for-each-ref` was vacuous after 91d0578
        // removed the last tail-path use of that command.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !p2_logged(&log, "rev-list") {
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
        // Round-3 P1: the must-not twin also runs the `rev-list`
        // command (the actual tail walk). `for-each-ref` is dead in
        // the tail path; the previous marker made the assertion
        // vacuous. The new marker pins the same command the
        // positive-control sibling above uses, so a future change
        // that drops the tail leaves both tests red together.
        assert!(
            !p2_logged(&log, "rev-list"),
            "a failed receive-pack must spawn no replication tail: pinning and \
             announcing a half-applied repo is exactly what release(false) refuses \
             to upload"
        );
    }

    // ── #285 P1 finding 1: cancellation before the PUT is dispatched ───────

    /// A minimal object-store stub that COUNTS PUTs and answers every HEAD 404.
    ///
    /// Not a semantics mock: the whole claim of the tests below is that no PUT
    /// ever arrives, so the only thing it has to do faithfully is notice one.
    async fn p3_put_counting_store() -> (
        String,
        Arc<std::sync::atomic::AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        let puts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let app = axum::Router::new().route(
            "/{*key}",
            axum::routing::any({
                let puts = Arc::clone(&puts);
                move |method: axum::http::Method, _body: axum::body::Bytes| {
                    let puts = Arc::clone(&puts);
                    async move {
                        if method == axum::http::Method::PUT {
                            puts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            return axum::http::StatusCode::OK;
                        }
                        // Nothing is stored, so the acquire-side refresh takes the
                        // create-only arm and downloads nothing.
                        axum::http::StatusCode::NOT_FOUND
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (endpoint, puts, server)
    }

    /// A push handler whose release-side publish parks INSIDE the blocking
    /// compression, which is the window the finding is about: the conditional PUT
    /// is not constructed until compression returns, so a handler cancelled here
    /// definitely never attempted publication.
    ///
    /// Path-scoped for the same reason as `p2_parked_release_state`: the tail's
    /// withheld walk is the observable, and without a path-scoped rule
    /// `replication_withheld_set` takes the no-walk shortcut and spawns no git.
    ///
    /// The bare repo is created directly rather than through `repo_store.init`,
    /// which would spawn a background create-only upload of its own and pollute
    /// the PUT count this test reads.
    #[cfg(unix)]
    async fn p3_compression_gated_state(
        pool: sqlx::PgPool,
        tmp: &std::path::Path,
        owner: &str,
        name: &str,
        gate: Arc<crate::git::tigris::BlockingGate>,
        report_ok: bool,
    ) -> (
        AppState,
        std::path::PathBuf,
        Arc<std::sync::atomic::AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        let log = tmp.join("git.log");
        // `report_ok` fakes a report-status `ok refs/heads/main` so the push
        // proves a landing and `disposition.spawn_tail` admits the live tail;
        // the plain logging shim leaves the push report-absent, which under
        // the proven-refs gate spawns no tail at all.
        let git_bin = if report_ok {
            write_fake_git(
                tmp,
                &format!(
                    "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"{}\"\n\
                     case \"$1\" in receive-pack) cat >/dev/null 2>/dev/null; printf '0022\\001unpack ok\\nok refs/heads/main\\n0000'; exit 0 ;; esac\n\
                     exec git \"$@\"\n",
                    log.display()
                ),
            )
        } else {
            f2a_logging_git(tmp, &log)
        };
        let repos_dir = tmp.join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        let (endpoint, puts, server) = p3_put_counting_store().await;

        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.git_bin = git_bin;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.repo_store = crate::git::repo_store::RepoStore::new(
            repos_dir.clone(),
            Some(
                crate::git::tigris::TigrisClient::for_testing_with_endpoint(
                    "test-bucket",
                    &endpoint,
                )
                .with_compress_gate(gate),
            ),
            pool.clone(),
            std::time::Duration::from_secs(300),
        );
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
                &["did:key:z6MkP3TailReaderAAAAAAAAAAAAAAAAAAAAAA".to_string()],
                &rec.owner_did,
            )
            .await
            .unwrap();
        let bare =
            crate::git::repo_store::validated_repo_disk_path(&repos_dir, &rec.owner_did, name)
                .expect("test repo path");
        crate::git::store::init_bare(&bare).expect("a bare repo on disk");
        (state, log, puts, server)
    }

    /// #285 P1 FINDING 1 (RED-before/GREEN-after). A client disconnect while the
    /// release-side archive is still being COMPRESSED must not count as publish
    /// durability.
    ///
    /// `TigrisClient::upload` awaits `spawn_blocking(compress_repo)` and does not
    /// construct, let alone send, the conditional PUT until that returns. So a
    /// handler dropped in this window definitively never attempted publication —
    /// and the detached tail must do NOTHING: no IPFS/Pinata pin, no P2P
    /// announcement, no GraphQL publication, no Arweave work, no peer
    /// notification, all for refs that exist only in a local write the store
    /// never saw.
    ///
    /// Load-bearing: with the slot recording `UploadUnknowable` for every
    /// cancellation after release starts (the pre-fix shape), the tail is
    /// admitted and its withheld walk's `for-each-ref` appears in the git log
    /// (RED). Reading the publish STAGE instead classifies this as a definite
    /// non-publication and the walk never runs (GREEN).
    ///
    /// The existing `receive_pack_tail_survives_a_disconnect_during_release`
    /// parks at the pre-unlock point, which is AFTER the upload, so it cannot
    /// reach this boundary at all.
    #[cfg(unix)]
    #[sqlx::test]
    async fn receive_pack_cancelled_during_compression_publishes_nothing_and_runs_no_tail(
        pool: sqlx::PgPool,
    ) {
        let tmp = tempfile::TempDir::new().unwrap();
        // Shut: every compression from this store parks until the gate opens.
        let gate = Arc::new(crate::git::tigris::BlockingGate::shut());
        let (state, log, puts, server) =
            p3_compression_gated_state(pool, tmp.path(), "z6p3comp", "c1", Arc::clone(&gate), true)
                .await;

        let mut fut = Box::pin(p2_push(&state, "z6p3comp", "c1"));
        let mut ran = false;
        for _ in 0..1000 {
            let step = tokio::time::timeout(std::time::Duration::from_millis(10), &mut fut).await;
            assert!(
                step.is_err(),
                "the handler must park inside the release-side compression, not return"
            );
            if p2_logged(&log, "receive-pack") {
                ran = true;
                break;
            }
        }
        assert!(ran, "the push must reach receive-pack");
        // Settle: the handler is now inside `release`, blocked on the gate with
        // no PUT constructed.
        for _ in 0..10 {
            let _ = tokio::time::timeout(std::time::Duration::from_millis(10), &mut fut).await;
        }
        assert_eq!(
            puts.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "compression has not finished, so no PUT can have been built yet"
        );

        // THE DISCONNECT, inside the compression window.
        drop(fut);

        // Give the tail every chance to misbehave. Pre-fix it is admitted the
        // instant the slot's Drop installs its verdict, so this window is far
        // more than enough for the walk to show up.
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

        assert!(
            !p2_logged(&log, "for-each-ref"),
            "RED: a push cancelled before its PUT was even constructed still ran the \
             replication tail. Nothing was published, so pinning, announcing and \
             replicating these refs advertises a write no other node can read. git log:\n{}",
            f2a_log(&log)
        );
        assert_eq!(
            puts.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no PUT may have reached the store at any point"
        );

        // Release the parked blocking task so the runtime can tear down cleanly.
        gate.open();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        server.abort();
    }

    /// THE CONTROL, and what makes the assertion above attributable. Same setup,
    /// same handler, but nothing holds the gate: the publish completes, the store
    /// sees the PUT, and the tail DOES run its walk.
    ///
    /// Without this, a green negative would prove only that the walk never runs
    /// in this harness, not that the CANCELLATION is what stops it.
    #[cfg(unix)]
    #[sqlx::test]
    async fn receive_pack_that_completes_its_publish_still_runs_the_tail(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        // Open from the start: this control must publish for real.
        let gate = Arc::new(crate::git::tigris::BlockingGate::shut());
        gate.open();
        let (state, log, puts, server) =
            p3_compression_gated_state(pool, tmp.path(), "z6p3ctrl", "c1", gate, true).await;

        p2_push(&state, "z6p3ctrl", "c1")
            .await
            .expect("an uncontended push must succeed");

        assert_eq!(
            puts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the release must have published exactly once"
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !p2_logged(&log, "for-each-ref") {
            assert!(
                std::time::Instant::now() < deadline,
                "a confirmed publish must admit the replication tail; git log:\n{}",
                f2a_log(&log)
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }

        server.abort();
    }

    // ── #285 U3: the abandoned write path settles the live tree ────────────
    //
    // The sibling above proves the replication TAIL is withheld when a push is
    // cancelled before its PUT is dispatched. Nothing yet stops the next READ
    // from serving the very refs that tail refused to announce: the write guard
    // drops without classifying the tree, so `acquire` finds a live directory,
    // no marker, and hands it out.

    /// The sidecar marker path for a live tree, derived the way production
    /// derives it (`.{name}.git.quarantine` beside the validated path) rather
    /// than returned by the state builder.
    #[cfg(unix)]
    fn p3_quarantine_marker(
        repos_dir: &std::path::Path,
        owner_did: &str,
        name: &str,
    ) -> std::path::PathBuf {
        let live = crate::git::repo_store::validated_repo_disk_path(repos_dir, owner_did, name)
            .expect("test repo path");
        let file = live
            .file_name()
            .expect("a live tree always has a file name")
            .to_string_lossy()
            .to_string();
        live.parent()
            .expect("a live tree always has a parent")
            .join(format!(".{file}.quarantine"))
    }

    /// #285 U3, gap-driving. A push cancelled inside the release-side
    /// compression definitely never attempted publication, so the refs it wrote
    /// exist only on this node's disk. The next read must not serve them.
    ///
    /// The p3 store answers every HEAD 404, so there is nothing stored to serve
    /// in their place: the correct outcome is that the abandoned tree is gone,
    /// not that a stale copy is handed out.
    #[cfg(unix)]
    #[sqlx::test]
    async fn receive_pack_cancelled_during_compression_leaves_no_servable_refs(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let gate = Arc::new(crate::git::tigris::BlockingGate::shut());
        let (state, log, puts, server) = p3_compression_gated_state(
            pool,
            tmp.path(),
            "z6p3quar",
            "c1",
            Arc::clone(&gate),
            false,
        )
        .await;
        let rec = state.db.get_repo("z6p3quar", "c1").await.unwrap().unwrap();
        let repos_dir = tmp.path().join("repos");
        let live =
            crate::git::repo_store::validated_repo_disk_path(&repos_dir, &rec.owner_did, "c1")
                .expect("test repo path")
                .into_path_buf();
        let marker = p3_quarantine_marker(&repos_dir, &rec.owner_did, "c1");

        let mut fut = Box::pin(p2_push(&state, "z6p3quar", "c1"));
        let mut ran = false;
        for _ in 0..1000 {
            let step = tokio::time::timeout(std::time::Duration::from_millis(10), &mut fut).await;
            assert!(
                step.is_err(),
                "the handler must park inside the release-side compression, not return"
            );
            if p2_logged(&log, "receive-pack") {
                ran = true;
                break;
            }
        }
        assert!(ran, "the push must reach receive-pack");
        for _ in 0..10 {
            let _ = tokio::time::timeout(std::time::Duration::from_millis(10), &mut fut).await;
        }
        assert_eq!(
            puts.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "compression has not finished, so no PUT can have been built yet"
        );

        // THE DISCONNECT, inside the compression window.
        drop(fut);
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        // Release the orphaned compression BEFORE the assertions. The guard has
        // already dropped, so nothing below depends on the gate, and a failing
        // assertion would otherwise leave a blocking task parked forever and
        // hang the runtime teardown instead of reporting.
        gate.open();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert!(
            marker.exists(),
            "a push cancelled before its PUT was dispatched must leave a marker beside the live tree"
        );
        // The read resolves the marker: a definite non-publication, so the tree
        // is dropped and the stored generation (there is none here) is what
        // would serve.
        let _ = state.repo_store.acquire(&rec.owner_did, "c1").await;
        assert!(
            !live.exists(),
            "a push cancelled before its PUT was dispatched left its refs servable on the live path"
        );

        server.abort();
    }

    /// #285 U3, gap-driving. The disconnect one step earlier: receive-pack has
    /// already APPLIED a ref and the client goes away before `release` is ever
    /// entered, so the publish stage is still `Idle`. The guard rides the
    /// admission guard into the detached reaper, so it drops once the git group
    /// is torn down, and at that point the tree carries refs no PUT ever
    /// described.
    ///
    /// The fake git applies the ref and then hangs, which is what puts the
    /// disconnect in that window; argv is
    /// `<bin> receive-pack --stateless-rpc <repo path>`, so `$3` is the tree.
    #[cfg(unix)]
    #[sqlx::test]
    async fn receive_pack_disconnected_after_refs_are_applied_leaves_no_servable_refs(
        pool: sqlx::PgPool,
    ) {
        let tmp = tempfile::TempDir::new().unwrap();
        let gate = Arc::new(crate::git::tigris::BlockingGate::shut());
        let (mut state, _log, _puts, server) = p3_compression_gated_state(
            pool,
            tmp.path(),
            "z6p3disc",
            "c1",
            Arc::clone(&gate),
            false,
        )
        .await;
        // Its own directory: `write_fake_git` always writes `fakegit`, and the
        // state builder has already put the logging shim at that name.
        let gitdir = tmp.path().join("hanging-git");
        std::fs::create_dir_all(&gitdir).unwrap();
        state.git_bin = write_fake_git(
            &gitdir,
            r#"#!/bin/sh
case "$1" in
  receive-pack)
    mkdir -p "$3/refs/heads"
    printf '%s\n' 1111111111111111111111111111111111111111 > "$3/refs/heads/main"
    sleep 30
    ;;
  *) : ;;
esac
exit 0
"#,
        );

        let rec = state.db.get_repo("z6p3disc", "c1").await.unwrap().unwrap();
        let repos_dir = tmp.path().join("repos");
        let live =
            crate::git::repo_store::validated_repo_disk_path(&repos_dir, &rec.owner_did, "c1")
                .expect("test repo path")
                .into_path_buf();
        let marker = p3_quarantine_marker(&repos_dir, &rec.owner_did, "c1");
        let ref_path = live.join("refs").join("heads").join("main");

        let mut fut = Box::pin(p2_push(&state, "z6p3disc", "c1"));
        let mut applied = false;
        for _ in 0..2000 {
            let step = tokio::time::timeout(std::time::Duration::from_millis(10), &mut fut).await;
            assert!(
                step.is_err(),
                "the handler must park inside the hanging receive-pack, not return"
            );
            if ref_path.exists() {
                applied = true;
                break;
            }
        }
        assert!(applied, "the push must apply its ref before the disconnect");

        // THE DISCONNECT, after the refs landed and before release is entered.
        drop(fut);
        // Nothing below depends on the gate: this disconnect never reaches
        // release, so no compression is parked on it. Opened here anyway so a
        // failing assertion reports rather than hanging the teardown.
        gate.open();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !marker.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "a push disconnected after receive-pack applied its refs must mark the tree, or acquire serves refs object storage does not hold"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        let _ = state.repo_store.acquire(&rec.owner_did, "c1").await;
        assert!(
            !ref_path.exists(),
            "refs applied by a disconnected push must not be served"
        );

        server.abort();
    }

    /// #285 U3, the REAP WINDOW. The sibling above waits for the marker before
    /// it reads, so it proves the settled state and cannot see the interval
    /// between the disconnect and the settlement. This one reads inside that
    /// interval: `RepoWriteGuard::drop` runs on the guard clone that rode the
    /// admission guard into `KillGroupOnDrop`'s detached reaper, so the marker
    /// cannot exist until the receive-pack group is torn down, and `acquire`
    /// takes no advisory lock on the way to the live tree.
    ///
    /// The read happens immediately after the handler future is dropped, while
    /// the fake receive-pack is still sleeping, so the guard is still alive in
    /// the reaper.
    #[cfg(unix)]
    #[sqlx::test]
    async fn receive_pack_read_inside_the_reap_window_serves_no_abandoned_refs(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let gate = Arc::new(crate::git::tigris::BlockingGate::shut());
        let (mut state, _log, _puts, server) = p3_compression_gated_state(
            pool.clone(),
            tmp.path(),
            "z6p3rwin",
            "c1",
            Arc::clone(&gate),
            false,
        )
        .await;
        let gitdir = tmp.path().join("hanging-git");
        std::fs::create_dir_all(&gitdir).unwrap();
        // Ignores SIGTERM and re-parks after each interrupted `sleep`, so the
        // process group outlives the reaper's grace period and only SIGKILL ends
        // it. A plain `sleep 30` does NOT hold this window open: the group kill
        // TERMs the sleep, the shell falls through the case and exits, and the
        // reaper can free the advisory lock before the probe below runs, which
        // turns this test into its own INCONCLUSIVE branch instead of an
        // observation of the window it names.
        state.git_bin = write_fake_git(
            &gitdir,
            r#"#!/bin/sh
trap '' TERM
case "$1" in
  receive-pack)
    mkdir -p "$3/refs/heads"
    printf '%s\n' 1111111111111111111111111111111111111111 > "$3/refs/heads/main"
    i=0
    while [ "$i" -lt 300 ]; do
      sleep 1
      i=$((i+1))
    done
    ;;
  *) : ;;
esac
exit 0
"#,
        );

        let rec = state.db.get_repo("z6p3rwin", "c1").await.unwrap().unwrap();
        let repos_dir = tmp.path().join("repos");
        let marker = p3_quarantine_marker(&repos_dir, &rec.owner_did, "c1");
        let live =
            crate::git::repo_store::validated_repo_disk_path(&repos_dir, &rec.owner_did, "c1")
                .expect("test repo path")
                .into_path_buf();
        let ref_path = live.join("refs").join("heads").join("main");

        let mut fut = Box::pin(p2_push(&state, "z6p3rwin", "c1"));
        let mut applied = false;
        for _ in 0..2000 {
            let step = tokio::time::timeout(std::time::Duration::from_millis(10), &mut fut).await;
            assert!(
                step.is_err(),
                "the handler must park inside the hanging receive-pack, not return"
            );
            if ref_path.exists() {
                applied = true;
                break;
            }
        }
        assert!(applied, "the push must apply its ref before the disconnect");

        // THE DISCONNECT. Nothing parks on the gate here, opened only so a
        // failing assertion reports instead of hanging teardown.
        drop(fut);
        gate.open();
        tokio::task::yield_now().await;

        // THE PROBE, inside the window. What makes the read INSIDE it is that the
        // receive-pack group is still being reaped, and the write lock rides that
        // reaper: the guard's last copy is held by `KillGroupOnDrop`, so the
        // advisory lock is still taken at this instant. Sampled before the read,
        // from an independent session, and filtered to this test's own database,
        // which `#[sqlx::test]` gives it exclusively.
        //
        // Keying conclusiveness on the LOCK rather than on the marker's absence:
        // the marker is what the settlement writes, so requiring it to be missing
        // would demand the very state the fix removes, and no correct
        // implementation could satisfy it.
        let locks_held: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' \
             AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
        )
        .fetch_one(&pool)
        .await
        .expect("count the advisory locks this test's database holds");
        let marker_before = marker.exists();
        let served = state.repo_store.acquire(&rec.owner_did, "c1").await;
        let refs_after = ref_path.exists();
        let served_ok = served.is_ok();

        assert!(
            locks_held.0 >= 1,
            "INCONCLUSIVE: the write lock was already free when the probe ran, so the \
             reaper had finished and this read never observed the reap window"
        );
        // THE FIX'S OWN PROPERTY, asserted rather than only reported. The marker
        // has to be on disk at the DISCONNECT instant, which is what moving the
        // settlement out of the reaper-held guard buys; without this the test
        // reddens only through the refs below, which a settlement arriving late
        // can still satisfy by accident once the reaper catches up.
        assert!(
            marker_before,
            "the settlement must land at the disconnect, not at reaper exit: no quarantine \
             marker existed when the probe read inside the reap window (acquire={served:?})"
        );
        // Unconditional on the refs, not `!(served_ok && refs_after)`. That form
        // also passed when `acquire` failed for a reason unrelated to the
        // withholding while the abandoned refs were still sitting on the live
        // tree, which is a pass for the wrong reason.
        assert!(
            !refs_after,
            "a read inside the reap window left the abandoned refs on the live tree: \
             marker_before={marker_before}, acquire={served:?}, served_ok={served_ok}"
        );

        server.abort();
    }

    /// THE CONTROL for both of the above. Same builder, no disconnect: the
    /// publish completes, the store acknowledges the PUT, and the tree stays
    /// readable with nothing withholding it. Without this a green refusal above
    /// would prove only that this harness never serves.
    #[cfg(unix)]
    #[sqlx::test]
    async fn receive_pack_that_completes_its_publish_leaves_the_tree_servable(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let gate = Arc::new(crate::git::tigris::BlockingGate::shut());
        gate.open();
        let (state, _log, puts, server) =
            p3_compression_gated_state(pool, tmp.path(), "z6p3serv", "c1", gate, false).await;
        let rec = state.db.get_repo("z6p3serv", "c1").await.unwrap().unwrap();
        let repos_dir = tmp.path().join("repos");
        let marker = p3_quarantine_marker(&repos_dir, &rec.owner_did, "c1");

        p2_push(&state, "z6p3serv", "c1")
            .await
            .expect("an uncontended push must succeed");
        assert_eq!(
            puts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the release must have published exactly once"
        );

        let served = state.repo_store.acquire(&rec.owner_did, "c1").await;
        assert!(
            served.is_ok() && !marker.exists(),
            "a confirmed publish must leave the tree readable with no marker"
        );

        server.abort();
    }

    // ── #285 P1 finding 3: fork confirmation is bound to the attempt ───────

    /// A repo row under `owner/name` owned by some OTHER attempt.
    async fn p3_seed_foreign_row(
        state: &AppState,
        owner_did: &str,
        name: &str,
    ) -> crate::db::RepoRecord {
        let now = Utc::now();
        let rec = crate::db::RepoRecord {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            owner_did: owner_did.to_string(),
            description: None,
            is_public: true,
            default_branch: "main".to_string(),
            created_at: now,
            updated_at: now,
            disk_path: format!("/unused/{name}"),
            forked_from: None,
            machine_id: None,
        };
        state
            .db
            .create_repo(&rec)
            .await
            .expect("seed the other row");
        rec
    }

    /// #285 P1 FINDING 3, interleaving (a): another row COMMITS UNDER THE NAME
    /// before this attempt's confirmation runs.
    ///
    /// The ordering is the barrier: the successor's insert completes, and only
    /// then does the failed attempt look up. Keyed on owner/name, that lookup
    /// answered "a row exists" and the request returned 201 carrying the
    /// successor's row — even though its own uploaded archive, disk path and fork
    /// provenance belong to no row at all. Keyed on `record.id` it cannot.
    #[sqlx::test]
    async fn fork_confirmation_never_claims_a_concurrent_attempts_row(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;
        let owner = "did:key:z6MkForkIdentityAAAAAAAAAAAAAAAAAAAAAAAA";
        let short = crate::db::normalize_owner_key(owner);
        let name = "contested-fork";

        // Interleaving: the successor commits first.
        let successor = p3_seed_foreign_row(&state, owner, name).await;

        // Then this attempt, whose own insert did NOT land, confirms.
        let mine = Uuid::new_v4().to_string();
        let confirmation = confirm_fork_repo_row(&state.db, &mine, short, name)
            .await
            .expect("the lookup itself succeeds");
        match confirmation {
            ForkRowConfirmation::Foreign => {}
            ForkRowConfirmation::Ours(row) => panic!(
                "the failed attempt claimed the successor's row {} as its own commit",
                row.id
            ),
            ForkRowConfirmation::Absent => {
                panic!("a row for this name does exist, so Absent would license compensation")
            }
        }
        assert_ne!(successor.id, mine);
    }

    /// The must-do direction: when this attempt's OWN insert did commit, the
    /// confirmation has to recognize it, or a transport-level error on a
    /// successful write would turn into a spurious failure plus compensation of
    /// a live repository.
    #[sqlx::test]
    async fn fork_confirmation_recognizes_this_attempts_own_committed_row(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;
        let owner = "did:key:z6MkForkIdentityBBBBBBBBBBBBBBBBBBBBBBBB";
        let short = crate::db::normalize_owner_key(owner);
        let name = "my-fork";

        let mine = p3_seed_foreign_row(&state, owner, name).await;
        match confirm_fork_repo_row(&state.db, &mine.id, short, name)
            .await
            .expect("lookup")
        {
            ForkRowConfirmation::Ours(row) => assert_eq!(row.id, mine.id),
            other => panic!(
                "this attempt's own row must confirm as Ours, got {}",
                match other {
                    ForkRowConfirmation::Foreign => "Foreign",
                    ForkRowConfirmation::Absent => "Absent",
                    ForkRowConfirmation::Ours(_) => unreachable!(),
                }
            ),
        }
    }

    /// And the third arm: nothing owns the name, which is the only state that
    /// licenses compensation at all.
    #[sqlx::test]
    async fn fork_confirmation_reports_absent_when_nothing_owns_the_name(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;
        let short = "z6MkForkIdentityCCCCCCCCCCCCCCCCCCCCCCCC";
        assert!(matches!(
            confirm_fork_repo_row(&state.db, &Uuid::new_v4().to_string(), short, "nobody-here")
                .await
                .expect("lookup"),
            ForkRowConfirmation::Absent
        ));
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
            None,
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
            None,
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
            None,
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
    #[cfg(unix)]
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
            None,
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

    /// A ref-update command line that is not valid UTF-8 refuses the whole
    /// push. Git accepts refnames with bytes >= 0x80, so silently skipping
    /// such a line would plant a ref the namespace gate never sees and no
    /// durable child row covers. Removing the Err arm (skip-and-continue)
    /// turns the expect_err red.
    #[test]
    fn parse_ref_updates_refuses_non_utf8_command_line() {
        // Well-formed section first: one command + flush parses fine.
        let good_payload = format!("{} {} refs/heads/main\n", "0".repeat(40), "1".repeat(40));
        let good_body = format!("{:04x}{}0000", good_payload.len() + 4, good_payload);
        let updates = parse_ref_updates(good_body.as_bytes()).expect("well-formed section parses");
        assert_eq!(updates.len(), 1, "one command line yields one update");
        assert_eq!(updates[0].ref_name, "refs/heads/main");

        // Same framing, but the refname carries a raw 0xFF byte (note: `b"\xff"`
        // is one raw byte; `"\xff"` in a str literal would be U+00FF instead).
        let mut payload = Vec::new();
        payload.extend_from_slice(b"0000000000000000000000000000000000000000 ");
        payload.extend_from_slice(b"1111111111111111111111111111111111111111 ");
        payload.extend_from_slice(b"refs/gitlawb/issues/\xffx\n");
        let mut body = format!("{:04x}", payload.len() + 4).into_bytes();
        body.extend_from_slice(&payload);
        body.extend_from_slice(b"0000");
        let err =
            parse_ref_updates(&body).expect_err("a non-UTF-8 command line must refuse the push");
        assert!(
            matches!(err, AppError::BadRequest(_)),
            "undecodable ref-update line is a client error (400), got {err:?}"
        );
    }

    /// The spawned guard cleanup commits stashed fates instead of a blanket
    /// `uncertain`: an `ok` child lands `applied`, an `ng` child lands
    /// `cancelled` (terminal, purgeable — reconcile could never resolve a
    /// proven rejection left `uncertain`), and the parent carries the parsed
    /// report. Reverting the fates arm to `mark_receive_pack_interrupted`
    /// flips the ng child to `uncertain` and turns this red.
    #[sqlx::test]
    async fn guard_retry_with_fates_commits_them_not_blanket_uncertain(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;
        let now = chrono::Utc::now().to_rfc3339();
        let req = crate::db::ReceivePackRequest {
            id: "req-guard-fates".to_string(),
            repo_id: "repo-guard-fates".to_string(),
            pusher_did: "did:key:z6pusher".to_string(),
            node_did: state.node_did.to_string(),
            request_bytes: Vec::new(),
            request_bytes_hash: vec![7u8; 32],
            state: crate::db::request_state::RECEIVED.to_string(),
            git_exit_ok: None,
            parsed_report: None,
            accepted_ordinal: None,
            attempt_count: 0,
            last_error: None,
            next_attempt_at: None,
            created_at: now.clone(),
            completed_at: None,
            signature_header: Some("sig".to_string()),
            signature_input: Some("sig-input".to_string()),
            content_digest: Some("digest".to_string()),
        };
        let updates = vec![
            RefUpdate {
                old_sha: "0".repeat(40),
                new_sha: "1".repeat(40),
                ref_name: "refs/heads/main".to_string(),
            },
            RefUpdate {
                old_sha: "0".repeat(40),
                new_sha: "2".repeat(40),
                ref_name: "refs/heads/feat".to_string(),
            },
        ];
        state
            .db
            .insert_receive_pack_request_with_children(
                &req,
                "repo-guard-fates",
                &state.node_did.to_string(),
                "did:key:z6pusher",
                &updates,
                "sig",
                "sig-input",
                "digest",
            )
            .await
            .unwrap();
        let fates = ComputedFates {
            ok_names: vec!["refs/heads/main".to_string()],
            ng_names: vec!["refs/heads/feat".to_string()],
            uncertain_names: Vec::new(),
            unpack_failed: false,
            git_exit_ok: true,
            parsed_json: Some(serde_json::json!({
                "unpack_ok": true,
                "ref_results": [
                    {"ref_name": "refs/heads/main", "ok": true},
                    {"ref_name": "refs/heads/feat", "ok": false},
                ],
            })),
            accepted_ordinal: Some(0),
            rejected_reason: None,
            terminal_no_effects: false,
        };
        retry_guard_cleanup(&state.db, "req-guard-fates", true, Some(fates)).await;

        let parent = state
            .db
            .get_receive_pack_request("req-guard-fates")
            .await
            .unwrap()
            .expect("parent exists");
        assert_eq!(
            parent.state,
            crate::db::request_state::OUTCOMES_COMMITTED,
            "fates commit advances the parent"
        );
        assert!(
            parent.parsed_report.is_some(),
            "committed fates carry the parsed report"
        );
        let children = state
            .db
            .list_pending_ref_transitions_for_request("req-guard-fates")
            .await
            .unwrap();
        let by_name: std::collections::HashMap<&str, &str> = children
            .iter()
            .map(|c| (c.ref_name.as_str(), c.state.as_str()))
            .collect();
        assert_eq!(
            by_name.get("refs/heads/main"),
            Some(&crate::db::pending_state::APPLIED),
            "ok child applies"
        );
        assert_eq!(
            by_name.get("refs/heads/feat"),
            Some(&crate::db::pending_state::CANCELLED),
            "git-proven rejection cancels (never blanket uncertain)"
        );
    }

    /// Without stashed fates the post-git cleanup falls back to
    /// `mark_receive_pack_interrupted`, and a non-`received` aggregate stops
    /// the loop immediately. A missing id exhausts only the (short test)
    /// budget and returns — proving the budget exit without a 30s test.
    #[sqlx::test]
    async fn guard_retry_without_fates_marks_interrupted_and_stops_when_terminal(
        pool: sqlx::PgPool,
    ) {
        let state = crate::test_support::test_state(pool).await;
        let now = chrono::Utc::now().to_rfc3339();
        let req = crate::db::ReceivePackRequest {
            id: "req-guard-nofates".to_string(),
            repo_id: "repo-guard-nofates".to_string(),
            pusher_did: "did:key:z6pusher".to_string(),
            node_did: state.node_did.to_string(),
            request_bytes: Vec::new(),
            request_bytes_hash: vec![7u8; 32],
            state: crate::db::request_state::RECEIVED.to_string(),
            git_exit_ok: None,
            parsed_report: None,
            accepted_ordinal: None,
            attempt_count: 0,
            last_error: None,
            next_attempt_at: None,
            created_at: now.clone(),
            completed_at: None,
            signature_header: Some("sig".to_string()),
            signature_input: Some("sig-input".to_string()),
            content_digest: Some("digest".to_string()),
        };
        let updates = vec![RefUpdate {
            old_sha: "0".repeat(40),
            new_sha: "1".repeat(40),
            ref_name: "refs/heads/main".to_string(),
        }];
        state
            .db
            .insert_receive_pack_request_with_children(
                &req,
                "repo-guard-nofates",
                &state.node_did.to_string(),
                "did:key:z6pusher",
                &updates,
                "sig",
                "sig-input",
                "digest",
            )
            .await
            .unwrap();

        retry_guard_cleanup(&state.db, "req-guard-nofates", true, None).await;
        let parent = state
            .db
            .get_receive_pack_request("req-guard-nofates")
            .await
            .unwrap()
            .expect("parent exists");
        assert_eq!(
            parent.state,
            crate::db::request_state::REJECTED_AT_GIT,
            "no-fates fallback terminalizes the parent"
        );
        let children = state
            .db
            .list_pending_ref_transitions_for_request("req-guard-nofates")
            .await
            .unwrap();
        assert_eq!(
            children[0].state,
            crate::db::pending_state::UNCERTAIN,
            "no-fates fallback leaves the child uncertain for reconcile"
        );

        // Terminal aggregate: returns without touching anything.
        retry_guard_cleanup(&state.db, "req-guard-nofates", true, None).await;
        let again = state
            .db
            .get_receive_pack_request("req-guard-nofates")
            .await
            .unwrap()
            .expect("parent exists");
        assert_eq!(
            again.state,
            crate::db::request_state::REJECTED_AT_GIT,
            "cleanup on a terminal aggregate is a no-op"
        );

        // Missing id: only the budget decides; a millisecond budget proves
        // the exit without waiting out production 30s.
        retry_guard_cleanup_with_budget(
            &state.db,
            "req-never-existed",
            false,
            None,
            std::time::Duration::from_millis(150),
        )
        .await;
    }

    /// Each cleanup attempt is bounded, not just the loop: with the parent
    /// row locked by an open transaction, the refuse UPDATE blocks until the
    /// per-attempt timeout fires, and the loop exits at the (short test)
    /// budget instead of parking the task past it. Unwrapping the attempt
    /// timeout parks the UPDATE forever and this hangs (caught by the outer
    /// guard timeout, slow-red rather than green).
    #[sqlx::test]
    async fn guard_retry_attempt_bounded_under_row_lock(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool.clone()).await;
        let now = chrono::Utc::now().to_rfc3339();
        let req = crate::db::ReceivePackRequest {
            id: "req-row-locked".to_string(),
            repo_id: "repo-row-locked".to_string(),
            pusher_did: "did:key:z6pusher".to_string(),
            node_did: state.node_did.to_string(),
            request_bytes: Vec::new(),
            request_bytes_hash: vec![7u8; 32],
            state: crate::db::request_state::RECEIVED.to_string(),
            git_exit_ok: None,
            parsed_report: None,
            accepted_ordinal: None,
            attempt_count: 0,
            last_error: None,
            next_attempt_at: None,
            created_at: now.clone(),
            completed_at: None,
            signature_header: Some("sig".to_string()),
            signature_input: Some("sig-input".to_string()),
            content_digest: Some("digest".to_string()),
        };
        state
            .db
            .insert_receive_pack_request_with_children(
                &req,
                "repo-row-locked",
                &state.node_did.to_string(),
                "did:key:z6pusher",
                &[],
                "sig",
                "sig-input",
                "digest",
            )
            .await
            .unwrap();

        // Hold the parent row locked inside an EXPLICIT transaction for the
        // whole call: a pooled `SELECT ... FOR UPDATE` outside a transaction
        // releases at statement end (autocommit) and holds nothing. Every
        // cleanup UPDATE below blocks on this lock until the per-attempt
        // timeout fires.
        let mut locker = pool.begin().await.expect("locker transaction");
        sqlx::query("SELECT 1 FROM receive_pack_requests WHERE id = $1 FOR UPDATE")
            .bind("req-row-locked")
            .fetch_one(&mut *locker)
            .await
            .unwrap();

        // GREEN returns at the test budget with elapsed below the 10s
        // per-attempt cap, proving the clamp (not just the loop budget):
        // without the per-attempt bound the UPDATE parks until the lock
        // releases — never, in this test — and trips the outer guard.
        // The outer guard sits above the 10s cap but far below infinity so
        // a regression slow-fails instead of wedging the suite.
        let started = std::time::Instant::now();
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            retry_guard_cleanup_with_budget(
                &state.db,
                "req-row-locked",
                false,
                None,
                std::time::Duration::from_secs(2),
            ),
        )
        .await
        .expect("bounded attempts must return, not park past the outer guard");
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "cleanup under a held row lock must return inside the per-attempt \
             bound, not park the UPDATE; took {elapsed:?}"
        );
        // Releasing the lock lets the stranded aggregate terminalize.
        locker.rollback().await.unwrap();
    }

    /// The internal-namespace predicate covers the bare `refs/gitlawb` name
    /// and the whole subtree, and nothing else. The handler denies any push
    /// naming such a ref before intent is written; narrowing the predicate
    /// (e.g. dropping the bare-name arm) turns these red.
    #[test]
    fn internal_namespace_gate_covers_bare_name_and_subtree() {
        // Denied: bare name, subtree root, exempt namespaces, attacker refs.
        for denied in [
            "refs/gitlawb",
            "refs/gitlawb/",
            "refs/gitlawb/requests/550e8400-e29b-41d4-a716-446655440000",
            "refs/gitlawb/issues/abc123",
            "refs/gitlawb/evil",
        ] {
            assert!(
                ref_is_internal_namespace(denied),
                "push gate must deny {denied}"
            );
        }
        // Allowed: content refs, lookalike prefixes, empty.
        for allowed in [
            "refs/heads/main",
            "refs/tags/v1",
            "refs/gitlawbfoo",
            "refs/heads/gitlawb/x",
            "",
        ] {
            assert!(
                !ref_is_internal_namespace(allowed),
                "push gate must allow {allowed}"
            );
        }
    }
}

#[cfg(test)]
mod push_event_wiring_tests {
    /// The catch-up scenarios in `api/events.rs` drive `record_push_events`
    /// directly, because a full receive-pack POST needs a real pack. That proves
    /// the mechanism and says nothing about the sink: delete the call from the
    /// effect bundle and every one of them still passes while no push is ever
    /// discoverable by polling again. Pin the wiring by source, the way the
    /// stored-head guard above and the authz guards in `api/mod.rs` do. The
    /// slice stops at the bundle's own closing brace (the first `}` in column 0)
    /// so a call in a later function cannot satisfy this, and full-line comments
    /// are stripped so the doc comment on the call cannot stand in for the call.
    ///
    /// The id is pinned alongside the call: `record_push_events` must derive it
    /// from `(request_id, ordinal)`, not mint a random one, because a recovery
    /// replay against the same accepted transition has to re-derive the same id
    /// for the `ON CONFLICT` to collapse the replay instead of doubling the event.
    #[test]
    fn the_effect_bundle_actually_records_push_events() {
        let src = include_str!("../durable_outbox.rs");
        let body = crate::test_support::scrape_source_region(
            src,
            Some("fn run_effect_bundle("),
            Some("\n}"),
        )
        .expect("run_effect_bundle not found (renamed or removed?)");

        assert!(
            body.contains("record_push_events(&state.db, &req.id, accepted_children)"),
            "the effect bundle must feed the ACCEPTED transition rows to the \
             push-event recorder; without that call the catch-up poll surface is \
             fed by nothing and every scenario test for it passes against a \
             helper the push path never invokes"
        );
    }

    /// The event id is deterministic on the request, so a recovery replay
    /// records each landing exactly once no matter which path runs it.
    #[test]
    fn the_push_event_recorder_derives_deterministic_ids() {
        let src = include_str!("repos.rs");
        let body = crate::test_support::scrape_source_region(
            src,
            Some("async fn record_push_events("),
            Some("\n}"),
        )
        .expect("record_push_events not found (renamed or removed?)");

        assert!(
            body.contains("repo_push_event_id_for(request_id"),
            "a random id would double-deliver a landing on every replay; the \
             id must derive from the request identity the drain re-reads"
        );
    }

    /// The containment constraint as a source property, independent of any one
    /// scenario: the producer must never write a local push into the table the
    /// unauthenticated global feed reads.
    #[test]
    fn the_push_event_recorder_never_targets_the_gossip_table() {
        let src = include_str!("repos.rs");
        let body = crate::test_support::scrape_source_region(
            src,
            Some("async fn record_push_events("),
            Some("\n}"),
        )
        .expect("record_push_events not found (renamed or removed?)");

        // This is a must-not assertion, so it passes on an empty region. Pin what
        // the scan covered first: without this, a helper that returned nothing
        // would make the guard below green while proving nothing.
        assert!(
            body.contains("insert_repo_push_events("),
            "the scan must cover the recorder's own body, which writes through \
             insert_repo_push_events; got: {body}"
        );
        assert!(
            !body.contains("insert_ref_update"),
            "a local push must not be written into received_ref_updates, which the \
             anonymous /api/v1/events/ref-updates feed also reads"
        );
    }
}
