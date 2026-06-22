use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Json;
use bytes::Bytes;
use std::sync::Arc;

use crate::auth::AuthenticatedDid;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cert;
use crate::error::{AppError, Result};
use crate::git::{smart_http, store, visibility_pack};
use crate::state::AppState;
use crate::visibility::{visibility_check, Decision};
use crate::webhooks;

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
    Json(req): Json<CreateRepoRequest>,
) -> Result<(StatusCode, Json<RepoResponse>)> {
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

    let disk_path = state
        .repo_store
        .init(&owner_did, &req.name)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;

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
pub async fn list_repos(
    State(state): State<AppState>,
    Query(query): Query<ListReposQuery>,
) -> Result<Response> {
    use axum::http::HeaderValue;
    use axum::response::IntoResponse;

    if let Some(raw_limit) = query.limit {
        let limit = raw_limit.clamp(1, 200);
        let offset = query.offset.unwrap_or(0).max(0);
        let (rows, total) = state
            .db
            .list_all_repos_paged(query.owner.as_deref(), limit, offset)
            .await?;
        let body: Vec<RepoResponse> = rows
            .into_iter()
            .map(|(r, stars)| to_response(&r, &state, stars))
            .collect();
        let mut response = Json(body).into_response();
        response.headers_mut().insert(
            "X-Total-Count",
            HeaderValue::from_str(&total.to_string()).unwrap_or(HeaderValue::from_static("0")),
        );
        return Ok(response);
    }

    let repos = state.db.list_all_repos_with_stars().await?;
    let filtered: Vec<_> = repos
        .iter()
        .filter(|(r, _)| {
            if let Some(owner) = &query.owner {
                let short = r.owner_did.split(':').next_back().unwrap_or(&r.owner_did);
                short == owner.as_str() || r.owner_did == owner.as_str()
            } else {
                true
            }
        })
        .collect();
    let total = filtered.len() as i64;
    let resp: Vec<_> = filtered
        .into_iter()
        .map(|(r, stars)| to_response(r, &state, *stars))
        .collect();
    let mut response = Json(resp).into_response();
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
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, caller, "/").await?;

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

/// GET /:owner/:repo.git/info/refs?service=git-upload-pack
pub async fn git_info_refs(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<InfoRefsQuery>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Response> {
    let name = repo.trim_end_matches(".git");
    tracing::info!(owner = %owner, repo = %name, "info/refs request");
    let record = state
        .db
        .get_repo(&owner, name)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;

    let service = query
        .service
        .ok_or_else(|| AppError::BadRequest("missing ?service= parameter".into()))?;
    tracing::debug!(service = %service, repo = %name, "info/refs service");

    // Enforce read (clone/fetch) visibility. The push advertisement
    // (service=git-receive-pack) is authorized separately on the
    // git-receive-pack POST, so leave it untouched here.
    if service == "git-upload-pack" {
        let rules = state.db.list_visibility_rules(&record.id).await?;
        let caller = auth.as_ref().map(|e| e.0 .0.as_str());
        // Subtree (mode B) rules do not gate the advertisement: refs expose commit
        // tips only, and blob withholding happens in the upload-pack pack build.
        if visibility_check(&rules, record.is_public, &record.owner_did, caller, "/")
            == Decision::Deny
        {
            tracing::debug!(repo = %name, caller = ?caller, "info/refs read denied by visibility");
            return Err(AppError::RepoNotFound(format!("{owner}/{name}")));
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

/// POST /:owner/:repo.git/git-upload-pack
pub async fn git_upload_pack(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
    body: Bytes,
) -> Result<Response> {
    let name = repo.trim_end_matches(".git");
    let record = state
        .db
        .get_repo(&owner, name)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;

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

    // withheld_blob_oids walks every ref with blocking `git ls-tree`; keep that
    // off the async worker thread.
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

    let resp = if withheld.is_empty() {
        smart_http::upload_pack(&disk_path, body).await
    } else {
        tracing::info!(repo = %name, caller = ?caller, withheld = withheld.len(), "serving filtered pack");
        smart_http::upload_pack_excluding(&disk_path, body, &withheld).await
    }
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("bad line length") || msg.contains("protocol error") {
            tracing::warn!(repo = %name, err = %msg, "git-upload-pack: bad client request");
            AppError::BadRequest(msg)
        } else {
            tracing::error!(repo = %name, err = %msg, "git-upload-pack failed");
            AppError::Git(msg)
        }
    })?;
    crate::metrics::record_fetch(&format!("{owner}/{name}"));
    crate::metrics::observe_pack_size(body_len as f64);
    Ok(resp)
}

/// POST /:owner/:repo.git/git-receive-pack  (AUTH REQUIRED — enforced by middleware)
pub async fn git_receive_pack(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let name = repo.trim_end_matches(".git");
    tracing::info!(owner = %owner, repo = %name, "receive-pack request");
    let record = state
        .db
        .get_repo(&owner, name)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;

    // Parse ref updates from pkt-line body before handing to git
    let ref_updates = parse_ref_updates(&body);
    tracing::debug!(
        ref_count = ref_updates.len(),
        "parsed ref updates from pack"
    );

    // ── Branch protection check ──────────────────────────────────────────
    let pusher_did_for_check = extract_did_from_auth(&headers);
    tracing::debug!(pusher_did = ?pusher_did_for_check, "extracted pusher DID from auth headers");
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
        {
            let owner_short = record
                .owner_did
                .split(':')
                .next_back()
                .unwrap_or(&record.owner_did);
            let is_owner = pusher_did_for_check
                .as_deref()
                .map(|did| did == record.owner_did || did == owner_short)
                .unwrap_or(false);
            if !is_owner {
                tracing::warn!(
                    branch = %branch,
                    pusher = ?pusher_did_for_check,
                    owner_did = %record.owner_did,
                    "branch protection: rejecting push from non-owner"
                );
                return Err(AppError::BadRequest(format!(
                    "branch '{branch}' is protected — only the repo owner can push to it"
                )));
            }
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
    let receive_result = smart_http::receive_pack(&disk_path, body).await;

    // Always release the advisory lock — even on error — to prevent stale locks
    // from blocking subsequent pushes. Only upload to Tigris when the push
    // succeeded; uploading a half-applied repo would propagate corruption.
    guard.release(receive_result.is_ok()).await;

    let result = receive_result.map_err(|e| {
        tracing::error!(repo = %name, err = %e, "git receive-pack failed");
        AppError::Git(e.to_string())
    })?;

    // Update the repo's updated_at timestamp after a successful push
    let _ = state.db.touch_repo(&record.id).await;

    // Record the successful push for metrics. The body has already been
    // consumed by smart_http::receive_pack so we observe size up front.
    crate::metrics::record_push(&record.id);
    crate::metrics::observe_pack_size(body_len as f64);

    // Record push event for trust score and issue a signed ref certificate
    let pusher_did = extract_did_from_auth(&headers);
    if let Some(ref did) = pusher_did {
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

        let ref_name = ref_updates
            .first()
            .map(|u| u.ref_name.as_str())
            .unwrap_or("refs/heads/main");
        let old_sha = ref_updates
            .first()
            .map(|u| u.old_sha.as_str())
            .unwrap_or("0000000000000000000000000000000000000000");

        // Issue a signed ref-update certificate
        match cert::issue_ref_certificate(&state, &record.id, ref_name, old_sha, &commit_hash, did)
            .await
        {
            Ok(c) => {
                tracing::info!(cert_id = %c.id, repo = %record.name, pusher = %did, "issued ref certificate")
            }
            Err(e) => tracing::warn!(err = %e, "failed to issue ref certificate"),
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
        let owner_short = record
            .owner_did
            .split(':')
            .next_back()
            .unwrap_or(&record.owner_did);
        let clone_url = format!("{}/{}/{}.git", base_url, owner_short, record.name);

        for update in &ref_updates {
            let payload = serde_json::json!({
                "ref": update.ref_name,
                "before": update.old_sha,
                "after": update.new_sha,
                "created": update.old_sha == "0000000000000000000000000000000000000000",
                "forced": false,
                "pusher": {
                    "did": pusher_did.as_deref().unwrap_or("unknown"),
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
    let announce = match &rules_opt {
        Some(rules) => {
            visibility_check(rules, record.is_public, &record.owner_did, None, "/")
                == Decision::Allow
        }
        None => false,
    };
    let withheld: Option<std::collections::HashSet<String>> = if !announce {
        None
    } else {
        match &rules_opt {
            Some(rules) if rules.is_empty() => Some(std::collections::HashSet::new()),
            // withheld_blob_oids walks every ref with blocking `git ls-tree`;
            // keep that off the async worker thread.
            Some(rules) => {
                let path = disk_path.clone();
                let rules = rules.clone();
                let owner_did = record.owner_did.clone();
                let is_public = record.is_public;
                tokio::task::spawn_blocking(move || {
                    crate::git::visibility_pack::withheld_blob_oids(
                        &path, &rules, is_public, &owner_did, None,
                    )
                })
                .await
                .map_err(|e| {
                    tracing::warn!(err = %e, "withheld_blob_oids task panicked; skipping replication for this push")
                })
                .ok()
                .and_then(|r| {
                    r.map_err(|e| {
                        tracing::warn!(err = %e, "withheld_blob_oids failed; skipping replication for this push")
                    })
                    .ok()
                })
            }
            None => None,
        }
    };

    // Pin new git objects to the local IPFS node (no-op if ipfs_api is empty).
    // Skipped entirely when the public cannot read the repo (withheld == None).
    if let Some(withheld_ipfs) = withheld.clone() {
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
                &db_clone,
                &withheld_ipfs,
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
            if let Some(rules) = rules_for_enc.filter(|r| !r.is_empty()) {
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
                        let owner_short = owner_did.split(':').next_back().unwrap_or(&owner_did);
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
            record
                .owner_did
                .split(':')
                .next_back()
                .unwrap_or(&record.owner_did),
            record.name
        );
        let ref_updates_clone = ref_updates
            .iter()
            .map(|u| (u.ref_name.clone(), u.new_sha.clone()))
            .collect::<Vec<_>>();
        let p2p_handle = state.p2p.clone();
        let pusher_did_clone = pusher_did.clone().unwrap_or_default();
        let db_for_peers = state.db.clone();
        let ref_update_tx = state.ref_update_tx.clone();
        let irys_url = state.config.irys_url.clone();
        let owner_did_for_arweave = record.owner_did.clone();
        let self_public_url = state.config.public_url.clone();
        let node_keypair = Arc::clone(&state.node_keypair);
        let withheld_pinata = withheld;
        tokio::spawn(async move {
            let pinned = match &withheld_pinata {
                Some(withheld) => {
                    crate::pinata::pin_new_objects(
                        &http_client,
                        &pinata_upload_url,
                        &pinata_jwt,
                        &repo_path_clone,
                        &db_clone,
                        withheld,
                    )
                    .await
                }
                None => Vec::new(),
            };

            if !pinned.is_empty() {
                tracing::info!(count = pinned.len(), "pinned git objects to Pinata");
            }

            // Build sha→cid map from pinned objects
            let cid_map: std::collections::HashMap<String, String> = pinned.into_iter().collect();

            // Record branch→CID for each ref update and publish gossip
            for (ref_name, new_sha) in &ref_updates_clone {
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
                            old_sha: "".to_string(),
                            new_sha: new_sha.clone(),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                            cert_id: None,
                            cid: cid.map(|s| s.to_string()),
                        })
                        .await;
                    }
                }
            }

            // HTTP peer notification — notify all known peers to pull from us.
            // This is the reliable fallback when Gossipsub p2p is not yet connected.
            // Suppressed for repos the public cannot read.
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
                        let path = "/api/v1/sync/notify";
                        let notify_url = format!("{peer_url}{path}");
                        let body = serde_json::json!({
                            "repo": repo_slug.clone(),
                            "ref_name": ref_updates_clone.first().map(|(r, _)| r).unwrap_or(&String::new()),
                            "new_sha": ref_updates_clone.first().map(|(_, s)| s).unwrap_or(&String::new()),
                            "node_did": node_did_str.clone(),
                            "pusher_did": pusher_did_clone.clone(),
                            "old_sha": "0000000000000000000000000000000000000000",
                            "timestamp": chrono::Utc::now().to_rfc3339(),
                        });
                        let body_bytes = match serde_json::to_vec(&body) {
                            Ok(bytes) => bytes,
                            Err(e) => {
                                tracing::warn!(peer = %peer.did, err = %e, "failed to serialize peer sync notify");
                                continue;
                            }
                        };
                        let signed = gitlawb_core::http_sig::sign_request(
                            node_keypair.as_ref(),
                            "POST",
                            path,
                            &body_bytes,
                        );
                        match http_client
                            .post(&notify_url)
                            .header("Content-Type", "application/json")
                            .header("Content-Digest", signed.content_digest)
                            .header("Signature-Input", signed.signature_input)
                            .header("Signature", signed.signature)
                            .body(body_bytes)
                            .send()
                            .await
                        {
                            Ok(r) if r.status().is_success() => {
                                tracing::info!(peer = %peer.did, repo = %repo_slug, "notified peer to sync")
                            }
                            Ok(r) => {
                                tracing::warn!(peer = %peer.did, status = %r.status(), "peer sync notify returned error")
                            }
                            Err(e) => {
                                tracing::warn!(peer = %peer.did, err = %e, "failed to notify peer")
                            }
                        }
                    }
                }
            }

            // Broadcast ref update to GraphQL subscription listeners
            let now_ts = chrono::Utc::now().to_rfc3339();
            let _ = ref_update_tx.send(crate::state::RefUpdateBroadcast {
                repo: repo_slug.clone(),
                ref_name: ref_updates_clone
                    .first()
                    .map(|(r, _)| r.clone())
                    .unwrap_or_default(),
                old_sha: "0000000000000000000000000000000000000000".to_string(),
                new_sha: ref_updates_clone
                    .first()
                    .map(|(_, s)| s.clone())
                    .unwrap_or_default(),
                pusher_did: pusher_did_clone.clone(),
                node_did: node_did_str.clone(),
                timestamp: now_ts.clone(),
            });

            // Arweave permanent anchoring — fire for each ref update.
            // Suppressed for repos the public cannot read (public permanent ledger).
            if announce && !irys_url.is_empty() {
                for (ref_name, new_sha) in &ref_updates_clone {
                    let cid = cid_map.get(new_sha).cloned();
                    let anchor = crate::arweave::RefAnchor {
                        repo: repo_slug.clone(),
                        owner_did: owner_did_for_arweave.clone(),
                        ref_name: ref_name.clone(),
                        old_sha: "0".repeat(64),
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
                                    old_sha: "0".repeat(64).as_str(),
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
) -> Result<Json<serde_json::Value>> {
    let local_repos = state.db.list_all_repos_with_stars().await?;
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
    Json(req): Json<ForkRepoRequest>,
) -> Result<(StatusCode, Json<RepoResponse>)> {
    // Enforce read visibility on the source before cloning: an unauthorized
    // caller must not be able to fork (full mirror) a repo they cannot read.
    let (source, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, Some(auth.0.as_str()), "/").await?;

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
    let forker_short = forker_did.split(':').next_back().unwrap_or(&forker_did);
    if state.db.get_repo(forker_short, &fork_name).await?.is_some() {
        return Err(AppError::BadRequest(format!(
            "you already have a repo named {fork_name}"
        )));
    }

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

    tracing::info!(fork = %fork_name, source = %source.name, forker = %forker_did, "forked repository");

    Ok((StatusCode::CREATED, Json(to_response(&record, &state, 0))))
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

/// Extract the DID from RFC 9421 Signature-Input header (keyid="...").
/// Falls back to draft-cavage Authorization header for old clients.
fn extract_did_from_auth(headers: &HeaderMap) -> Option<String> {
    // RFC 9421: Signature-Input: sig1=(...);keyid="did:key:z6Mk...";...
    if let Some(sig_input) = headers.get("signature-input").and_then(|v| v.to_str().ok()) {
        if let Some(start) = sig_input.find("keyid=\"") {
            let rest = &sig_input[start + 7..];
            if let Some(end) = rest.find('"') {
                return Some(rest[..end].to_string());
            }
        }
    }
    // Fallback: draft-cavage Authorization: Signature keyId="..."
    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(start) = auth.find("keyId=\"") {
            let rest = &auth[start + 7..];
            if let Some(end) = rest.find('"') {
                return Some(rest[..end].to_string());
            }
        }
    }
    None
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn to_response(record: &crate::db::RepoRecord, state: &AppState, star_count: i64) -> RepoResponse {
    let owner_short = record
        .owner_did
        .split(':')
        .next_back()
        .unwrap_or(&record.owner_did);

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
