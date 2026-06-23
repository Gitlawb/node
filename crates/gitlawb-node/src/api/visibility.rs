//! Path-scoped visibility management API. Owner-only, mirrors `api/protect.rs`.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::auth::AuthenticatedDid;
use crate::db::VisibilityMode;
use crate::error::{AppError, Result};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct SetVisibilityRequest {
    pub path_glob: String,
    /// "a" or "b"; defaults to "b" if absent or unrecognized.
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub reader_dids: Vec<String>,
}

#[derive(Deserialize)]
pub struct RemoveVisibilityRequest {
    pub path_glob: String,
}

fn require_owner(record: &crate::db::RepoRecord, caller: &str) -> Result<()> {
    // DID-safe owner match (collapses did:key full vs bare on both sides, never
    // across methods), shared with require_repo_owner — not a trailing-segment
    // compare that only normalized the owner side.
    if crate::api::did_matches(caller, &record.owner_did) {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "only the repo owner can manage visibility".into(),
        ))
    }
}

/// Reject malformed globs before they reach the store, where they would
/// silently misconfigure access (an empty glob behaves like "/", and a glob
/// without a leading "/" never matches a real repo path). The accepted forms
/// match what `visibility_check` understands: "/", "/prefix", or "/prefix/**".
fn validate_path_glob(path_glob: &str) -> Result<()> {
    if !path_glob.starts_with('/') {
        return Err(AppError::BadRequest("path_glob must start with '/'".into()));
    }
    if path_glob == "/**" {
        return Err(AppError::BadRequest(
            "use '/' for whole-repo scope, not '/**'".into(),
        ));
    }
    if path_glob != "/" && path_glob.ends_with('/') {
        return Err(AppError::BadRequest(
            "path_glob must not end with '/'".into(),
        ));
    }
    if path_glob.contains('*') && !path_glob.ends_with("/**") {
        return Err(AppError::BadRequest(
            "the only supported wildcard is a trailing '/**'".into(),
        ));
    }
    Ok(())
}

/// PUT /api/v1/repos/{owner}/{repo}/visibility
pub async fn set_visibility(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, repo)): Path<(String, String)>,
    Json(req): Json<SetVisibilityRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    let record = state
        .db
        .get_repo(&owner, &repo)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{repo}")))?;
    require_owner(&record, &auth.0)?;
    validate_path_glob(&req.path_glob)?;

    let mode = match req.mode.as_deref() {
        Some("a") => VisibilityMode::A,
        _ => VisibilityMode::B,
    };

    // Mode A hides existence and is only coherent for the whole repo; a subtree
    // cannot hide its existence without rewriting git history (see spec).
    if mode == VisibilityMode::A && req.path_glob != "/" {
        return Err(AppError::BadRequest(
            "mode 'a' (hide) is only allowed for the whole repo (path_glob '/'); use mode 'b' for subtrees".into(),
        ));
    }

    // An empty reader_dids list is valid and intentional: the owner is always
    // allowed by visibility_check, so a "/" rule with no readers is exactly the
    // whole-repo "private to owner only" case.
    state
        .db
        .set_visibility_rule(&record.id, &req.path_glob, mode, &req.reader_dids, &auth.0)
        .await?;

    let subtree_warning = req.path_glob != "/";
    tracing::info!(
        repo = %repo, caller = %auth.0, path_glob = %req.path_glob, mode = %mode.as_str(),
        subtree_pending = subtree_warning,
        "visibility rule set"
    );

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "status": "set",
            "repo": format!("{owner}/{repo}"),
            "path_glob": req.path_glob,
            "mode": mode.as_str(),
            "reader_dids": req.reader_dids,
            "subtree_clone_enforcement_pending": subtree_warning,
        })),
    ))
}

/// DELETE /api/v1/repos/{owner}/{repo}/visibility
pub async fn remove_visibility(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, repo)): Path<(String, String)>,
    Json(req): Json<RemoveVisibilityRequest>,
) -> Result<Json<serde_json::Value>> {
    let record = state
        .db
        .get_repo(&owner, &repo)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{repo}")))?;
    require_owner(&record, &auth.0)?;

    state
        .db
        .remove_visibility_rule(&record.id, &req.path_glob)
        .await?;

    tracing::info!(
        repo = %repo, caller = %auth.0, path_glob = %req.path_glob,
        "visibility rule removed"
    );

    Ok(Json(serde_json::json!({
        "status": "removed",
        "repo": format!("{owner}/{repo}"),
        "path_glob": req.path_glob,
    })))
}

/// GET /api/v1/repos/{owner}/{repo}/visibility
pub async fn list_visibility(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    let record = state
        .db
        .get_repo(&owner, &repo)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{repo}")))?;
    require_owner(&record, &auth.0)?;

    let rules = state.db.list_visibility_rules(&record.id).await?;
    let rules_json: Vec<_> = rules
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "path_glob": r.path_glob,
                "mode": r.mode.as_str(),
                "reader_dids": r.reader_dids,
                "created_by": r.created_by,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "repo": format!("{owner}/{repo}"),
        "count": rules_json.len(),
        "rules": rules_json,
    })))
}

/// GET /api/v1/repos/{owner}/{repo}/withheld-paths
///
/// Returns the path globs the (optionally authenticated) caller is denied
/// (`withheld`) plus any more-specific globs that are allowed underneath a
/// denied one (`reinclude`), so a clean-clone client can sparse-exclude the
/// denied subtrees while re-including the allowed nested paths. Unlike
/// `list_visibility` this is not owner-gated and never exposes reader_dids.
pub async fn withheld_paths(
    State(state): State<AppState>,
    auth: Option<Extension<AuthenticatedDid>>,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    let record = state
        .db
        .get_repo(&owner, &repo)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{repo}")))?;

    let rules = state.db.list_visibility_rules(&record.id).await?;
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());

    // Whole-repo read gate: a caller who cannot read "/" gets repo-not-found,
    // matching the git read endpoints, so this never discloses a private repo's
    // existence or its path layout to an unauthorized caller.
    if crate::visibility::visibility_check(&rules, record.is_public, &record.owner_did, caller, "/")
        == crate::visibility::Decision::Deny
    {
        return Err(AppError::RepoNotFound(format!("{owner}/{repo}")));
    }

    let withheld =
        crate::visibility::withheld_globs(&rules, record.is_public, &record.owner_did, caller);
    let reinclude =
        crate::visibility::reincluded_globs(&rules, record.is_public, &record.owner_did, caller);

    Ok(Json(serde_json::json!({
        "repo": format!("{owner}/{repo}"),
        "withheld": withheld,
        "reinclude": reinclude,
    })))
}

#[cfg(test)]
mod tests {
    use super::validate_path_glob;

    #[test]
    fn accepts_supported_globs() {
        for g in ["/", "/secret", "/secret/**", "/a/b/c", "/a/b/**"] {
            assert!(validate_path_glob(g).is_ok(), "{g} should be valid");
        }
    }

    #[test]
    fn rejects_malformed_globs() {
        // empty, no leading slash, whole-repo via "/**", trailing slash, and
        // non-trailing wildcards are all rejected.
        for g in ["", "secret/**", "/**", "/secret/", "/a*b", "/*/x"] {
            assert!(validate_path_glob(g).is_err(), "{g} should be rejected");
        }
    }
}
