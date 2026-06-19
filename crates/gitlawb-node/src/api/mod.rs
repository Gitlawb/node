use crate::db::{RepoRecord, VisibilityRule};
use crate::error::{AppError, Result};
use crate::state::AppState;
use crate::visibility::{visibility_check, Decision};

pub mod agents;
pub mod arweave;
pub mod bounties;
pub mod certs;
pub mod changelog;
pub mod encrypted;
pub mod events;
pub mod ipfs;
pub mod issues;
pub mod labels;
pub mod peers;
pub mod profiles;
pub mod protect;
pub mod pulls;
pub mod register;
pub mod replicas;
pub mod repos;
pub mod resolve;
pub mod stars;
pub mod tasks;
pub mod visibility;
pub mod webhooks;

/// Resolve a repo for a read request and enforce path-scoped visibility.
///
/// Returns 404 (`RepoNotFound`) if the repo does not exist or the caller may not
/// read `path`, using the same opaque response the git serve path returns so
/// existence is not confirmed. Returns the record and its visibility rules so a
/// content handler can apply an extra per-path check without a second DB query.
///
/// Callers pass `"/"` for repo-level reads (listings); content endpoints pass the
/// specific path so a withheld subtree is denied even on an otherwise-public repo.
pub(crate) async fn authorize_repo_read(
    state: &AppState,
    owner: &str,
    name: &str,
    caller: Option<&str>,
    path: &str,
) -> Result<(RepoRecord, Vec<VisibilityRule>)> {
    let record = state
        .db
        .get_repo(owner, name)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;
    let rules = state.db.list_visibility_rules(&record.id).await?;
    if visibility_check(&rules, record.is_public, &record.owner_did, caller, path) == Decision::Deny
    {
        return Err(AppError::RepoNotFound(format!("{owner}/{name}")));
    }
    Ok((record, rules))
}
