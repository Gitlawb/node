//! Issue API endpoints — issues stored as git refs.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthenticatedDid;
use crate::db::IssueComment;
use crate::error::{AppError, Result};
use crate::git::issues as git_issues;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateIssueRequest {
    pub title: String,
    pub body: Option<String>,
    /// Signed JSON payload (optional — if provided, stored as-is for verification)
    pub signed_payload: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IssueRecord {
    pub id: String,
    pub title: String,
    pub body: Option<String>,
    pub author: Option<String>,
    pub created_at: String,
    pub status: String,
    pub signed_payload: Option<serde_json::Value>,
}

/// POST /api/v1/repos/{owner}/{repo}/issues
pub async fn create_issue(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, repo)): Path<(String, String)>,
    Json(req): Json<CreateIssueRequest>,
) -> Result<(StatusCode, Json<IssueRecord>)> {
    // Authorize the caller as a reader before accepting an issue: a non-reader
    // must not be able to file an issue against a private repo they cannot read.
    // Mirrors create_issue_comment / create_review / create_bounty.
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &repo, Some(auth.0.as_str()), "/").await?;

    let issue_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let issue = IssueRecord {
        id: issue_id.clone(),
        title: req.title.clone(),
        body: req.body.clone(),
        author: Some(auth.0),
        created_at: now,
        status: "open".to_string(),
        signed_payload: req.signed_payload.clone(),
    };

    let json_str = serde_json::to_string(&issue)
        .map_err(|e| AppError::BadRequest(format!("serialization error: {e}")))?;

    let guard = state
        .repo_store
        .acquire_write(&record.owner_did, &record.name)
        .await?;
    let disk_path = guard.path().to_path_buf();

    let create_result = git_issues::create_issue(&disk_path, &issue_id, &json_str);

    // Always release the advisory lock — even on error; upload to Tigris only on success.
    // A refused publish short-circuits here, before the trust bump and before
    // the 201: the issue is on local disk but not in object storage, so no
    // other node can read it and the client must retry rather than be told it
    // was filed.
    guard.release(create_result.is_ok()).await.into_result()?;

    create_result.map_err(|e| AppError::Git(e.to_string()))?;

    // Bump trust score for the issue author — increment current score by 0.05
    // (avoids the push_count=0 stuck-at-0.05 bug for agents who only file issues)
    if let Some(ref author_did) = issue.author {
        let current = state.db.get_trust_score(author_did).await.unwrap_or(0.05);
        let new_score = (current + 0.05).min(1.0);
        let _ = state.db.update_trust_score(author_did, new_score).await;
    }

    Ok((StatusCode::CREATED, Json(issue)))
}

/// GET /api/v1/repos/{owner}/{repo}/issues
pub async fn list_issues(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &repo, caller, "/").await?;

    let disk_path = state
        .repo_store
        .acquire(&record.owner_did, &record.name)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;

    let raw_issues =
        git_issues::list_issues(&disk_path).map_err(|e| AppError::Git(e.to_string()))?;

    let mut issues: Vec<serde_json::Value> = Vec::new();
    for raw in raw_issues {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
            issues.push(v);
        }
    }

    Ok(Json(serde_json::json!({ "issues": issues })))
}

/// GET /api/v1/repos/{owner}/{repo}/issues/{id}
pub async fn get_issue(
    State(state): State<AppState>,
    Path((owner, repo, issue_id)): Path<(String, String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &repo, caller, "/").await?;

    let disk_path = state
        .repo_store
        .acquire(&record.owner_did, &record.name)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;

    let raw = git_issues::get_issue(&disk_path, &issue_id)
        .map_err(|e| AppError::Git(e.to_string()))?
        .ok_or_else(|| AppError::RepoNotFound(format!("issue {issue_id} not found")))?;

    let issue: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| AppError::BadRequest(format!("invalid issue data: {e}")))?;

    Ok(Json(issue))
}

#[derive(Debug, Deserialize)]
pub struct CreateIssueCommentRequest {
    pub body: String,
}

/// POST /api/v1/repos/{owner}/{repo}/issues/{id}/comments
pub async fn create_issue_comment(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, repo, issue_id)): Path<(String, String, String)>,
    Json(req): Json<CreateIssueCommentRequest>,
) -> Result<(StatusCode, Json<IssueComment>)> {
    if req.body.trim().is_empty() {
        return Err(AppError::BadRequest(
            "comment body must not be empty".into(),
        ));
    }

    // Read-gate: a commenter must be able to read the repo, but need not own it.
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &repo, Some(auth.0.as_str()), "/").await?;

    let disk_path = state
        .repo_store
        .acquire(&record.owner_did, &record.name)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;
    // Verify issue exists
    crate::git::issues::get_issue(&disk_path, &issue_id)
        .map_err(|e| AppError::Git(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("issue {issue_id} not found")))?;

    let comment = IssueComment {
        id: Uuid::new_v4().to_string(),
        issue_id: issue_id.clone(),
        author_did: auth.0,
        body: req.body,
        created_at: Utc::now().to_rfc3339(),
    };

    state.db.create_issue_comment(&comment).await?;
    Ok((StatusCode::CREATED, Json(comment)))
}

/// GET /api/v1/repos/{owner}/{repo}/issues/{id}/comments
pub async fn list_issue_comments(
    State(state): State<AppState>,
    Path((owner, repo, issue_id)): Path<(String, String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &repo, caller, "/").await?;

    let disk_path = state
        .repo_store
        .acquire(&record.owner_did, &record.name)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;
    // Resolve the full issue ID (accepts 8-char prefix) so the DB fetch
    // below uses the same canonical id as the git ref.
    let full_id = match git_issues::resolve_issue_id(&disk_path, &issue_id)
        .map_err(|e| AppError::Git(e.to_string()))?
    {
        Some(id) => id,
        None => {
            return Err(AppError::RepoNotFound(format!(
                "issue {issue_id} not found"
            )))
        }
    };

    let comments = state.db.list_issue_comments(&full_id).await?;
    Ok(Json(serde_json::json!({ "comments": comments })))
}

/// POST /api/v1/repos/{owner}/{repo}/issues/{id}/close
pub async fn close_issue(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, repo, issue_id)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>> {
    let record = state
        .db
        .get_repo(&owner, &repo)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{repo}")))?;

    // AUTHORIZE BEFORE ACQUIRING. The per-repo advisory lock genuinely excludes
    // now, so taking it first would hand any caller with read access a way to hold
    // that lock on demand and be refused afterwards, while a legitimate writer
    // burned its retry budget against it. On a public repo that is every
    // permissionless identity. The lock must not be reachable by a caller who is
    // about to be refused the write.
    let is_owner = crate::api::require_repo_owner(&record, &auth.0).is_ok();
    if !is_owner {
        // Not the owner, so the author fallback decides it, and the author lives in
        // the issue's git-JSON blob rather than a DB column.
        //
        // Read it WITHOUT the write lock, from a NON-MUTATING SNAPSHOT. The
        // justification is NOT that authorship is immutable — it is not:
        // `refs/gitlawb/**` is pushable, so a forged author blob can be pushed
        // (tracked separately; it is what makes this fallback only as trustworthy
        // as push authorization). The justification is that this read is only a
        // PRE-CHECK, deciding whether to take the lock at all. It is NOT the
        // authorization decision: `acquire_write` re-downloads the archive after
        // locking, so the tree that gets mutated is routinely not this one, and the
        // authoritative owner-or-author check runs again under the guard below.
        // Refusing here early just keeps a caller who is already visibly
        // unauthorized from reaching the lock.
        //
        // `read_snapshot`, not `acquire_fresh`: acquire's fast path returns as soon
        // as the directory exists and never contacts object storage, so on a node
        // with a stale copy the author's own issue would be invisible and the
        // cannot-establish-authorship arm below would 403 a legitimate author.
        // read_snapshot refreshes the same way, but unpacks into a throwaway temp
        // dir instead of publishing into the live repo path — an unlocked
        // pre-check must not delete or swap the directory under a concurrent
        // guarded write on the same path.
        let snapshot = state
            .repo_store
            .read_snapshot(&record.owner_did, &record.name)
            .await?;
        let snapshot_path = snapshot.path().to_path_buf();
        let author_did: Option<String> = match git_issues::get_issue(&snapshot_path, &issue_id) {
            Ok(Some(raw)) => serde_json::from_str::<IssueRecord>(&raw)
                .ok()
                .and_then(|i| i.author),
            // Cannot establish authorship, so fail closed. Deliberately 403 rather
            // than 404 for a non-owner: a caller who is not authorized to write
            // should not learn from this route whether the issue exists. Both arms
            // below return None; they are split only so a read failure is visible
            // to operators, since a genuinely absent issue and an unreadable one
            // are the same answer to the client but not the same event.
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(
                    repo = %repo,
                    issue = %issue_id,
                    err = %e,
                    "get_issue failed during close_issue authorship pre-check"
                );
                None
            }
        };
        let is_author = author_did
            .as_deref()
            .is_some_and(|a| crate::api::did_matches(&auth.0, a));
        if !is_author {
            return Err(AppError::Forbidden(
                "only the repo owner or the issue author can close this issue".into(),
            ));
        }
    }

    // Authorized. Only now is the lock taken.
    // Propagate rather than stringify: AppError's From<anyhow::Error> downcasts to
    // sqlx::Error so a pool timeout or a database outage surfaces as a retryable
    // 503. Calling .to_string() first destroys that and reports both as a 500.
    let guard = state
        .repo_store
        .acquire_write(&record.owner_did, &record.name)
        .await?;
    let disk_path = guard.path().to_path_buf();

    // Re-read under the guard and RE-AUTHORIZE against what we read, rather than
    // only confirming the issue still exists. The pre-lock read decided whether to
    // take the lock; it cannot be the authorization decision, because acquire_write
    // re-downloads the archive after locking, so this is frequently a different tree
    // than the one the author was read from. Checking existence alone would leave the
    // whole decision resting on the earlier read of a tree we are no longer looking
    // at. The blob is already in hand here, so this costs a deserialize.
    match git_issues::get_issue(&disk_path, &issue_id) {
        Ok(Some(raw)) => {
            let author_now: Option<String> = serde_json::from_str::<IssueRecord>(&raw)
                .ok()
                .and_then(|i| i.author);
            let is_author_now = author_now
                .as_deref()
                .is_some_and(|a| crate::api::did_matches(&auth.0, a));
            if !is_owner && !is_author_now {
                // Consumed, NOT propagated, and that is deliberate at all three
                // `release(false)` sites below. These release without
                // publishing, so there is nothing for the store to refuse, and
                // mapping the outcome here would let a 503 shadow the
                // authorization answer this route exists to give.
                let _ = guard.release(false).await;
                return Err(AppError::Forbidden(
                    "only the repo owner or the issue author can close this issue".into(),
                ));
            }
        }
        Ok(None) => {
            let _ = guard.release(false).await;
            // The owner keeps the informative 404; a non-owner must not learn from
            // this route whether the issue exists, matching the pre-check above.
            return Err(if is_owner {
                AppError::NotFound(format!("issue {issue_id} not found"))
            } else {
                AppError::Forbidden(
                    "only the repo owner or the issue author can close this issue".into(),
                )
            });
        }
        Err(e) => {
            let _ = guard.release(false).await;
            return Err(AppError::Git(e.to_string()));
        }
    }

    let close_result = git_issues::close_issue(&disk_path, &issue_id);

    // Always release the advisory lock — even on error; upload to Tigris only on success.
    // Same short-circuit as create_issue, and before the 200 body below.
    guard.release(close_result.is_ok()).await.into_result()?;

    let updated = close_result
        .map_err(|e| AppError::Git(e.to_string()))?
        .ok_or_else(|| AppError::RepoNotFound(format!("issue {issue_id} not found")))?;

    let issue: serde_json::Value = serde_json::from_str(&updated)
        .map_err(|e| AppError::BadRequest(format!("invalid issue data: {e}")))?;

    tracing::info!(repo = %repo, issue = %issue_id, "issue closed");

    Ok(Json(issue))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    /// U7: once the advisory lock actually excludes, taking it BEFORE authorizing
    /// turns close_issue into a wedge primitive. Any caller with repo read access
    /// (on a public repo, any permissionless identity) could take the per-repo
    /// write lock on demand and be refused the write afterwards, while the owner's
    /// push burned its retry budget against a lock held by someone with no write
    /// authorization.
    ///
    /// The observable: hold the lock from an independent session, then call the
    /// handler as a stranger. If it authorizes first it refuses immediately; if it
    /// acquires first it sits in the 60-attempt retry loop and the deadline fires.
    #[sqlx::test]
    async fn stranger_is_refused_without_waiting_on_the_write_lock(pool: PgPool) {
        use sqlx::Connection;
        let opts = (*pool.connect_options()).clone();
        let state = crate::test_support::test_state(pool.clone()).await;

        let owner = "did:key:z6MkU7Owner";
        state
            .db
            .upsert_mirror_repo("z6MkU7Owner", "u7repo", "/tmp/u7repo", None, true)
            .await
            .expect("seed repo");
        let record = state
            .db
            .get_repo("z6MkU7Owner", "u7repo")
            .await
            .expect("get_repo")
            .expect("repo exists");

        // An independent session holds the repo's write lock for the whole call.
        let key = crate::git::repo_store::advisory_lock_key_for_test(
            &record.owner_did.replace([':', '/'], "_"),
            &record.name,
        );
        let mut holder = sqlx::PgConnection::connect_with(&opts).await.unwrap();
        let held: (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
            .bind(key)
            .fetch_one(&mut holder)
            .await
            .unwrap();
        assert!(
            held.0,
            "the test must hold the lock for this to mean anything"
        );
        let _ = owner;

        let stranger = crate::auth::AuthenticatedDid("did:key:z6MkU7Stranger".to_string());
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            close_issue(
                axum::extract::State(state.clone()),
                axum::Extension(stranger),
                axum::extract::Path((
                    "z6MkU7Owner".to_string(),
                    "u7repo".to_string(),
                    "1".to_string(),
                )),
            ),
        )
        .await;

        let refused = outcome.expect(
            "a caller with no write authorization must be refused WITHOUT waiting on the \
             write lock; hitting this deadline means the handler tried to acquire first, \
             which is the wedge primitive",
        );
        assert!(
            matches!(refused, Err(AppError::Forbidden(_))),
            "expected 403 Forbidden for a stranger, got {:?}",
            refused.err().map(|e| format!("{e:?}"))
        );
    }

    /// Seed a real bare repo with one issue blob whose author is `author_did`, at
    /// the on-disk path the store will resolve for (owner_did, repo).
    async fn seed_repo_with_issue(
        state: &crate::state::AppState,
        owner_slug: &str,
        owner_did: &str,
        repo: &str,
        issue_id: &str,
        author_did: &str,
    ) -> std::path::PathBuf {
        state
            .db
            .upsert_mirror_repo(owner_slug, repo, "/unused", None, true)
            .await
            .expect("seed repo row");
        // Seed at the path the HANDLER will resolve. upsert_mirror_repo stores the
        // bare slug in owner_did, and close_issue resolves from record.owner_did, so
        // seeding from the full did:key would create the repo in a different
        // directory and the handler would find nothing.
        let record = state
            .db
            .get_repo(owner_slug, repo)
            .await
            .expect("get_repo")
            .expect("seeded repo exists");
        let _ = owner_did;
        let path = state
            .repo_store
            .acquire(&record.owner_did, &record.name)
            .await
            .expect("resolve disk path");
        let _ = std::fs::remove_dir_all(&path);
        crate::git::store::init_bare(&path).expect("init bare repo");
        // Must deserialize as a real IssueRecord: `created_at` and `status` are
        // required, and a parse failure would silently drop the author (the
        // `.ok()` on from_str), which reads as a 403 rather than as a broken fixture.
        let json = serde_json::to_string(&IssueRecord {
            id: issue_id.to_string(),
            title: "seeded".to_string(),
            body: Some(String::new()),
            author: Some(author_did.to_string()),
            created_at: chrono::Utc::now().to_rfc3339(),
            status: "open".to_string(),
            signed_payload: None,
        })
        .expect("serialize seeded issue");
        crate::git::issues::create_issue(&path, issue_id, &json).expect("seed issue blob");
        path
    }

    /// INV-21(c) positive twin 1: the OWNER can still close. The reorder moved the
    /// owner check above the lock, so this is the arm most likely to have broken,
    /// and the deny test alone could not see it.
    ///
    /// The issue is seeded with a THIRD party as its author, deliberately. Seeding
    /// the owner as their own author made this test unable to fail: with the owner
    /// check disabled, the author fallback granted the close anyway and the test
    /// stayed green. Only the owner arm can grant here now.
    #[sqlx::test]
    async fn owner_can_still_close_after_the_reorder(pool: PgPool) {
        let state = crate::test_support::test_state(pool.clone()).await;
        let owner_did = "did:key:z6MkT1Owner";
        seed_repo_with_issue(
            &state,
            "z6MkT1Owner",
            owner_did,
            "t1repo",
            "1",
            "did:key:z6MkT1Stranger",
        )
        .await;

        let res = close_issue(
            axum::extract::State(state.clone()),
            axum::Extension(crate::auth::AuthenticatedDid(owner_did.to_string())),
            axum::extract::Path((
                "z6MkT1Owner".to_string(),
                "t1repo".to_string(),
                "1".to_string(),
            )),
        )
        .await;
        assert!(
            res.is_ok(),
            "the owner must still be able to close: {:?}",
            res.err().map(|e| format!("{e:?}"))
        );
    }

    /// INV-21(c) positive twin 2: the non-owner AUTHOR can still close, through both
    /// the pre-lock check and the re-assertion under the guard.
    ///
    /// It does NOT cover the acquire-vs-acquire_fresh distinction, despite that being
    /// the reason the call changed. `RepoStore::for_testing` hardcodes `tigris: None`,
    /// which makes `acquire` and `acquire_fresh` identical in every test here, so
    /// reverting that line leaves this green. Separating them needs an object-storage
    /// seam, which is out of scope for this change and tracked separately. Claiming
    /// the coverage here would be worse than admitting the gap.
    #[sqlx::test]
    async fn issue_author_who_is_not_the_owner_can_still_close(pool: PgPool) {
        let state = crate::test_support::test_state(pool.clone()).await;
        let owner_did = "did:key:z6MkT2Owner";
        let author_did = "did:key:z6MkT2Author";
        seed_repo_with_issue(&state, "z6MkT2Owner", owner_did, "t2repo", "1", author_did).await;

        let res = close_issue(
            axum::extract::State(state.clone()),
            axum::Extension(crate::auth::AuthenticatedDid(author_did.to_string())),
            axum::extract::Path((
                "z6MkT2Owner".to_string(),
                "t2repo".to_string(),
                "1".to_string(),
            )),
        )
        .await;
        assert!(
            res.is_ok(),
            "the issue author, who is NOT the repo owner, must still be able to close: {:?}",
            res.err().map(|e| format!("{e:?}"))
        );
    }
}
