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
        .await
        .map_err(|e| crate::api::repos::acquire_write_app_error(&e, &repo))?;
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
    headers: axum::http::HeaderMap,
    crate::rate_limit::PeerAddr(peer): crate::rate_limit::PeerAddr,
) -> Result<Json<serde_json::Value>> {
    let record = state
        .db
        .get_repo(&owner, &repo)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{repo}")))?;

    // Per-IP flood brake, layered on the same shared limiter and trusted-proxy
    // policy as the push advertisement. The pre-lock snapshot downloads the
    // whole archive and runs a blocking extraction, so an unlimited route would
    // let disposable identities drive unbounded transfer/CPU/disk with parallel
    // close requests for arbitrary issue ids. Applied before the snapshot work
    // so a rejected request does none of it.
    if let Some(key) = crate::rate_limit::client_key(&headers, peer, state.push_limiter_trust) {
        if !state.push_rate_limiter.check(&key).await {
            tracing::warn!(repo = %repo, key = %key, "close_issue rate limited");
            return Err(AppError::TooManyRequests(
                "rate limit exceeded — try again later".into(),
            ));
        }
    }

    // READ-GATE before any snapshot work. The author fallback below needs the
    // issue blob, which needs the repo tree, so authorship cannot be established
    // without a download; but a caller who cannot even READ the repo must be
    // stopped here, cheaply, before any Tigris transfer or extraction happens.
    // Without this, any signed non-owner could issue parallel close requests for
    // arbitrary issue ids and drive unbounded downloads and blocking extraction
    // (a disposable-identity DoS), because the route has no other pre-authorization.
    //
    // mirror-rows-handled: a repo row synced from a peer is stored public and
    // carries none of the owner's visibility rules, so for such a row this check
    // can only return allow. That is deliberate rather than overlooked, and it is
    // the same verdict every other read gate in this API reaches for one. Refusing
    // instead would deny the repo's real owner and the issue's real author on any
    // node whose only copy of the repo is a synced one, which is an ordinary state
    // here, and it would not buy the protection it appears to, because a synced
    // row's recorded owner comes from the peer that sent it. The expensive work
    // this check guards is bounded ahead of it by the per-IP limiter above, and the
    // authoritative owner-or-author decision still runs below and again under the
    // write lock.
    {
        let rules = state.db.list_visibility_rules(&record.id).await?;
        let caller = auth.0.as_str();
        if crate::visibility::visibility_check(
            &rules,
            record.is_public,
            &record.owner_did,
            Some(caller),
            "/",
        ) == crate::visibility::Decision::Deny
        {
            return Err(AppError::RepoNotFound(format!("{owner}/{repo}")));
        }
    }

    // AUTHORIZE BEFORE ACQUIRING. The per-repo advisory lock genuinely excludes
    // now, so taking it first would hand any caller with read access a way to hold
    // that lock on demand and be refused afterwards, while a legitimate writer
    // burned its retry budget against it. On a public repo that is every
    // permissionless identity. The lock must not be reachable by a caller who is
    // about to be refused the write.
    let is_owner = crate::api::require_repo_owner(&record, &auth.0).is_ok();
    if !is_owner {
        // Cap concurrent snapshot work on the shared read pool. The hourly rate
        // bucket above is not a concurrent-work brake; without this, parallel close
        // attempts from read-capable callers could each drive a full archive
        // download and blocking extraction before the author denial below.
        let _read_permit = state
            .git_read_semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                tracing::warn!(
                    repo = %repo,
                    "close_issue snapshot refused — git read pool at capacity"
                );
                AppError::Overloaded("git service at capacity, retry shortly".into())
            })?;

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
        let snapshot = tokio::time::timeout(
            std::time::Duration::from_secs(state.config.lock_held_transfer_timeout_secs),
            state
                .repo_store
                .read_snapshot(&record.owner_did, &record.name),
        )
        .await
        .map_err(|_elapsed| {
            tracing::warn!(
                repo = %repo,
                bound_secs = state.config.lock_held_transfer_timeout_secs,
                "close_issue snapshot exceeded the transfer bound — shedding as a retryable refusal"
            );
            AppError::RepoUnavailable
        })??;
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
        .await
        .map_err(|e| crate::api::repos::acquire_write_app_error(&e, &repo))?;
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
                axum::http::HeaderMap::new(),
                crate::rate_limit::PeerAddr(Some("203.0.113.64:5000".parse().unwrap())),
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

    /// The read-gate's blind spot, pinned rather than left to be rediscovered.
    ///
    /// A repo row synced from a peer is stored public and carries none of the
    /// owner's visibility rules, so the gate's own inputs can only produce allow
    /// for it. The gate above therefore does not carry this class of row, and the
    /// test that does cover it (`non_reader_is_refused_before_the_snapshot`) seeds
    /// a locally created repo, which cannot observe this: a passing test there is
    /// not coverage here.
    ///
    /// Two things are asserted, and the second is why the first is acceptable.
    /// The gate's verdict for such a row is allow for an arbitrary caller, and the
    /// handler still refuses that caller afterwards, because the decision that
    /// matters is the owner-or-author check rather than this one. If a later change
    /// makes the gate the load-bearing decision for this route, the first assertion
    /// breaks and this comment is where to start.
    #[sqlx::test]
    async fn a_synced_row_is_not_gated_by_its_own_visibility(pool: PgPool) {
        let state = crate::test_support::test_state(pool.clone()).await;

        // Only a synced row exists for this repo, with no locally created twin.
        state
            .db
            .upsert_mirror_repo("z6MkSyncOwner", "syncrepo", "/tmp/syncrepo", None, false)
            .await
            .expect("seed synced repo"); // false = not quarantined, the ordinary case
        let record = state
            .db
            .get_repo("z6MkSyncOwner", "syncrepo")
            .await
            .expect("get_repo")
            .expect("repo exists")
            .clone();
        assert!(
            record.id.contains('/'),
            "this test is only meaningful against a synced row; got id {}",
            record.id
        );

        // The gate's two inputs, and what they force.
        let rules = state
            .db
            .list_visibility_rules(&record.id)
            .await
            .expect("list rules");
        assert!(rules.is_empty(), "a synced row carries no rules of its own");
        assert!(record.is_public, "a synced row is stored public");
        assert_eq!(
            crate::visibility::visibility_check(
                &rules,
                record.is_public,
                &record.owner_did,
                Some("did:key:z6MkSyncStranger"),
                "/",
            ),
            crate::visibility::Decision::Allow,
            "the gate can only allow for a synced row, which is the property the \
             handler's mirror-rows-handled note records",
        );

        // So the refusal has to come from the decision that is actually load-bearing.
        let stranger = crate::auth::AuthenticatedDid("did:key:z6MkSyncStranger".to_string());
        let outcome = close_issue(
            axum::extract::State(state.clone()),
            axum::Extension(stranger),
            axum::extract::Path((
                "z6MkSyncOwner".to_string(),
                "syncrepo".to_string(),
                "1".to_string(),
            )),
            axum::http::HeaderMap::new(),
            crate::rate_limit::PeerAddr(Some("203.0.113.99:5000".parse().unwrap())),
        )
        .await;
        assert!(
            outcome.is_err(),
            "a stranger must still be refused on a synced row, gate or no gate",
        );
        let body = format!("{:?}", outcome.err().unwrap());
        assert!(
            !body.contains("syncrepo/") && !body.to_lowercase().contains("issue body"),
            "the refusal must not leak repo contents: {body}",
        );
    }

    /// The read-gate added for the pre-lock snapshot: a caller who cannot READ
    /// the repo (private repo, no rule granting them access) must be refused with
    /// a not-found BEFORE any snapshot download or extraction happens. The
    /// observable is the refusal itself; the cheaper part (no Tigris work) is
    /// structural (the gate precedes the snapshot call in the handler).
    #[sqlx::test]
    async fn non_reader_is_refused_before_the_snapshot(pool: PgPool) {
        let state = crate::test_support::test_state(pool.clone()).await;
        let now = chrono::Utc::now();
        state
            .db
            .create_repo(&crate::db::RepoRecord {
                id: uuid::Uuid::new_v4().to_string(),
                name: "priv-close".to_string(),
                owner_did: "z6MkT3Owner".to_string(),
                description: None,
                is_public: false,
                default_branch: "main".to_string(),
                created_at: now,
                updated_at: now,
                disk_path: "/tmp/priv-close".to_string(),
                forked_from: None,
                machine_id: None,
            })
            .await
            .expect("seed private repo");

        let stranger = crate::auth::AuthenticatedDid("did:key:z6MkT3Stranger".to_string());
        let res = close_issue(
            axum::extract::State(state.clone()),
            axum::Extension(stranger),
            axum::extract::Path((
                "z6MkT3Owner".to_string(),
                "priv-close".to_string(),
                "1".to_string(),
            )),
            axum::http::HeaderMap::new(),
            crate::rate_limit::PeerAddr(Some("203.0.113.67:5000".parse().unwrap())),
        )
        .await;
        assert!(
            matches!(res, Err(AppError::RepoNotFound(_))),
            "a non-reader must be refused as not-found, got {:?}",
            res.err().map(|e| format!("{e:?}"))
        );
    }

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
            axum::http::HeaderMap::new(),
            crate::rate_limit::PeerAddr(Some("203.0.113.65:5000".parse().unwrap())),
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
            axum::http::HeaderMap::new(),
            crate::rate_limit::PeerAddr(Some("203.0.113.66:5000".parse().unwrap())),
        )
        .await;
        assert!(
            res.is_ok(),
            "the issue author, who is NOT the repo owner, must still be able to close: {:?}",
            res.err().map(|e| format!("{e:?}"))
        );
    }
}

/// #173 F1 follow-up: issue write paths reach `acquire_write` with no admission
/// permit, so an exhausted write-lock pool must shed 503 + Retry-After.
#[cfg(test)]
mod lock_pool_shed_tests {
    use super::*;
    use axum::response::IntoResponse;
    use sqlx::PgPool;

    fn seed_repo(owner_did: &str, name: &str) -> crate::db::RepoRecord {
        let now = Utc::now();
        crate::db::RepoRecord {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            owner_did: owner_did.to_string(),
            description: None,
            is_public: true,
            default_branch: "main".to_string(),
            created_at: now,
            updated_at: now,
            disk_path: format!("/tmp/{name}"),
            forked_from: None,
            machine_id: None,
        }
    }

    async fn one_connection_lock_pool_state(pool: &PgPool) -> AppState {
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.repo_store = crate::git::repo_store::RepoStore::new(
            std::path::PathBuf::from("/tmp/gitlawb-issues-lockpool"),
            None,
            crate::git::repo_store::build_lock_pool(pool, 1, std::time::Duration::from_secs(1)),
            std::time::Duration::from_secs(300),
        );
        state
    }

    fn assert_sheds_503_with_retry_after(err: AppError, what: &str) {
        let resp = err.into_response();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{what}: an exhausted write-lock pool must shed 503, not a 500 git error"
        );
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .map(|v| v.to_str().unwrap()),
            Some("1"),
            "{what}: a capacity shed must tell the client when to retry"
        );
    }

    #[sqlx::test]
    async fn create_issue_lock_pool_exhaustion_sheds_503_not_500(pool: PgPool) {
        let owner = "did:key:zISSUECREATELOCKPOOLAAAAAAAAAAAAAAAAAAAA";
        let state = one_connection_lock_pool_state(&pool).await;
        state
            .db
            .create_repo(&seed_repo(owner, "lp-create"))
            .await
            .expect("seed repo");

        let held = state
            .repo_store
            .acquire_write(owner, "other-repo")
            .await
            .expect("the first write takes the only lock-pool connection");

        let shed = create_issue(
            State(state.clone()),
            Extension(AuthenticatedDid(owner.to_string())),
            Path((owner.to_string(), "lp-create".to_string())),
            Json(CreateIssueRequest {
                title: "t".to_string(),
                body: None,
                signed_payload: None,
            }),
        )
        .await;
        let err = shed.expect_err("an exhausted lock pool must fail the call");
        assert_sheds_503_with_retry_after(err, "create_issue");

        let _ = held.release(false).await;
        let admitted = create_issue(
            State(state.clone()),
            Extension(AuthenticatedDid(owner.to_string())),
            Path((owner.to_string(), "lp-create".to_string())),
            Json(CreateIssueRequest {
                title: "t".to_string(),
                body: None,
                signed_payload: None,
            }),
        )
        .await;
        assert!(
            !matches!(admitted, Err(AppError::Overloaded(_))),
            "with the lock pool free, create_issue must not be shed as capacity; got {:?}",
            admitted.err()
        );
    }

    #[sqlx::test]
    async fn close_issue_read_pool_exhaustion_sheds_before_snapshot(pool: PgPool) {
        use std::sync::Arc;
        let owner = "did:key:zISSUECLOSEREADPOOLBBBBBBBBBBBBBBBBBBBBB";
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.git_read_semaphore = Arc::new(tokio::sync::Semaphore::new(0));
        state
            .db
            .create_repo(&seed_repo(owner, "read-cap"))
            .await
            .expect("seed repo");

        let shed = close_issue(
            State(state.clone()),
            Extension(AuthenticatedDid(
                "did:key:zISSUECLOSEREADSTRANGER".to_string(),
            )),
            Path((
                owner.to_string(),
                "read-cap".to_string(),
                "deadbeef".to_string(),
            )),
            axum::http::HeaderMap::new(),
            crate::rate_limit::PeerAddr(None),
        )
        .await;
        assert!(
            matches!(shed, Err(AppError::Overloaded(_))),
            "an exhausted read pool must shed before snapshot work; got {shed:?}"
        );
    }

    #[sqlx::test]
    async fn close_issue_lock_pool_exhaustion_sheds_503_not_500(pool: PgPool) {
        let owner = "did:key:zISSUECLOSELOCKPOOLBBBBBBBBBBBBBBBBBBBBB";
        let state = one_connection_lock_pool_state(&pool).await;
        state
            .db
            .create_repo(&seed_repo(owner, "lp-close"))
            .await
            .expect("seed repo");

        let held = state
            .repo_store
            .acquire_write(owner, "other-repo")
            .await
            .expect("the first write takes the only lock-pool connection");

        let shed = close_issue(
            State(state.clone()),
            Extension(AuthenticatedDid(owner.to_string())),
            Path((
                owner.to_string(),
                "lp-close".to_string(),
                "deadbeef".to_string(),
            )),
            axum::http::HeaderMap::new(),
            crate::rate_limit::PeerAddr(None),
        )
        .await;
        let err = shed.expect_err("an exhausted lock pool must fail the call");
        assert_sheds_503_with_retry_after(err, "close_issue");

        let _ = held.release(false).await;
        let admitted = close_issue(
            State(state.clone()),
            Extension(AuthenticatedDid(owner.to_string())),
            Path((
                owner.to_string(),
                "lp-close".to_string(),
                "deadbeef".to_string(),
            )),
            axum::http::HeaderMap::new(),
            crate::rate_limit::PeerAddr(None),
        )
        .await;
        assert!(
            !matches!(admitted, Err(AppError::Overloaded(_))),
            "with the lock pool free, close_issue must not be shed as capacity; got {:?}",
            admitted.err()
        );
    }
}
