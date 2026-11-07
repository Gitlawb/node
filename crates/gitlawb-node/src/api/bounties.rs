//! Bounty API endpoints — token-powered task marketplace for AI agents.

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthenticatedDid;
use crate::db::BountyRecord;
use crate::error::{AppError, Result};
use crate::state::AppState;

// ── Request / response types ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateBountyRequest {
    pub title: String,
    pub amount: i64,
    pub issue_id: Option<String>,
    /// On-chain tx hash of the escrow deposit (optional — verified by clients)
    pub tx_hash: Option<String>,
    /// Deadline in seconds (default 7 days = 604800)
    pub deadline_secs: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ClaimBountyRequest {
    /// Wallet address for receiving payout
    pub wallet: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SubmitBountyRequest {
    pub pr_id: String,
}

#[derive(Debug, Deserialize)]
pub struct ApproveBountyRequest {
    /// On-chain tx hash of the payout (optional)
    pub tx_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListBountiesQuery {
    pub status: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct BountyStatsResponse {
    pub open: i64,
    pub claimed: i64,
    pub completed: i64,
    pub leaderboard: Vec<AgentBountyEntry>,
}

#[derive(Debug, Serialize)]
pub struct AgentBountyEntry {
    pub did: String,
    pub completed: i64,
    pub total_earned: i64,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// POST /api/v1/repos/{owner}/{repo}/bounties
pub async fn create_bounty(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, repo)): Path<(String, String)>,
    Json(req): Json<CreateBountyRequest>,
) -> Result<(StatusCode, Json<BountyRecord>)> {
    if req.title.trim().is_empty() {
        return Err(AppError::BadRequest("title must not be empty".into()));
    }
    if req.amount <= 0 {
        return Err(AppError::BadRequest("amount must be positive".into()));
    }

    // Read-gate: anyone who can read the repo may fund a bounty on it (this closes
    // the private-repo bounty leak); ownership is not required.
    crate::api::authorize_repo_read(&state, &owner, &repo, Some(auth.0.as_str()), "/").await?;

    let now = Utc::now().to_rfc3339();
    let bounty = BountyRecord {
        id: Uuid::new_v4().to_string(),
        repo_owner: owner,
        repo_name: repo,
        issue_id: req.issue_id,
        title: req.title,
        amount: req.amount,
        creator_did: auth.0,
        claimant_did: None,
        claimant_wallet: None,
        pr_id: None,
        status: "open".to_string(),
        created_at: now,
        claimed_at: None,
        submitted_at: None,
        completed_at: None,
        deadline_secs: req.deadline_secs.unwrap_or(604800),
        tx_hash: req.tx_hash,
    };

    state.db.create_bounty(&bounty).await?;
    tracing::info!(bounty_id = %bounty.id, amount = bounty.amount, "bounty created");

    Ok((StatusCode::CREATED, Json(bounty)))
}

const MAX_BOUNTY_LIMIT: i64 = 200;

/// GET /api/v1/repos/{owner}/{repo}/bounties
pub async fn list_repo_bounties(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    Query(q): Query<ListBountiesQuery>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    crate::api::authorize_repo_read(&state, &owner, &repo, caller, "/").await?;

    let limit = q.limit.unwrap_or(50).clamp(1, MAX_BOUNTY_LIMIT);
    let bounties = state
        .db
        .list_bounties(
            Some(&owner),
            Some(&repo),
            q.status.as_deref(),
            limit,
            None,
            None,
        )
        .await?;

    Ok(Json(serde_json::json!({ "bounties": bounties })))
}

/// GET /api/v1/bounties — global bounty feed
pub async fn list_all_bounties(
    State(state): State<AppState>,
    Query(q): Query<ListBountiesQuery>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let raw_limit = q.limit.unwrap_or(50);
    let limit = raw_limit.clamp(1, MAX_BOUNTY_LIMIT);

    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let mut memo = std::collections::HashMap::new();
    let mut allowed: Vec<BountyRecord> = Vec::new();
    let page_size = (limit * 5).clamp(1, 200);
    let max_scanned = 10_000i64;
    let mut total_scanned: i64 = 0;
    let mut cursor: Option<(String, String)> = None;

    while (allowed.len() as i64) < limit {
        let after = cursor.as_ref().map(|(ts, id)| (ts.as_str(), id.as_str()));
        let bounties = state
            .db
            .list_bounties(
                None,
                None,
                q.status.as_deref(),
                page_size,
                after.map(|(ts, _)| ts),
                after.map(|(_, id)| id),
            )
            .await?;
        if bounties.is_empty() {
            break;
        }

        total_scanned += bounties.len() as i64;
        if total_scanned > max_scanned {
            return Err(AppError::Incomplete(
                "too many rows scanned; refine your filters".into(),
            ));
        }

        let last = bounties.last().unwrap();
        for b in &bounties {
            if (allowed.len() as i64) >= limit {
                break;
            }
            let key = format!("{}/{}", b.repo_owner, b.repo_name);
            let admitted = if let Some(&result) = memo.get(&key) {
                result
            } else {
                let result = crate::api::authorize_repo_read(
                    &state,
                    &b.repo_owner,
                    &b.repo_name,
                    caller,
                    "/",
                )
                .await
                .is_ok();
                memo.insert(key, result);
                result
            };
            if admitted {
                allowed.push(b.clone());
            }
        }
        cursor = Some((last.created_at.clone(), last.id.clone()));
    }

    Ok(Json(serde_json::json!({ "bounties": allowed })))
}

/// GET /api/v1/bounties/{id}
pub async fn get_bounty(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<BountyRecord>> {
    let not_found = || AppError::NotFound(format!("bounty {id} not found"));

    let bounty = state.db.get_bounty(&id).await?.ok_or_else(not_found)?;

    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    if crate::api::authorize_repo_read(&state, &bounty.repo_owner, &bounty.repo_name, caller, "/")
        .await
        .is_err()
    {
        return Err(not_found());
    }

    Ok(Json(bounty))
}

/// POST /api/v1/bounties/{id}/claim
pub async fn claim_bounty(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path(id): Path<String>,
    Json(req): Json<ClaimBountyRequest>,
) -> Result<Json<BountyRecord>> {
    let not_found = || AppError::NotFound(format!("bounty {id} not found"));

    let bounty = state.db.get_bounty(&id).await?.ok_or_else(not_found)?;

    if crate::api::authorize_repo_read(
        &state,
        &bounty.repo_owner,
        &bounty.repo_name,
        Some(auth.0.as_str()),
        "/",
    )
    .await
    .is_err()
    {
        return Err(not_found());
    }

    if bounty.status != "open" {
        return Err(AppError::BadRequest(format!(
            "bounty is {}, not open",
            bounty.status
        )));
    }

    let now = Utc::now().to_rfc3339();
    state
        .db
        .claim_bounty(&id, &auth.0, req.wallet.as_deref(), &now)
        .await?;

    tracing::info!(bounty_id = %id, agent = %auth.0, "bounty claimed");

    let updated = state
        .db
        .get_bounty(&id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("bounty {id} not found")))?;
    Ok(Json(updated))
}

/// POST /api/v1/bounties/{id}/submit
pub async fn submit_bounty(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path(id): Path<String>,
    Json(req): Json<SubmitBountyRequest>,
) -> Result<Json<BountyRecord>> {
    let not_found = || AppError::NotFound(format!("bounty {id} not found"));

    let bounty = state.db.get_bounty(&id).await?.ok_or_else(not_found)?;

    if crate::api::authorize_repo_read(
        &state,
        &bounty.repo_owner,
        &bounty.repo_name,
        Some(auth.0.as_str()),
        "/",
    )
    .await
    .is_err()
    {
        return Err(not_found());
    }

    if bounty.status != "claimed" {
        return Err(AppError::BadRequest(format!(
            "bounty is {}, not claimed",
            bounty.status
        )));
    }
    let is_claimant = bounty
        .claimant_did
        .as_deref()
        .is_some_and(|c| crate::api::did_matches(&auth.0, c));
    if !is_claimant {
        return Err(AppError::Forbidden("only the claimant can submit".into()));
    }

    let now = Utc::now().to_rfc3339();
    state.db.submit_bounty(&id, &req.pr_id, &now).await?;

    tracing::info!(bounty_id = %id, pr_id = %req.pr_id, "bounty submission");

    let updated = state
        .db
        .get_bounty(&id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("bounty {id} not found")))?;
    Ok(Json(updated))
}

/// POST /api/v1/bounties/{id}/approve
pub async fn approve_bounty(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path(id): Path<String>,
    Json(req): Json<ApproveBountyRequest>,
) -> Result<Json<BountyRecord>> {
    let not_found = || AppError::NotFound(format!("bounty {id} not found"));

    let bounty = state.db.get_bounty(&id).await?.ok_or_else(not_found)?;

    if crate::api::authorize_repo_read(
        &state,
        &bounty.repo_owner,
        &bounty.repo_name,
        Some(auth.0.as_str()),
        "/",
    )
    .await
    .is_err()
    {
        return Err(not_found());
    }

    if bounty.status != "submitted" {
        return Err(AppError::BadRequest(format!(
            "bounty is {}, not submitted",
            bounty.status
        )));
    }
    if !crate::api::did_matches(&auth.0, &bounty.creator_did) {
        return Err(AppError::Forbidden(
            "only the bounty creator can approve".into(),
        ));
    }

    let now = Utc::now().to_rfc3339();
    state
        .db
        .approve_bounty(&id, &now, req.tx_hash.as_deref())
        .await?;

    // Bump claimant trust score
    if let Some(ref agent_did) = bounty.claimant_did {
        let current = state.db.get_trust_score(agent_did).await.unwrap_or(0.1);
        let new_score = (current + 0.1).min(1.0);
        let _ = state.db.update_trust_score(agent_did, new_score).await;
    }

    tracing::info!(bounty_id = %id, "bounty approved");

    let updated = state
        .db
        .get_bounty(&id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("bounty {id} not found")))?;
    Ok(Json(updated))
}

/// POST /api/v1/bounties/{id}/cancel
pub async fn cancel_bounty(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path(id): Path<String>,
) -> Result<Json<BountyRecord>> {
    let not_found = || AppError::NotFound(format!("bounty {id} not found"));

    let bounty = state.db.get_bounty(&id).await?.ok_or_else(not_found)?;

    if crate::api::authorize_repo_read(
        &state,
        &bounty.repo_owner,
        &bounty.repo_name,
        Some(auth.0.as_str()),
        "/",
    )
    .await
    .is_err()
    {
        return Err(not_found());
    }

    if bounty.status != "open" {
        return Err(AppError::BadRequest(format!(
            "can only cancel open bounties, status is {}",
            bounty.status
        )));
    }
    if !crate::api::did_matches(&auth.0, &bounty.creator_did) {
        return Err(AppError::Forbidden(
            "only the bounty creator can cancel".into(),
        ));
    }

    state.db.cancel_bounty(&id).await?;
    tracing::info!(bounty_id = %id, "bounty cancelled");

    let updated = state
        .db
        .get_bounty(&id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("bounty {id} not found")))?;
    Ok(Json(updated))
}

/// POST /api/v1/bounties/{id}/dispute
pub async fn dispute_bounty(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path(id): Path<String>,
) -> Result<Json<BountyRecord>> {
    let not_found = || AppError::NotFound(format!("bounty {id} not found"));

    let bounty = state.db.get_bounty(&id).await?.ok_or_else(not_found)?;

    if crate::api::authorize_repo_read(
        &state,
        &bounty.repo_owner,
        &bounty.repo_name,
        Some(auth.0.as_str()),
        "/",
    )
    .await
    .is_err()
    {
        return Err(not_found());
    }

    if bounty.status != "claimed" && bounty.status != "submitted" {
        return Err(AppError::BadRequest(format!(
            "can only dispute claimed/submitted bounties, status is {}",
            bounty.status
        )));
    }

    // Only the bounty creator or the current claimant may dispute (N19 — this
    // endpoint had no identity check at all).
    let is_creator = crate::api::did_matches(&auth.0, &bounty.creator_did);
    let is_claimant = bounty
        .claimant_did
        .as_deref()
        .is_some_and(|c| crate::api::did_matches(&auth.0, c));
    if !is_creator && !is_claimant {
        return Err(AppError::Forbidden(
            "only the bounty creator or claimant can dispute this bounty".into(),
        ));
    }

    // Check if deadline exceeded
    if let Some(ref claimed_at) = bounty.claimed_at {
        if let Ok(claimed) = chrono::DateTime::parse_from_rfc3339(claimed_at) {
            let deadline = claimed + chrono::Duration::seconds(bounty.deadline_secs);
            if Utc::now() < deadline {
                return Err(AppError::BadRequest(
                    "deadline has not been exceeded yet".into(),
                ));
            }
        }
    }

    state.db.dispute_bounty(&id).await?;
    tracing::info!(bounty_id = %id, actor = %auth.0, "bounty disputed - reopened");

    let updated = state
        .db
        .get_bounty(&id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("bounty {id} not found")))?;
    Ok(Json(updated))
}

/// Resolve the set of `(owner_did, name)` pairs for repos an anonymous caller
/// can list.  Mirrors the `stats()` pattern in `server.rs` (#104): batch-load
/// all deduped repos, batch-load their visibility rules, keep only those that
/// pass `listable_at_root`.  Pure I/O after the two DB round-trips — no
/// per-repo authorization queries.
///
/// Both bounty stats handlers mount behind `optional_signature` (see
/// `bounty_read_routes` in server.rs), so the caller is always `None` for
/// anonymous access.  Every caller, signed or not, currently receives the
/// anonymous-scoped aggregates (matching the #104 pattern); per-caller
/// visibility can be threaded through here when that work lands.
///
/// A database error is returned to the caller, never collapsed to an empty
/// set: an empty set would render as HTTP 200 with zero counts, which a client
/// reads as confirmed absence of activity.
async fn visible_repo_pairs(state: &AppState) -> Result<Vec<(String, String)>> {
    let rows = state.db.list_all_repos_deduped().await?;
    let ids: Vec<String> = rows.iter().map(|r| r.id.clone()).collect();
    let rules_by_repo = state.db.list_visibility_rules_for_repos(&ids).await?;
    let pairs = rows
        .iter()
        .filter(|r| {
            let rules = rules_by_repo.get(&r.id).map(Vec::as_slice).unwrap_or(&[]);
            // mirror-rows-handled: a mirror with a canonical twin is deduped to the
            // canonical row and its rules; a mirror-only repo counts as public, the
            // same answer authorize_repo_read and /stats give. Pinned by
            // bounty_stats_mirror_rows_follow_canonical_twin_or_count_when_alone.
            crate::visibility::listable_at_root(rules, r.is_public, &r.owner_did, None)
        })
        .map(|r| {
            (
                crate::db::normalize_owner_key(&r.owner_did).to_string(),
                r.name.clone(),
            )
        })
        .collect();
    Ok(pairs)
}

/// GET /api/v1/bounties/stats
///
/// Aggregates are restricted to anonymously-listable repos so private-repo
/// bounty activity is not exposed (#477).  The visible-repo set is resolved
/// once per request via `visible_repo_pairs` (two SQL round-trips), then
/// passed into the filtered aggregate queries.
pub async fn bounty_stats(State(state): State<AppState>) -> Result<Json<BountyStatsResponse>> {
    let visible = visible_repo_pairs(&state).await?;

    let open = state
        .db
        .count_bounties_by_status_visible("open", &visible)
        .await?;
    let claimed = state
        .db
        .count_bounties_by_status_visible("claimed", &visible)
        .await?;
    let completed = state
        .db
        .count_bounties_by_status_visible("completed", &visible)
        .await?;

    let leaders = state.db.bounty_leaderboard_visible(10, &visible).await?;
    let leaderboard = leaders
        .into_iter()
        .map(|(did, cnt, total)| AgentBountyEntry {
            did,
            completed: cnt,
            total_earned: total,
        })
        .collect();

    Ok(Json(BountyStatsResponse {
        open,
        claimed,
        completed,
        leaderboard,
    }))
}

/// GET /api/v1/agents/{did}/bounties
///
/// Per-agent earnings restricted to anonymously-listable repos (#477).
pub async fn agent_bounty_stats(
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let visible = visible_repo_pairs(&state).await?;
    let (count, total) = state.db.agent_bounty_stats_visible(&did, &visible).await?;
    Ok(Json(serde_json::json!({
        "did": did,
        "completed_bounties": count,
        "total_earned": total,
    })))
}
