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

    // Verify repo exists
    let _ = state
        .db
        .get_repo(&owner, &repo)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{repo}")))?;

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

/// GET /api/v1/repos/{owner}/{repo}/bounties
pub async fn list_repo_bounties(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    Query(q): Query<ListBountiesQuery>,
) -> Result<Json<serde_json::Value>> {
    let bounties = state
        .db
        .list_bounties(
            Some(&owner),
            Some(&repo),
            q.status.as_deref(),
            q.limit.unwrap_or(50),
        )
        .await?;

    Ok(Json(serde_json::json!({ "bounties": bounties })))
}

/// GET /api/v1/bounties — global bounty feed
pub async fn list_all_bounties(
    State(state): State<AppState>,
    Query(q): Query<ListBountiesQuery>,
) -> Result<Json<serde_json::Value>> {
    let bounties = state
        .db
        .list_bounties(None, None, q.status.as_deref(), q.limit.unwrap_or(50))
        .await?;

    Ok(Json(serde_json::json!({ "bounties": bounties })))
}

/// GET /api/v1/bounties/{id}
pub async fn get_bounty(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<BountyRecord>> {
    let bounty = state
        .db
        .get_bounty(&id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("bounty {id} not found")))?;
    Ok(Json(bounty))
}

/// POST /api/v1/bounties/{id}/claim
pub async fn claim_bounty(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path(id): Path<String>,
    Json(req): Json<ClaimBountyRequest>,
) -> Result<Json<BountyRecord>> {
    let bounty = state
        .db
        .get_bounty(&id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("bounty {id} not found")))?;

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
    let bounty = state
        .db
        .get_bounty(&id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("bounty {id} not found")))?;

    if bounty.status != "claimed" {
        return Err(AppError::BadRequest(format!(
            "bounty is {}, not claimed",
            bounty.status
        )));
    }
    if bounty.claimant_did.as_deref() != Some(&auth.0) {
        return Err(AppError::BadRequest("only the claimant can submit".into()));
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
    let bounty = state
        .db
        .get_bounty(&id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("bounty {id} not found")))?;

    if bounty.status != "submitted" {
        return Err(AppError::BadRequest(format!(
            "bounty is {}, not submitted",
            bounty.status
        )));
    }
    if bounty.creator_did != auth.0 {
        return Err(AppError::BadRequest(
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
    let bounty = state
        .db
        .get_bounty(&id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("bounty {id} not found")))?;

    if bounty.status != "open" {
        return Err(AppError::BadRequest(format!(
            "can only cancel open bounties, status is {}",
            bounty.status
        )));
    }
    if bounty.creator_did != auth.0 {
        return Err(AppError::BadRequest(
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
    let bounty = state
        .db
        .get_bounty(&id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("bounty {id} not found")))?;

    if bounty.status != "claimed" && bounty.status != "submitted" {
        return Err(AppError::BadRequest(format!(
            "can only dispute claimed/submitted bounties, status is {}",
            bounty.status
        )));
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

/// GET /api/v1/bounties/stats
pub async fn bounty_stats(State(state): State<AppState>) -> Result<Json<BountyStatsResponse>> {
    let open = state.db.count_bounties_by_status("open").await.unwrap_or(0);
    let claimed = state
        .db
        .count_bounties_by_status("claimed")
        .await
        .unwrap_or(0);
    let completed = state
        .db
        .count_bounties_by_status("completed")
        .await
        .unwrap_or(0);

    let leaders = state.db.bounty_leaderboard(10).await.unwrap_or_default();
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
pub async fn agent_bounty_stats(
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let (count, total) = state.db.agent_bounty_stats(&did).await.unwrap_or((0, 0));
    Ok(Json(serde_json::json!({
        "did": did,
        "completed_bounties": count,
        "total_earned": total,
    })))
}
