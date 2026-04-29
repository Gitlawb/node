//! Agent-related API endpoints.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct TrustResponse {
    pub did: String,
    pub trust_score: f64,
    pub push_count: i64,
    pub level: &'static str,
}

fn trust_level(score: f64) -> &'static str {
    if score < 0.1 {
        "newcomer"
    } else if score < 0.3 {
        "contributor"
    } else if score < 0.7 {
        "trusted"
    } else {
        "maintainer"
    }
}

#[derive(Debug, Deserialize)]
pub struct AgentListQuery {
    pub capability: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AgentResponse {
    pub did: String,
    pub trust_score: f64,
    pub capabilities: Vec<String>,
    pub registered_at: String,
    pub last_seen: Option<String>,
}

/// GET /api/v1/agents
pub async fn list_agents(
    State(state): State<AppState>,
    Query(params): Query<AgentListQuery>,
) -> Result<Json<serde_json::Value>> {
    let agents = state.db.list_agents(params.capability.as_deref()).await?;
    let list: Vec<AgentResponse> = agents.into_iter().map(|a| AgentResponse {
        did: a.did,
        trust_score: a.trust_score,
        capabilities: a.capabilities,
        registered_at: a.registered_at,
        last_seen: a.last_seen,
    }).collect();
    Ok(Json(serde_json::json!({ "agents": list })))
}

/// GET /api/v1/agents/{did}
pub async fn show_agent(
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<(StatusCode, Json<AgentResponse>)> {
    let agent = state.db.get_agent(&did).await?
        .ok_or_else(|| AppError::NotFound(format!("agent {did} not found")))?;
    Ok((StatusCode::OK, Json(AgentResponse {
        did: agent.did,
        trust_score: agent.trust_score,
        capabilities: agent.capabilities,
        registered_at: agent.registered_at,
        last_seen: agent.last_seen,
    })))
}

/// GET /api/v1/agents/{did}/trust
pub async fn get_trust(
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<Json<TrustResponse>> {
    let trust_score = state.db.get_trust_score(&did).await?;
    let push_count = state.db.get_push_count(&did).await?;
    let level = trust_level(trust_score);

    Ok(Json(TrustResponse {
        did,
        trust_score,
        push_count,
        level,
    }))
}
