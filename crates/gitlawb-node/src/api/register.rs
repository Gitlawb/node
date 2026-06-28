use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use gitlawb_core::did::Did;
use gitlawb_core::ucan::Ucan;

use crate::error::{AppError, Result};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub did: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[allow(dead_code)]
    pub model: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub status: String,
    pub did: String,
    pub ucan: String,
    pub node: String,
    pub expires: String,
    pub trust_score: f64,
    pub capabilities: Vec<String>,
    pub message: String,
}

/// POST /api/register
/// Accepts only requests with a valid HTTP Signature (enforced by middleware).
pub async fn register(
    State(state): State<AppState>,
    axum::Extension(auth): axum::Extension<crate::auth::AuthenticatedDid>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>)> {
    // iCaptcha proof-of-intelligence gate (inert unless ICAPTCHA_MODE is set).
    crate::icaptcha::check(&state.db, &headers, &auth.0).await?;

    // Parse and validate the DID
    let agent_did: Did = req
        .did
        .parse()
        .map_err(|e: gitlawb_core::Error| AppError::BadRequest(e.to_string()))?;

    // Bind registration to the authenticated signer: an agent may only register
    // itself, not create or refresh a trust row for a DID it does not control.
    if !crate::api::did_matches(&auth.0, agent_did.as_str()) {
        return Err(AppError::Forbidden(
            "did must be the authenticated signer".into(),
        ));
    }

    // Store the agent in the local index
    state
        .db
        .register_agent(agent_did.as_str(), &req.capabilities)
        .await?;

    // Grant a small baseline trust score on first registration (verified via HTTP Signature).
    // Score grows further with pushes, PRs, and issue activity.
    let initial_trust = 0.05;
    let _ = state
        .db
        .update_trust_score(agent_did.as_str(), initial_trust)
        .await;

    // Issue a bootstrap UCAN from the node's identity
    let ucan = Ucan::bootstrap(&state.node_keypair, agent_did.clone())
        .map_err(|e| AppError::Internal(e.into()))?;

    let exp = Utc::now() + chrono::Duration::days(30);
    let ucan_encoded = ucan.encode().map_err(|e| AppError::Internal(e.into()))?;

    tracing::info!(did = %agent_did, "registered new agent");

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            status: "accepted".to_string(),
            did: agent_did.to_string(),
            ucan: ucan_encoded,
            node: format!("{}:{}", state.config.host, state.config.port),
            expires: exp.to_rfc3339(),
            trust_score: initial_trust,
            capabilities: req.capabilities,
            message: "welcome to the network, agent.".to_string(),
        }),
    ))
}
