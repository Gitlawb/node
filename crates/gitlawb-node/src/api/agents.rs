//! Agent-related API endpoints.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};

use crate::auth::AuthenticatedDid;
use crate::error::{AppError, Result};
use crate::state::AppState;

fn normalize_agent_did(did: &str) -> String {
    if did.starts_with("did:") {
        did.to_string()
    } else {
        format!("did:key:{did}")
    }
}

fn agent_key_segment(did: &str) -> &str {
    did.split(':').next_back().unwrap_or(did)
}

/// Whether `caller` (the verified `AuthenticatedDid`) is the same identity as
/// `target` (the DID being acted on), tolerant of full `did:key:...` vs short
/// key-only forms on either side. Used to gate self-deregistration so a DID
/// can only retire itself.
fn caller_matches_did(caller: &str, target: &str) -> bool {
    agent_key_segment(caller) == agent_key_segment(target)
}

async fn resolve_agent_did(state: &AppState, did: &str) -> Result<String> {
    let normalized_did = normalize_agent_did(did);
    if state.db.get_agent(&normalized_did).await?.is_some() {
        return Ok(normalized_did);
    }

    let requested_key = agent_key_segment(&normalized_did);
    let matching_agent = state
        .db
        .list_agents(None)
        .await?
        .into_iter()
        .find(|agent| agent_key_segment(&agent.did).starts_with(requested_key));

    Ok(matching_agent
        .map(|agent| agent.did)
        .unwrap_or(normalized_did))
}

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
    /// Lifecycle status: `active` or `revoked`.
    pub status: String,
}

/// GET /api/v1/agents
pub async fn list_agents(
    State(state): State<AppState>,
    Query(params): Query<AgentListQuery>,
) -> Result<Json<serde_json::Value>> {
    let agents = state.db.list_agents(params.capability.as_deref()).await?;
    let list: Vec<AgentResponse> = agents
        .into_iter()
        .map(|a| AgentResponse {
            did: a.did,
            trust_score: a.trust_score,
            capabilities: a.capabilities,
            registered_at: a.registered_at,
            last_seen: a.last_seen,
            status: a.status,
        })
        .collect();
    Ok(Json(serde_json::json!({ "agents": list })))
}

/// GET /api/v1/agents/{did}
pub async fn show_agent(
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<(StatusCode, Json<AgentResponse>)> {
    let normalized_did = resolve_agent_did(&state, &did).await?;
    let agent = state
        .db
        .get_agent(&normalized_did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("agent {normalized_did} not found")))?;
    Ok((
        StatusCode::OK,
        Json(AgentResponse {
            did: agent.did,
            trust_score: agent.trust_score,
            capabilities: agent.capabilities,
            registered_at: agent.registered_at,
            last_seen: agent.last_seen,
            status: agent.status,
        }),
    ))
}

/// GET /api/v1/agents/{did}/trust
pub async fn get_trust(
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<Json<TrustResponse>> {
    let normalized_did = resolve_agent_did(&state, &did).await?;
    let trust_score = state.db.get_trust_score(&normalized_did).await?;
    let push_count = state.db.get_push_count(&normalized_did).await?;
    let level = trust_level(trust_score);

    Ok(Json(TrustResponse {
        did: normalized_did,
        trust_score,
        push_count,
        level,
    }))
}

/// DELETE /api/v1/agents/{did}
///
/// Self-deregistration: the holder of a DID's key marks their own agent
/// `revoked`, removing it from discovery (issue #29). Authenticated by the
/// rfc9421 signature middleware; a caller may only retire its own DID.
pub async fn deregister_agent(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path(did): Path<String>,
) -> Result<StatusCode> {
    // Authorize on the verified identity, and act on it too. The path DID is
    // only an intent check (it must name the caller); the row we revoke is the
    // authenticated DID itself, never a value derived from the untrusted path.
    // Revoking `resolve_agent_did(did)` instead would let the fuzzy prefix
    // resolver act on a different identity than the one just authorized.
    if !caller_matches_did(&auth.0, &did) {
        return Err(AppError::BadRequest(
            "an agent can only deregister itself".into(),
        ));
    }

    if state.db.revoke_agent(&auth.0).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound(format!("agent {} not found", auth.0)))
    }
}

#[cfg(test)]
mod tests {
    use super::{agent_key_segment, caller_matches_did, normalize_agent_did, AgentResponse};

    #[test]
    fn caller_matches_own_did_full_form() {
        assert!(caller_matches_did(
            "did:key:z6MkExample",
            "did:key:z6MkExample"
        ));
    }

    #[test]
    fn caller_matches_own_did_short_form() {
        // Authenticated full DID vs short path form, and vice versa.
        assert!(caller_matches_did("did:key:z6MkExample", "z6MkExample"));
        assert!(caller_matches_did("z6MkExample", "did:key:z6MkExample"));
    }

    #[test]
    fn caller_cannot_revoke_a_different_did() {
        // The core authorization property for issue #29.
        assert!(!caller_matches_did(
            "did:key:z6MkAttacker",
            "did:key:z6MkVictim"
        ));
        assert!(!caller_matches_did("did:key:z6MkAttacker", "z6MkVictim"));
    }

    #[test]
    fn agent_response_surfaces_status() {
        // A revoked DID's response must carry its status so callers can see it
        // is retired (issue #29).
        let resp = AgentResponse {
            did: "did:key:orphan".to_string(),
            trust_score: 0.1,
            capabilities: vec!["reputation:score".to_string()],
            registered_at: "2026-06-19T00:00:00Z".to_string(),
            last_seen: None,
            status: "revoked".to_string(),
        };

        let json = serde_json::to_value(&resp).unwrap();

        assert_eq!(json["status"], "revoked");
        assert!(json.get("replaced_by").is_none());
    }

    #[test]
    fn agent_response_active_status() {
        let resp = AgentResponse {
            did: "did:key:active".to_string(),
            trust_score: 0.5,
            capabilities: vec![],
            registered_at: "2026-06-19T00:00:00Z".to_string(),
            last_seen: None,
            status: "active".to_string(),
        };

        let json = serde_json::to_value(&resp).unwrap();

        assert_eq!(json["status"], "active");
    }

    #[test]
    fn normalize_agent_did_preserves_full_did() {
        let did = "did:key:z6MkExample";

        assert_eq!(normalize_agent_did(did), did);
    }

    #[test]
    fn normalize_agent_did_expands_bare_key() {
        assert_eq!(normalize_agent_did("z6MkExample"), "did:key:z6MkExample");
    }

    #[test]
    fn agent_key_segment_extracts_did_key_material() {
        assert_eq!(agent_key_segment("did:key:z6MkExample"), "z6MkExample");
        assert_eq!(agent_key_segment("z6MkExample"), "z6MkExample");
    }
}
