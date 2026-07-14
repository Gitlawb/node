//! Repo replica registration API.
//!
//! Lets a node tell the origin "I'm hosting a replica of your repo." The
//! origin records the (replica DID, replica URL) pair and exposes the list
//! publicly so anyone can see how many nodes are mirroring a given repo.
//!
//! Endpoints:
//! - `PUT  /api/v1/repos/:owner/:repo/replicas`     (auth)   register
//! - `DELETE /api/v1/repos/:owner/:repo/replicas`   (auth)   unregister
//! - `GET  /api/v1/repos/:owner/:repo/replicas`     (public) list
//!
//! Auth model: the caller's DID (verified via HTTP Signatures) is the
//! replica's identity. There's no separate "claim this URL" check — replicas
//! self-report their public URL. Operators viewing the list should treat
//! replica URLs as advisory until they actually reach out and verify.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::auth::AuthenticatedDid;
use crate::error::{AppError, Result};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct RegisterReplicaRequest {
    /// Publicly reachable URL of the replica node (e.g. `https://my-node.example.com`).
    pub url: String,
}

/// PUT /api/v1/repos/:owner/:repo/replicas
/// Idempotent — first registration returns 201, subsequent ones update the URL and return 200.
pub async fn register_replica(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, repo)): Path<(String, String)>,
    Json(req): Json<RegisterReplicaRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    validate_replica_url(&req.url)?;

    let record = state
        .db
        .get_repo(&owner, &repo)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{repo}")))?;

    let replica_did = &auth.0;

    // Don't let an owner register themselves as a replica of their own repo
    // (did_matches handles the full vs bare did:key owner form).
    if crate::api::did_matches(replica_did, &record.owner_did) {
        return Err(AppError::BadRequest(
            "the repo owner is not a replica of their own repo".into(),
        ));
    }

    let inserted = state
        .db
        .register_replica(&record.id, replica_did, &req.url)
        .await?;
    let count = state.db.count_replicas(&record.id).await?;

    let status = if inserted {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };

    tracing::info!(
        repo = %repo,
        replica = %replica_did,
        url = %req.url,
        "replica registered"
    );

    Ok((
        status,
        Json(serde_json::json!({
            "status": "registered",
            "repo": format!("{owner}/{repo}"),
            "replica_did": replica_did,
            "replica_url": req.url,
            "replica_count": count,
        })),
    ))
}

/// DELETE /api/v1/repos/:owner/:repo/replicas
/// Idempotent — no error if the caller wasn't registered.
pub async fn unregister_replica(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    let record = state
        .db
        .get_repo(&owner, &repo)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{repo}")))?;

    let replica_did = &auth.0;
    state.db.unregister_replica(&record.id, replica_did).await?;
    let count = state.db.count_replicas(&record.id).await?;

    tracing::info!(repo = %repo, replica = %replica_did, "replica unregistered");

    Ok(Json(serde_json::json!({
        "status": "unregistered",
        "repo": format!("{owner}/{repo}"),
        "replica_count": count,
    })))
}

/// GET /api/v1/repos/:owner/:repo/replicas
/// Public — returns the list of replicas (DID + URL + registration timestamp).
pub async fn list_replicas(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    let record = state
        .db
        .get_repo(&owner, &repo)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{repo}")))?;

    let replicas = state.db.list_replicas(&record.id).await?;

    Ok(Json(serde_json::json!({
        "repo": format!("{owner}/{repo}"),
        "replica_count": replicas.len(),
        "replicas": replicas,
    })))
}

/// Basic URL hygiene — must be http(s), parseable, length-bounded.
fn validate_replica_url(url: &str) -> Result<()> {
    if url.is_empty() {
        return Err(AppError::BadRequest("replica url is empty".into()));
    }
    if url.len() > 512 {
        return Err(AppError::BadRequest("replica url exceeds 512 chars".into()));
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(AppError::BadRequest(
            "replica url must start with http:// or https://".into(),
        ));
    }
    // No spaces / control chars / newlines.
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(AppError::BadRequest(
            "replica url contains whitespace or control characters".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_accepts_normal_https() {
        validate_replica_url("https://node.example.com").unwrap();
        validate_replica_url("https://my-node.example.com:7545").unwrap();
        validate_replica_url("http://localhost:7545").unwrap();
    }

    #[test]
    fn url_rejects_empty() {
        assert!(validate_replica_url("").is_err());
    }

    #[test]
    fn url_rejects_non_http_scheme() {
        for bad in [
            "ftp://host",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "/path",
        ] {
            assert!(validate_replica_url(bad).is_err(), "{bad:?} must reject");
        }
    }

    #[test]
    fn url_rejects_whitespace_and_control() {
        for bad in [
            "https://host .com",
            "https://host\n.com",
            "https://host\t.com",
            "https://host\0evil.com",
        ] {
            assert!(validate_replica_url(bad).is_err(), "{bad:?} must reject");
        }
    }

    #[test]
    fn url_rejects_overlong() {
        let long = format!("https://{}.com", "a".repeat(600));
        assert!(validate_replica_url(&long).is_err());
    }
}
