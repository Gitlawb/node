//! Agent profile API handlers.
//!
//! - `PUT /api/v1/profile` — upsert the caller's profile (requires HTTP Signature)
//! - `GET /api/v1/agents/{did}/profile` — read any agent's profile (public)

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::auth::AuthenticatedDid;
use crate::pinata;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct SetProfileRequest {
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub avatar_url: Option<String>,
    pub website: Option<String>,
    pub socials: Option<SocialsInput>,
    pub pin_to_ipfs: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SocialsInput {
    pub twitter: Option<String>,
    pub github: Option<String>,
    pub farcaster: Option<String>,
    pub telegram: Option<String>,
}

pub async fn set_profile(
    State(state): State<AppState>,
    axum::Extension(auth): axum::Extension<AuthenticatedDid>,
    Json(req): Json<SetProfileRequest>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let did = auth.0;

    if let Some(ref bio) = req.bio {
        if bio.len() > 280 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "message": "bio must be 280 characters or fewer" })),
            ));
        }
    }

    if let Some(ref name) = req.display_name {
        if name.len() > 50 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "message": "display_name must be 50 characters or fewer" })),
            ));
        }
    }

    let socials_json = req
        .socials
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap_or_else(|_| "{}".to_string()));

    let result = state
        .db
        .upsert_profile(
            &did,
            req.display_name.as_deref(),
            req.bio.as_deref(),
            req.avatar_url.as_deref(),
            req.website.as_deref(),
            socials_json.as_deref(),
        )
        .await;

    match result {
        Ok(profile) => {
            let mut resp = json!({
                "did": profile.did,
                "display_name": profile.display_name,
                "bio": profile.bio,
                "avatar_url": profile.avatar_url,
                "website": profile.website,
                "updated_at": profile.updated_at,
            });

            if let Some(ref socials_str) = profile.socials {
                if let Ok(socials) = serde_json::from_str::<Value>(socials_str) {
                    resp["socials"] = socials;
                }
            }

            if req.pin_to_ipfs.unwrap_or(false) && !state.config.pinata_jwt.is_empty() {
                let profile_json = serde_json::to_vec(&resp).unwrap_or_default();
                match pinata::pin_object(
                    &state.http_client,
                    &state.config.pinata_upload_url,
                    &state.config.pinata_jwt,
                    &format!("profile-{}", &did),
                    &profile_json,
                )
                .await
                {
                    Ok(cid) if !cid.is_empty() => {
                        if let Err(e) = state.db.set_profile_cid(&did, &cid).await {
                            tracing::warn!(did = %did, err = %e, "failed to store profile CID");
                        }
                        resp["profile_cid"] = json!(cid);
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(did = %did, err = %e, "IPFS pin failed — profile saved without CID");
                    }
                }
            } else if let Some(cid) = profile.profile_cid {
                resp["profile_cid"] = json!(cid);
            }

            Ok((StatusCode::OK, Json(resp)))
        }
        Err(e) => {
            tracing::error!(did = %did, error = %e, "failed to upsert profile");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "message": "failed to save profile" })),
            ))
        }
    }
}

pub async fn get_profile(
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let profile = state.db.get_profile(&did).await.map_err(|e| {
        tracing::error!(did = %did, error = %e, "failed to fetch profile");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "message": "failed to fetch profile" })),
        )
    })?;

    match profile {
        Some(p) => {
            let mut resp = json!({
                "did": p.did,
                "display_name": p.display_name,
                "bio": p.bio,
                "avatar_url": p.avatar_url,
                "website": p.website,
                "profile_cid": p.profile_cid,
                "created_at": p.created_at,
                "updated_at": p.updated_at,
            });

            if let Some(ref socials_str) = p.socials {
                if let Ok(socials) = serde_json::from_str::<Value>(socials_str) {
                    resp["socials"] = socials;
                }
            }

            Ok(Json(resp))
        }
        None => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "message": "profile not found" })),
        )),
    }
}
