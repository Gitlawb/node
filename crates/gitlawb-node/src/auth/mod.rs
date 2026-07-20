use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use http_body_util::BodyExt;
use serde_json::json;
use std::collections::HashMap;

use gitlawb_core::did::Did;
use gitlawb_core::ucan::Ucan;

use crate::state::AppState;

/// The authenticated agent's DID, injected into request extensions by `require_signature`.
#[derive(Clone, Debug)]
pub struct AuthenticatedDid(pub String);

/// The raw RFC 9421 HTTP Signature value (the `Signature` header), injected into
/// request extensions by `require_signature`. Pushers sign the request, and the
/// node persists this signature so it can be presented as proof of authorization.
#[derive(Clone, Debug)]
pub struct PusherSignature(pub String);

/// Whether `caller` is authorized to push to `record`.
///
/// Phase 1 (`GITLAWB_ENFORCE_OWNER_PUSH`): owner-only, via the canonical
/// [`crate::api::did_matches`] owner comparison (DID-safe on both sides). This is
/// intentionally a distinct, intent-named gate rather than a bare owner check so
/// that Phase 2 can extend it to honor a verified UCAN `git/push` capability as a
/// pure addition (`did_matches(..) || ucan_grants_push(..)`) without rewriting
/// call sites.
pub fn caller_authorized_to_push(record: &crate::db::RepoRecord, caller: &str) -> bool {
    crate::api::did_matches(caller, &record.owner_did)
}

use base64::Engine as _;
use gitlawb_core::http_sig::{
    build_signing_string, compute_content_digest, HttpSignature, COVERED_COMPONENTS,
};
use gitlawb_core::identity::verify;

/// Axum middleware that enforces HTTP Signature authentication (RFC 9421).
///
/// Every write request must carry:
///   Content-Digest:   sha-256=:base64hash:
///   Signature-Input:  sig1=("@method" "@path" "content-digest");keyid="did:key:...";alg="ed25519";created=<unix>
///   Signature:        sig1=:base64signature:
///
/// The middleware:
///   1. Buffers the request body (needed for content-digest verification)
///   2. Parses Signature-Input + Signature headers (RFC 9421)
///   3. Checks clock skew on `created` parameter
///   4. Resolves the did:key to an Ed25519 VerifyingKey
///   5. Rebuilds the signing string and verifies the Ed25519 signature
///   6. Verifies Content-Digest matches the request body
pub async fn require_signature(request: Request, next: Next) -> Response {
    // Buffer the body so we can verify content-digest and pass it downstream
    let (parts, body) = request.into_parts();
    let body_bytes =
        match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({ "error": "unreadable_body", "message": "could not read request body" }),
                ),
            )
                .into_response(),
        };

    let sig_input = parts
        .headers
        .get("signature-input")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let sig_header = parts
        .headers
        .get("signature")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let (sig_input, sig_header) = match (sig_input, sig_header) {
        (Some(i), Some(s)) => (i, s),
        _ => {
            return human_detected(
                "missing Signature-Input or Signature headers — use RFC 9421 HTTP Signatures",
            )
            .into_response();
        }
    };

    let sig = match HttpSignature::parse(&sig_input, &sig_header) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_signature",
                    "message": e.to_string(),
                })),
            )
                .into_response()
        }
    };

    // Check clock skew on `created`
    if let Err(e) = sig.check_created() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "clock_skew", "message": e.to_string() })),
        )
            .into_response();
    }

    // Check all required components are covered
    let missing = sig.missing_components();
    if !missing.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "incomplete_signature",
                "message": format!(
                    "Signature must cover: {}. Missing: {}",
                    COVERED_COMPONENTS.join(", "),
                    missing.join(", ")
                ),
                "hint": "See https://gitlawb.com/agents#authentication",
            })),
        )
            .into_response();
    }

    if sig.alg != "ed25519" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "unsupported_algorithm",
                "message": format!("algorithm '{}' not supported, use 'ed25519'", sig.alg),
            })),
        )
            .into_response();
    }

    // Resolve did:key → VerifyingKey
    let verifying_key = match sig.key_id.to_verifying_key() {
        Ok(vk) => vk,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "unresolvable_did",
                    "message": format!("cannot resolve DID '{}': {e}", sig.key_id),
                    "hint": "only did:key is supported in alpha",
                })),
            )
                .into_response()
        }
    };

    // Reconstruct the signing string from the actual request
    let method = parts.method.as_str().to_uppercase();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();

    let content_digest = parts
        .headers
        .get("content-digest")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let mut request_values: HashMap<String, String> = HashMap::new();
    request_values.insert("@method".to_string(), method);
    request_values.insert("@path".to_string(), path_and_query);
    request_values.insert("content-digest".to_string(), content_digest);

    // The @signature-params value is the part of Signature-Input after "sig1="
    let sig_params_value = sig_input.strip_prefix("sig1=").unwrap_or(&sig_input);

    let components_ref: Vec<&str> = sig.components.iter().map(String::as_str).collect();

    let signing_string =
        match build_signing_string(&components_ref, sig_params_value, &request_values) {
            Ok(s) => s,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "signing_string_error", "message": e.to_string() })),
                )
                    .into_response()
            }
        };

    // Verify Ed25519 signature
    let sig_array: [u8; 64] = match sig.signature_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_signature",
                    "message": "Ed25519 signature must be exactly 64 bytes",
                })),
            )
                .into_response()
        }
    };

    if let Err(e) = verify(&verifying_key, signing_string.as_bytes(), &sig_array) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "invalid_signature",
                "message": format!("Ed25519 verification failed: {e}"),
            })),
        )
            .into_response();
    }

    // Verify Content-Digest matches the actual request body
    if let Some(claimed) = parts
        .headers
        .get("content-digest")
        .and_then(|v| v.to_str().ok())
    {
        let actual = compute_content_digest(&body_bytes);
        if claimed != actual {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "content_digest_mismatch",
                    "message": "Content-Digest does not match request body",
                })),
            )
                .into_response();
        }
    }

    tracing::info!(did = %sig.key_id, "✓ authenticated request");

    let mut request = Request::from_parts(parts, Body::from(body_bytes));
    request
        .extensions_mut()
        .insert(AuthenticatedDid(sig.key_id.to_string()));
    request.extensions_mut().insert(PusherSignature(
        base64::engine::general_purpose::STANDARD.encode(&sig.signature_bytes),
    ));
    next.run(request).await
}

/// Optional variant for rolling upgrades: verify and inject `AuthenticatedDid` when
/// RFC 9421 signature headers are present, but allow legacy unsigned requests to
/// continue when no signature attempt was made.
pub async fn optional_signature(request: Request, next: Next) -> Response {
    let has_signature_headers = request.headers().contains_key("signature-input")
        || request.headers().contains_key("signature");
    if has_signature_headers {
        return require_signature(request, next).await;
    }
    next.run(request).await
}

/// Validate a raw UCAN token string supplied in `X-Ucan`.
///
/// Checks performed:
///   1. The token decodes to a valid [`Ucan`] structure.
///   2. The UCAN issuer (`iss`) matches `signer_did` — the DID that signed the
///      HTTP request — preventing replay of another agent's UCAN.
///   3. The UCAN audience (`aud`) matches `expected_aud` — the node's own DID.
///   4. The full proof chain is cryptographically valid (signatures, expiry,
///      not-before, chain linkage, and capability attenuation).
fn validate_ucan_chain(
    token: &str,
    expected_aud: &Did,
    signer_did: &Did,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let ucan = Ucan::decode(token).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid_ucan", "message": e.to_string() })),
        )
    })?;

    if &ucan.payload.iss != signer_did {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "invalid_ucan",
                "message": format!(
                    "UCAN issuer {} does not match request signer {}",
                    ucan.payload.iss, signer_did
                ),
            })),
        ));
    }

    ucan.verify_audience(expected_aud).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid_ucan", "message": e.to_string() })),
        )
    })?;

    ucan.verify_chain().map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid_ucan", "message": e.to_string() })),
        )
    })?;

    Ok(())
}

/// Axum middleware that validates a UCAN chain when `X-Ucan` is present.
///
/// Must be layered so that it runs after [`require_signature`], which sets the
/// [`AuthenticatedDid`] extension consumed here.
///
/// When `X-Ucan` is absent the request passes through unchanged, preserving
/// backward compatibility for agents that pre-date UCAN delegation. When the
/// header is present the full chain is validated: the UCAN issuer must match
/// the HTTP Signature identity, the audience must be this node's DID, and
/// every proof in the chain must be cryptographically sound with no capability
/// escalation.
pub async fn require_ucan_chain(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let token = match request
        .headers()
        .get("x-ucan")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
    {
        Some(t) => t,
        None => return next.run(request).await,
    };

    let signer_did: Did = match request.extensions().get::<AuthenticatedDid>() {
        Some(a) => match a.0.parse() {
            Ok(did) => did,
            Err(e) => {
                tracing::warn!(raw_did = %a.0, err = %e, "failed to parse DID from authenticated identity");
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "error": "invalid_identity", "message": "invalid DID in token" })),
                )
                    .into_response();
            }
        },
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "invalid_ucan",
                    "message": "UCAN validation requires a valid HTTP Signature",
                })),
            )
                .into_response()
        }
    };

    if let Err((status, body)) = validate_ucan_chain(&token, &state.node_did, &signer_did) {
        return (status, body).into_response();
    }

    tracing::debug!(did = %signer_did, "UCAN chain validated");
    next.run(request).await
}

fn human_detected(message: &str) -> impl IntoResponse {
    (
        StatusCode::UNAUTHORIZED,
        [
            (
                "WWW-Authenticate",
                "Signature realm=\"gitlawb-alpha\", alg=\"ed25519\"",
            ),
            ("X-Gitlawb-Error", "human_detected"),
        ],
        Json(json!({
            "error": "not_an_agent",
            "message": message,
            "hint": "gl identity new && gl register",
            "docs": "https://gitlawb.com/agents",
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{middleware, Router};
    use gitlawb_core::identity::Keypair;
    use gitlawb_core::ucan::{caps, Capability, Ucan};
    use std::{path::PathBuf, sync::Arc, time::Duration};
    use tower::ServiceExt;

    fn bootstrap_ucan(node: &Keypair, agent_did: Did) -> Ucan {
        Ucan::bootstrap(node, agent_did).unwrap()
    }

    fn delegation_ucan(agent: &Keypair, node_did: Did, proof: &Ucan) -> Ucan {
        Ucan::delegate(
            agent,
            node_did,
            vec![Capability::new("gitlawb://alpha", caps::NETWORK_JOIN)],
            None,
            proof,
        )
        .unwrap()
    }

    #[test]
    fn validate_ucan_chain_valid() {
        let node = Keypair::generate();
        let agent = Keypair::generate();
        let node_did = node.did();
        let agent_did = agent.did();

        let proof = bootstrap_ucan(&node, agent_did.clone());
        let delegation = delegation_ucan(&agent, node_did.clone(), &proof);
        let token = delegation.encode().unwrap();

        assert!(validate_ucan_chain(&token, &node_did, &agent_did).is_ok());
    }

    #[test]
    fn validate_ucan_chain_wrong_issuer() {
        let node = Keypair::generate();
        let agent = Keypair::generate();
        let other = Keypair::generate();
        let node_did = node.did();
        let agent_did = agent.did();

        let proof = bootstrap_ucan(&node, agent_did.clone());
        let delegation = delegation_ucan(&agent, node_did.clone(), &proof);
        let token = delegation.encode().unwrap();

        // signer_did is `other` but UCAN iss is `agent` — must be rejected
        let err = validate_ucan_chain(&token, &node_did, &other.did()).unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        let body = err.1 .0.to_string();
        assert!(body.contains("does not match request signer"));
    }

    #[test]
    fn validate_ucan_chain_wrong_audience() {
        let node = Keypair::generate();
        let agent = Keypair::generate();
        let other_node = Keypair::generate();
        let node_did = node.did();
        let agent_did = agent.did();

        let proof = bootstrap_ucan(&node, agent_did.clone());
        let delegation = delegation_ucan(&agent, node_did.clone(), &proof);
        let token = delegation.encode().unwrap();

        // expected_aud is a different node — must be rejected
        let err = validate_ucan_chain(&token, &other_node.did(), &agent_did).unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        let body = err.1 .0.to_string();
        assert!(body.contains("audience mismatch"));
    }

    #[test]
    fn validate_ucan_chain_expired_proof() {
        let node = Keypair::generate();
        let agent = Keypair::generate();
        let node_did = node.did();
        let agent_did = agent.did();

        let exp = chrono::Utc::now() - chrono::Duration::hours(1);
        let proof = Ucan::issue(
            &node,
            agent_did.clone(),
            vec![Capability::new("gitlawb://alpha", caps::NETWORK_JOIN)],
            Some(exp),
        )
        .unwrap();
        let delegation = delegation_ucan(&agent, node_did.clone(), &proof);
        let token = delegation.encode().unwrap();

        let err = validate_ucan_chain(&token, &node_did, &agent_did).unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        let body = err.1 .0.to_string();
        assert!(body.contains("expired"));
    }

    fn make_test_state(node_did: gitlawb_core::did::Did) -> crate::state::AppState {
        use crate::{config::Config, graphql, rate_limit::RateLimiter};
        use clap::Parser;

        let keypair = Keypair::generate();
        let (ref_tx, _) = tokio::sync::broadcast::channel(1);
        let (task_tx, _) = tokio::sync::broadcast::channel(1);
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/gitlawb_test_placeholder")
            .expect("lazy pool creation should not fail");
        let db = Arc::new(crate::db::Db::for_testing(pool.clone()));
        let schema = Arc::new(graphql::build_schema(
            db.clone(),
            ref_tx.clone(),
            task_tx.clone(),
        ));
        crate::state::AppState {
            config: Arc::new(Config::parse_from(["gitlawb-node"])),
            db,
            node_did,
            node_keypair: Arc::new(keypair),
            p2p: None,
            http_client: Arc::new(reqwest::Client::new()),
            ref_update_tx: ref_tx,
            task_event_tx: task_tx,
            graphql_schema: schema,
            machine_id: None,
            repo_store: crate::git::repo_store::RepoStore::for_testing(PathBuf::from("/tmp"), pool),
            rate_limiter: RateLimiter::new(100, Duration::from_secs(60)),
            create_ip_rate_limiter: RateLimiter::new(1000, Duration::from_secs(3600)),
            push_rate_limiter: RateLimiter::new(600, Duration::from_secs(3600)),
            push_limiter_trust: crate::rate_limit::TrustedProxy::None,
            sync_trigger_rate_limiter: RateLimiter::new(60, Duration::from_secs(3600)),
            peer_write_rate_limiter: RateLimiter::new(600, Duration::from_secs(3600)),
            shutdown_tx: tokio::sync::watch::channel(false).0,
        }
    }

    #[tokio::test]
    async fn require_ucan_chain_no_header_passes_through() {
        let state = make_test_state(Keypair::generate().did());
        let app = Router::new()
            .route("/", axum::routing::get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn_with_state(state, require_ucan_chain));

        let req = Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn require_ucan_chain_missing_did_returns_401() {
        let state = make_test_state(Keypair::generate().did());
        let app = Router::new()
            .route("/", axum::routing::get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn_with_state(state, require_ucan_chain));

        // x-ucan present but no AuthenticatedDid extension → 401
        let req = Request::builder()
            .uri("/")
            .header("x-ucan", "any-token")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn require_ucan_chain_wrong_issuer_returns_401() {
        let node = Keypair::generate();
        let agent = Keypair::generate();
        let other = Keypair::generate();
        let node_did = node.did();
        let agent_did = agent.did();

        // Build a valid token where iss = agent, but supply `other` as the signer.
        let proof = bootstrap_ucan(&node, agent_did.clone());
        let token = delegation_ucan(&agent, node_did.clone(), &proof)
            .encode()
            .unwrap();

        let state = make_test_state(node_did);
        let app = Router::new()
            .route("/", axum::routing::get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn_with_state(state, require_ucan_chain));

        // AuthenticatedDid is `other`, UCAN iss is `agent` → issuer mismatch → 401
        let req = Request::builder()
            .uri("/")
            .header("x-ucan", token)
            .extension(AuthenticatedDid(other.did().to_string()))
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn require_ucan_chain_malformed_token_returns_401() {
        let state = make_test_state(Keypair::generate().did());
        let app = Router::new()
            .route("/", axum::routing::get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn_with_state(state, require_ucan_chain));

        // Malformed x-ucan (invalid JSON)
        let req = Request::builder()
            .uri("/")
            .header("x-ucan", "invalid-token-structure")
            .extension(AuthenticatedDid(Keypair::generate().did().to_string()))
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 2048).await.unwrap();
        let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body_json["error"], "invalid_ucan");
    }
}
