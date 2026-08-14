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

/// A UCAN that passed full chain validation, with the root issuer the chain
/// rests on. Inserted into request extensions by [`require_ucan_chain`] when
/// `X-Ucan` is present; absent when the header is.
///
/// `root` is carried rather than recomputed so the chain is walked once per
/// request. Holding this is not itself an authorization decision — a caller must
/// still compare `root` against an identity it independently trusts, because
/// `did:key` is self-certifying and anyone can mint a chain that verifies.
#[derive(Clone, Debug)]
pub struct VerifiedUcan {
    pub ucan: Ucan,
    pub root: Did,
}

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

/// Whether `with` names this repository.
///
/// Structural, not a string compare: `owner_did` is stored as a full
/// `did:key:z6Mk…` on canonical rows and as a bare `z6Mk…` on mirror rows, so a
/// literal match would deny a valid delegation for every mirror. `"*"` keeps the
/// wildcard meaning [`gitlawb_core::ucan::Capability::is_attenuated_by`] gives it.
fn repo_capability_matches(with: &str, record: &crate::db::RepoRecord) -> bool {
    if with == "*" {
        return true;
    }
    let Some(rest) = with.strip_prefix("gitlawb://repos/") else {
        return false;
    };
    // The owner segment is a DID and may contain ':' but never '/', so the last
    // separator splits owner from name.
    let Some((owner_seg, name_seg)) = rest.rsplit_once('/') else {
        return false;
    };
    !owner_seg.is_empty()
        && crate::api::did_matches(owner_seg, &record.owner_did)
        && name_seg == record.name
}

/// Whether a verified UCAN authorizes a push to `record`.
///
/// Two conditions, both required:
///   1. The chain roots at this repo's owner. This is the trust anchor — the
///      repo record is data the node holds independently of the token, so a
///      self-minted chain cannot satisfy it.
///   2. Some capability in the leaf covers `git/push` on this repo.
///
/// Only the leaf is examined for (2): [`gitlawb_core::ucan::Ucan::verify_chain`]
/// has already established that each leaf capability is attenuated by its proof,
/// transitively to the root, so a surviving leaf capability is no broader than
/// what the root granted.
///
/// A capability carrying `nb` (constraints) authorizes nothing. Constraints are
/// not interpreted yet, and an owner who writes them means to restrict; granting
/// while ignoring them would be strictly more permissive than intended.
pub fn ucan_grants_push(record: &crate::db::RepoRecord, verified: &VerifiedUcan) -> bool {
    if !crate::api::did_matches(&verified.root.to_string(), &record.owner_did) {
        return false;
    }
    verified.ucan.payload.att.iter().any(|cap| {
        cap.constraints.is_none()
            && (cap.can == gitlawb_core::ucan::caps::GIT_PUSH
                || cap.can == "*"
                || cap.can == gitlawb_core::ucan::caps::REPO_ADMIN)
            && repo_capability_matches(&cap.with, record)
    })
}

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
) -> Result<VerifiedUcan, (StatusCode, Json<serde_json::Value>)> {
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

    let root = ucan.verify_chain().map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid_ucan", "message": e.to_string() })),
        )
    })?;

    Ok(VerifiedUcan { ucan, root })
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

    let verified = match validate_ucan_chain(&token, &state.node_did, &signer_did) {
        Ok(v) => v,
        Err((status, body)) => return (status, body).into_response(),
    };

    tracing::debug!(did = %signer_did, root = %verified.root, "UCAN chain validated");

    // Park the verified token where a handler can reach it. Validation alone
    // grants nothing; the authorization decision is made downstream, by a caller
    // that knows which identity it trusts for the resource being touched.
    let mut request = request;
    request.extensions_mut().insert(verified);
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

    /// The middleware validated a token and threw the result away, so no handler
    /// could ever read it and `Ucan::can` had no call site in the node. Validation
    /// must hand back both the token and the root the chain rests on.
    #[test]
    fn validate_ucan_chain_hands_back_the_root_and_the_token() {
        let owner = Keypair::generate();
        let agent = Keypair::generate();
        let node = Keypair::generate();
        let caps_vec = vec![Capability::new("gitlawb://repos/zowner/r", caps::GIT_PUSH)];

        let delegation =
            Ucan::issue(&owner, agent.did(), caps_vec.clone(), None).expect("issue delegation");
        let invocation = Ucan::delegate(&agent, node.did(), caps_vec, None, &delegation)
            .expect("wrap invocation");
        let token = invocation.encode().expect("encode");

        let verified = validate_ucan_chain(&token, &node.did(), &agent.did())
            .expect("a well-formed owner-rooted invocation must validate");

        assert_eq!(
            verified.root,
            owner.did(),
            "the root must be the owner, so a caller can anchor against the repo record"
        );
        assert_eq!(
            verified.ucan.payload.iss,
            agent.did(),
            "the token itself must come back so a caller can read its capabilities"
        );
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
            git_read_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            git_write_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            git_push_advert_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            git_encrypt_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            pin_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            encrypt_inflight: crate::state::EncryptInflight::new(),
            repo_write_leases: crate::state::RepoWriteLeases::new(8),
            git_read_per_caller: crate::rate_limit::PerCallerConcurrency::with_default_max_keys(16),
            git_push_advert_per_caller:
                crate::rate_limit::PerCallerConcurrency::with_default_max_keys(8),
            git_write_per_caller: crate::rate_limit::PerCallerConcurrency::with_default_max_keys(8),
            git_ipfs_walk_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            git_ipfs_walk_per_caller:
                crate::rate_limit::PerCallerConcurrency::with_default_max_keys(16),
            ipfs_rate_limiter: RateLimiter::new(600, Duration::from_secs(3600)),
            git_bin: "git".to_string(),
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

#[cfg(test)]
mod ucan_push_tests {
    use super::*;
    use gitlawb_core::identity::Keypair;
    use gitlawb_core::ucan::{caps, Capability, Ucan};

    const OWNER_KEY: &str = "z6MkOwnerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// `RepoRecord` does not derive `Default`, and adding the derive to a
    /// production DB type purely to serve a test is the wrong direction.
    fn repo(owner_did: &str, name: &str) -> crate::db::RepoRecord {
        crate::db::RepoRecord {
            id: "repo-id".to_string(),
            name: name.to_string(),
            owner_did: owner_did.to_string(),
            description: None,
            is_public: true,
            default_branch: "main".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            disk_path: "/unused".to_string(),
            forked_from: None,
            machine_id: None,
        }
    }

    /// The token's own issuer and audience are irrelevant to this predicate: the
    /// middleware has already bound `iss` to the request signer and `aud` to this
    /// node. Only the capabilities and the chain's root matter here.
    fn verified(root: &str, caps_vec: Vec<Capability>) -> VerifiedUcan {
        let agent = Keypair::generate();
        let node = Keypair::generate();
        let ucan = Ucan::issue(&agent, node.did(), caps_vec, None).expect("issue");
        VerifiedUcan {
            ucan,
            root: root.parse().expect("root DID must parse"),
        }
    }

    fn owner_full() -> String {
        format!("did:key:{OWNER_KEY}")
    }

    fn push_cap_for(owner: &str, name: &str) -> Capability {
        Capability::new(format!("gitlawb://repos/{owner}/{name}"), caps::GIT_PUSH)
    }

    #[test]
    fn grants_push_when_the_chain_roots_at_the_owner_and_names_the_repo() {
        let rec = repo(&owner_full(), "myrepo");
        let v = verified(&owner_full(), vec![push_cap_for(&owner_full(), "myrepo")]);
        assert!(ucan_grants_push(&rec, &v));
    }

    #[test]
    fn matches_a_bare_owner_key_against_a_full_did_record() {
        // Mirror rows store the bare key. A literal string compare would fail
        // here, denying a delegation that is in fact valid.
        let rec = repo(OWNER_KEY, "myrepo");
        let v = verified(&owner_full(), vec![push_cap_for(&owner_full(), "myrepo")]);
        assert!(ucan_grants_push(&rec, &v));
    }

    #[test]
    fn refuses_a_self_minted_root() {
        // The whole point: a token nobody delegated grants nothing, however
        // permissive its capabilities look.
        let stranger = Keypair::generate();
        let rec = repo(&owner_full(), "myrepo");
        let v = verified(&stranger.did().to_string(), vec![Capability::new("*", "*")]);
        assert!(!ucan_grants_push(&rec, &v));
    }

    #[test]
    fn refuses_a_capability_for_a_different_repo() {
        let rec = repo(&owner_full(), "myrepo");
        let v = verified(
            &owner_full(),
            vec![push_cap_for(&owner_full(), "otherrepo")],
        );
        assert!(!ucan_grants_push(&rec, &v));
    }

    #[test]
    fn refuses_a_capability_carrying_constraints() {
        // `nb` is not interpreted yet. An owner who writes {"refs": [...]} means
        // to restrict; honouring the capability while ignoring nb would grant
        // strictly more than they intended, so it authorizes nothing.
        let rec = repo(&owner_full(), "myrepo");
        let v = verified(
            &owner_full(),
            vec![push_cap_for(&owner_full(), "myrepo")
                .with_constraints(serde_json::json!({ "refs": ["refs/heads/feat/*"] }))],
        );
        assert!(!ucan_grants_push(&rec, &v));
    }

    #[test]
    fn refuses_a_non_push_capability() {
        let rec = repo(&owner_full(), "myrepo");
        let v = verified(
            &owner_full(),
            vec![Capability::new(
                format!("gitlawb://repos/{}/myrepo", owner_full()),
                caps::ISSUE_CREATE,
            )],
        );
        assert!(!ucan_grants_push(&rec, &v));
    }

    #[test]
    fn honours_the_resource_wildcard_and_repo_admin() {
        let rec = repo(&owner_full(), "myrepo");
        let wildcard = verified(&owner_full(), vec![Capability::new("*", caps::GIT_PUSH)]);
        assert!(ucan_grants_push(&rec, &wildcard));

        let admin = verified(
            &owner_full(),
            vec![Capability::new(
                format!("gitlawb://repos/{}/myrepo", owner_full()),
                caps::REPO_ADMIN,
            )],
        );
        assert!(ucan_grants_push(&rec, &admin));
    }

    #[test]
    fn refuses_a_malformed_resource_uri() {
        let rec = repo(&owner_full(), "myrepo");
        for bad in [
            "",
            "myrepo",
            "https://repos/x/myrepo",
            "gitlawb://repos/myrepo",
        ] {
            let v = verified(&owner_full(), vec![Capability::new(bad, caps::GIT_PUSH)]);
            assert!(!ucan_grants_push(&rec, &v), "{bad} must not grant push");
        }
    }
}
