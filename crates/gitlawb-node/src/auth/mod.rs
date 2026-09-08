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
/// The repo owner, or a caller presenting a verified UCAN whose chain roots at
/// that owner and which carries `git/push` for this repo.
///
/// `verified` is optional because `X-Ucan` is: a push carrying no token reaches
/// the same owner-only decision it always did. The owner check is unconditional
/// and runs first, so this can only ever turn a refusal into an acceptance,
/// never the reverse.
pub fn caller_authorized_to_push(
    record: &crate::db::RepoRecord,
    caller: &str,
    verified: Option<&VerifiedUcan>,
) -> bool {
    crate::api::did_matches(caller, &record.owner_did)
        || verified.is_some_and(|v| ucan_grants_push(record, v))
}

/// Whether a verified UCAN authorizes a push to `record`.
///
/// Three conditions, all required:
///   1. The chain roots at this repo's owner. This is the trust anchor — the
///      repo record is data the node holds independently of the token, so a
///      self-minted chain cannot satisfy it.
///   2. Every link is bounded. There is no revocation path, so an unbounded link
///      is a permanent grant.
///   3. Every link — the leaf and every proof behind it — carries an
///      unconstrained push-class capability naming this repository. That is
///      [`gitlawb_core::ucan::Ucan::chain_grants_push_to`], the same rule
///      `gl ucan import` applies before storing a token and `git-remote-gitlawb`
///      applies before minting an invocation, so what one boundary accepts the
///      next does not refuse.
///
/// (3) walks the whole chain on purpose. Refusing a wildcard leaf alone did
/// nothing: `is_attenuated_by` accepts a concrete child under a `*` parent, and
/// that narrowing was exactly what the helper performed, so one owner-issued
/// `with: "*"` proof let a delegate mint a concrete leaf for ANY repository the
/// owner had — or created later — and both the chain check and the owner-root
/// check passed. A delegation's scope is fixed when it is issued.
pub fn ucan_grants_push(record: &crate::db::RepoRecord, verified: &VerifiedUcan) -> bool {
    if !crate::api::did_matches(&verified.root.to_string(), &record.owner_did) {
        return false;
    }
    // A write capability must lapse on its own. `exp` is optional in the format and
    // there is no revocation path, so a chain with an unbounded link is a permanent
    // grant: once the token leaks, the owner cannot withdraw it short of rotating
    // the DID the repo is keyed on. Refusing here is what makes "the damage window
    // is the token's expiry" a true statement rather than an aspiration.
    if !verified.ucan.chain_lifetime_is_bounded() {
        return false;
    }
    verified
        .ucan
        .chain_grants_push_to(&record.owner_did, &record.name)
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
        let scan_token_key = crate::state::AppState::derive_scan_token_key(&keypair);
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
            ipfs_rate_limiter: RateLimiter::new(600, Duration::from_secs(3600)),
            ipfs_work_rate_limiter: RateLimiter::new(600, Duration::from_secs(3600)),
            ipfs_max_history_walks: crate::api::ipfs::MAX_HISTORY_WALKS_PER_REQUEST,
            ipfs_max_legacy_probes: crate::api::ipfs::MAX_LEGACY_PROBES_PER_REQUEST,
            ipfs_legacy_scan_page_rows: crate::api::ipfs::LEGACY_SCAN_PAGE_ROWS,
            ipfs_max_legacy_scan_rows: crate::api::ipfs::MAX_LEGACY_SCAN_ROWS_PER_REQUEST,
            ipfs_max_legacy_scan_rule_bytes:
                crate::api::ipfs::MAX_LEGACY_SCAN_RULE_BYTES_PER_REQUEST,
            ipfs_scan_token_key: Arc::new(scan_token_key),
            ipfs_max_served_object_bytes: crate::api::ipfs::MAX_SERVED_OBJECT_BYTES,
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
        verified_with_exp(
            root,
            caps_vec,
            Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        )
    }

    fn verified_with_exp(
        root: &str,
        caps_vec: Vec<Capability>,
        exp: Option<chrono::DateTime<chrono::Utc>>,
    ) -> VerifiedUcan {
        let agent = Keypair::generate();
        let node = Keypair::generate();
        let ucan = Ucan::issue(&agent, node.did(), caps_vec, exp).expect("issue");
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

    /// A perpetual grant is refused even when it is otherwise perfectly valid:
    /// owner-rooted, right repo, right action. Without revocation, an unbounded
    /// delegation cannot be withdrawn once it leaks.
    #[test]
    fn refuses_a_delegation_that_never_expires() {
        let rec = repo(&owner_full(), "myrepo");
        let v = verified_with_exp(
            &owner_full(),
            vec![push_cap_for(&owner_full(), "myrepo")],
            None,
        );
        assert!(!ucan_grants_push(&rec, &v));
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

    /// A resource wildcard must NOT authorize a push, even though attenuation
    /// accepts it. The helper narrows a `*` delegation before signing, but the node
    /// cannot rely on that: a delegate can sign an invocation that keeps the
    /// wildcard, and it would otherwise reach every repository the owner has — or
    /// will later create. This test previously asserted the opposite.
    #[test]
    fn refuses_a_resource_wildcard_and_honours_repo_admin() {
        let rec = repo(&owner_full(), "myrepo");
        let wildcard = verified(&owner_full(), vec![Capability::new("*", caps::GIT_PUSH)]);
        assert!(
            !ucan_grants_push(&rec, &wildcard),
            "a wildcard resource must not authorize a push at the node"
        );

        // The ACTION wildcard is a different axis and stays: attenuation bounds it,
        // and it still has to name a concrete repository.
        let action_wildcard = verified(
            &owner_full(),
            vec![Capability::new(
                format!("gitlawb://repos/{}/myrepo", owner_full()),
                "*",
            )],
        );
        assert!(ucan_grants_push(&rec, &action_wildcard));

        let admin = verified(
            &owner_full(),
            vec![Capability::new(
                format!("gitlawb://repos/{}/myrepo", owner_full()),
                caps::REPO_ADMIN,
            )],
        );
        assert!(ucan_grants_push(&rec, &admin));
    }

    /// The attack the wildcard refusal exists to stop: one `*` delegation reaching a
    /// repository it was never issued against, including one created afterwards.
    #[test]
    fn a_wildcard_delegation_cannot_reach_a_second_repository() {
        let other = repo(&owner_full(), "a-repo-created-later");
        let wildcard = verified(&owner_full(), vec![Capability::new("*", caps::GIT_PUSH)]);
        assert!(!ucan_grants_push(&other, &wildcard));
    }

    /// The round-8 P1, executed rather than reasoned: an owner-issued `*` PROOF with
    /// a concrete leaf for a repository that did not exist at issuance. Refusing a
    /// wildcard *leaf* did nothing here — `is_attenuated_by` accepts a concrete child
    /// under a `*` parent, and that narrowing is exactly what `build_invocation` did,
    /// so the first-party helper was the working mint path.
    #[test]
    fn a_wildcard_proof_cannot_reach_a_repo_created_later() {
        let owner = Keypair::generate();
        let agent = Keypair::generate();
        let node = Keypair::generate();
        let hour = chrono::Utc::now() + chrono::Duration::hours(1);

        let parent = Ucan::issue(
            &owner,
            agent.did(),
            vec![Capability::new("*", caps::GIT_PUSH)],
            Some(hour),
        )
        .unwrap();
        let later = format!("gitlawb://repos/{}/a-repo-created-later", owner.did());
        let invocation = Ucan::delegate(
            &agent,
            node.did(),
            vec![Capability::new(&later, caps::GIT_PUSH)],
            Some(hour),
            &parent,
        )
        .unwrap();

        let root = invocation.verify_chain().expect("the chain still verifies");
        let rec = repo(&owner.did().to_string(), "a-repo-created-later");
        assert!(
            !ucan_grants_push(
                &rec,
                &VerifiedUcan {
                    ucan: invocation,
                    root
                }
            ),
            "a wildcard proof must not authorize a repo it never named"
        );
    }

    /// The shipping flow must keep working: a proof that names the repository
    /// authorizes a push to it. Guards against fixing the wildcard by refusing
    /// everything with a `prf`.
    #[test]
    fn a_concrete_proof_still_authorizes_the_repo_it_names() {
        let owner = Keypair::generate();
        let agent = Keypair::generate();
        let node = Keypair::generate();
        let hour = chrono::Utc::now() + chrono::Duration::hours(1);
        let resource = format!("gitlawb://repos/{}/myrepo", owner.did());

        let parent = Ucan::issue(
            &owner,
            agent.did(),
            vec![Capability::new(&resource, caps::GIT_PUSH)],
            Some(hour),
        )
        .unwrap();
        let invocation = Ucan::delegate(
            &agent,
            node.did(),
            vec![Capability::new(&resource, caps::GIT_PUSH)],
            Some(hour),
            &parent,
        )
        .unwrap();

        let root = invocation.verify_chain().expect("chain verifies");
        let rec = repo(&owner.did().to_string(), "myrepo");
        assert!(ucan_grants_push(
            &rec,
            &VerifiedUcan {
                ucan: invocation,
                root
            }
        ));
    }

    /// A `*` two links up. The immediate proof names the repository, so a walk that
    /// checks only one level of `prf` stays green here — this is the case that
    /// makes the recursion load-bearing rather than incidental.
    #[test]
    fn a_wildcard_grandparent_cannot_reach_the_repo_through_a_concrete_parent() {
        let owner = Keypair::generate();
        let intermediary = Keypair::generate();
        let agent = Keypair::generate();
        let node = Keypair::generate();
        let hour = chrono::Utc::now() + chrono::Duration::hours(1);
        let resource = format!("gitlawb://repos/{}/myrepo", owner.did());

        let grandparent = Ucan::issue(
            &owner,
            intermediary.did(),
            vec![Capability::new("*", caps::GIT_PUSH)],
            Some(hour),
        )
        .unwrap();
        let parent = Ucan::delegate(
            &intermediary,
            agent.did(),
            vec![Capability::new(&resource, caps::GIT_PUSH)],
            Some(hour),
            &grandparent,
        )
        .unwrap();
        let invocation = Ucan::delegate(
            &agent,
            node.did(),
            vec![Capability::new(&resource, caps::GIT_PUSH)],
            Some(hour),
            &parent,
        )
        .unwrap();

        let root = invocation.verify_chain().expect("chain verifies");
        assert_eq!(root, owner.did());
        let rec = repo(&owner.did().to_string(), "myrepo");
        assert!(
            !ucan_grants_push(
                &rec,
                &VerifiedUcan {
                    ucan: invocation,
                    root
                }
            ),
            "a wildcard anywhere in the chain must deny, not just in the immediate proof"
        );
    }

    /// And the same three-link shape with every link concrete must still grant, so
    /// the walk is refusing the wildcard and not the depth.
    #[test]
    fn a_three_link_concrete_chain_still_authorizes() {
        let owner = Keypair::generate();
        let intermediary = Keypair::generate();
        let agent = Keypair::generate();
        let node = Keypair::generate();
        let hour = chrono::Utc::now() + chrono::Duration::hours(1);
        let resource = format!("gitlawb://repos/{}/myrepo", owner.did());
        let cap = || vec![Capability::new(&resource, caps::GIT_PUSH)];

        let grandparent = Ucan::issue(&owner, intermediary.did(), cap(), Some(hour)).unwrap();
        let parent =
            Ucan::delegate(&intermediary, agent.did(), cap(), Some(hour), &grandparent).unwrap();
        let invocation = Ucan::delegate(&agent, node.did(), cap(), Some(hour), &parent).unwrap();

        let root = invocation.verify_chain().unwrap();
        let rec = repo(&owner.did().to_string(), "myrepo");
        assert!(ucan_grants_push(
            &rec,
            &VerifiedUcan {
                ucan: invocation,
                root
            }
        ));
    }

    /// The round-ten P1, pinned where it bites. The middleware verifies the chain
    /// on the `X-Ucan` header of any signed request before the scope walk runs,
    /// so a depth bound that lived only in `chain_grants_push_to` protected
    /// nothing: a hand-built header reached the unbounded recursion first. A
    /// chain at `MAX_CHAIN_DEPTH` links validates; one link more is refused here,
    /// with 401 and a message that names depth, before any authorization runs.
    #[test]
    fn validate_ucan_chain_stops_at_the_depth_bound() {
        use gitlawb_core::ucan::MAX_CHAIN_DEPTH;

        let owner = Keypair::generate();
        let node = Keypair::generate();
        let hour = chrono::Utc::now() + chrono::Duration::hours(1);
        let resource = format!("gitlawb://repos/{}/myrepo", owner.did());
        let cap = || vec![Capability::new(&resource, caps::GIT_PUSH)];

        // owner -> k1 -> ... -> signer: MAX_CHAIN_DEPTH - 1 links, all concrete,
        // all signed, all expiring. Only the length is in question.
        let mut signer = Keypair::generate();
        let mut cur = Ucan::issue(&owner, signer.did(), cap(), Some(hour)).unwrap();
        for _ in 2..MAX_CHAIN_DEPTH {
            let next = Keypair::generate();
            cur = Ucan::delegate(&signer, next.did(), cap(), Some(hour), &cur).unwrap();
            signer = next;
        }

        // Wrapped into an invocation for the node: exactly MAX_CHAIN_DEPTH links.
        let at_bound = Ucan::delegate(&signer, node.did(), cap(), Some(hour), &cur).unwrap();
        let verified = validate_ucan_chain(&at_bound.encode().unwrap(), &node.did(), &signer.did())
            .expect("a chain at the bound must still validate");
        assert_eq!(verified.root, owner.did());

        // One more link and it is past the bound.
        let next = Keypair::generate();
        let deeper = Ucan::delegate(&signer, next.did(), cap(), Some(hour), &cur).unwrap();
        let past_bound = Ucan::delegate(&next, node.did(), cap(), Some(hour), &deeper).unwrap();
        let (status, body) =
            match validate_ucan_chain(&past_bound.encode().unwrap(), &node.did(), &next.did()) {
                Ok(_) => panic!("a chain past the bound must be refused, not walked"),
                Err(refusal) => refusal,
            };
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let message = body.0["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("deeper than"),
            "the refusal must name depth as the reason: {message}"
        );
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
