use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use http_body_util::BodyExt;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use gitlawb_core::did::Did;
use gitlawb_core::ucan::Ucan;

use crate::state::AppState;

/// The authenticated agent's DID, injected into request extensions by `require_signature`.
#[derive(Clone, Debug)]
pub struct AuthenticatedDid(pub String);

/// The canonical identity of a verified HTTP signature, published into request
/// extensions by [`require_signature`] so a spent-signature ledger can be keyed
/// without re-parsing headers.
///
/// `signing_string_hash` is a hex SHA-256 of the *reconstructed* signing string,
/// never of the raw `Signature` header. `HttpSignature::parse` trims, and the
/// header is not a covered component, so whitespace variants are distinct header
/// bytes that reconstruct to one signing string; hashing the reconstruction is
/// what collapses those variants to a single ledger key. The signing string also
/// embeds `keyid` and `created` through its `@signature-params` line, so the
/// hash cannot collide across DIDs.
#[derive(Clone, Debug)]
pub struct SignatureIdentity {
    /// The signing DID, as it appeared in the `keyid` parameter. Human-readable
    /// and good for logs; NOT an identity key — see [`Self::key_fingerprint`].
    pub keyid: String,
    /// Hex of the 32 resolved Ed25519 public key bytes: the canonical identity.
    ///
    /// `Did` stores the wire string verbatim while `to_verifying_key` resolves
    /// it through `multibase::decode`, which accepts any multibase prefix. One
    /// keypair therefore has many valid `did:key` spellings (`z6Mk…` base58btc,
    /// `f…` base16, `m…` base64url, and more) that are all distinct strings and
    /// all resolve to the same key. Anything counting per identity by string
    /// equality hands that keypair a fresh budget per spelling, so per-identity
    /// accounting keys on this instead.
    pub key_fingerprint: String,
    /// The `nonce` parameter, absent on signatures from a pre-nonce signer.
    /// Present but short is not the same as unique: see [`unique_nonce`].
    pub nonce: Option<String>,
    /// Hex SHA-256 of the reconstructed signing string: exactly 64 characters.
    pub signing_string_hash: String,
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

use gitlawb_core::http_sig::{
    build_signing_string, compute_content_digest, HttpSignature, COVERED_COMPONENTS,
    MAX_FUTURE_SKEW_SECS, MAX_SIGNATURE_AGE_SECS,
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
    // Publish the canonical ledger key while the verified signing string is still
    // in hand. Hashing `signing_string` (the reconstruction that was just verified
    // against) rather than any raw header is deliberate: see `SignatureIdentity`.
    request.extensions_mut().insert(SignatureIdentity {
        keyid: sig.key_id.to_string(),
        key_fingerprint: hex::encode(verifying_key.to_bytes()),
        nonce: sig.nonce.clone(),
        signing_string_hash: hex::encode(Sha256::digest(signing_string.as_bytes())),
    });
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

/// How long a spent signature stays in the ledger, in seconds.
///
/// Retention must cover the whole window in which the signature would still be
/// accepted, or a key is evicted while its signature still passes the time
/// check. `check_created` accepts a request when `created` falls in
/// `[now - 300, now + 30]`, so for one fixed signature the acceptable *arrival*
/// window is `[created - 30, created + 300]`: 330 seconds wide. Expiry is
/// computed from arrival rather than from `created`, which can only over-retain
/// (an early arrival is charged the full 330s from when it landed), never
/// under-retain.
///
/// 330 + [`CROSS_INSTANCE_SKEW_MARGIN_SECS`] = 390. The margin is not slack:
/// single-node a flush 330 is exactly right (at `now = created + 300` the sweep
/// predicate `expires_at < now` is false so the row survives, and at
/// `created + 301` the signature is already too old), but the sweep runs on
/// whichever instance's timer fires, using ITS clock. With instance B running
/// `d` seconds ahead of A, a flush TTL has B delete the row at true time
/// `created + 300 - d` while A still accepts the replay until `created + 300`,
/// a replay window of exactly `d`. 60s covers the disagreement an NTP-synced
/// fleet can actually reach.
///
/// Derived rather than written out so it cannot drift from the window it has to
/// cover: widening either skew bound in `gitlawb-core` carries the TTL with it.
const SIGNATURE_LEDGER_TTL_SECS: i64 =
    MAX_SIGNATURE_AGE_SECS + MAX_FUTURE_SKEW_SECS + CROSS_INSTANCE_SKEW_MARGIN_SECS;

/// Clock disagreement between two instances that the ledger TTL must absorb.
const CROSS_INSTANCE_SKEW_MARGIN_SECS: i64 = 60;

/// The shortest nonce this node will treat as a unique ledger key.
///
/// `HttpSignature::parse` maps the raw parameter, so `nonce=""` arrives as
/// `Some("")` rather than `None`. Length is the only property a verifier can
/// check (entropy is not observable), so it is the floor: 16 characters is 64
/// bits even on the weakest plausible alphabet, hex at 4 bits per character. At
/// the enforced ceiling of `MAX_LIVE_SIGNATURES_PER_KEYID` (512) live rows per
/// identity, the birthday probability of an accidental collision within one
/// identity is about `512^2 / 2^65`, roughly 1e-14.
///
/// Set below the 32 hex characters (128 bits) our own `sign_request` emits so
/// the floor costs no upgrade churn, yet still admits a third-party client
/// signing a 22-character base64 UUID or a 16-character hex draw.
const MIN_NONCE_CHARS: usize = 16;

/// The nonce, but only when it is long enough to stand in as a unique key.
///
/// Without this filter an empty nonce is `Some("")`, which both satisfies the
/// staged `require a nonce` flag (whose stated purpose is that every client
/// signs one) and puts [`ledger_key`] on its `(key, nonce)` arm with a value
/// that is CONSTANT per identity: every mutation from that keypair would
/// collapse onto one ledger key, so the first one in a retention window would
/// succeed and every later one would be refused as a replay.
fn unique_nonce(identity: &SignatureIdentity) -> Option<&str> {
    identity
        .nonce
        .as_deref()
        .filter(|nonce| nonce.chars().count() >= MIN_NONCE_CHARS)
}

/// The ledger key for a verified signature: always a 64-character hex SHA-256,
/// which is what the `consumed_signatures` CHECK constraint requires.
///
/// Two disjoint schemes, kept apart by a domain tag so a nonce key can never
/// collide with a signing-string key:
///   * with a nonce of usable width, `(key_fingerprint, nonce)` — short,
///     fixed-width, and it lets two legitimately identical requests be told
///     apart;
///   * otherwise the signing-string hash, which is canonical by construction
///     and collapses whitespace variants of the `Signature` header onto one key.
///
/// A too-short nonce takes the second arm rather than the first. That is the
/// safe direction: the hash arm is unique by construction, so a client with a
/// weak nonce loses only the ability to repeat byte-identical requests inside
/// one second, whereas trusting the nonce would collapse its whole traffic onto
/// one key. The fingerprint rather than `keyid` keeps the nonce arm on the
/// resolved key, so two spellings of one DID cannot reuse a nonce.
fn ledger_key(identity: &SignatureIdentity) -> String {
    let mut hasher = Sha256::new();
    match unique_nonce(identity) {
        Some(nonce) => {
            hasher.update(b"gitlawb/sig-nonce\x00");
            hasher.update(identity.key_fingerprint.as_bytes());
            hasher.update(b"\x00");
            hasher.update(nonce.as_bytes());
        }
        None => {
            hasher.update(b"gitlawb/sig-string\x00");
            hasher.update(identity.signing_string_hash.as_bytes());
        }
    }
    hex::encode(hasher.finalize())
}

fn ledger_rejection(status: StatusCode, code: &'static str, message: &str) -> Response {
    (
        status,
        [("X-Gitlawb-Error", code)],
        Json(json!({ "error": code, "message": message })),
    )
        .into_response()
}

/// Axum middleware that spends a verified HTTP signature exactly once.
///
/// Layer it so it runs *after* [`require_signature`] (which publishes the
/// [`SignatureIdentity`] read here) and after [`require_ucan_chain`], but before
/// the handler. Consuming last means only a request that cleared every auth
/// check spends its signature, so a valid signature paired with a rejected UCAN
/// can be retried with the same bytes; consuming before the handler is what
/// closes the concurrent-replay race.
pub async fn consume_signature(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    // Skip reads. `write_routes` chains `PUT/DELETE/GET` on one path
    // (`/api/v1/repos/{owner}/{repo}/visibility`, `server.rs`), so
    // `list_visibility` is served by a router inside `add_auth_layers` and `gl`
    // drives it through `get_signed`. Ledgering there would put a database write
    // on the signed read path, which R7 forbids. A method check is the general
    // form of that exclusion and needs no router split: replaying a read has no
    // side effect to spend.
    if matches!(*request.method(), Method::GET | Method::HEAD) {
        return next.run(request).await;
    }

    let identity = match request.extensions().get::<SignatureIdentity>() {
        Some(identity) => identity.clone(),
        None => {
            // Fail closed. If this passed the request through, a wrong layer
            // order would silently delete the replay defense while every test
            // that exercises the correct stack kept passing.
            tracing::error!(
                path = %request.uri().path(),
                "signature ledger reached without a verified SignatureIdentity — check the layer order",
            );
            return ledger_rejection(
                StatusCode::INTERNAL_SERVER_ERROR,
                "signature_identity_missing",
                "the request reached the signature ledger without a verified identity",
            );
        }
    };

    // Staged rollout of R6: once every client signs a nonce, an operator closes
    // the signing-string fallback here. This runs after the method skip above,
    // so it never reaches a signed read, and before the ledger is charged, so a
    // refused request spends nothing.
    if state.config.require_signature_nonce && unique_nonce(&identity).is_none() {
        // A present-but-short nonce gets its own code. It is a different
        // client bug from a pre-nonce signer (the client already emits the
        // parameter, it just does not fill it), and the two need different
        // instructions.
        return match identity.nonce {
            None => {
                tracing::warn!(did = %identity.keyid, "rejected a nonce-less signature: a nonce is required");
                ledger_rejection(
                    StatusCode::BAD_REQUEST,
                    "signature_nonce_required",
                    "this node requires a `nonce` parameter in Signature-Input — upgrade your client",
                )
            }
            Some(nonce) => {
                tracing::warn!(
                    did = %identity.keyid,
                    len = nonce.chars().count(),
                    "rejected a signature whose nonce is too short to be unique",
                );
                ledger_rejection(
                    StatusCode::BAD_REQUEST,
                    "signature_nonce_too_short",
                    &format!(
                        "the `nonce` parameter in Signature-Input must be at least \
                         {MIN_NONCE_CHARS} characters drawn from a CSPRNG — \
                         `gl` signs 32 hex characters",
                    ),
                )
            }
        };
    }

    let key = ledger_key(&identity);
    let now = chrono::Utc::now().timestamp();
    // Charge the cap against the RESOLVED key, never the wire DID: see
    // `SignatureIdentity::key_fingerprint`. This does not weaken single-use,
    // which never depended on the identity column — a replay has to reproduce
    // the signed bytes, and `keyid` sits inside `@signature-params`, so
    // re-spelling the DID changes the signing string and needs a fresh
    // signature. It fixes the per-identity cap only.
    match state
        .db
        .consume_signature(
            &key,
            &identity.key_fingerprint,
            now,
            now + SIGNATURE_LEDGER_TTL_SECS,
        )
        .await
    {
        Ok(crate::db::ConsumeSignature::Inserted) => next.run(request).await,
        Ok(crate::db::ConsumeSignature::Replayed) => {
            tracing::warn!(did = %identity.keyid, "rejected a replayed HTTP signature");
            ledger_rejection(
                StatusCode::CONFLICT,
                "signature_replayed",
                "this signature has already been used — sign a fresh request",
            )
        }
        Ok(crate::db::ConsumeSignature::IdentityLedgerFull) => {
            // A rate condition, not a permanent rejection: the caller's live
            // rows drain as they expire, so this is retryable.
            tracing::warn!(did = %identity.keyid, "signature ledger full for this identity");
            ledger_rejection(
                StatusCode::TOO_MANY_REQUESTS,
                "signature_ledger_full",
                "too many unexpired signatures for this identity — retry shortly",
            )
        }
        Err(e) => {
            // Fail closed (KTD5). An outage is exactly when a holder of a
            // captured signature would try, and the mutation handlers all need
            // the same database anyway.
            tracing::error!(did = %identity.keyid, err = %e, "signature ledger unavailable");
            ledger_rejection(
                StatusCode::SERVICE_UNAVAILABLE,
                "signature_ledger_unavailable",
                "the signature ledger is unavailable — retry shortly",
            )
        }
    }
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
            signed_write_rate_limiter: RateLimiter::new(600, Duration::from_secs(3600)),
            shutdown_tx: tokio::sync::watch::channel(false).0,
        }
    }

    /// The ledger TTL must keep a spent signature past the last instant any
    /// instance would still accept it, INCLUDING one whose clock disagrees.
    /// The sweep runs on whichever instance's timer fires, using its own clock,
    /// so a TTL flush against the acceptance window lets an instance running
    /// ahead delete a row that a lagging instance would still honour.
    #[test]
    fn ledger_ttl_keeps_a_margin_over_the_acceptance_window() {
        // For one fixed signature the arrival window is
        // `[created - MAX_FUTURE_SKEW_SECS, created + MAX_SIGNATURE_AGE_SECS]`.
        let arrival_window = MAX_SIGNATURE_AGE_SECS + MAX_FUTURE_SKEW_SECS;
        assert_eq!(arrival_window, 330, "the window this TTL is derived from");

        // The floor is written out rather than read from
        // `CROSS_INSTANCE_SKEW_MARGIN_SECS`, so zeroing that constant is caught
        // here instead of quietly satisfying the comparison against itself.
        let margin = SIGNATURE_LEDGER_TTL_SECS - arrival_window;
        assert!(
            margin >= 60,
            "TTL {SIGNATURE_LEDGER_TTL_SECS}s leaves {margin}s over a {arrival_window}s \
             arrival window, under the 60s skew budget: an instance running ahead \
             would sweep a row still accepted elsewhere"
        );
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
