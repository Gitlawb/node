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
use gitlawb_core::node_denial::NodeDenial;
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
    MAX_FUTURE_SKEW_SECS, MAX_SIGNATURE_AGE_SECS,
};
use gitlawb_core::identity::verify;

/// Per-route-group ceiling on how much request body [`require_signature`] will
/// buffer BEFORE it has authenticated anything.
///
/// This is middleware state rather than a constant because a single number cannot
/// serve both a 2 GB git push and a 2 MB profile update: the git write group
/// passes `GITLAWB_MAX_PACK_BYTES`, every other signed group passes
/// [`crate::server::SIGNED_BODY_LIMIT`]. Making it a required piece of state means
/// a new signed route group cannot be wired up without choosing a limit.
#[derive(Clone, Copy, Debug)]
pub struct SignatureBodyLimit(pub usize);

/// The hint for an unresolvable DID, chosen by method. The hint is only true
/// for a method we have no resolver for: a did:key that parsed and then failed
/// on its key material (a small-order key, wrong multicodec, wrong length)
/// would be sent looking for the wrong problem by the alpha-support wording.
fn unresolvable_did_hint(key_id: &Did) -> &'static str {
    if key_id.is_did_key() {
        "the DID is a did:key whose key material did not resolve"
    } else {
        "only did:key is supported in alpha"
    }
}

/// Bound the echoed keyid in the unresolvable-DID message. `key_id` is
/// unauthenticated request input, so reflecting it back at whatever length the
/// caller chose would amplify attacker input into the response body. The bound
/// is slack (a did:key method-id is a fixed 48 characters) and only defends
/// the echo, not the resolution.
fn bounded_did_echo(key_id: &str) -> String {
    key_id.chars().take(96).collect()
}

/// Axum middleware that enforces HTTP Signature authentication (RFC 9421).
///
/// Every write request must carry:
///   Content-Digest:   sha-256=:base64hash:
///   Signature-Input:  sig1=("@method" "@path" "content-digest");keyid="did:key:...";alg="ed25519";created=<unix>;nonce="..."
///   Signature:        sig1=:base64signature:
///
/// The middleware:
///   1. Buffers the request body (needed for content-digest verification)
///   2. Parses Signature-Input + Signature headers (RFC 9421)
///   3. Checks clock skew on `created` parameter
///   4. Resolves the did:key to an Ed25519 VerifyingKey
///   5. Rebuilds the signing string and verifies the Ed25519 signature
///   6. Verifies Content-Digest matches the request body
pub async fn require_signature(
    State(SignatureBodyLimit(limit)): State<SignatureBodyLimit>,
    request: Request,
    next: Next,
) -> Response {
    verify_signature(limit, request, next).await
}

/// The signature check itself, shared by [`require_signature`] and the optional
/// variant. `limit` bounds the pre-auth buffer; see [`SignatureBodyLimit`].
async fn verify_signature(limit: usize, request: Request, next: Next) -> Response {
    // Buffer the body so we can verify content-digest and pass it downstream.
    //
    // The buffer is bounded, because this runs BEFORE any identity check: an
    // unauthenticated caller with no DID, no signature and no repo reaches this
    // line. Nothing upstream supplies the bound. On the git write routes
    // `RequestBodyLimitLayer` sits on the inner router, and a later `.layer()` is
    // the OUTER service, so this middleware runs first and sees the raw body. On
    // every other signed group axum's 2 MB `DefaultBodyLimit` is enforced by the
    // `Bytes`/`Json` extractors through a request extension, which collecting the
    // body here bypasses. `Limited` stops reading at the limit rather than reading
    // everything and then measuring it, which is the property that matters.
    let (parts, body) = request.into_parts();
    let body_bytes = match http_body_util::Limited::new(body, limit).collect().await {
        Ok(collected) => collected.to_bytes(),
        // Over the limit: a distinct status from the 401 an unsigned request gets
        // and the 400 below, so a client can tell "too big" from "not authenticated"
        // and from "your body did not arrive".
        Err(e) if e.is::<http_body_util::LengthLimitError>() => return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({
                "error": "body_too_large",
                "message": format!("request body exceeds the {limit}-byte limit for this route"),
            })),
        )
            .into_response(),
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({ "error": "unreadable_body", "message": "could not read request body" }),
                ),
            )
                .into_response()
        }
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
                "hint": "See https://twigpine.com/agents#authentication",
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
                    "message": format!(
                        "cannot resolve DID '{}': {e}",
                        bounded_did_echo(&sig.key_id.to_string())
                    ),
                    "hint": unresolvable_did_hint(&sig.key_id),
                })),
            )
                .into_response();
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

    // Required, never defaulted. The signing string is rebuilt from the request,
    // so an absent header would make the covered `content-digest` empty on both
    // sides: verification would pass and the digest-versus-body comparison below
    // would have nothing to compare, leaving a signed request free to carry a
    // body its signature never covered. `sign_request` always emits the header,
    // so refusing here costs no conforming client anything.
    let content_digest = match parts
        .headers
        .get("content-digest")
        .and_then(|v| v.to_str().ok())
    {
        Some(v) => v.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "missing_content_digest",
                    "message": "Content-Digest header is required on a signed request",
                })),
            )
                .into_response()
        }
    };

    let mut request_values: HashMap<String, String> = HashMap::new();
    request_values.insert("@method".to_string(), method);
    request_values.insert("@path".to_string(), path_and_query);
    request_values.insert("content-digest".to_string(), content_digest.clone());

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

    // Verify Content-Digest matches the actual request body. Unconditional: the
    // header's presence was established above, so there is no branch here that
    // skips the comparison.
    if content_digest != compute_content_digest(&body_bytes) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "content_digest_mismatch",
                "message": "Content-Digest does not match request body",
            })),
        )
            .into_response();
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
pub async fn optional_signature(
    State(SignatureBodyLimit(limit)): State<SignatureBodyLimit>,
    request: Request,
    next: Next,
) -> Response {
    let has_signature_headers = request.headers().contains_key("signature-input")
        || request.headers().contains_key("signature");
    if has_signature_headers {
        // Same pre-auth buffer, same bound: presenting signature headers is not
        // authentication, so this path is as reachable as the required one.
        return verify_signature(limit, request, next).await;
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

/// Refuse a signed write with one of the shared ledger denial codes.
///
/// The code and status both come from [`NodeDenial`], which `gl` matches
/// exhaustively, so the two halves cannot drift: adding a variant there is a
/// compile error in the client until it handles it.
fn ledger_rejection(denial: NodeDenial, message: &str) -> Response {
    let code = denial.as_str();
    (
        // Infallible: every `NodeDenial::status` is a real HTTP status,
        // which `denial_statuses_are_valid_http_codes` proves over every
        // variant.
        StatusCode::from_u16(denial.status()).expect("NodeDenial status is a valid HTTP code"),
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
        crate::metrics::record_signature_ledger("skipped_read");
        return next.run(request).await;
    }

    let identity = match request.extensions().get::<SignatureIdentity>() {
        Some(identity) => identity.clone(),
        None => {
            crate::metrics::record_signature_ledger("identity_missing");
            // Fail closed. If this passed the request through, a wrong layer
            // order would silently delete the replay defense while every test
            // that exercises the correct stack kept passing.
            tracing::error!(
                path = %request.uri().path(),
                "signature ledger reached without a verified SignatureIdentity — check the layer order",
            );
            return ledger_rejection(
                NodeDenial::IdentityMissing,
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
                crate::metrics::record_signature_ledger("nonce_required");
                tracing::warn!(did = %identity.keyid, "rejected a nonce-less signature: a nonce is required");
                ledger_rejection(
                    NodeDenial::NonceRequired,
                    "this node requires a `nonce` parameter in Signature-Input — upgrade your client",
                )
            }
            Some(nonce) => {
                crate::metrics::record_signature_ledger("nonce_too_short");
                tracing::warn!(
                    did = %identity.keyid,
                    len = nonce.chars().count(),
                    "rejected a signature whose nonce is too short to be unique",
                );
                ledger_rejection(
                    NodeDenial::NonceTooShort,
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
        Ok(crate::db::ConsumeSignature::Inserted) => {
            crate::metrics::record_signature_ledger("admitted");
            next.run(request).await
        }
        Ok(crate::db::ConsumeSignature::Replayed) => {
            crate::metrics::record_signature_ledger("replayed");
            tracing::warn!(did = %identity.keyid, "rejected a replayed HTTP signature");
            ledger_rejection(
                NodeDenial::Replayed,
                "this signature has already been used — sign a fresh request",
            )
        }
        Ok(crate::db::ConsumeSignature::IdentityLedgerFull) => {
            // A rate condition, not a permanent rejection: the caller's live
            // rows drain as they expire, so this is retryable.
            crate::metrics::record_signature_ledger("identity_ledger_full");
            tracing::warn!(did = %identity.keyid, "signature ledger full for this identity");
            ledger_rejection(
                NodeDenial::LedgerFull,
                "too many unexpired signatures for this identity — retry shortly",
            )
        }
        Err(e) => {
            // Fail closed (KTD5). An outage is exactly when a holder of a
            // captured signature would try, and the mutation handlers all need
            // the same database anyway.
            crate::metrics::record_signature_ledger("unavailable");
            tracing::error!(did = %identity.keyid, err = %e, "signature ledger unavailable");
            ledger_rejection(
                NodeDenial::LedgerUnavailable,
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
            "docs": "https://twigpine.com/agents",
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

    /// `ledger_rejection` converts `NodeDenial::status` with an `expect`.
    /// This is what makes that infallible: every variant is a real HTTP status,
    /// and it is the status the node has always paired with that code.
    #[test]
    fn denial_statuses_are_valid_http_codes() {
        for denial in NodeDenial::ALL {
            let status = StatusCode::from_u16(denial.status())
                .unwrap_or_else(|e| panic!("{denial} has an invalid status: {e}"));
            assert_eq!(status.as_u16(), denial.status());
        }
    }

    /// The exact bytes `consume_signature` puts on the wire for each denial:
    /// the `X-Gitlawb-Error` header, the body's `error` field, and the status
    /// must all agree, because `gl` keys on the header and `gl init` keys on the
    /// body field.
    #[tokio::test]
    async fn ledger_rejection_emits_the_code_in_both_the_header_and_the_body() {
        for denial in NodeDenial::ALL {
            let resp = ledger_rejection(denial, "why it was refused");
            assert_eq!(resp.status().as_u16(), denial.status(), "{denial}");
            assert_eq!(
                resp.headers().get("X-Gitlawb-Error").unwrap(),
                denial.as_str(),
                "{denial}",
            );
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["error"], denial.as_str(), "{denial}");
            assert_eq!(json["message"], "why it was refused", "{denial}");
        }
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

    /// The two-branch hint selection is the point of the unresolvable-DID
    /// change: a did:key that failed on its key material must be told the key
    /// material did not resolve, and any other method must be told only did:key
    /// is supported. A regression that drops the is_did_key() check would send
    /// a did:key caller after the wrong problem, so both branches are pinned.
    #[test]
    fn unresolvable_did_hint_distinguishes_key_material_from_method() {
        // A real did:key whose key material fails to resolve (small-order):
        // key-material hint.
        let mut weak = [0u8; 32];
        weak[0] = 1; // compressed identity point
        let weak_vk = ed25519_dalek::VerifyingKey::from_bytes(&weak).unwrap();
        let weak_did = Did::from_verifying_key(&weak_vk);
        assert!(
            weak_did.to_verifying_key().is_err(),
            "fixture precondition: small-order did:key must not resolve"
        );
        assert_eq!(
            unresolvable_did_hint(&weak_did),
            "the DID is a did:key whose key material did not resolve"
        );

        // A method with no resolver: alpha-support hint.
        let web = Did::web("example.com");
        assert!(
            web.to_verifying_key().is_err(),
            "fixture precondition: did:web must not resolve locally"
        );
        assert_eq!(
            unresolvable_did_hint(&web),
            "only did:key is supported in alpha"
        );
    }

    /// The unresolvable-DID message echoes the keyid, which is unauthenticated
    /// request input. The echoed value must be bounded so a hostile caller
    /// cannot amplify arbitrary-length input into the response body.
    #[test]
    fn unresolvable_did_message_bounds_the_echoed_keyid() {
        let long_keyid = format!("did:key:z{}", "A".repeat(2000));
        let shown = bounded_did_echo(&long_keyid);
        assert!(
            shown.len() <= 96,
            "echoed keyid must be bounded, got {} chars",
            shown.len()
        );
        assert!(
            !shown.contains(&"A".repeat(1000)),
            "the full keyid must not survive into the message"
        );
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
        let webhook_secret_key = crate::state::AppState::derive_webhook_secret_key(&keypair);
        let (ref_tx, _) = tokio::sync::broadcast::channel(1);
        let (task_tx, _) = tokio::sync::broadcast::channel(1);
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/gitlawb_test_placeholder")
            .expect("lazy pool creation should not fail");
        let db = Arc::new(crate::db::Db::for_testing(pool.clone()));
        let task_cursor_key = crate::api::task_cursor::TaskCursorKey::derive(&keypair.to_seed());
        let schema = Arc::new(graphql::build_schema(
            db.clone(),
            ref_tx.clone(),
            task_tx.clone(),
            task_cursor_key.clone(),
        ));
        let ws_schema = Arc::new(graphql::build_ws_schema(
            db.clone(),
            ref_tx.clone(),
            task_tx.clone(),
            task_cursor_key.clone(),
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
            graphql_ws_schema: ws_schema,
            task_cursor_key,
            machine_id: None,
            repo_store: crate::git::repo_store::RepoStore::for_testing(PathBuf::from("/tmp"), pool),
            rate_limiter: RateLimiter::new(100, Duration::from_secs(60)),
            create_ip_rate_limiter: RateLimiter::new(1000, Duration::from_secs(3600)),
            write_rate_limiter: RateLimiter::new(1000, Duration::from_secs(3600)),
            push_rate_limiter: RateLimiter::new(600, Duration::from_secs(3600)),
            close_issue_rate_limiter: RateLimiter::new(120, Duration::from_secs(3600)),
            ipfs_rate_limiter: RateLimiter::new(600, Duration::from_secs(3600)),
            ipfs_work_rate_limiter: RateLimiter::new(600, Duration::from_secs(3600)),
            ipfs_max_history_walks: crate::api::ipfs::MAX_HISTORY_WALKS_PER_REQUEST,
            ipfs_max_legacy_probes: crate::api::ipfs::MAX_LEGACY_PROBES_PER_REQUEST,
            ipfs_legacy_scan_page_rows: crate::api::ipfs::LEGACY_SCAN_PAGE_ROWS,
            ipfs_max_legacy_scan_rows: crate::api::ipfs::MAX_LEGACY_SCAN_ROWS_PER_REQUEST,
            ipfs_max_legacy_scan_rule_bytes:
                crate::api::ipfs::MAX_LEGACY_SCAN_RULE_BYTES_PER_REQUEST,
            ipfs_scan_token_key: Arc::new(scan_token_key),
            webhook_secret_key: Arc::new(webhook_secret_key),
            ipfs_max_served_object_bytes: crate::api::ipfs::MAX_SERVED_OBJECT_BYTES,
            push_limiter_trust: crate::rate_limit::TrustedProxy::None,
            sync_trigger_rate_limiter: RateLimiter::new(60, Duration::from_secs(3600)),
            peer_write_rate_limiter: RateLimiter::new(600, Duration::from_secs(3600)),
            federated_rate_limiter: RateLimiter::new_bounded(12, Duration::from_secs(60), 10_000),
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
            task_read_rate_limiter: RateLimiter::new(1200, Duration::from_secs(3600)),
            git_bin: "git".to_string(),
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

    // ── `gitlawb_signature_ledger_total{outcome}` ────────────────────────────
    //
    // The ledger fails CLOSED, so a fault local to it (statement timeout, lock
    // contention) turns every REST mutation into a 503 while the handlers' own
    // queries stay healthy. These assert the counter is really charged on each
    // terminal outcome, driven through the layer and read back through the same
    // gather/encode path `/metrics` serves.
    //
    // Each assertion is a strict increase rather than an exact delta: the
    // counter is process-wide, `metrics::init` is a `OnceLock`, and the ledger
    // tests in `test_support` run in the same binary, so a concurrent test can
    // add to any outcome. Pollution can only ever add, never subtract, so a
    // strict increase never flakes; to attribute a delta exactly (e.g. when
    // mutating out a `record_*` call to confirm RED), run these serially:
    // `cargo test --bin gitlawb-node ledger_metrics -- --test-threads=1`.

    fn ledger_metric(outcome: &str) -> u64 {
        let needle = format!("gitlawb_signature_ledger_total{{outcome=\"{outcome}\"}} ");
        crate::metrics::encode()
            .expect("encode should succeed after init")
            .lines()
            .find_map(|line| line.strip_prefix(needle.as_str()))
            .map(|value| value.trim().parse().expect("counter value is an integer"))
            .unwrap_or(0)
    }

    /// One route, mounted behind `consume_signature` alone. The layer reads the
    /// `SignatureIdentity` extension, so tests inject it directly rather than
    /// producing real RFC-9421 signatures.
    fn ledger_app(state: crate::state::AppState) -> Router {
        Router::new()
            .route(
                "/probe",
                axum::routing::post(|| async { StatusCode::OK }).get(|| async { StatusCode::OK }),
            )
            .layer(middleware::from_fn_with_state(state, consume_signature))
    }

    fn ledger_identity(seed: &str, nonce: Option<&str>) -> SignatureIdentity {
        SignatureIdentity {
            keyid: format!("did:key:zLedgerMetrics{seed}"),
            key_fingerprint: hex::encode(Sha256::digest(format!("key/{seed}").as_bytes())),
            nonce: nonce.map(str::to_owned),
            signing_string_hash: hex::encode(Sha256::digest(format!("sig/{seed}").as_bytes())),
        }
    }

    fn ledger_request(identity: Option<SignatureIdentity>) -> Request {
        let builder = Request::builder().method(Method::POST).uri("/probe");
        let builder = match identity {
            Some(identity) => builder.extension(identity),
            None => builder,
        };
        builder.body(Body::empty()).expect("request builder")
    }

    async fn ledger_status(state: crate::state::AppState, request: Request) -> StatusCode {
        ledger_app(state)
            .oneshot(request)
            .await
            .expect("router response")
            .status()
    }

    #[tokio::test]
    async fn ledger_metrics_count_a_skipped_read() {
        crate::metrics::init("0.0.0-test", "did:key:test");
        let before = ledger_metric("skipped_read");

        let request = Request::builder()
            .method(Method::GET)
            .uri("/probe")
            .body(Body::empty())
            .expect("request builder");
        let status = ledger_status(make_test_state(Keypair::generate().did()), request).await;

        assert_eq!(status, StatusCode::OK, "a read must still pass through");
        assert!(
            ledger_metric("skipped_read") > before,
            "the read skip must be counted, or the outcomes do not sum to the layer's traffic"
        );
    }

    #[tokio::test]
    async fn ledger_metrics_count_a_missing_identity() {
        crate::metrics::init("0.0.0-test", "did:key:test");
        let before = ledger_metric("identity_missing");

        let status = ledger_status(
            make_test_state(Keypair::generate().did()),
            ledger_request(None),
        )
        .await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(ledger_metric("identity_missing") > before);
    }

    #[tokio::test]
    async fn ledger_metrics_count_the_nonce_rejections() {
        use clap::Parser;

        crate::metrics::init("0.0.0-test", "did:key:test");
        let mut state = make_test_state(Keypair::generate().did());
        state.config = Arc::new(crate::config::Config::parse_from([
            "gitlawb-node",
            "--require-signature-nonce",
        ]));

        let before_required = ledger_metric("nonce_required");
        let status = ledger_status(
            state.clone(),
            ledger_request(Some(ledger_identity("no-nonce", None))),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(ledger_metric("nonce_required") > before_required);

        let before_short = ledger_metric("nonce_too_short");
        let status = ledger_status(
            state,
            ledger_request(Some(ledger_identity("short-nonce", Some("abc")))),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(ledger_metric("nonce_too_short") > before_short);
    }

    /// The fail-closed 503 is the outcome an operator most needs a numerator
    /// for: it is returned by the ledger while the handlers are healthy. The
    /// state here carries a lazy pool pointed at a database that does not
    /// exist, so `consume_signature` returns `Err`.
    #[tokio::test]
    async fn ledger_metrics_count_a_ledger_error() {
        crate::metrics::init("0.0.0-test", "did:key:test");
        let before = ledger_metric("unavailable");

        let status = ledger_status(
            make_test_state(Keypair::generate().did()),
            ledger_request(Some(ledger_identity("db-down", None))),
        )
        .await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(ledger_metric("unavailable") > before);
    }

    #[sqlx::test]
    async fn ledger_metrics_count_admitted_and_replayed(pool: sqlx::PgPool) {
        crate::metrics::init("0.0.0-test", "did:key:test");
        let state = crate::test_support::test_state(pool).await;
        let identity = ledger_identity("spend-once", None);

        let before_admitted = ledger_metric("admitted");
        let status = ledger_status(state.clone(), ledger_request(Some(identity.clone()))).await;
        assert_eq!(status, StatusCode::OK, "a fresh signature is admitted");
        assert!(ledger_metric("admitted") > before_admitted);

        let before_replayed = ledger_metric("replayed");
        let status = ledger_status(state, ledger_request(Some(identity))).await;
        assert_eq!(status, StatusCode::CONFLICT, "the same signature replays");
        assert!(ledger_metric("replayed") > before_replayed);
    }

    #[sqlx::test]
    async fn ledger_metrics_count_a_full_identity_ledger(pool: sqlx::PgPool) {
        crate::metrics::init("0.0.0-test", "did:key:test");
        let state = crate::test_support::test_state(pool.clone()).await;
        let identity = ledger_identity("capped", None);

        // Seeded through SQL rather than 512 requests. The cap is charged
        // against the resolved key, which is the `keyid` column's value.
        sqlx::query(
            "INSERT INTO consumed_signatures (sig_hash, keyid, expires_at)
             SELECT md5(i::text) || md5((i + 1)::text), $1, $2
             FROM generate_series(1, $3) AS i",
        )
        .bind(&identity.key_fingerprint)
        .bind(9_000_000_000i64)
        .bind(crate::db::MAX_LIVE_SIGNATURES_PER_KEYID)
        .execute(&pool)
        .await
        .expect("seed a full ledger for this identity");

        let before = ledger_metric("identity_ledger_full");
        let status = ledger_status(state, ledger_request(Some(identity))).await;

        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(ledger_metric("identity_ledger_full") > before);
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

    /// A request that signs `content-digest` as the EMPTY string and then sends
    /// no Content-Digest header at all must be refused before any handler runs.
    ///
    /// This is the whole point of requiring the header rather than defaulting it:
    /// the middleware rebuilds the signing string from the request, so an absent
    /// header makes the covered digest empty on both sides. The Ed25519 check
    /// passes, the body-versus-digest comparison is skipped for want of a header,
    /// and a signed request carries a body the signature never covered.
    #[tokio::test]
    async fn signed_request_without_content_digest_is_rejected() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use std::sync::atomic::{AtomicBool, Ordering};

        static REACHED: AtomicBool = AtomicBool::new(false);

        let kp = Keypair::generate();
        let did = kp.did();
        let created = chrono::Utc::now().timestamp();
        let signature_input = format!(
            r#"sig1=("@method" "@path" "content-digest");keyid="{did}";alg="ed25519";created={created}"#
        );
        let sig_params_value = &signature_input["sig1=".len()..];

        let mut values: HashMap<String, String> = HashMap::new();
        values.insert("@method".to_string(), "POST".to_string());
        values.insert("@path".to_string(), "/x".to_string());
        // Exactly what the middleware derives when the header is absent.
        values.insert("content-digest".to_string(), String::new());
        let signing_string =
            build_signing_string(COVERED_COMPONENTS, sig_params_value, &values).unwrap();
        let signature = format!(
            "sig1=:{}:",
            STANDARD.encode(kp.sign(signing_string.as_bytes()).to_bytes())
        );

        let app = Router::new()
            .route(
                "/x",
                axum::routing::post(|| async {
                    REACHED.store(true, Ordering::SeqCst);
                    StatusCode::OK
                }),
            )
            .layer(middleware::from_fn_with_state(
                SignatureBodyLimit(crate::server::SIGNED_BODY_LIMIT),
                require_signature,
            ));

        let req = Request::builder()
            .method("POST")
            .uri("/x")
            .header("signature-input", signature_input)
            .header("signature", signature)
            .body(Body::from("a body no signature covers"))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "a signed request with no Content-Digest header must be refused"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), 2048).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body["error"], "missing_content_digest",
            "the refusal must name the absent Content-Digest header"
        );
        assert!(
            !REACHED.load(Ordering::SeqCst),
            "the handler must never see a request whose body no signature covers"
        );
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

    /// A delegation can be issued against the remote's spelling (`myrepo.git`):
    /// the matcher strips the same single `.git` the smart-HTTP routes do, so
    /// the capability lands on the canonical record name.
    #[test]
    fn grants_push_when_the_capability_carries_the_git_suffix() {
        let rec = repo(&owner_full(), "myrepo");
        let v = verified(
            &owner_full(),
            vec![push_cap_for(&owner_full(), "myrepo.git")],
        );
        assert!(ucan_grants_push(&rec, &v));
    }

    /// Mirror-created rows can carry a literal `.git` name; reaching one takes
    /// `foo.git.git`, the same spelling the remote URL uses. A single `.git`
    /// capability resolves to `foo` and must not fall through to `foo.git`.
    #[test]
    fn a_repo_literally_named_dot_git_needs_the_doubled_suffix() {
        let rec = repo(&owner_full(), "foo.git");
        let single = verified(&owner_full(), vec![push_cap_for(&owner_full(), "foo.git")]);
        assert!(!ucan_grants_push(&rec, &single));
        let doubled = verified(
            &owner_full(),
            vec![push_cap_for(&owner_full(), "foo.git.git")],
        );
        assert!(ucan_grants_push(&rec, &doubled));
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
