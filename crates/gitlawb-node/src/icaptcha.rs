//! iCaptcha proof-of-intelligence gate.
//!
//! Spam-prone endpoints (repo creation, agent registration) can require the
//! caller to present an iCaptcha proof: a small Ed25519-signed token minted by
//! <https://icaptcha.gitlawb.com> after the caller solves an escalating
//! challenge. We verify the proof OFFLINE (no per-request call to iCaptcha)
//! using its published public key, and bind each proof to the authenticated
//! agent DID so a proof cannot be shared between identities.
//!
//! Behaviour is controlled by `ICAPTCHA_MODE`:
//!   * `off`     (default) — gate is inert, nothing is checked.
//!   * `shadow`  — verify and log would-be rejections, but always allow.
//!   * `enforce` — reject requests without a valid, sufficiently-strong proof.
//!
//! Config (env):
//!   ICAPTCHA_MODE            off | shadow | enforce         (default off)
//!   ICAPTCHA_URL             base URL                        (default https://icaptcha.gitlawb.com)
//!   ICAPTCHA_PUBKEY          base64url Ed25519 public key    (optional; else fetched from /v1/pubkey)
//!   ICAPTCHA_REQUIRED_LEVEL  minimum proof level             (default 3)

use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::HeaderMap;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

use crate::error::AppError;

const PROOF_HEADER: &str = "x-icaptcha-proof";

/// How long a mirror-admission `jti` stays in the replay ledger. The direct
/// request path spends a proof against its own `exp` (it can't be presented once
/// expired). The propagation path deliberately accepts already-expired proofs,
/// so spending against `exp` would store an already-past expiry that the next
/// sweep deletes — letting the same token admit another mirror minutes later.
/// We instead retain the mirror replay record for a long, fixed window so the
/// per-node single-use property is durable.
const MIRROR_REPLAY_RETENTION_SECS: i64 = 365 * 24 * 60 * 60;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Off,
    Shadow,
    Enforce,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Shadow => "shadow",
            Mode::Enforce => "enforce",
        }
    }
}

/// Parse `ICAPTCHA_MODE`. Returns `None` for unrecognized values so the caller
/// can surface the typo instead of silently disabling the gate.
fn parse_mode(s: &str) -> Option<Mode> {
    match s.trim().to_ascii_lowercase().as_str() {
        "" | "off" => Some(Mode::Off),
        "shadow" => Some(Mode::Shadow),
        "enforce" => Some(Mode::Enforce),
        _ => None,
    }
}

/// Parse `ICAPTCHA_REQUIRED_LEVEL`. Defaults to 3; warns (rather than silently
/// lowering the threshold) when a non-empty value fails to parse.
fn parse_required_level() -> u32 {
    const DEFAULT: u32 = 3;
    match std::env::var("ICAPTCHA_REQUIRED_LEVEL") {
        Ok(v) if !v.trim().is_empty() => v.trim().parse().unwrap_or_else(|_| {
            tracing::warn!(
                value = %v,
                default = DEFAULT,
                "invalid ICAPTCHA_REQUIRED_LEVEL; using default"
            );
            DEFAULT
        }),
        _ => DEFAULT,
    }
}

struct Verifier {
    mode: Mode,
    url: String,
    required_level: u32,
    key: Option<VerifyingKey>,
}

static VERIFIER: OnceLock<Verifier> = OnceLock::new();

#[derive(Deserialize, Debug)]
struct ProofClaims {
    sub: String,
    level: u32,
    exp: i64,
    /// Unique proof id, consumed once so a proof cannot be replayed.
    jti: String,
}

#[derive(Deserialize)]
struct Jwk {
    x: String,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn decode_key(b64url: &str) -> Option<VerifyingKey> {
    let bytes = URL_SAFE_NO_PAD.decode(b64url.trim()).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

async fn fetch_key(url: &str) -> Option<VerifyingKey> {
    let endpoint = format!("{}/v1/pubkey", url.trim_end_matches('/'));
    // Bounded request: a hung /v1/pubkey must never block node startup. On
    // timeout/error we return None and the gate stays inert (fail safe).
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?;
    let jwks: Jwks = client.get(&endpoint).send().await.ok()?.json().await.ok()?;
    decode_key(&jwks.keys.first()?.x)
}

/// Initialize the gate from the environment. Call once at startup. Never panics;
/// if the gate is active but no key can be loaded, it stays inert and warns.
pub async fn init() {
    let raw_mode = std::env::var("ICAPTCHA_MODE").unwrap_or_default();
    let mode = parse_mode(&raw_mode).unwrap_or_else(|| {
        tracing::warn!(value = %raw_mode, "invalid ICAPTCHA_MODE; disabling iCaptcha gate");
        Mode::Off
    });
    let url = std::env::var("ICAPTCHA_URL")
        .unwrap_or_else(|_| "https://icaptcha.gitlawb.com".to_string());
    let required_level = parse_required_level();

    let key = if mode == Mode::Off {
        None
    } else {
        match std::env::var("ICAPTCHA_PUBKEY") {
            Ok(b64) if !b64.is_empty() => decode_key(&b64),
            _ => fetch_key(&url).await,
        }
    };

    if mode != Mode::Off {
        if key.is_some() {
            tracing::info!(mode = mode.as_str(), required_level, "iCaptcha gate active");
        } else {
            tracing::warn!(
                mode = mode.as_str(),
                "iCaptcha gate enabled but no public key could be loaded; staying inert"
            );
        }
    }

    let _ = VERIFIER.set(Verifier {
        mode,
        url,
        required_level,
        key,
    });
}

/// Outcome of the synchronous, IO-free decision step.
#[derive(Debug)]
enum Decision {
    /// Allow the request (off, shadow, inert/no-key, or verified non-enforcing).
    Allow,
    /// Enforce mode and verification failed; reject with this reason.
    Reject(String),
    /// Enforce mode and the proof verified; the caller must consume its `jti`
    /// (and reject replays) before allowing, then may persist it.
    Consume(VerifiedProof),
}

/// A verified proof: the raw token plus the claims we act on. Carried by a
/// [`ProofGuard`] so that, once consumed, the gated handler can persist it with
/// the created repo — letting the proof travel with the repo when it propagates
/// to peers (see [`admit_mirror`]).
#[derive(Debug)]
pub struct VerifiedProof {
    token: String,
    sub: String,
    level: u32,
    jti: String,
    exp: i64,
}

impl VerifiedProof {
    /// Persist this proof against a freshly-created repo so a mirroring peer can
    /// re-verify it. Best-effort callers may ignore failures; the gate's
    /// security does not depend on it (propagation just falls back to quarantine).
    pub async fn record_for_repo(&self, db: &crate::db::Db, repo_id: &str) -> Result<(), AppError> {
        db.record_repo_proof(
            repo_id,
            &self.token,
            &self.sub,
            self.level as i32,
            &self.jti,
            self.exp,
        )
        .await?;
        Ok(())
    }
}

/// A verified proof awaiting consumption. Verification (which rejects invalid or
/// missing proofs) is separated from consumption (which spends the single-use
/// `jti`) so a request rejected by later validation never burns a valid proof.
/// The caller must `consume()` this guard immediately before the gated write.
/// For off/shadow/inert there is nothing to consume.
#[must_use = "a verified iCaptcha proof must be consumed before the gated action"]
pub struct ProofGuard(Option<VerifiedProof>);

impl ProofGuard {
    /// Spend the proof's `jti` (single-use) and return the verified proof so the
    /// caller can persist it. A replay is rejected. Returns `None` when there is
    /// nothing to consume (off/shadow/inert).
    pub async fn consume(self, db: &crate::db::Db) -> Result<Option<VerifiedProof>, AppError> {
        match self.0 {
            Some(p) => {
                if !db.consume_proof_jti(&p.jti, p.exp).await? {
                    return Err(AppError::IcaptchaProofRequired(
                        "iCaptcha proof already used (replay); solve a fresh challenge".to_string(),
                    ));
                }
                Ok(Some(p))
            }
            None => Ok(None),
        }
    }
}

/// Verify the proof in `headers` belongs to `did`. Rejects missing/invalid
/// proofs early (enforce mode); off/shadow never reject. Returns a [`ProofGuard`]
/// the caller must `consume()` right before the gated write. Off/shadow/inert
/// yield a no-op guard that consumes nothing.
pub fn verify_request(headers: &HeaderMap, did: &str) -> Result<ProofGuard, AppError> {
    let v = match VERIFIER.get() {
        Some(v) => v,
        None => return Ok(ProofGuard(None)), // not initialized -> inert
    };
    match decide(v, headers, did, now_secs()) {
        Decision::Allow => Ok(ProofGuard(None)),
        Decision::Reject(reason) => Err(reject_error(v, &reason)),
        Decision::Consume(proof) => Ok(ProofGuard(Some(proof))),
    }
}

fn reject_error(v: &Verifier, reason: &str) -> AppError {
    AppError::IcaptchaProofRequired(format!(
        "iCaptcha proof required ({reason}). Solve a challenge at {} for level >= {} and resend with the {} header.",
        v.url, v.required_level, PROOF_HEADER
    ))
}

/// Mode-aware decision. Pure and IO-free (no DB; clock injected via `now`) so it
/// is fully unit-testable. The caller performs jti consumption for `Consume`.
fn decide(v: &Verifier, headers: &HeaderMap, did: &str, now: i64) -> Decision {
    if v.mode == Mode::Off {
        return Decision::Allow;
    }

    // Fail safe: if no public key could be loaded (e.g. iCaptcha was unreachable
    // at startup), stay inert rather than rejecting every request. The operator
    // already saw a startup warning. An iCaptcha hiccup must never break repo
    // creation or registration.
    if v.key.is_none() {
        return Decision::Allow;
    }

    let token = headers.get(PROOF_HEADER).and_then(|h| h.to_str().ok());
    let result = match token {
        Some(t) => verify_token(v, t, did, now, true).map(|claims| (t, claims)),
        None => Err("missing proof header".to_string()),
    };

    match result {
        Ok((token, claims)) => match v.mode {
            Mode::Enforce => Decision::Consume(VerifiedProof {
                token: token.to_string(),
                sub: claims.sub,
                level: claims.level,
                jti: claims.jti,
                exp: claims.exp,
            }),
            // Shadow/Off: never reject, and do not consume (observational only).
            _ => Decision::Allow,
        },
        Err(reason) => match v.mode {
            Mode::Shadow => {
                tracing::warn!(did = %did, reason, "iCaptcha (shadow) would reject");
                Decision::Allow
            }
            Mode::Enforce => Decision::Reject(reason),
            Mode::Off => Decision::Allow,
        },
    }
}

/// Header-extracting wrapper over [`verify_token`] (enforces expiry). The
/// production path inlines this in [`decide`]; retained as the unit-test entry
/// point that also exercises header extraction.
#[cfg(test)]
fn verify(v: &Verifier, headers: &HeaderMap, did: &str, now: i64) -> Result<ProofClaims, String> {
    let proof = headers
        .get(PROOF_HEADER)
        .and_then(|h| h.to_str().ok())
        .ok_or("missing proof header")?;
    verify_token(v, proof, did, now, true)
}

/// Core verification of a raw proof token, separated for testability and reuse.
/// Checks the Ed25519 signature, the required level, and the DID binding. `exp`
/// is only enforced when `check_exp` is true: the direct request path enforces
/// freshness, but the propagation path ([`admit_mirror`]) does not — a proof has
/// usually expired by the time a repo mirrors, and the origin enforced freshness
/// at creation. `now` is unix seconds.
fn verify_token(
    v: &Verifier,
    token: &str,
    did: &str,
    now: i64,
    check_exp: bool,
) -> Result<ProofClaims, String> {
    let key = v.key.as_ref().ok_or("verifier has no public key")?;

    let (payload, sig_b64) = token.split_once('.').ok_or("malformed proof")?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| "bad signature encoding")?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| "bad signature length")?;
    key.verify_strict(payload.as_bytes(), &sig)
        .map_err(|_| "signature verification failed")?;

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| "bad payload encoding")?;
    let claims: ProofClaims = serde_json::from_slice(&claims_bytes).map_err(|_| "bad claims")?;

    if check_exp && claims.exp < now {
        return Err("proof expired".to_string());
    }
    if claims.level < v.required_level {
        return Err(format!(
            "level {} below required {}",
            claims.level, v.required_level
        ));
    }
    if !crate::api::did_matches(did, &claims.sub) {
        return Err("proof subject does not match authenticated DID".to_string());
    }
    Ok(claims)
}

/// Outcome of admitting a repo mirrored from a peer.
#[derive(Debug, PartialEq, Eq)]
pub enum MirrorAdmission {
    /// Admit the mirror normally (off/shadow/inert, or a valid proof in enforce).
    Admit,
    /// Enforce mode and the mirror's proof is missing/invalid/replayed — mirror
    /// it but quarantine until an operator releases it. Carries the reason.
    Quarantine(String),
}

/// Decide whether to admit a repo being mirrored from a peer, given the proof
/// token the origin served (`None` if it had none or the fetch failed) and the
/// mirrored repo's owner DID.
///
/// Off/shadow/inert always admit (shadow logs the would-be quarantine and writes
/// nothing). In enforce mode the proof is re-verified offline against the local
/// public key — signature, level, and owner-DID binding, but NOT expiry — and
/// its `jti` is consumed in the local ledger, so one solved challenge admits at
/// most one mirror per node (a malicious origin cannot reuse one proof to bless
/// many spam repos here).
///
/// LIMITATION (proof is not repo-bound): an iCaptcha proof commits only to the
/// solver's DID (`sub`), never to a repo — the proof is minted before the repo
/// exists. So the guarantee enforced here is "a level≥N challenge was solved by
/// this repo's owner DID", not "the owner intended THIS repo". A malicious origin
/// that harvests a victim's public proof (served by `get_icaptcha_proof`) can use
/// it to get ONE spam repo nominally owned by that victim admitted per node — the
/// per-node `jti` single-use caps the amplification at one repo per distinct
/// harvested proof, but does not eliminate it. Fully binding a proof to a repo
/// would require the iCaptcha service to embed a repo/target identifier in the
/// signed challenge (a protocol change, tracked as future work).
pub async fn admit_mirror(
    db: &crate::db::Db,
    token: Option<&str>,
    owner_did: &str,
) -> MirrorAdmission {
    let v = match VERIFIER.get() {
        Some(v) => v,
        None => return MirrorAdmission::Admit, // not initialized -> inert
    };
    // Off, or inert because no key could be loaded: admit unconditionally.
    if v.mode == Mode::Off || v.key.is_none() {
        return MirrorAdmission::Admit;
    }
    let shadow = v.mode == Mode::Shadow;

    // Quarantine in enforce; in shadow just log and admit (observational, no IO).
    let quarantine = |reason: String| -> MirrorAdmission {
        if shadow {
            tracing::warn!(owner = %owner_did, reason, "iCaptcha (shadow) would quarantine mirror");
            MirrorAdmission::Admit
        } else {
            MirrorAdmission::Quarantine(reason)
        }
    };

    let token = match token {
        Some(t) => t,
        None => return quarantine("origin served no iCaptcha proof".to_string()),
    };

    match verify_token(v, token, owner_did, now_secs(), false) {
        Ok(claims) => {
            if shadow {
                // Observational: a valid proof would admit. Do not consume, so a
                // later switch to enforce still sees the jti as fresh.
                return MirrorAdmission::Admit;
            }
            // Retain the replay record on a fixed forward window, NOT the proof's
            // own (already-past) exp — otherwise the next sweep frees the jti and
            // the same token could admit another mirror here.
            let retain_until = now_secs().saturating_add(MIRROR_REPLAY_RETENTION_SECS);
            match db.consume_proof_jti(&claims.jti, retain_until).await {
                Ok(true) => MirrorAdmission::Admit,
                Ok(false) => MirrorAdmission::Quarantine(
                    "iCaptcha proof already used to admit another mirror".to_string(),
                ),
                Err(e) => {
                    tracing::warn!(owner = %owner_did, err = %e, "iCaptcha mirror ledger error; quarantining");
                    MirrorAdmission::Quarantine("iCaptcha proof ledger unavailable".to_string())
                }
            }
        }
        Err(reason) => quarantine(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real values captured from https://icaptcha.gitlawb.com (a live proof).
    const PUBKEY_X: &str = "xjyPNqIbvc9U-kwXW6u9mDqRJ7E2UUMOaJdUWhpEXq8";
    const PROOF: &str = "eyJzdWIiOiJkaWQ6a2V5Onp0ZXN0IiwibGV2ZWwiOjMsImlzcyI6ImljYXB0Y2hhIiwiaWF0IjoxNzgyNTcyODUxLCJleHAiOjE3ODI1NzMxNTEsImp0aSI6IjRiNTIyOGE1YmVkNzEyMmRlZTlmNDdmZiJ9.5UXVPZ8Eo91VnlcvgDXtW-Fx7J2jr7h535SAstQEpigxBr7FF7V6R0XB4PBDgdoBPnhdH_kVEfRPfdHPSdB0CA";
    const SUB: &str = "did:key:ztest";
    const IAT: i64 = 1782572851; // within the proof's validity window

    fn verifier(level: u32) -> Verifier {
        Verifier {
            mode: Mode::Enforce,
            url: "https://icaptcha.gitlawb.com".to_string(),
            required_level: level,
            key: decode_key(PUBKEY_X),
        }
    }

    fn headers_with(proof: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(PROOF_HEADER, proof.parse().unwrap());
        h
    }

    #[test]
    fn accepts_a_real_proof() {
        let v = verifier(3);
        assert!(verify(&v, &headers_with(PROOF), SUB, IAT).is_ok());
    }

    #[test]
    fn rejects_expired_proof() {
        let v = verifier(3);
        let err = verify(&v, &headers_with(PROOF), SUB, 9_999_999_999).unwrap_err();
        assert!(err.contains("expired"), "{err}");
    }

    #[test]
    fn rejects_wrong_did() {
        let v = verifier(3);
        let err = verify(&v, &headers_with(PROOF), "did:key:zsomeoneelse", IAT).unwrap_err();
        assert!(err.contains("subject"), "{err}");
    }

    #[test]
    fn rejects_insufficient_level() {
        let v = verifier(5); // proof is level 3
        let err = verify(&v, &headers_with(PROOF), SUB, IAT).unwrap_err();
        assert!(err.contains("below required"), "{err}");
    }

    #[test]
    fn rejects_tampered_signature() {
        let v = verifier(3);
        // Flip one base64url char in the signature so it is guaranteed different.
        let (payload, sig) = PROOF.split_once('.').unwrap();
        let mut chars: Vec<char> = sig.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        let tampered = format!("{}.{}", payload, chars.into_iter().collect::<String>());
        assert!(verify(&v, &headers_with(&tampered), SUB, IAT).is_err());
    }

    #[test]
    fn rejects_missing_header() {
        let v = verifier(3);
        let err = verify(&v, &HeaderMap::new(), SUB, IAT).unwrap_err();
        assert!(err.contains("missing"), "{err}");
    }

    #[test]
    fn parse_mode_accepts_documented_values_and_rejects_junk() {
        assert_eq!(parse_mode(""), Some(Mode::Off));
        assert_eq!(parse_mode("off"), Some(Mode::Off));
        assert_eq!(parse_mode("  Shadow "), Some(Mode::Shadow));
        assert_eq!(parse_mode("ENFORCE"), Some(Mode::Enforce));
        // Typos must NOT silently disable the gate.
        assert_eq!(parse_mode("enforced"), None);
        assert_eq!(parse_mode("on"), None);
    }

    #[test]
    fn off_mode_allows_everything() {
        let mut v = verifier(3);
        v.mode = Mode::Off;
        assert!(matches!(
            decide(&v, &HeaderMap::new(), SUB, IAT),
            Decision::Allow
        ));
    }

    #[test]
    fn enforce_without_key_stays_inert() {
        // iCaptcha unreachable at startup -> no key -> must not reject.
        let v = Verifier {
            mode: Mode::Enforce,
            url: "https://icaptcha.gitlawb.com".to_string(),
            required_level: 3,
            key: None,
        };
        assert!(matches!(
            decide(&v, &HeaderMap::new(), SUB, IAT),
            Decision::Allow
        ));
    }

    #[test]
    fn enforce_with_key_rejects_missing_proof() {
        let v = verifier(3);
        assert!(matches!(
            decide(&v, &HeaderMap::new(), SUB, IAT),
            Decision::Reject(_)
        ));
    }

    #[test]
    fn shadow_allows_despite_bad_proof() {
        let mut v = verifier(3);
        v.mode = Mode::Shadow;
        assert!(matches!(
            decide(&v, &HeaderMap::new(), SUB, IAT),
            Decision::Allow
        ));
    }

    #[test]
    fn enforce_valid_proof_requires_consuming_its_jti() {
        // A verified proof under enforce must yield Consume carrying the jti, so
        // the caller can spend it once and reject replays.
        let v = verifier(3);
        match decide(&v, &headers_with(PROOF), SUB, IAT) {
            Decision::Consume(p) => {
                assert_eq!(p.jti, "4b5228a5bed7122dee9f47ff");
                assert_eq!(p.exp, 1782573151);
                assert_eq!(p.token, PROOF, "the raw token is retained for persistence");
                assert_eq!(p.sub, SUB);
            }
            other => panic!("expected Consume, got {other:?}"),
        }
    }

    #[test]
    fn propagation_accepts_an_expired_proof() {
        // The mirror-admission path verifies sig/level/DID but NOT expiry, since a
        // proof has usually expired by the time a repo propagates. The same proof
        // that the direct path rejects as expired must verify here.
        let v = verifier(3);
        let now = 9_999_999_999; // far past the proof's exp
        assert!(
            verify_token(&v, PROOF, SUB, now, true).is_err(),
            "direct path (check_exp=true) rejects the expired proof"
        );
        assert!(
            verify_token(&v, PROOF, SUB, now, false).is_ok(),
            "propagation path (check_exp=false) accepts it"
        );
    }

    #[test]
    fn propagation_still_enforces_signature_level_and_did() {
        let v = verifier(3);
        // wrong owner DID
        assert!(verify_token(&v, PROOF, "did:key:zother", IAT, false).is_err());
        // insufficient level
        let v5 = verifier(5);
        assert!(verify_token(&v5, PROOF, SUB, IAT, false).is_err());
        // tampered signature
        let (payload, sig) = PROOF.split_once('.').unwrap();
        let mut chars: Vec<char> = sig.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        let tampered = format!("{}.{}", payload, chars.into_iter().collect::<String>());
        assert!(verify_token(&v, &tampered, SUB, IAT, false).is_err());
    }
}
