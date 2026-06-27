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

#[derive(Deserialize)]
struct ProofClaims {
    sub: String,
    level: u32,
    exp: i64,
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

/// Gate an authenticated request. `did` is the authenticated agent DID the proof
/// must belong to. Returns `Ok(())` to allow, `Err(Unauthorized)` to reject.
/// Honors the configured mode (Off/Shadow never reject).
pub fn check(headers: &HeaderMap, did: &str) -> Result<(), AppError> {
    let v = match VERIFIER.get() {
        Some(v) => v,
        None => return Ok(()), // not initialized -> inert
    };
    decide(v, headers, did, now_secs())
}

/// Mode-aware decision, separated from the global state for testability.
fn decide(v: &Verifier, headers: &HeaderMap, did: &str, now: i64) -> Result<(), AppError> {
    if v.mode == Mode::Off {
        return Ok(());
    }

    // Fail safe: if no public key could be loaded (e.g. iCaptcha was unreachable
    // at startup), stay inert rather than rejecting every request. The operator
    // already saw a startup warning. An iCaptcha hiccup must never break repo
    // creation or registration.
    if v.key.is_none() {
        return Ok(());
    }

    match verify(v, headers, did, now) {
        Ok(()) => Ok(()),
        Err(reason) => match v.mode {
            Mode::Shadow => {
                tracing::warn!(did = %did, reason, "iCaptcha (shadow) would reject");
                Ok(())
            }
            Mode::Enforce => Err(AppError::Unauthorized(format!(
                "iCaptcha proof required ({reason}). Solve a challenge at {} for level >= {} and resend with the {} header.",
                v.url, v.required_level, PROOF_HEADER
            ))),
            Mode::Off => Ok(()),
        },
    }
}

/// Core verification, separated for testability. `now` is unix seconds.
fn verify(v: &Verifier, headers: &HeaderMap, did: &str, now: i64) -> Result<(), String> {
    let key = v.key.as_ref().ok_or("verifier has no public key")?;
    let proof = headers
        .get(PROOF_HEADER)
        .and_then(|h| h.to_str().ok())
        .ok_or("missing proof header")?;

    let (payload, sig_b64) = proof.split_once('.').ok_or("malformed proof")?;
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

    if claims.exp < now {
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
    Ok(())
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
        assert!(decide(&v, &HeaderMap::new(), SUB, IAT).is_ok());
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
        assert!(decide(&v, &HeaderMap::new(), SUB, IAT).is_ok());
    }

    #[test]
    fn enforce_with_key_rejects_missing_proof() {
        let v = verifier(3);
        assert!(decide(&v, &HeaderMap::new(), SUB, IAT).is_err());
    }

    #[test]
    fn shadow_allows_despite_bad_proof() {
        let mut v = verifier(3);
        v.mode = Mode::Shadow;
        assert!(decide(&v, &HeaderMap::new(), SUB, IAT).is_ok());
    }

    #[test]
    fn enforce_accepts_valid_proof_via_decide() {
        let v = verifier(3);
        assert!(decide(&v, &headers_with(PROOF), SUB, IAT).is_ok());
    }
}
