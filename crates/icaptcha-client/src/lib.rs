//! Client for the iCaptcha proof-of-intelligence service.
//!
//! The node gates spam-prone writes (repo create / fork / register) behind an
//! iCaptcha proof. This crate implements the *sanctioned client flow*: on a
//! `403 icaptcha_proof_required`, request a challenge for the required level,
//! solve the deterministic computational types locally, obtain the signed
//! proof, and hand it back so the caller can retry the original signed request
//! with the `x-icaptcha-proof` header.
//!
//! `requesterId` is always the caller's DID, so the proof's `sub` claim matches
//! the authenticated signer (the node enforces `sub == authenticated DID`).
//!
//! Blocking HTTP (reqwest::blocking) so the git remote helper can use it
//! directly; `gl` (async) calls it via `tokio::task::spawn_blocking`.

use std::io::Read;

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use serde_json::json;

pub mod pow;
pub mod solvers;

/// Default iCaptcha service base URL (used when the node doesn't advertise one).
pub const DEFAULT_URL: &str = "https://icaptcha.gitlawb.com";
/// Default required level (the node's default floor).
pub const DEFAULT_LEVEL: u32 = 3;
/// Header the gated write must echo the proof back in.
pub const PROOF_HEADER: &str = "x-icaptcha-proof";

/// Cap on bytes read from an error response, and characters kept in the excerpt.
/// The iCaptcha origin is only as trusted as the node that advertised it (a MITM
/// on the default transport qualifies), so its error bodies are attacker-
/// influenceable bytes that reach the TTY — they must be bounded and stripped of
/// control characters before printing (CWE-150, same treatment as #137).
const MAX_ERR_BYTES: u64 = 4096;
const MAX_ERR_CHARS: usize = 500;

/// Read a bounded error body and return a control-char-stripped, length-capped
/// single-line excerpt safe to print to a terminal.
fn error_excerpt(resp: reqwest::blocking::Response) -> String {
    let mut buf = Vec::new();
    if resp.take(MAX_ERR_BYTES).read_to_end(&mut buf).is_err() {
        return String::new();
    }
    sanitize_excerpt(&String::from_utf8_lossy(&buf))
}

/// Strip C0/C1 control characters, collapse whitespace runs to single spaces,
/// and cap the length — so a hostile response body cannot inject terminal
/// escapes or flood the TTY.
fn sanitize_excerpt(s: &str) -> String {
    let mut out = String::new();
    let mut pending_space = false;
    let mut kept = 0;
    for ch in s.trim().chars() {
        if kept >= MAX_ERR_CHARS {
            break;
        }
        if ch.is_control() {
            if matches!(ch, '\n' | '\r' | '\t') {
                pending_space = true;
            }
            continue;
        }
        if ch.is_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space && !out.is_empty() {
            out.push(' ');
            kept += 1;
            if kept >= MAX_ERR_CHARS {
                break;
            }
        }
        out.push(ch);
        kept += 1;
        pending_space = false;
    }
    out
}

/// Whether `u` parses as an `https` URL.
fn is_https(u: &str) -> bool {
    reqwest::Url::parse(u)
        .map(|p| p.scheme() == "https")
        .unwrap_or(false)
}

/// Lowercased host of a URL, if it parses and has one.
fn host_of(u: &str) -> Option<String> {
    reqwest::Url::parse(u)
        .ok()
        .and_then(|p| p.host_str().map(|h| h.to_ascii_lowercase()))
}

/// Decide which iCaptcha origin to actually talk to, and whether it is trusted
/// enough to receive the operator's API key.
///
/// The node-advertised `x-icaptcha-url` is untrusted: a hostile node could point
/// it at an attacker origin (client-side SSRF) or capture a bearer token on the
/// first hop. So an advertised URL is honored only when it is `https` AND its
/// host is allowlisted — the public default host, or the operator's own
/// `GITLAWB_ICAPTCHA_URL`. Otherwise we fall back to the operator/default origin.
///
/// The API key is attached only when the resolved origin is the operator's
/// explicitly-configured host (never a node-discovered one), so a key is never
/// exfiltrated to an origin the operator did not choose.
fn resolve_solver_url(advertised: Option<&str>, operator: Option<&str>) -> (String, bool) {
    let operator = operator.filter(|u| is_https(u));
    let operator_host = operator.and_then(host_of);
    let default_host = host_of(DEFAULT_URL);

    let allowed = |host: &Option<String>| -> bool {
        host.as_ref()
            .map(|h| Some(h) == default_host.as_ref() || Some(h) == operator_host.as_ref())
            .unwrap_or(false)
    };

    let fallback = || {
        operator
            .map(String::from)
            .unwrap_or_else(|| DEFAULT_URL.to_string())
    };

    let chosen = match advertised {
        Some(a) if is_https(a) && allowed(&host_of(a)) => a.to_string(),
        Some(a) => {
            tracing::warn!(
                advertised = %a,
                "ignoring iCaptcha URL advertised by node (must be https with an allowlisted host); using trusted origin"
            );
            fallback()
        }
        None => fallback(),
    };

    // Key goes only to the operator's own configured origin.
    let key_trusted = operator_host.is_some() && host_of(&chosen) == operator_host;
    (chosen, key_trusted)
}

/// Computational challenge types this client solves locally. Restricting the
/// request to these avoids dictionary (anagram/logic) and LLM (wordproblem/
/// riddle) types, which can't be auto-solved.
const SOLVABLE_TYPES: [&str; 3] = ["arithmetic", "algebra", "sequence"];

/// Bound on challenge/answer rounds (the service escalates difficulty on a miss;
/// correct solvers shouldn't escalate, but cap it regardless).
const MAX_ROUNDS: usize = 8;

/// Where + at what level to solve. `did` becomes the proof's `sub`.
#[derive(Debug, Clone)]
pub struct IcaptchaCfg {
    pub url: String,
    pub did: String,
    pub level: u32,
    /// Optional bearer token for an API-key-protected iCaptcha deployment.
    pub api_key: Option<String>,
}

impl IcaptchaCfg {
    /// Build config from the caller DID plus an optionally node-advertised
    /// url/level (e.g. the `x-icaptcha-url` / `x-icaptcha-level` headers) and
    /// optional level.
    ///
    /// The advertised URL is validated and allowlisted (see [`resolve_solver_url`])
    /// so a hostile node cannot redirect the solve to an attacker origin. The
    /// `GITLAWB_ICAPTCHA_API_KEY` bearer token is attached only when the resolved
    /// origin is the operator's own `GITLAWB_ICAPTCHA_URL`, never a
    /// node-discovered one.
    pub fn new(did: impl Into<String>, url: Option<String>, level: Option<u32>) -> Self {
        let operator = std::env::var("GITLAWB_ICAPTCHA_URL")
            .ok()
            .filter(|s| !s.is_empty());
        let (resolved_url, key_trusted) = resolve_solver_url(url.as_deref(), operator.as_deref());
        let api_key = if key_trusted {
            std::env::var("GITLAWB_ICAPTCHA_API_KEY")
                .ok()
                .filter(|s| !s.is_empty())
        } else {
            None
        };
        Self {
            url: resolved_url,
            did: did.into(),
            level: level.unwrap_or(DEFAULT_LEVEL),
            api_key,
        }
    }
}

/// A challenge handed back by the service (mirrors `icaptcha` `Challenge`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
    pub challenge_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub difficulty: u32,
    pub prompt: String,
    pub token: String,
    /// Proof-of-work to solve and echo back as `powNonce` on the answer. Present
    /// only when the service has PoW enabled; absent/None means no PoW required.
    #[serde(default)]
    pub pow: Option<pow::PowChallenge>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
enum AnswerResult {
    Passed { proof: String },
    Continue { challenge: Challenge },
    Failed { reason: String },
}

/// Solver callback for types this crate can't solve deterministically.
pub type Solver<'a> = dyn Fn(&Challenge) -> Option<String> + 'a;

/// Run the full challenge → solve → answer loop and return a fresh proof token.
///
/// `solver` is consulted for challenge types the built-in solvers don't handle
/// (anagram/logic/LLM); pass `None` to fall back to an interactive stdin prompt.
pub fn obtain_proof(cfg: &IcaptchaCfg, solver: Option<&Solver>) -> Result<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("build iCaptcha http client")?;

    let mut challenge = request_challenge(&client, cfg)?;
    for _ in 0..MAX_ROUNDS {
        let answer = solvers::solve(&challenge.kind, &challenge.prompt)
            .or_else(|| solver.and_then(|s| s(&challenge)))
            .or_else(|| interactive_prompt(&challenge))
            .ok_or_else(|| {
                anyhow!(
                    "cannot solve iCaptcha challenge type '{}' automatically; \
                     set GITLAWB_ICAPTCHA_API_KEY/solver or solve interactively",
                    challenge.kind
                )
            })?;

        // Solve the proof-of-work bound to this challenge, if the service
        // requires one. A required-but-unsolvable PoW (unknown algorithm or a
        // difficulty above our cap) is a hard error — submitting without it
        // would just be rejected.
        let pow_nonce = match &challenge.pow {
            Some(p) => Some(pow::solve(p).ok_or_else(|| {
                anyhow!(
                    "cannot solve iCaptcha proof-of-work (algorithm '{}', difficulty {})",
                    p.algorithm,
                    p.difficulty
                )
            })?),
            None => None,
        };

        match submit_answer(
            &client,
            cfg,
            &challenge.token,
            &answer,
            pow_nonce.as_deref(),
        )? {
            AnswerResult::Passed { proof } => return Ok(proof),
            AnswerResult::Continue { challenge: next } => challenge = next,
            AnswerResult::Failed { reason } => {
                bail!("iCaptcha challenge failed: {}", sanitize_excerpt(&reason))
            }
        }
    }
    bail!("iCaptcha not solved within {MAX_ROUNDS} rounds")
}

fn request_challenge(client: &reqwest::blocking::Client, cfg: &IcaptchaCfg) -> Result<Challenge> {
    let url = format!("{}/v1/challenge", cfg.url.trim_end_matches('/'));
    let body = json!({
        "requesterId": cfg.did,
        "requiredLevel": cfg.level,
        "types": SOLVABLE_TYPES,
    });
    let mut req = client.post(&url).json(&body);
    if let Some(key) = &cfg.api_key {
        req = req.bearer_auth(key);
    }
    let resp = req.send().with_context(|| format!("POST {url}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = error_excerpt(resp);
        bail!("iCaptcha challenge request failed ({status}): {text}");
    }
    resp.json::<Challenge>().context("parse iCaptcha challenge")
}

fn submit_answer(
    client: &reqwest::blocking::Client,
    cfg: &IcaptchaCfg,
    token: &str,
    answer: &str,
    pow_nonce: Option<&str>,
) -> Result<AnswerResult> {
    let url = format!("{}/v1/answer", cfg.url.trim_end_matches('/'));
    let mut body = json!({ "token": token, "answer": answer });
    if let Some(nonce) = pow_nonce {
        body["powNonce"] = json!(nonce);
    }
    let mut req = client.post(&url).json(&body);
    if let Some(key) = &cfg.api_key {
        req = req.bearer_auth(key);
    }
    let resp = req.send().with_context(|| format!("POST {url}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = error_excerpt(resp);
        bail!("iCaptcha answer request failed ({status}): {text}");
    }
    resp.json::<AnswerResult>()
        .context("parse iCaptcha answer result")
}

/// Last-resort fallback: show the prompt and read an answer from the terminal.
/// Returns `None` when stdin isn't a usable interactive source (e.g. an agent),
/// so the caller surfaces a clear "couldn't auto-solve" error instead.
fn interactive_prompt(challenge: &Challenge) -> Option<String> {
    use std::io::{stderr, stdin, Write};
    let mut err = stderr();
    let _ = writeln!(
        err,
        "iCaptcha challenge ({}, level {}): {}\nAnswer: ",
        challenge.kind, challenge.difficulty, challenge.prompt
    );
    let _ = err.flush();
    let mut line = String::new();
    match stdin().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => {
            let a = line.trim().to_string();
            if a.is_empty() {
                None
            } else {
                Some(a)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── P1: hostile error bodies must not reach the terminal raw ──────────

    #[test]
    fn sanitize_strips_control_chars_and_escapes() {
        // ESC-based terminal escape + NUL + bell must all be removed.
        let hostile = "\x1b[2J\x1b[31mowned\x07\0 done";
        let clean = sanitize_excerpt(hostile);
        assert!(!clean.contains('\x1b'), "ESC survived: {clean:?}");
        assert!(
            !clean.chars().any(|c| c.is_control()),
            "control survived: {clean:?}"
        );
        assert!(clean.contains("owned") && clean.contains("done"));
    }

    #[test]
    fn sanitize_collapses_whitespace_and_caps_length() {
        let collapsed = sanitize_excerpt("a\n\n\t  b");
        assert_eq!(collapsed, "a b");
        let long = "x".repeat(MAX_ERR_CHARS + 500);
        assert_eq!(sanitize_excerpt(&long).chars().count(), MAX_ERR_CHARS);
    }

    // ── P2: never talk to (or hand a key to) an untrusted node-chosen URL ──

    #[test]
    fn rejects_non_https_advertised_url() {
        // A plaintext node-advertised URL is ignored; we fall back to default.
        let (url, key_trusted) = resolve_solver_url(Some("http://evil.example/x"), None);
        assert_eq!(url, DEFAULT_URL);
        assert!(!key_trusted);
    }

    #[test]
    fn rejects_https_url_with_non_allowlisted_host() {
        let (url, key_trusted) = resolve_solver_url(Some("https://evil.example"), None);
        assert_eq!(url, DEFAULT_URL, "attacker host must not be honored");
        assert!(!key_trusted);
    }

    #[test]
    fn honors_advertised_default_host_but_withholds_key_without_operator() {
        // Default public host is allowlisted for talking, but with no operator
        // origin configured the API key has no trusted destination.
        let (url, key_trusted) = resolve_solver_url(Some("https://icaptcha.gitlawb.com/v2"), None);
        assert_eq!(url, "https://icaptcha.gitlawb.com/v2");
        assert!(!key_trusted);
    }

    #[test]
    fn key_trusted_only_for_operator_configured_origin() {
        let op = "https://icap.mynode.example";
        // Node advertises the operator's own origin → talk there, key allowed.
        let (url, key_trusted) =
            resolve_solver_url(Some("https://icap.mynode.example/v1"), Some(op));
        assert_eq!(url, "https://icap.mynode.example/v1");
        assert!(key_trusted);

        // Node advertises an attacker origin while an operator is configured →
        // ignore the advert, fall back to the operator origin, key stays with it.
        let (url, key_trusted) = resolve_solver_url(Some("https://evil.example"), Some(op));
        assert_eq!(url, op);
        assert!(key_trusted);
    }

    #[test]
    fn no_advert_uses_operator_or_default() {
        let op = "https://icap.mynode.example";
        assert_eq!(resolve_solver_url(None, Some(op)), (op.to_string(), true));
        assert_eq!(
            resolve_solver_url(None, None),
            (DEFAULT_URL.to_string(), false)
        );
    }

    #[test]
    fn non_https_operator_is_not_trusted() {
        // A misconfigured plaintext operator URL is not a valid key destination.
        let (url, key_trusted) = resolve_solver_url(None, Some("http://icap.mynode.example"));
        assert_eq!(url, DEFAULT_URL);
        assert!(!key_trusted);
    }
}
