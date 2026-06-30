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

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use serde_json::json;

pub mod solvers;

/// Default iCaptcha service base URL (used when the node doesn't advertise one).
pub const DEFAULT_URL: &str = "https://icaptcha.gitlawb.com";
/// Default required level (the node's default floor).
pub const DEFAULT_LEVEL: u32 = 3;
/// Header the gated write must echo the proof back in.
pub const PROOF_HEADER: &str = "x-icaptcha-proof";

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
    /// Build config from the caller DID plus optionally-discovered url/level
    /// (e.g. the node's `x-icaptcha-url` / `x-icaptcha-level` headers), falling
    /// back to defaults. Reads `GITLAWB_ICAPTCHA_API_KEY` for the bearer token.
    pub fn new(did: impl Into<String>, url: Option<String>, level: Option<u32>) -> Self {
        Self {
            url: url.unwrap_or_else(|| DEFAULT_URL.to_string()),
            did: did.into(),
            level: level.unwrap_or(DEFAULT_LEVEL),
            api_key: std::env::var("GITLAWB_ICAPTCHA_API_KEY")
                .ok()
                .filter(|s| !s.is_empty()),
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

        match submit_answer(&client, cfg, &challenge.token, &answer)? {
            AnswerResult::Passed { proof } => return Ok(proof),
            AnswerResult::Continue { challenge: next } => challenge = next,
            AnswerResult::Failed { reason } => bail!("iCaptcha challenge failed: {reason}"),
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
        let text = resp.text().unwrap_or_default();
        bail!("iCaptcha challenge request failed ({status}): {text}");
    }
    resp.json::<Challenge>().context("parse iCaptcha challenge")
}

fn submit_answer(
    client: &reqwest::blocking::Client,
    cfg: &IcaptchaCfg,
    token: &str,
    answer: &str,
) -> Result<AnswerResult> {
    let url = format!("{}/v1/answer", cfg.url.trim_end_matches('/'));
    let mut req = client
        .post(&url)
        .json(&json!({ "token": token, "answer": answer }));
    if let Some(key) = &cfg.api_key {
        req = req.bearer_auth(key);
    }
    let resp = req.send().with_context(|| format!("POST {url}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
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
