//! GET /ipfs/{cid} — content-addressed retrieval of git objects by CIDv1.
//!
//! Every git object stored on this node is addressable by its IPFS CIDv1.
//! The CID is computed as:
//!
//!   CIDv1(codec=raw, multihash=sha2-256(content_bytes))
//!
//! where `content_bytes` is the raw object content as returned by
//! `git cat-file <type> <sha256>` (i.e. without the git framing header).
//! This is consistent with how `gitlawb_core::cid::Cid::from_git_object_bytes`
//! computes CIDs when objects are pushed.
//!
//! Serving is access-controlled: an object is returned only from a repo row the
//! requesting caller is permitted to read (per-caller path-scoped visibility,
//! see `get_by_cid`).

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use cid::CidGeneric;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::Deserialize;
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth::AuthenticatedDid;
use crate::error::{AppError, Result};
use crate::git::store;
use crate::git::visibility_pack::{allowed_blob_set_for_caller, has_path_scoped_rule};
use crate::state::AppState;
use crate::visibility::{visibility_check, Decision};

/// GET /ipfs/{cid}
///
/// Search all repos on the node for a git object whose SHA-256 hash matches
/// the given CIDv1, returning its raw content if the caller may read it.
///
/// Visibility (#110, #126): the object is served only from a repo row the
/// caller passes. For each iterated row we gate against that row's OWN rules
/// (`visibility_check` at `"/"`), never re-resolving via `authorize_repo_read`
/// — `get_repo`'s fuzzy match could otherwise authorize a different physical
/// row than the one read (KTD2a). We check object existence via
/// `store::object_type` *before* the expensive reachability walk so random-CID
/// spray cannot trigger full-history git walks on repos that don't carry the
/// object. When the row carries path-scoped rules (KTD4) the served object
/// must be either a non-blob (trees/commits are structural; KTD3) OR a blob
/// in the caller's *reachable* allowed-set (`allowed_blob_set_for_caller`).
/// The reachable allowed-set excludes dangling blobs — a blob written via
/// `git hash-object -w` and never committed has no path to gate, so it is
/// fail-closed 404'd under path-scoped rules (#126). Denial and genuine
/// not-found both fall through to an opaque 404.
///
/// Scope: this closes the direct unauthenticated scan, including the dangling
/// case. A stale-public mirror row still serves withheld content (tracked
/// separately, #124).
pub async fn get_by_cid(
    Path(cid_str): Path<String>,
    State(state): State<AppState>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Response> {
    // 1. Decode the CID and extract the SHA-256 digest
    let cid = CidGeneric::<64>::from_str(&cid_str)
        .map_err(|e| AppError::BadRequest(format!("invalid CID: {e}")))?;

    let mh = cid.hash();
    // multihash code 0x12 = sha2-256
    const SHA2_256_CODE: u64 = 0x12;
    if mh.code() != SHA2_256_CODE {
        return Err(AppError::BadRequest(
            "only sha2-256 CIDs are supported".to_string(),
        ));
    }

    let sha256_hex = hex::encode(mh.digest());
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let caller_owned = caller.map(|c| c.to_string());

    // 2. Search all repos for an object with this SHA-256
    let repos = state
        .db
        .list_all_repos()
        .await
        .map_err(AppError::Internal)?;

    // Fetch every repo's visibility rules in one query rather than one per row
    // (the gate runs each row against its OWN rules — KTD2a). A row absent from
    // the map has no rules.
    let repo_ids: Vec<String> = repos.iter().map(|r| r.id.clone()).collect();
    let rules_by_repo = state
        .db
        .list_visibility_rules_for_repos(&repo_ids)
        .await
        .map_err(AppError::Internal)?;

    // Request-scoped memo of the per-repo allowed-blob set (KTD1, #126). The
    // caller is constant for one request, so `repo.id` alone is a safe,
    // sufficient key — never a coarse caller "class", which
    // `visibility_check`'s exact full-DID reader match would make unsafe.
    //
    // We flipped from a deny-set (`withheld_blob_oids`) to an allowed-set
    // (`allowed_blob_set_for_caller`) so dangling blobs — never enumerated by
    // the reachable walk — fail closed instead of slipping through an empty
    // deny entry (#126).
    let mut allowed_memo: HashMap<String, HashSet<String>> = HashMap::new();

    for repo in &repos {
        // Repo-level read gate against THIS row's own rules (KTD2a).
        let rules: &[crate::db::VisibilityRule] = rules_by_repo
            .get(&repo.id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if visibility_check(rules, repo.is_public, &repo.owner_did, caller, "/") == Decision::Deny {
            continue;
        }

        let repo_path = match state.repo_store.acquire(&repo.owner_did, &repo.name).await {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Check whether the object exists in this repo before any expensive
        // reachability walk. This prevents random-CID spray from triggering
        // full-history git walks on repos that don't carry the object.
        let obj_type = match store::object_type(&repo_path, &sha256_hex) {
            Ok(Some(t)) => t,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(repo = %repo.name, err = %e, "error checking git object type");
                continue;
            }
        };

        // Per-blob gating only applies when a path-scoped rule exists (KTD4).
        // Without any path-scoped rule, the "/" gate above is the whole story.
        // Trees/commits are always served under path-scoped rules (KTD3).
        let path_scoped = has_path_scoped_rule(rules);
        if path_scoped && obj_type == "blob" {
            if !allowed_memo.contains_key(&repo.id) {
                let rp = repo_path.clone();
                let r = rules.to_vec();
                let is_public = repo.is_public;
                let owner = repo.owner_did.clone();
                let caller_for_walk = caller_owned.clone();
                // Full-history walk shells out to git — keep it off the async runtime.
                let walk = tokio::task::spawn_blocking(move || {
                    let uncancelled = AtomicBool::new(false);
                    allowed_blob_set_for_caller(
                        &rp,
                        &r,
                        is_public,
                        &owner,
                        caller_for_walk.as_deref(),
                        &uncancelled,
                    )
                })
                .await;
                // Fail closed on EITHER a task panic (JoinError) or a walk error:
                // we cannot prove the caller may read here, so skip this repo and
                // let a public copy (if any) serve. Never serve on an unproven gate.
                let set = match walk {
                    Ok(Ok(set)) => set,
                    Ok(Err(e)) => {
                        tracing::warn!(repo = %repo.name, err = %e, "allowed-blob walk failed; skipping repo");
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(repo = %repo.name, err = %e, "allowed-blob walk task panicked; skipping repo");
                        continue;
                    }
                };
                allowed_memo.insert(repo.id.clone(), set);
            }
            let in_allowed = allowed_memo
                .get(&repo.id)
                .is_some_and(|set| set.contains(&sha256_hex));
            if !in_allowed {
                continue;
            }
        }

        // Now that we've passed the gate, read the content.
        let content = match store::read_object_content(&repo_path, &sha256_hex, &obj_type) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(repo = %repo.name, err = %e, "error reading git object content");
                continue;
            }
        };

        // 3. Return the content with IPFS-style headers
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/octet-stream"),
        );
        headers.insert(
            HeaderName::from_static("x-content-cid"),
            HeaderValue::from_str(&cid_str).unwrap_or_else(|_| HeaderValue::from_static("invalid")),
        );
        headers.insert(
            HeaderName::from_static("x-git-hash"),
            HeaderValue::from_str(&sha256_hex)
                .unwrap_or_else(|_| HeaderValue::from_static("invalid")),
        );

        return Ok((StatusCode::OK, headers, content).into_response());
    }

    // Not found in any repo
    Err(AppError::RepoNotFound(format!(
        "no git object found for CID {cid_str}"
    )))
}

/// Query parameters for `GET /api/v1/ipfs/pins`.
#[derive(Debug, Deserialize, Clone)]
pub struct ListPinsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    pub cursor: Option<String>,
    pub truncated_cursor: Option<String>,
}

fn default_limit() -> i64 {
    50
}

/// Derive a dedicated 32-byte cursor cipher key from the node's Ed25519 seed
/// using HKDF with a domain-separated info string. This decouples cursor
/// confidentiality from the write-signing identity and avoids feeding the raw
/// seed into an unrelated primitive.
fn derive_cursor_key(seed: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, seed.as_slice());
    let mut okm = [0u8; 32];
    hk.expand(b"gitlawb-ipfs-cursor-v1", &mut okm)
        .expect("32 bytes is a valid HKDF output length");
    okm
}

/// Create an opaque, self-contained truncated cursor token using
/// XChaCha20Poly1305 AEAD.
///
/// Format: `base64_url_no_pad(nonce_24 || ciphertext)` where `ciphertext` =
/// XChaCha20Poly1305-encrypt(expiry_be_8 || cursor_string) with the 16-byte
/// AEAD tag appended by the encryptor. The caller cannot decode hidden-row
/// metadata without the server's Ed25519 seed. Tokens are durable (survive
/// restart, cross-node routing, retries) and expire after 600 seconds.
fn create_opaque_cursor(seed: &[u8; 32], cursor: &str) -> String {
    let cursor_key = derive_cursor_key(seed);
    let cipher = XChaCha20Poly1305::new_from_slice(&cursor_key)
        .expect("32-byte key is valid for XChaCha20Poly1305");

    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let expiry = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + 600)
        .to_be_bytes();

    let mut plaintext = Vec::with_capacity(8 + cursor.len());
    plaintext.extend_from_slice(&expiry);
    plaintext.extend_from_slice(cursor.as_bytes());

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .expect("AEAD encrypt should never fail");

    let mut token = Vec::with_capacity(24 + ciphertext.len());
    token.extend_from_slice(nonce.as_ref());
    token.extend_from_slice(&ciphertext);

    URL_SAFE_NO_PAD.encode(&token)
}

/// Decode and verify an opaque truncated cursor token.
/// Returns the original cursor string if valid and not expired.
fn decode_opaque_cursor(seed: &[u8; 32], token: &str) -> Option<(String, String)> {
    let cursor_key = derive_cursor_key(seed);
    let cipher = XChaCha20Poly1305::new_from_slice(&cursor_key)
        .expect("32-byte key is valid for XChaCha20Poly1305");

    let data = URL_SAFE_NO_PAD.decode(token.as_bytes()).ok()?;
    if data.len() < 24 + 1 {
        return None;
    }

    let (nonce_bytes, ciphertext) = data.split_at(24);
    let nonce = XNonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext).ok()?;
    if plaintext.len() < 8 {
        return None;
    }

    let expiry = u64::from_be_bytes(plaintext[..8].try_into().ok()?);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now >= expiry {
        return None;
    }

    let cursor = std::str::from_utf8(&plaintext[8..]).ok()?;

    let parts: Vec<&str> = cursor.splitn(2, '|').collect();
    if parts.len() == 2 {
        Some((parts[0].to_string(), parts[1].to_string()))
    } else {
        None
    }
}

/// Batch-check git object types for many SHAs in a single repo, using one
/// `git cat-file --batch-check` subprocess instead of N individual `cat-file -t`
/// calls. Returns a map from SHA → `Some("blob"|"commit"|"tree"|"tag")` or
/// `None` (missing/dangling).
///
/// Must be called from a blocking context (e.g. `tokio::task::spawn_blocking`)
/// since it spawns a child process and reads its output synchronously.
fn batch_object_types(
    repo_path: &std::path::Path,
    shas: &[String],
    cancelled: &AtomicBool,
) -> Result<HashMap<String, Option<String>>> {
    use anyhow::Context;

    let mut child = Command::new("git")
        .args(["cat-file", "--batch-check"])
        .current_dir(repo_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to spawn git cat-file --batch-check")?;

    {
        let stdin = child.stdin.as_mut().context("stdin not captured")?;
        for sha in shas {
            writeln!(stdin, "{sha}").context("failed to write sha to cat-file stdin")?;
        }
    }

    // Drop stdin so the child sees EOF on its input pipe.
    drop(child.stdin.take());

    // Poll for completion, checking the cancellation flag between iterations.
    let output = loop {
        if cancelled.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(HashMap::new());
        }
        match child.try_wait() {
            Ok(Some(_status)) => {
                break child
                    .wait_with_output()
                    .context("git cat-file --batch-check failed")?;
            }
            Ok(None) => {
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            Err(e) => {
                return Err(AppError::Git(format!(
                    "git cat-file --batch-check wait failed: {e}",
                )));
            }
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut results = HashMap::with_capacity(shas.len());
    for line in stdout.lines() {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            continue;
        }
        let sha = parts[0].to_string();
        match parts[1] {
            "missing" => {
                results.insert(sha, None);
            }
            obj_type => {
                results.insert(sha, Some(obj_type.to_string()));
            }
        }
    }
    Ok(results)
}

/// GET /api/v1/ipfs/pins
///
/// Returns all CIDs that have been pinned to the local IPFS node from git
/// objects received via push. Each entry includes the git SHA-256 hex, the
/// CIDv1 string, and the timestamp when it was pinned.
///
/// Requires authentication: the global pin index would otherwise disclose
/// metadata for every object ever pushed here (#121).
///
/// The global listing filters each pinned object on current repo visibility
/// to prevent metadata disclosure when repos are made private after push (#136).
/// Only pins from repos the caller can currently read are returned.
pub async fn list_pins(
    State(state): State<AppState>,
    Query(query): Query<ListPinsQuery>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());

    // Reject anonymous callers: the pin index spans the entire node and would
    // expose metadata for every object ever pushed here (#121).
    if caller.is_none() {
        return Err(AppError::Unauthorized(
            "authentication required for pin listing".into(),
        ));
    }
    let caller_str = caller.unwrap();
    let caller_owned = Some(caller_str.to_string());

    // Per-DID rate limit: the listing performs expensive git walks and cat-file
    // probes, so a throwaway DID with a valid signature can exhaust resources (P1).
    if !state.ipfs_list_rate_limiter.check(caller_str).await {
        return Err(AppError::TooManyRequests(
            "rate limit exceeded for IPFS pin listing".into(),
        ));
    }

    // Build the set of readable repo slugs and owner DIDs from the deduped repo view
    // (mirror rows already collapsed, quarantined excluded), then query
    // pins bounded in SQL.
    let repos = state
        .db
        .list_all_repos_deduped()
        .await
        .map_err(AppError::Internal)?;
    let repo_ids: Vec<String> = repos.iter().map(|r| r.id.clone()).collect();
    let rules_by_repo = state
        .db
        .list_visibility_rules_for_repos(&repo_ids)
        .await
        .map_err(AppError::Internal)?;

    // Build parallel vectors of readable (slug, owner_did) pairs to query in SQL,
    // plus a boolean flag per pair indicating whether the repo has *no* path-scoped
    // visibility rules.  The SQL ROW_NUMBER dedup uses this flag to prefer
    // associations from rule-free repos (always visible at root level) over those
    // from repos with /secret/**-style rules (P2).
    let mut query_repos = Vec::new();
    let mut query_owner_dids = Vec::new();
    let mut query_no_rules = Vec::new();

    for r in &repos {
        let rules = rules_by_repo.get(&r.id).map(Vec::as_slice).unwrap_or(&[]);
        if visibility_check(rules, r.is_public, &r.owner_did, caller, "/") == Decision::Deny {
            continue;
        }
        let short = crate::db::normalize_owner_key(&r.owner_did);
        let slug = format!("{}/{}", short, r.name);
        query_repos.push(slug);
        query_owner_dids.push(r.owner_did.clone());
        query_no_rules.push(!has_path_scoped_rule(rules));
    }

    let max_visible = query.limit.clamp(0, 200);

    if max_visible == 0 {
        return Ok(Json(serde_json::json!({
            "pins": [],
            "count": 0,
        })));
    }

    // Global rate limit: keyed on a fixed value so DID rotation cannot
    // bypass the enumeration cost guard (P1).  Checked after the limit=0
    // fast path so short-lived requests do not drain the shared bucket (P2).
    if !state.ipfs_list_global_limiter.check("global").await {
        return Err(AppError::TooManyRequests(
            "rate limit exceeded for IPFS pin listing".into(),
        ));
    }

    // Decode the optional keyset cursor from base64.
    // Internal format: "pinned_at|sha256_hex" (2-tuple) for normal
    // pagination, or just "pinned_at" (1-tuple) for the truncated resume.
    let decode_cursor = |s: &str| -> Option<(String, String)> {
        let bytes = URL_SAFE_NO_PAD.decode(s.as_bytes()).ok()?;
        let decoded = String::from_utf8(bytes).ok()?;
        let parts: Vec<&str> = decoded.splitn(2, '|').collect();
        if parts.len() == 2 {
            Some((parts[0].to_string(), parts[1].to_string()))
        } else {
            None
        }
    };
    let encode_cursor =
        |pa: &str, sha: &str| -> String { URL_SAFE_NO_PAD.encode(format!("{pa}|{sha}")) };

    let initial_cursor = match query.cursor.as_ref() {
        Some(c) => match decode_cursor(c) {
            Some(cursor) => Some(cursor),
            None => {
                return Err(AppError::BadRequest(
                    "invalid cursor: expected base64-encoded pinned_at|sha256_hex".into(),
                ))
            }
        },
        None => None,
    };

    // Truncated resume cursor: XChaCha20Poly1305 AEAD token. Decrypts to the
    // same (pinned_at, repo, sha256_hex) cursor on the server side but the
    // caller cannot decode hidden-row metadata from the wire format. If the
    // token is present but undecodable we return an explicit error so the
    // client does not silently restart at page 1.
    let truncated_resume = match query.truncated_cursor.as_ref() {
        Some(t) => {
            let seed = state.node_keypair.to_seed();
            match decode_opaque_cursor(&seed, t) {
                Some(c) => Some(c),
                None => {
                    return Err(AppError::BadRequest(
                        "invalid or expired truncated_cursor".into(),
                    ))
                }
            }
        }
        None => None,
    };

    // Build a lookup of slug -> (repo, rules) once.
    let mut repos_by_slug = HashMap::new();
    for r in repos {
        let short = crate::db::normalize_owner_key(&r.owner_did);
        let slug = format!("{}/{}", short, r.name);
        let rules = rules_by_repo.get(&r.id).cloned().unwrap_or_default();
        repos_by_slug.insert(slug, (r, rules));
    }

    // Use keyset pagination to fetch batches and post-filter path-scoped
    // hidden pins so the caller still receives up to `max_visible` visible
    // entries even when newer pins are hidden under /secret/** rules.
    // Keyset cursor avoids duplicate/skip rows when new pins land between
    // batches (unlike LIMIT/OFFSET) and removes the cost of deep OFFSET
    // re-scanning.
    //
    // The loop is bounded by MAX_BATCHES to prevent a single request from
    // scanning an unbounded number of hidden rows. Path-scoped git walks
    // are independently bounded by MAX_WALKS as a secondary safeguard.
    //
    // next_cursor is derived from the last *accepted* (visible) pin, never
    // from the last scanned row, to avoid leaking withheld-blob metadata
    // or skipping rows the caller was never shown.
    const BATCH_SIZE: i64 = 200;
    const MAX_BATCHES: usize = 10;
    const MAX_WALKS: usize = 50;
    const MAX_PROBES: usize = 200;
    // P1: hard deadline for cumulative visibility-walk work so a single
    // request with many path-scoped repos cannot hold the global permits
    // for minutes on end.
    const LISTING_DEADLINE_SECS: u64 = 120;
    let listing_deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(LISTING_DEADLINE_SECS);
    let mut batch_count = 0usize;
    let mut batch_hit_limit = false;
    let mut pins = Vec::new();
    // Within-batch dedup by sha256_hex: SQL ROW_NUMBER guarantees one row
    // per SHA across pages, but within a single batch of an all-deferred
    // page the same object could still appear via a different association
    // (P2).  Track seen SHAs so each object is emitted at most once.
    let mut seen_shas: HashSet<String> = HashSet::new();
    let mut db_cursor: Option<(String, String)> = truncated_resume.or(initial_cursor);
    let mut response_cursor: Option<(String, String)> = None;
    let mut allowed_blobs_by_repo: HashMap<String, (HashSet<String>, PathBuf)> = HashMap::new();
    let mut page_truncated = false;
    // Per-repo cache of sha256_hex → is_structural (true for commit/tree/tag).
    let mut structural_cache: HashMap<String, HashMap<String, bool>> = HashMap::new();
    let mut probe_count = 0usize;
    let mut probe_limit = usize::MAX;

    'fetch: loop {
        if batch_count >= MAX_BATCHES {
            batch_hit_limit = true;
            break;
        }
        batch_count += 1;

        let batch = if query_repos.is_empty() {
            Vec::new()
        } else {
            state
                .db
                .list_pinned_cids_for_repos(
                    &query_repos,
                    &query_owner_dids,
                    &query_no_rules,
                    BATCH_SIZE,
                    db_cursor
                        .as_ref()
                        .map(|(pa, sha)| (pa.as_str(), sha.as_str())),
                )
                .await
                .map_err(AppError::Internal)?
        };

        if batch.is_empty() {
            break;
        }

        // Snapshot the cursor used to fetch THIS batch so Phase 3 can retry
        // the first row inclusively when it is deferred (P2).
        let batch_cursor = db_cursor.clone();

        // ── Phase 1 — collect structural candidates per repo ──────────────
        // Track per-pin outcome: None = structural candidate (needs type check
        // before final decision), Some(false) = hidden, Some(true) = visible.
        let mut pin_outcome: Vec<Option<bool>> = Vec::with_capacity(batch.len());
        let mut structural_candidates: HashMap<String, Vec<(usize, String)>> = HashMap::new();
        let mut walk_limit_idx = batch.len();

        for (i, pin) in batch.iter().enumerate() {
            if pin.repo.is_empty() {
                db_cursor = Some((pin.pinned_at.clone(), pin.sha256_hex.clone()));
                pin_outcome.push(None);
                continue;
            }
            let Some((repo, rules)) = repos_by_slug.get(&pin.repo) else {
                // Unknown slug — advance cursor past it, no visibility check.
                db_cursor = Some((pin.pinned_at.clone(), pin.sha256_hex.clone()));
                pin_outcome.push(None);
                continue;
            };

            if !has_path_scoped_rule(rules) {
                // No path-scoped rules — every pin from this repo is visible.
                pin_outcome.push(Some(true));
                continue;
            }

            // Path-scoped repo — ensure walk result is cached.
            if !allowed_blobs_by_repo.contains_key(&repo.id) {
                if allowed_blobs_by_repo.len() >= MAX_WALKS {
                    // Walk budget exhausted. Stop before this pin and leave
                    // db_cursor at the last processed pin so the next request
                    // picks up here and retries the walk.
                    page_truncated = true;
                    walk_limit_idx = i;
                    break;
                }
                // Respect the total visibility-walk deadline so a single
                // request cannot hold the global permits for minutes (P1).
                if tokio::time::Instant::now() >= listing_deadline {
                    page_truncated = true;
                    if i < walk_limit_idx {
                        walk_limit_idx = i;
                    }
                    continue;
                }

                // Acquire a concurrency permit so a flood of requests cannot
                // exhaust the blocking-pool worker or leave unbounded git
                // children running (P1).
                let permit = match state.walk_semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        // All walk slots are occupied — defer this repo's pins
                        // to the next request.
                        page_truncated = true;
                        if i < walk_limit_idx {
                            walk_limit_idx = i;
                        }
                        continue;
                    }
                };

                // Wrap acquire() in a timeout so a slow Tigris fetch does not
                // hold the walk permit unboundedly (P2).
                let acquire_fut = state.repo_store.acquire(&repo.owner_did, &repo.name);
                match tokio::time::timeout(std::time::Duration::from_secs(30), acquire_fut).await {
                    Ok(Ok(rp)) => {
                        let rp_clone = rp.clone();
                        let r_clone = rules.clone();
                        let is_public = repo.is_public;
                        let owner = repo.owner_did.clone();
                        let caller_for_walk = caller_owned.clone();
                        let cancelled = Arc::new(AtomicBool::new(false));
                        let cancelled_clone = Arc::clone(&cancelled);

                        // Move the semaphore permit into the blocking task so it
                        // is released only when the walk truly completes — even
                        // on timeout the permit stays alive until the git child
                        // is killed and the worker returns (P1).
                        let walk_fut = tokio::task::spawn_blocking(move || {
                            let _hold = permit;
                            allowed_blob_set_for_caller(
                                &rp_clone,
                                &r_clone,
                                is_public,
                                &owner,
                                caller_for_walk.as_deref(),
                                &cancelled_clone,
                            )
                        });
                        match tokio::time::timeout(std::time::Duration::from_secs(60), walk_fut)
                            .await
                        {
                            Ok(Ok(Ok(allowed))) => {
                                allowed_blobs_by_repo.insert(repo.id.clone(), (allowed, rp));
                            }
                            _ => {
                                // Walk failed (timeout / error / panic).
                                cancelled.store(true, Ordering::Relaxed);
                                page_truncated = true;
                                if i < walk_limit_idx {
                                    walk_limit_idx = i;
                                }
                                allowed_blobs_by_repo
                                    .insert(repo.id.clone(), (HashSet::new(), PathBuf::new()));
                            }
                        }
                    }
                    Ok(Err(_)) | Err(_) => {
                        // Repo-store acquisition failed or timed out — same
                        // strategy (P2).  The walk permit is dropped here.
                        page_truncated = true;
                        if i < walk_limit_idx {
                            walk_limit_idx = i;
                        }
                        allowed_blobs_by_repo
                            .insert(repo.id.clone(), (HashSet::new(), PathBuf::new()));
                    }
                };
            }

            let (allowed, repo_path) = allowed_blobs_by_repo.get(&repo.id).unwrap();
            if allowed.contains(&pin.sha256_hex) {
                pin_outcome.push(Some(true));
            } else if !repo_path.as_os_str().is_empty() {
                // Not in the allowed set — could be a withheld blob or a
                // structural object (commit/tree/tag).  Mark as structural
                // candidate; Phase 2 will probe the type.
                pin_outcome.push(None); // deferred — decided after phase 2
                structural_candidates
                    .entry(repo.id.clone())
                    .or_default()
                    .push((i, pin.sha256_hex.clone()));
            } else {
                pin_outcome.push(Some(false));
            }
        }

        // When Phase 1 never advanced db_cursor (all pins are path-scoped and
        // no walk permit was available), keep the batch-fetch cursor so the
        // next request retries the same batch.  Only advance past the batch
        // when walk permits were available but the pins had no repo match,
        // because those rows are permanently unprocessable (P2).
        let all_deferred = walk_limit_idx == 0 && db_cursor.as_ref() == batch_cursor.as_ref();
        if all_deferred {
            // db_cursor already equals batch_cursor — the next fetch uses the
            // same position and retries the deferred path-scoped pins.
        } else if db_cursor.as_ref() == batch_cursor.as_ref() {
            // All pins had empty/unmatched repos — advance past the batch so
            // we don't loop forever on the same unprocessable rows (P1).
            if let Some(last) = batch.last() {
                db_cursor = Some((last.pinned_at.clone(), last.sha256_hex.clone()));
            }
        }

        // ── Phase 2 — batch-check structural candidates per repo ──────────
        'phase2: for (repo_id, candidates) in &structural_candidates {
            // Honor the same listing_deadline and walk_semaphore that Phase 1
            // respects, so probe subprocesses don't run past the total request
            // budget or outside the concurrency cap (P2).
            if tokio::time::Instant::now() >= listing_deadline {
                for &(idx, _) in candidates {
                    if idx < probe_limit {
                        probe_limit = idx;
                    }
                }
                continue 'phase2;
            }
            let probe_permit = match state.walk_semaphore.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    for &(idx, _) in candidates {
                        if idx < probe_limit {
                            probe_limit = idx;
                        }
                    }
                    continue 'phase2;
                }
            };
            if probe_count >= MAX_PROBES {
                // Probe budget exhausted. Fold EVERY remaining structural
                // candidate index (not just the current repo's) into
                // probe_limit so none are silently dropped as hidden.
                for &(idx, _) in candidates {
                    if idx < probe_limit {
                        probe_limit = idx;
                    }
                }
                continue 'phase2;
            }
            let rp = allowed_blobs_by_repo
                .get(repo_id)
                .map(|(_, p)| p.clone())
                .unwrap_or_default();
            if rp.as_os_str().is_empty() {
                continue;
            }
            // Filter to SHAs not already cached.
            let repo_cache = structural_cache.entry(repo_id.clone()).or_default();
            let to_check: Vec<String> = candidates
                .iter()
                .filter(|(_, sha)| !repo_cache.contains_key(sha))
                .map(|(_, sha)| sha.clone())
                .collect();
            if to_check.is_empty() {
                continue;
            }
            let remaining = MAX_PROBES.saturating_sub(probe_count);
            let to_check: Vec<String> = to_check.into_iter().take(remaining).collect();
            probe_count += to_check.len();

            // Fold any unprobed candidates from THIS repo into probe_limit
            // so Phase 3 stops before them (P2).
            if to_check.len() < candidates.len() {
                for &(idx, _) in candidates.iter().skip(to_check.len()) {
                    if idx < probe_limit {
                        probe_limit = idx;
                    }
                }
            }

            let rp_for_block = rp.clone();
            let cancelled_probe = Arc::new(AtomicBool::new(false));
            let cancelled_probe_clone = Arc::clone(&cancelled_probe);
            let probe_fut = tokio::task::spawn_blocking(move || {
                let _probe_hold = probe_permit;
                batch_object_types(&rp_for_block, &to_check, &cancelled_probe_clone)
            });
            let results =
                match tokio::time::timeout(std::time::Duration::from_secs(30), probe_fut).await {
                    Ok(Ok(Ok(map))) => map,
                    _ => {
                        // Probe timeout/error — don't cache empty results
                        // (they'd be classified as hidden).  Fold the current
                        // repo's candidates into probe_limit so Phase 3
                        // defers them to the next request (P2).
                        cancelled_probe.store(true, Ordering::Relaxed);
                        for &(idx, _) in candidates {
                            if idx < probe_limit {
                                probe_limit = idx;
                            }
                        }
                        HashMap::new()
                    }
                };
            for (sha, obj_type) in results {
                repo_cache.insert(sha, obj_type.is_some_and(|t| t != "blob"));
            }
        }

        // ── Phase 3 — emit visible pins ───────────────────────────────────
        for i in 0..batch.len() {
            if i >= walk_limit_idx.min(probe_limit) {
                // Past the MAX_WALKS wall or an unprobed structural candidate.
                // Remaining pins are handled by the next request; db_cursor
                // stays at the last processed pin so no row is skipped.
                if i < probe_limit && !page_truncated {
                    page_truncated = true;
                }
                // Save cursor so the keyset predicate < resumes at the
                // first unprocessed row.  When i == 0 there is no processed
                // pin — use the cursor that fetched this batch so the SQL
                // predicate < re-evaluates the deferred row (P2).  When
                // batch_cursor is None (page 1), keep the Phase 1 fallback
                // value so the response can produce a truncated_cursor (P1).
                if i == 0 {
                    if batch_cursor.is_some() {
                        db_cursor = batch_cursor;
                    }
                } else if let Some(pin) = i.checked_sub(1).and_then(|prev| batch.get(prev)) {
                    db_cursor = Some((pin.pinned_at.clone(), pin.sha256_hex.clone()));
                }
                break;
            }

            let pin = batch[i].clone();
            let Some((repo, rules)) = repos_by_slug.get(&pin.repo) else {
                // Already advanced past in phase 1 — just maintain cursor.
                db_cursor = Some((pin.pinned_at.clone(), pin.sha256_hex.clone()));
                continue;
            };

            if !has_path_scoped_rule(rules) {
                let pa = pin.pinned_at.clone();
                let sha = pin.sha256_hex.clone();

                // Dedup by sha256_hex (P2): only skip if already *emitted* —
                // do not suppress a visible association because a hidden one
                // appeared first in the batch.
                if !seen_shas.insert(sha.clone()) {
                    db_cursor = Some((pa, sha));
                    continue;
                }

                response_cursor = Some((pa.clone(), sha.clone()));
                pins.push(pin);
                db_cursor = Some((pa, sha));
            } else {
                let pa = pin.pinned_at.clone();
                let sha = pin.sha256_hex.clone();

                let visible = match pin_outcome[i] {
                    Some(v) => v,
                    None => {
                        // Structural candidate — consult cache. If the
                        // candidate was never probed (MAX_PROBES exhausted)
                        // this shouldn't be reached (probe_limit stops Phase 3
                        // before unprobed rows), but handle it defensively.
                        structural_cache
                            .get(&repo.id)
                            .and_then(|c| c.get(&pin.sha256_hex))
                            .copied()
                            .unwrap_or(false)
                    }
                };
                if visible {
                    if !seen_shas.insert(sha.clone()) {
                        db_cursor = Some((pa, sha));
                        continue;
                    }
                    response_cursor = Some((pa.clone(), sha.clone()));
                    pins.push(pin);
                }
                db_cursor = Some((pa, sha));
            }

            if pins.len() >= max_visible as usize {
                break 'fetch;
            }
        }
    }
    let page_filled = pins.len() >= max_visible as usize;
    if !page_truncated && batch_hit_limit {
        page_truncated = true;
    }
    pins.truncate(max_visible as usize);

    // When page 1 is all-deferred (no walk permit available) neither
    // response_cursor nor db_cursor was set.  Emit a sentinel opaque cursor
    // so the client can retry; on the retry the sentinel decodes to
    // ("\x7f", "\x7f") which the keyset WHERE < predicate treats
    // as "include every row" — effectively restarting from the beginning (P2).
    if page_truncated && response_cursor.is_none() && db_cursor.is_none() {
        db_cursor = Some(("\x7f".to_string(), "\x7f".to_string()));
    }

    let mut body = serde_json::json!({
        "pins": pins,
        "count": pins.len(),
    });

    if page_truncated {
        body["truncated"] = serde_json::json!(true);
    }
    if page_filled {
        // Page is full — provide a cursor from the last visible row so the
        // caller can paginate.
        if let Some((ref pa, ref sha)) = response_cursor {
            body["next_cursor"] = serde_json::json!(encode_cursor(pa, sha));
        }
    } else if page_truncated {
        // Scan bound hit before filling the page — opaque cursor fallback
        // when there are no visible rows to derive a keyset cursor from.
        if let Some((ref pa, ref sha)) = response_cursor {
            body["next_cursor"] = serde_json::json!(encode_cursor(pa, sha));
        } else if let Some((ref pa, ref sha)) = db_cursor {
            let cursor_str = format!("{pa}|{sha}");
            let seed = state.node_keypair.to_seed();
            let token = create_opaque_cursor(&seed, &cursor_str);
            body["truncated_cursor"] = serde_json::json!(token);
        }
    }

    Ok(Json(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthenticatedDid;
    use crate::test_support::test_state;
    use axum::extract::{Extension, Query, State};
    use sqlx::PgPool;

    #[sqlx::test]
    async fn test_ipfs_cursor_guard(pool: PgPool) {
        let app_state = test_state(pool.clone()).await;

        // Seed a path-scoped repo
        sqlx::query(
            "INSERT INTO repos (id, name, owner_did, description, is_public, default_branch, created_at, updated_at, disk_path)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
        )
        .bind("repo-ipfs-test")
        .bind("ipfstest")
        .bind("did:key:z6Mkwowner")
        .bind("desc")
        .bind(true)
        .bind("main")
        .bind("2026-07-03T00:00:00Z")
        .bind("2026-07-03T00:00:00Z")
        .bind("/srv/ipfstest")
        .execute(app_state.db.pool())
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO visibility_rules (id, repo_id, path_glob, mode, reader_dids, created_by, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind("rule-1")
        .bind("repo-ipfs-test")
        .bind("/secret/**")
        .bind("deny")
        .bind("")
        .bind("did:key:z6Mkwowner")
        .bind("2026-07-03T00:00:00Z")
        .execute(app_state.db.pool())
        .await
        .unwrap();

        // Seed another repo with NO path-scoped rules for visible pagination.
        sqlx::query(
            "INSERT INTO repos (id, name, owner_did, description, is_public, default_branch, created_at, updated_at, disk_path)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind("repo-ipfs-vis")
        .bind("ipfsvis")
        .bind("did:key:z6Mkwowner")
        .bind("desc")
        .bind(true)
        .bind("main")
        .bind("2026-07-03T00:00:00Z")
        .bind("2026-07-03T00:00:00Z")
        .bind("/srv/ipfsvis")
        .execute(app_state.db.pool())
        .await
        .unwrap();

        // Insert 1 visible pin, then a 2005-pin hidden stretch, then 1 visible pin.
        // The hidden pins go in `ipfstest` (which has a deny rule and no physical repo so allowed_blobs is empty).
        // The visible pins go in `ipfsvis` (which has no rules, so they are always visible).
        // Note: three separate execute calls — sqlx prepared statements do not
        // support multiple semicolon-delimited statements in a single query().
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, repo, owner_did)
             VALUES ('vis-1-sha', 'vis-1-cid', '2026-07-03T10:00:00Z', 'z6Mkwowner/ipfsvis', 'did:key:z6Mkwowner')",
        )
        .execute(app_state.db.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, repo, owner_did)
             SELECT 'hid-sha-' || i, 'hid-cid-' || i, '2026-07-03T09:00:00Z', 'z6Mkwowner/ipfstest', 'did:key:z6Mkwowner'
             FROM generate_series(1, 2005) as i",
        )
        .execute(app_state.db.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, repo, owner_did)
             VALUES ('vis-2-sha', 'vis-2-cid', '2026-07-03T08:00:00Z', 'z6Mkwowner/ipfsvis', 'did:key:z6Mkwowner')",
        )
        .execute(app_state.db.pool())
        .await
        .unwrap();

        // Visible pagination case asserting the cursor equals the last returned row
        let auth = Extension(AuthenticatedDid("did:key:z6Mkcaller".to_string()));
        let mut q = ListPinsQuery {
            limit: 1,
            cursor: None,
            truncated_cursor: None,
        };

        let res1 = list_pins(
            State(app_state.clone()),
            Query(q.clone()),
            Some(auth.clone()),
        )
        .await
        .unwrap()
        .0;
        let pins1 = res1["pins"].as_array().unwrap();
        assert_eq!(pins1.len(), 1);
        assert_eq!(pins1[0]["sha256_hex"], "vis-1-sha");

        let cursor1 = res1["next_cursor"].as_str().unwrap().to_string();
        // Decode to ensure it equals the last returned row
        let bytes = URL_SAFE_NO_PAD.decode(cursor1.as_bytes()).unwrap();
        let decoded = String::from_utf8(bytes).unwrap();
        assert!(decoded.contains("vis-1-sha"));

        // Case 2: Follow the cursor. The next 2005 rows are hidden.
        // It will hit MAX_BATCHES (2000 rows) and return a truncated_cursor
        // whose XChaCha20Poly1305-encrypted payload conceals the hidden SHA.
        q.cursor = Some(cursor1);
        let res2 = list_pins(
            State(app_state.clone()),
            Query(q.clone()),
            Some(auth.clone()),
        )
        .await
        .unwrap()
        .0;
        assert!(res2.get("pins").unwrap().as_array().unwrap().is_empty());
        assert_eq!(res2.get("truncated").unwrap().as_bool(), Some(true));
        assert!(res2.get("next_cursor").is_none());
        let truncated_cursor = res2["truncated_cursor"]
            .as_str()
            .expect("truncated_cursor should be present")
            .to_string();

        // Case 3: Resume with truncated_cursor. It should skip past the hidden
        // batch and reach the older visible pin (vis-2-sha at 08:00:00Z).
        q.cursor = None;
        q.truncated_cursor = Some(truncated_cursor);
        let res3 = list_pins(
            State(app_state.clone()),
            Query(q.clone()),
            Some(auth.clone()),
        )
        .await
        .unwrap()
        .0;
        let pins3 = res3["pins"].as_array().unwrap();
        assert!(
            !pins3.is_empty(),
            "must surface vis-2-sha behind hidden window"
        );
        assert_eq!(pins3[0]["sha256_hex"], "vis-2-sha");
    }

    #[test]
    fn test_truncated_cursor_does_not_leak_hidden_sha() {
        // The token is AEAD-encrypted with XChaCha20Poly1305: the hidden
        // sha256_hex must NOT be recoverable by a caller who knows the
        // pinned_at and repo prefix.  Unlike a stream-cipher XOR construction
        // (where known plaintext at offset i reveals keystream[i] via
        // keystream[i] = ciphertext[i] XOR plaintext[i]), the AEAD ciphertext
        // is ChaCha20 encryption with a per-nonce block counter applied to
        // 16-byte blocks, then authenticated by Poly1305 — so XOR at a single
        // offset does not yield a reusable keystream byte and the tag prevents
        // any chosen-ciphertext oracle.
        //
        // This test demonstrates the unrecoverability property by attempting a
        // known-plaintext attack against the ciphertext suffix.
        let seed = [0xab; 32]; // arbitrary test seed
        let pinned_at = "2026-07-03T09:00:00Z";
        let hidden_sha = "ab".repeat(32); // 64-char hex — well-known hidden SHA

        let cursor = format!("{pinned_at}|{hidden_sha}");
        let token = create_opaque_cursor(&seed, &cursor);

        // Decode the raw token bytes — these are (nonce_24 || ciphertext).
        let raw = URL_SAFE_NO_PAD.decode(token.as_bytes()).unwrap();
        let (_nonce, ciphertext) = raw.split_at(24);

        // Known plaintext: the first 19 chars of pinned_at "2026-07-03T09:00:00Z"
        // plus "|" = 20 bytes we know at the start.
        // In the XOR-from-stream-cipher world, XOR of known plaintext with the
        // ciphertext yields the keystream for those positions.  If the keystream
        // were reused at the sha suffix (modulo 32), XOR of known suffix with
        // the recovered keystream would yield the hidden sha.
        let known_prefix = format!("{pinned_at}|");
        let known_bytes = known_prefix.as_bytes();

        let attempted_keystream: Vec<u8> = known_bytes
            .iter()
            .zip(ciphertext.iter())
            .map(|(p, c)| p ^ c)
            .collect();

        // Use the "recovered keystream" at the same positions in the suffix
        // (which would be valid only with a repeating XOR keystream).  The
        // suffix is the last 64 bytes of the ciphertext (hidden_sha length).
        if ciphertext.len() >= known_bytes.len() + 64 {
            let suffix_start = ciphertext.len() - 64;
            let attempted_sha: String = ciphertext[suffix_start..]
                .iter()
                .zip(attempted_keystream.iter().cycle())
                .map(|(c, k)| (c ^ k) as char)
                .collect();

            // With a real AEAD the "recovered" suffix is garbage, not the sha.
            assert_ne!(
                attempted_sha, hidden_sha,
                "XOR-based known-plaintext attack on AEAD must NOT recover the hidden sha"
            );
        }

        // Substring check: the token bytes must not contain the sha256_hex in
        // the clear.
        let raw_str = std::str::from_utf8(&raw).unwrap_or("");
        assert!(
            !raw_str.contains(&hidden_sha),
            "truncated_cursor token MUST NOT contain hidden sha256_hex in the clear"
        );

        // Positive round-trip: correct seed decodes the full cursor.
        let decoded = decode_opaque_cursor(&seed, &token).unwrap();
        assert_eq!(decoded.0, pinned_at);
        assert_eq!(decoded.1, hidden_sha);

        // Wrong key must not decode.
        let wrong_seed = [0xcd; 32];
        assert!(decode_opaque_cursor(&wrong_seed, &token).is_none());
    }

    #[sqlx::test]
    async fn test_max_walks_plaintext_not_in_response_cursor(pool: PgPool) {
        let app_state = test_state(pool.clone()).await;

        // ── Create one visible repo (no path-scoped rules) ────────────────
        sqlx::query(
            "INSERT INTO repos (id, name, owner_did, description, is_public, default_branch, created_at, updated_at, disk_path)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind("repo-walks-vis")
        .bind("walksvis")
        .bind("did:key:z6Mkwowner")
        .bind("visible")
        .bind(true)
        .bind("main")
        .bind("2026-07-03T00:00:00Z")
        .bind("2026-07-03T00:00:00Z")
        .bind("/srv/walksvis")
        .execute(app_state.db.pool())
        .await
        .unwrap();

        // ── Seed > MAX_WALKS (50) path-scoped repos with hidden pins ─────
        let num_wall_repos = 55usize;
        for i in 0..num_wall_repos {
            let repo_id = format!("repo-wall-{i}");
            let repo_name = format!("wall{i}");
            let disk_path = format!("/srv/{repo_name}");
            sqlx::query(
                "INSERT INTO repos (id, name, owner_did, description, is_public, default_branch, created_at, updated_at, disk_path)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            )
            .bind(&repo_id)
            .bind(&repo_name)
            .bind("did:key:z6Mkwowner")
            .bind("desc")
            .bind(true)
            .bind("main")
            .bind("2026-07-03T00:00:00Z")
            .bind("2026-07-03T00:00:00Z")
            .bind(&disk_path)
            .execute(app_state.db.pool())
            .await
            .unwrap();

            // Add a /secret/** deny rule so the repo is path-scoped.
            sqlx::query(
                "INSERT INTO visibility_rules (id, repo_id, path_glob, mode, reader_dids, created_by, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(format!("rule-wall-{i}"))
            .bind(&repo_id)
            .bind("/secret/**")
            .bind("deny")
            .bind("")
            .bind("did:key:z6Mkwowner")
            .bind("2026-07-03T00:00:00Z")
            .execute(app_state.db.pool())
            .await
            .unwrap();

            // One hidden pin per wall repo.
            let sha = format!("wallsha{i:04}");
            let slug = format!("z6Mkwowner/{repo_name}");
            sqlx::query(
                "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, repo, owner_did)
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(&sha)
            .bind(format!("cid-wall-{i}"))
            .bind("2026-07-03T09:00:00Z")
            .bind(&slug)
            .bind("did:key:z6Mkwowner")
            .execute(app_state.db.pool())
            .await
            .unwrap();
        }

        // ── One visible pin (newest timestamp so it appears first) ────────
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, repo, owner_did)
             VALUES ('vis-walks-sha', 'vis-walks-cid', '2026-07-03T10:00:00Z', 'z6Mkwowner/walksvis', 'did:key:z6Mkwowner')",
        )
        .execute(app_state.db.pool())
        .await
        .unwrap();

        let auth = Extension(AuthenticatedDid("did:key:z6Mkstranger".to_string()));
        let res = list_pins(
            State(app_state.clone()),
            Query(ListPinsQuery {
                limit: 50,
                cursor: None,
                truncated_cursor: None,
            }),
            Some(auth),
        )
        .await
        .unwrap()
        .0;

        // The visible pin (newest) must be returned.
        let pins = res["pins"].as_array().unwrap();
        assert_eq!(pins.len(), 1, "must return the visible pin");
        assert_eq!(pins[0]["sha256_hex"], "vis-walks-sha");

        // The page is truncated (not filled) because MAX_WALKS was hit.
        assert_eq!(res.get("truncated").and_then(|v| v.as_bool()), Some(true));
        // next_cursor IS present — it points to the VISIBLE pin shown to the
        // caller (no leak).  When response_cursor holds a visible pin the
        // plaintext cursor is safe; the P1 leak only happened when skip_pos
        // (an un-walked hidden pin) was put in response_cursor.
        let nc = res["next_cursor"]
            .as_str()
            .expect("next_cursor must be present for visible pin pagination");
        let bytes = URL_SAFE_NO_PAD.decode(nc.as_bytes()).unwrap();
        let decoded = String::from_utf8(bytes).unwrap();
        assert!(
            decoded.contains("vis-walks-sha"),
            "next_cursor must reference the visible pin, not a hidden SHA: {decoded}"
        );
        // No truncated_cursor — next_cursor handles pagination.
        assert!(
            res.get("truncated_cursor").is_none(),
            "truncated_cursor must NOT be present when next_cursor suffices"
        );

        // ── Second request: skip past the visible pin into the hidden wall ──
        // The response must use the AEAD token (no plaintext next_cursor)
        // because no visible pin is in the returned batch.
        let auth = Extension(AuthenticatedDid("did:key:z6Mkstranger".to_string()));
        let res2 = list_pins(
            State(app_state.clone()),
            Query(ListPinsQuery {
                limit: 50,
                cursor: Some(nc.to_string()),
                truncated_cursor: None,
            }),
            Some(auth),
        )
        .await
        .unwrap()
        .0;

        let pins2 = res2["pins"].as_array().unwrap();
        assert!(pins2.is_empty(), "second page has no visible pins");
        assert_eq!(res2.get("truncated").and_then(|v| v.as_bool()), Some(true));
        // next_cursor must NOT be present — no visible pin in this batch.
        assert!(
            res2.get("next_cursor").is_none(),
            "next_cursor must not be present when no visible pin is returned"
        );
        // truncated_cursor MUST be present and AEAD-encrypted.
        let token = res2["truncated_cursor"]
            .as_str()
            .expect("truncated_cursor must be present for hidden-only page");
        for i in 0..num_wall_repos {
            let sha = format!("wallsha{i:04}");
            assert!(
                !token.contains(&sha),
                "truncated_cursor must not contain hidden sha256_hex in the clear: {sha}"
            );
        }
    }

    #[sqlx::test]
    async fn test_structural_pin_included_withheld_blob_excluded(pool: PgPool) {
        let app_state = test_state(pool.clone()).await;

        // ── Create a real on-disk bare repo with objects ──────────────────
        let owner_did = "did:key:z6Mkwowner";
        let repo_name = "structest";
        let owner_slug = owner_did.replace([':', '/'], "_");
        let repo_path = std::path::PathBuf::from("/tmp")
            .join(&owner_slug)
            .join(format!("{repo_name}.git"));

        // Remove leftovers from a prior failed run, then init a bare repo.
        let _ = std::fs::remove_dir_all(&repo_path);
        crate::git::store::init_bare(&repo_path).unwrap();

        // Create a blob: echo -n "secret content" | git hash-object -w --stdin
        let mut blob_child = Command::new("git")
            .args([
                "-C",
                repo_path.to_str().unwrap(),
                "hash-object",
                "-w",
                "--stdin",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        blob_child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"secret content")
            .unwrap();
        // Drop stdin to close it so hash-object can finish.
        drop(blob_child.stdin.take());
        let blob_output = blob_child.wait_with_output().unwrap();
        assert!(
            blob_output.status.success(),
            "git hash-object failed: {}",
            String::from_utf8_lossy(&blob_output.stderr)
        );
        let blob_sha = String::from_utf8_lossy(&blob_output.stdout)
            .trim()
            .to_string();
        assert!(!blob_sha.is_empty(), "blob sha must not be empty");

        // Create a sub-tree for "secret/" containing the blob at "file.txt"
        let sub_tree_input = format!("100644 blob {blob_sha}\tfile.txt");
        let mut sub_tree_child = Command::new("git")
            .args(["-C", repo_path.to_str().unwrap(), "mktree"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        sub_tree_child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(sub_tree_input.as_bytes())
            .unwrap();
        drop(sub_tree_child.stdin.take());
        let sub_tree_output = sub_tree_child.wait_with_output().unwrap();
        assert!(
            sub_tree_output.status.success(),
            "git mktree for secret/ failed: {}",
            String::from_utf8_lossy(&sub_tree_output.stderr)
        );
        let sub_tree_sha = String::from_utf8_lossy(&sub_tree_output.stdout)
            .trim()
            .to_string();
        assert!(!sub_tree_sha.is_empty(), "sub-tree sha must not be empty");

        // Create the root tree containing the secret/ sub-tree at path "secret"
        let root_tree_input = format!("040000 tree {sub_tree_sha}\tsecret");
        let mut root_tree_child = Command::new("git")
            .args(["-C", repo_path.to_str().unwrap(), "mktree"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        root_tree_child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(root_tree_input.as_bytes())
            .unwrap();
        drop(root_tree_child.stdin.take());
        let root_tree_output = root_tree_child.wait_with_output().unwrap();
        assert!(
            root_tree_output.status.success(),
            "git mktree for root tree failed: {}",
            String::from_utf8_lossy(&root_tree_output.stderr)
        );
        let tree_sha = String::from_utf8_lossy(&root_tree_output.stdout)
            .trim()
            .to_string();
        assert!(!tree_sha.is_empty(), "root tree sha must not be empty");

        // Create a commit pointing to the tree
        let commit_output = Command::new("git")
            .args([
                "-C",
                repo_path.to_str().unwrap(),
                "commit-tree",
                &tree_sha,
                "-m",
                "initial",
            ])
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@test.com")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@test.com")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert!(
            commit_output.status.success(),
            "git commit-tree failed: {}",
            String::from_utf8_lossy(&commit_output.stderr)
        );
        let commit_sha = String::from_utf8_lossy(&commit_output.stdout)
            .trim()
            .to_string();
        assert!(!commit_sha.is_empty(), "commit sha must not be empty");

        // Update HEAD so the blob walk can reach the blob.
        // In a bare repo HEAD is a symref to refs/heads/main, so we update the ref.
        let update_output = Command::new("git")
            .args([
                "-C",
                repo_path.to_str().unwrap(),
                "update-ref",
                "refs/heads/main",
                &commit_sha,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert!(
            update_output.status.success(),
            "git update-ref failed: {}",
            String::from_utf8_lossy(&update_output.stderr)
        );

        // ── Seed the DB ───────────────────────────────────────────────────
        // Slug must match what list_pins computes from normalize_owner_key:
        //   normalize_owner_key("did:key:z6Mkwowner") = "z6Mkwowner"
        //   slug = "z6Mkwowner/structest"
        let repo_slug = format!("z6Mkwowner/{repo_name}");
        sqlx::query(
            "INSERT INTO repos (id, name, owner_did, description, is_public, default_branch, created_at, updated_at, disk_path)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
        )
        .bind("repo-structest")
        .bind(repo_name)
        .bind(owner_did)
        .bind("structural test repo")
        .bind(true)
        .bind("main")
        .bind("2026-07-03T00:00:00Z")
        .bind("2026-07-03T00:00:00Z")
        .bind(repo_path.to_str().unwrap())
        .execute(app_state.db.pool())
        .await
        .unwrap();

        // Add a /secret/** deny rule so the blob is withheld from strangers.
        sqlx::query(
            "INSERT INTO visibility_rules (id, repo_id, path_glob, mode, reader_dids, created_by, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind("rule-structest")
        .bind("repo-structest")
        .bind("/secret/**")
        .bind("deny")
        .bind("")
        .bind("did:key:z6Mkwowner")
        .bind("2026-07-03T00:00:00Z")
        .execute(app_state.db.pool())
        .await
        .unwrap();

        // Pin the blob (must be withheld under /secret/**).
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, repo, owner_did)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&blob_sha)
        .bind("blob-cid")
        .bind("2026-07-03T12:00:00Z")
        .bind(&repo_slug)
        .bind(owner_did)
        .execute(app_state.db.pool())
        .await
        .unwrap();

        // Pin the tree (structural — must be visible).
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, repo, owner_did)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&tree_sha)
        .bind("tree-cid")
        .bind("2026-07-03T11:00:00Z")
        .bind(&repo_slug)
        .bind(owner_did)
        .execute(app_state.db.pool())
        .await
        .unwrap();

        // Pin the commit (structural — must be visible).
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, repo, owner_did)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&commit_sha)
        .bind("commit-cid")
        .bind("2026-07-03T10:00:00Z")
        .bind(&repo_slug)
        .bind(owner_did)
        .execute(app_state.db.pool())
        .await
        .unwrap();

        // ── Call list_pins as a stranger ──────────────────────────────────
        let stranger = Extension(AuthenticatedDid("did:key:z6Mkstranger".to_string()));
        let res = list_pins(
            State(app_state.clone()),
            Query(ListPinsQuery {
                limit: 50,
                cursor: None,
                truncated_cursor: None,
            }),
            Some(stranger),
        )
        .await
        .unwrap()
        .0;

        let pins = res["pins"].as_array().unwrap();
        let sha_hexes: Vec<&str> = pins
            .iter()
            .filter_map(|p| p["sha256_hex"].as_str())
            .collect();

        // The withheld blob at /secret/** must NOT appear.
        assert!(
            !sha_hexes.contains(&blob_sha.as_str()),
            "withheld blob pin under /secret/** must NOT appear for stranger"
        );
        // The tree and commit are structural objects not in the blob set —
        // they MUST appear (KTD3).
        assert!(
            sha_hexes.contains(&tree_sha.as_str()),
            "structural tree pin must appear for stranger"
        );
        assert!(
            sha_hexes.contains(&commit_sha.as_str()),
            "structural commit pin must appear for stranger"
        );

        // Clean up the on-disk repo.
        let _ = std::fs::remove_dir_all(&repo_path);
    }

    #[sqlx::test]
    async fn test_stranger_denied_private_repo_pins(pool: PgPool) {
        let app_state = test_state(pool.clone()).await;

        // Seed a fully private repo (is_public = false).
        sqlx::query(
            "INSERT INTO repos (id, name, owner_did, description, is_public, default_branch, created_at, updated_at, disk_path)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
        )
        .bind("repo-private")
        .bind("privaterepo")
        .bind("did:key:z6Mkwowner")
        .bind("private repo")
        .bind(false)
        .bind("main")
        .bind("2026-07-03T00:00:00Z")
        .bind("2026-07-03T00:00:00Z")
        .bind("/srv/privaterepo")
        .execute(app_state.db.pool())
        .await
        .unwrap();

        // Insert a pin owned by the owner.
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, repo, owner_did)
             VALUES ('priv-sha-1', 'priv-cid-1', '2026-07-03T12:00:00Z', 'z6Mkwowner/privaterepo', 'did:key:z6Mkwowner')",
        )
        .execute(app_state.db.pool())
        .await
        .unwrap();

        // A stranger (not the owner, not a listed reader) must see no pins.
        let stranger_auth = Extension(AuthenticatedDid("did:key:z6Mkstranger".to_string()));
        let res = list_pins(
            State(app_state.clone()),
            Query(ListPinsQuery {
                limit: 50,
                cursor: None,
                truncated_cursor: None,
            }),
            Some(stranger_auth),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(
            res["pins"].as_array().unwrap().len(),
            0,
            "stranger must not see pins from a private repo"
        );
        assert_eq!(res["count"].as_u64().unwrap(), 0);
    }

    #[sqlx::test]
    async fn test_orphan_empty_repo_pins_excluded(pool: PgPool) {
        let app_state = test_state(pool.clone()).await;

        // Seed a public repo (so the caller has some readable repo context).
        sqlx::query(
            "INSERT INTO repos (id, name, owner_did, description, is_public, default_branch, created_at, updated_at, disk_path)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
        )
        .bind("repo-public")
        .bind("pubrepo")
        .bind("did:key:z6Mkwowner")
        .bind("public repo")
        .bind(true)
        .bind("main")
        .bind("2026-07-03T00:00:00Z")
        .bind("2026-07-03T00:00:00Z")
        .bind("/srv/pubrepo")
        .execute(app_state.db.pool())
        .await
        .unwrap();

        // Insert a legit pin for the public repo.
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, repo, owner_did)
             VALUES ('legit-sha', 'legit-cid', '2026-07-03T12:00:00Z', 'z6Mkwowner/pubrepo', 'did:key:z6Mkwowner')",
        )
        .execute(app_state.db.pool())
        .await
        .unwrap();

        // Insert a legacy orphan pin with repo = '' (empty string) and owner_did = ''.
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, repo, owner_did)
             VALUES ('orphan-sha', 'orphan-cid', '2026-07-03T11:00:00Z', '', '')",
        )
        .execute(app_state.db.pool())
        .await
        .unwrap();

        // Signed caller must see the legit pin but NOT the orphan.
        let auth = Extension(AuthenticatedDid("did:key:z6Mkcaller".to_string()));
        let res = list_pins(
            State(app_state.clone()),
            Query(ListPinsQuery {
                limit: 50,
                cursor: None,
                truncated_cursor: None,
            }),
            Some(auth),
        )
        .await
        .unwrap()
        .0;
        let pins = res["pins"].as_array().unwrap();
        let sha_hexes: Vec<&str> = pins
            .iter()
            .filter_map(|p| p["sha256_hex"].as_str())
            .collect();
        assert!(sha_hexes.contains(&"legit-sha"), "legit pin must appear");
        assert!(
            !sha_hexes.contains(&"orphan-sha"),
            "orphan pin with repo='' must NOT appear"
        );
    }

    /// Verifies the non-sybil (global) rate limiter sheds requests after
    /// its cap is reached, even across distinct DIDs (P3).
    #[sqlx::test]
    async fn global_rate_limiter_sheds_after_budget_exhausted(pool: PgPool) {
        let mut state = test_state(pool).await;
        // Tighten the global limiter to max 2 with a singleton map so
        // rotating DIDs cannot bypass the cap.
        state.ipfs_list_global_limiter =
            crate::rate_limit::RateLimiter::new_bounded(2, std::time::Duration::from_secs(3600), 1);

        // First two requests with distinct DIDs are within budget.
        let r1 = list_pins(
            State(state.clone()),
            Query(ListPinsQuery {
                limit: 1,
                cursor: None,
                truncated_cursor: None,
            }),
            Some(Extension(AuthenticatedDid("did:key:z6MkwA".into()))),
        )
        .await;
        assert!(
            r1.is_ok() || matches!(r1, Err(AppError::Unauthorized(_))),
            "first caller should not be refused by global limiter, got {r1:?}",
        );

        let r2 = list_pins(
            State(state.clone()),
            Query(ListPinsQuery {
                limit: 1,
                cursor: None,
                truncated_cursor: None,
            }),
            Some(Extension(AuthenticatedDid("did:key:z6MkwB".into()))),
        )
        .await;
        assert!(
            r2.is_ok() || matches!(r2, Err(AppError::Unauthorized(_))),
            "second caller should not be refused by global limiter, got {r2:?}",
        );

        // Third request with a fresh DID — global bucket is empty.
        let r3 = list_pins(
            State(state.clone()),
            Query(ListPinsQuery {
                limit: 1,
                cursor: None,
                truncated_cursor: None,
            }),
            Some(Extension(AuthenticatedDid("did:key:z6MkwC".into()))),
        )
        .await;
        assert!(
            matches!(r3, Err(AppError::TooManyRequests(_))),
            "third caller should be refused by global limiter, got {r3:?}",
        );
    }

    /// Single DID that exhausts its per-DID budget does NOT drain the
    /// shared global bucket — the global check is charged only after the
    /// per-DID check passes (P2, P3).
    #[sqlx::test]
    async fn single_did_over_budget_does_not_drain_global(pool: PgPool) {
        let mut state = test_state(pool).await;
        // Per-DID limit of 1 so the second request from the same DID is
        // refused before the global limiter is charged.
        state.ipfs_list_rate_limiter = crate::rate_limit::RateLimiter::new_bounded(
            1,
            std::time::Duration::from_secs(3600),
            200_000,
        );
        // Global limit of 3 — generous enough that two distinct DIDs can
        // both pass even if the over-budget DID had drained the bucket.
        state.ipfs_list_global_limiter =
            crate::rate_limit::RateLimiter::new_bounded(3, std::time::Duration::from_secs(3600), 1);

        // DID A — first request passes per-DID and charges global.
        let r1 = list_pins(
            State(state.clone()),
            Query(ListPinsQuery {
                limit: 1,
                cursor: None,
                truncated_cursor: None,
            }),
            Some(Extension(AuthenticatedDid("did:key:z6MkwX".into()))),
        )
        .await;
        assert!(
            r1.is_ok() || matches!(&r1, Err(AppError::Unauthorized(_))),
            "DID A first request should not be refused, got {r1:?}",
        );

        // DID A — second request is refused by per-DID limiter (budget
        // exhausted), BEFORE the global bucket would be charged.
        let r2 = list_pins(
            State(state.clone()),
            Query(ListPinsQuery {
                limit: 1,
                cursor: None,
                truncated_cursor: None,
            }),
            Some(Extension(AuthenticatedDid("did:key:z6MkwX".into()))),
        )
        .await;
        assert!(
            matches!(r2, Err(AppError::TooManyRequests(_))),
            "DID A second request should get per-DID 429, got {r2:?}",
        );

        // DID B — should still pass because the global bucket was charged
        // only once (by DID A's first request, which passed per-DID).
        let r3 = list_pins(
            State(state.clone()),
            Query(ListPinsQuery {
                limit: 1,
                cursor: None,
                truncated_cursor: None,
            }),
            Some(Extension(AuthenticatedDid("did:key:z6MkwY".into()))),
        )
        .await;
        assert!(
            r3.is_ok() || matches!(&r3, Err(AppError::Unauthorized(_))),
            "DID B should not be refused (global bucket has 2 of 3 remaining), got {r3:?}",
        );
    }
}
