//! Opaque, integrity-protected continuation tokens for the task read surfaces.
//!
//! The task list pages by keyset over `(created_at, id)`, but the rows a
//! caller may *see* are a filtered subset of the rows the query has to
//! *examine*. Handing the caller a raw `(created_at, id)` cursor therefore
//! forced a choice between two broken options (#327 review): anchor the cursor
//! on the last visible row, and a window of denied tasks longer than the scan
//! budget stalls paging forever; or anchor it on the last examined row, and a
//! denied read leaks the id and timestamp of a task `GET /tasks/{id}` other-
//! wise 404s.
//!
//! A server-issued token removes the choice. The position it carries is the
//! last *examined* candidate, so paging always advances, and the payload is
//! opaque and MAC'd, so the caller learns nothing from it and cannot forge one
//! naming a row of their choosing.
//!
//! The position must be *confidential*, not merely unforgeable: a token that
//! merely signed a base64 payload would still let its holder read the id and
//! timestamp of the denied row it names, which is the disclosure the token
//! exists to prevent. The payload is therefore encrypted under a
//! synthetic-IV construction (SIV): the tag is an HMAC over the filter and the
//! plaintext, and it doubles as the IV seeding the keystream the plaintext is
//! XORed with. That needs no randomness source and no dependency beyond the
//! `hmac`/`sha2` pair already used for webhook signatures and blob recipient
//! tags, and it is decrypt-last: nothing is parsed until the tag verifies.
//!
//! Making the token the *only* accepted cursor also fixes the ordering-domain
//! bug the same review found. `agent_tasks.created_at` is TEXT and compared as
//! TEXT, so `...Z` and `...+00:00` denote one instant but sort differently. A
//! caller-typed timestamp could silently skip or repeat same-time rows. The
//! token instead carries the stored string verbatim, so the value compared is
//! always a value the server wrote.
//!
//! Wire form: `v1.<payload>.<tag>`, both parts base64url unpadded.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::AppError;

type HmacSha256 = Hmac<Sha256>;

const CURSOR_PREFIX: &str = "v1";
const KEY_DERIVATION_LABEL: &[u8] = b"gitlawb/tasks-cursor-key/v1";
const TAG_DOMAIN: &[u8] = b"gitlawb/tasks-cursor-tag/v1";
const STREAM_DOMAIN: &[u8] = b"gitlawb/tasks-cursor-stream/v1";
/// Truncated MAC length, and the synthetic IV width. 128 bits is far beyond
/// forgery reach for a token that carries no authority of its own (every page
/// re-runs the visibility gate against the presenting caller), and keeps the
/// token short enough to sit in a query string.
const TAG_LEN: usize = 16;

/// How long an issued cursor stays acceptable. Keyset positions never go stale
/// on their own — `created_at`/`id` are immutable — so this is not a
/// correctness bound. It bounds how long a token stays valid across a node
/// restart-and-rotate and keeps an abandoned page from being resumed
/// indefinitely.
const CURSOR_TTL_SECS: i64 = 24 * 60 * 60;

/// Node-keyed MAC key for continuation tokens, derived from the node keypair
/// seed so it needs no configuration and survives restarts of the same node.
/// Derived rather than used directly so a token forgery oracle could not
/// bear on the signing key itself.
#[derive(Clone)]
pub struct TaskCursorKey([u8; 32]);

impl std::fmt::Debug for TaskCursorKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TaskCursorKey(<redacted>)")
    }
}

impl TaskCursorKey {
    pub fn derive(node_seed: &[u8; 32]) -> Self {
        let mut mac = HmacSha256::new_from_slice(node_seed).expect("HMAC accepts any key length");
        mac.update(KEY_DERIVATION_LABEL);
        let mut key = [0u8; 32];
        key.copy_from_slice(&mac.finalize().into_bytes());
        Self(key)
    }
}

/// The keyset position a token carries: the last candidate row the previous
/// request examined, whether or not the caller was allowed to see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskPosition {
    pub created_at: String,
    pub id: String,
}

impl TaskPosition {
    pub fn new(created_at: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            created_at: created_at.into(),
            id: id.into(),
        }
    }

    pub fn as_pair(&self) -> (&str, &str) {
        (self.created_at.as_str(), self.id.as_str())
    }
}

#[derive(Serialize, Deserialize)]
struct CursorPayload<'a> {
    /// `created_at` of the last examined candidate, verbatim as stored.
    t: &'a str,
    /// `id` of the last examined candidate.
    i: &'a str,
    /// Unix expiry.
    e: i64,
}

/// The filter a page was issued under. A cursor is only meaningful against the
/// same `status`/`assignee_did` filter that produced it: resuming a filtered
/// scan from an unfiltered position (or the reverse) silently skips rows.
/// Bound into the MAC rather than stored in the payload, so it costs no token
/// length and cannot be edited without invalidating the tag.
#[derive(Debug, Clone, Copy)]
pub struct TaskFilter<'a> {
    pub status: Option<&'a str>,
    pub assignee_did: Option<&'a str>,
}

fn cursor_mac(key: &TaskCursorKey, filter: TaskFilter<'_>, plaintext: &[u8]) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC accepts any key length");
    mac.update(TAG_DOMAIN);
    // Length-prefix every field so no two distinct filter/plaintext triples can
    // produce the same MAC input.
    for field in [
        filter.status.unwrap_or("").as_bytes(),
        filter.assignee_did.unwrap_or("").as_bytes(),
        plaintext,
    ] {
        mac.update(&(field.len() as u64).to_be_bytes());
        mac.update(field);
    }
    // Presence is distinct from emptiness for the two optional fields.
    mac.update(&[
        u8::from(filter.status.is_some()),
        u8::from(filter.assignee_did.is_some()),
    ]);
    mac
}

/// Synthetic IV: the authentication tag over the filter and plaintext, which
/// also seeds the keystream. Deterministic by construction, so no randomness
/// source is needed and two tokens for the same page are byte-identical.
fn siv(key: &TaskCursorKey, filter: TaskFilter<'_>, plaintext: &[u8]) -> [u8; TAG_LEN] {
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(&cursor_mac(key, filter, plaintext).finalize().into_bytes()[..TAG_LEN]);
    out
}

/// XOR `buf` with the keystream for `iv`. Its own inverse, so encrypt and
/// decrypt are the same call.
fn apply_keystream(key: &TaskCursorKey, iv: &[u8; TAG_LEN], buf: &mut [u8]) {
    for (block_index, chunk) in buf.chunks_mut(32).enumerate() {
        let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC accepts any key length");
        mac.update(STREAM_DOMAIN);
        mac.update(iv);
        mac.update(&(block_index as u64).to_be_bytes());
        let block = mac.finalize().into_bytes();
        for (byte, k) in chunk.iter_mut().zip(block.iter()) {
            *byte ^= k;
        }
    }
}

/// Mint a token resuming at `position` for `filter`.
pub fn encode(key: &TaskCursorKey, filter: TaskFilter<'_>, position: &TaskPosition) -> String {
    let mut payload = serde_json::to_vec(&CursorPayload {
        t: &position.created_at,
        i: &position.id,
        e: chrono::Utc::now().timestamp() + CURSOR_TTL_SECS,
    })
    .expect("cursor payload is plain strings and an integer");
    let iv = siv(key, filter, &payload);
    apply_keystream(key, &iv, &mut payload);
    format!(
        "{CURSOR_PREFIX}.{}.{}",
        URL_SAFE_NO_PAD.encode(iv),
        URL_SAFE_NO_PAD.encode(&payload)
    )
}

/// One rejection message for every way a token can fail to verify. A caller
/// who mangled a token, replayed an expired one, or tried to move one to a
/// different filter learns only that the cursor is not usable — never which
/// of those it was, and never anything about the row it named.
const INVALID_CURSOR: &str = "invalid or expired cursor";

fn reject() -> AppError {
    AppError::BadRequest(INVALID_CURSOR.into())
}

/// Verify a token against `filter` and return the position it carries.
pub fn decode(
    key: &TaskCursorKey,
    filter: TaskFilter<'_>,
    token: &str,
) -> crate::error::Result<TaskPosition> {
    let mut parts = token.split('.');
    let (Some(version), Some(iv_b64), Some(body_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(reject());
    };
    if version != CURSOR_PREFIX {
        return Err(reject());
    }
    let iv_bytes = URL_SAFE_NO_PAD.decode(iv_b64).map_err(|_| reject())?;
    let mut plaintext = URL_SAFE_NO_PAD.decode(body_b64).map_err(|_| reject())?;
    let iv: [u8; TAG_LEN] = iv_bytes.try_into().map_err(|_| reject())?;

    apply_keystream(key, &iv, &mut plaintext);
    // Authenticate before parsing: until the tag matches, `plaintext` is just
    // attacker-chosen bytes run through a keystream. `verify_truncated_left`
    // is the constant-time compare, so a forgery attempt cannot be steered by
    // timing the first differing byte.
    cursor_mac(key, filter, &plaintext)
        .verify_truncated_left(&iv)
        .map_err(|_| reject())?;

    let decoded: CursorPayload<'_> = serde_json::from_slice(&plaintext).map_err(|_| reject())?;
    if decoded.e < chrono::Utc::now().timestamp() {
        return Err(reject());
    }
    Ok(TaskPosition::new(decoded.t, decoded.i))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> TaskCursorKey {
        TaskCursorKey::derive(&[7u8; 32])
    }

    fn unfiltered() -> TaskFilter<'static> {
        TaskFilter {
            status: None,
            assignee_did: None,
        }
    }

    #[test]
    fn round_trips_position_verbatim() {
        let k = key();
        // A stored timestamp the server wrote, fractional digits and all.
        let pos = TaskPosition::new("2026-01-03T00:00:00.123456789+00:00", "task-a");
        let token = encode(&k, unfiltered(), &pos);
        assert_eq!(decode(&k, unfiltered(), &token).unwrap(), pos);
    }

    /// The whole point of the token is that the caller may hold it without
    /// learning the denied row it names. A signed-but-plaintext payload would
    /// pass every other test here and still fail this one.
    #[test]
    fn token_does_not_expose_the_row_it_names() {
        let k = key();
        let token = encode(
            &k,
            unfiltered(),
            &TaskPosition::new("2026-01-03T00:00:00+00:00", "denied-task-id"),
        );
        let body = token.split('.').nth(2).expect("token has a body part");
        let raw = URL_SAFE_NO_PAD.decode(body).unwrap();
        let as_text = String::from_utf8_lossy(&raw);
        for secret in ["denied-task-id", "2026-01-03", "\"t\"", "\"i\""] {
            assert!(
                !as_text.contains(secret),
                "token body must not carry {secret:?} in the clear: {as_text:?}"
            );
        }
        // Also assert it is not merely reordered or whitespace-mangled JSON.
        assert!(
            serde_json::from_slice::<serde_json::Value>(&raw).is_err(),
            "token body must not be parseable as JSON"
        );
    }

    /// Callers paste the token straight into a query string, so it must carry
    /// no character that needs percent-encoding.
    #[test]
    fn token_is_url_safe_verbatim() {
        let token = encode(
            &key(),
            TaskFilter {
                status: Some("pending"),
                assignee_did: Some("did:key:z6MkAssignee"),
            },
            &TaskPosition::new("2026-01-03T00:00:00.123456789+00:00", "task-a"),
        );
        assert!(
            token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')),
            "token must be query-safe without encoding: {token}"
        );
    }

    /// Flipping any byte of a token must fail the tag, not decode to a
    /// different position: the keystream is malleable on its own, the tag is
    /// what stops a chosen-position forgery.
    #[test]
    fn rejects_any_tampered_byte() {
        let k = key();
        let token = encode(
            &k,
            unfiltered(),
            &TaskPosition::new("2026-01-03T00:00:00+00:00", "task-a"),
        );
        let parts: Vec<&str> = token.split('.').collect();
        for part in [1usize, 2] {
            for position in [0usize, 3] {
                let mut bytes = parts[part].as_bytes().to_vec();
                bytes[position] = if bytes[position] == b'A' { b'B' } else { b'A' };
                let mut mangled: Vec<String> = parts.iter().map(|p| p.to_string()).collect();
                mangled[part] = String::from_utf8(bytes).unwrap();
                assert!(
                    decode(&k, unfiltered(), &mangled.join(".")).is_err(),
                    "byte {position} of part {part} must not be malleable"
                );
            }
        }
        // Sanity: the untouched token still decodes, so the loop above is not
        // passing because every token is rejected.
        assert!(decode(&k, unfiltered(), &token).is_ok());
    }

    #[test]
    fn rejects_token_from_another_node() {
        let pos = TaskPosition::new("2026-01-03T00:00:00+00:00", "task-a");
        let token = encode(&TaskCursorKey::derive(&[1u8; 32]), unfiltered(), &pos);
        assert!(decode(&TaskCursorKey::derive(&[2u8; 32]), unfiltered(), &token).is_err());
    }

    #[test]
    fn rejects_cursor_moved_to_a_different_filter() {
        let k = key();
        let pos = TaskPosition::new("2026-01-03T00:00:00+00:00", "task-a");
        let token = encode(
            &k,
            TaskFilter {
                status: Some("pending"),
                assignee_did: None,
            },
            &pos,
        );
        assert!(decode(&k, unfiltered(), &token).is_err());
        assert!(decode(
            &k,
            TaskFilter {
                status: Some("claimed"),
                assignee_did: None
            },
            &token
        )
        .is_err());
        assert!(decode(
            &k,
            TaskFilter {
                status: Some("pending"),
                assignee_did: None
            },
            &token
        )
        .is_ok());
    }

    /// A filter of `Some("")` must not verify a token minted with `None`.
    #[test]
    fn distinguishes_absent_filter_from_empty_filter() {
        let k = key();
        let pos = TaskPosition::new("2026-01-03T00:00:00+00:00", "task-a");
        let token = encode(&k, unfiltered(), &pos);
        assert!(decode(
            &k,
            TaskFilter {
                status: Some(""),
                assignee_did: None
            },
            &token
        )
        .is_err());
    }

    /// Length-prefixing must stop a status/assignee pair from being re-split.
    #[test]
    fn rejects_field_boundary_shift() {
        let k = key();
        let pos = TaskPosition::new("2026-01-03T00:00:00+00:00", "task-a");
        let token = encode(
            &k,
            TaskFilter {
                status: Some("pend"),
                assignee_did: Some("ing"),
            },
            &pos,
        );
        assert!(decode(
            &k,
            TaskFilter {
                status: Some("pending"),
                assignee_did: Some("")
            },
            &token
        )
        .is_err());
    }

    #[test]
    fn rejects_expired_token() {
        let k = key();
        // Minted the same way `encode` does, but already past its expiry.
        let mut payload = serde_json::to_vec(&CursorPayload {
            t: "2026-01-03T00:00:00+00:00",
            i: "task-a",
            e: chrono::Utc::now().timestamp() - 1,
        })
        .unwrap();
        let iv = siv(&k, unfiltered(), &payload);
        apply_keystream(&k, &iv, &mut payload);
        let expired = format!(
            "v1.{}.{}",
            URL_SAFE_NO_PAD.encode(iv),
            URL_SAFE_NO_PAD.encode(&payload)
        );
        let err = decode(&k, unfiltered(), &expired).unwrap_err();
        assert!(err.to_string().contains(INVALID_CURSOR));
    }

    #[test]
    fn rejects_malformed_shapes() {
        let k = key();
        for bad in [
            "",
            "v1",
            "v1.",
            "v1.abc",
            "v2.abc.def",
            "v1.abc.def.ghi",
            "v1.!!!.def",
        ] {
            assert!(
                decode(&k, unfiltered(), bad).is_err(),
                "must reject {bad:?}"
            );
        }
    }

    /// Every rejection path renders the same text, so a caller cannot tell a
    /// forged token from an expired one from a filter mismatch.
    #[test]
    fn every_rejection_is_indistinguishable() {
        let k = key();
        for bad in ["v1.abc.def", "not-a-cursor", "v1..", "v9.a.b"] {
            assert_eq!(
                decode(&k, unfiltered(), bad).unwrap_err().to_string(),
                format!("invalid request: {INVALID_CURSOR}")
            );
        }
    }
}
