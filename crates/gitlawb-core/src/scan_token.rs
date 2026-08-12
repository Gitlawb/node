//! Sealed continuation token for the node's bounded legacy CID scan (INV-13).
//!
//! The `/ipfs/{cid}` resolver's legacy scan stops at a row ceiling and sheds a
//! retryable 503. To let a holder buried past that ceiling still be reached, the
//! shed carries the scan position so the caller can echo it back and resume. The
//! whole point of the design is that the node keeps NO server-side scan state: the
//! position rides in the caller's token.
//!
//! That makes the token an EMITTED continuation derived from a FETCHED row, and on
//! a scan that served nothing every fetched row is by construction a private or
//! quarantined repo the caller may not read. The row's `created_at` leaks its
//! creation time and its `id` carries the owner's DID, so both halves are withheld
//! fields and the token must be CONFIDENTIAL, not merely tamper-evident:
//!
//!   * AEAD-sealed (XChaCha20-Poly1305), never base64-of-plaintext and never
//!     signed plaintext. Integrity is not confidentiality.
//!   * A fresh `OsRng` nonce on EVERY seal. Under a stream cipher a repeated nonce
//!     means repeated keystream, and an attacker who can force the node to seal a
//!     position whose plaintext they know XORs two tokens and recovers a withheld
//!     row's fields in full — strictly worse than emitting plaintext.
//!   * FIXED-WIDTH plaintext. AEAD ciphertext is plaintext-length plus the tag, and
//!     both halves of a scan position vary in length, so a variable encoding would
//!     make token LENGTH a side channel for the sealed row (a short name under a
//!     short owner vs a long one). Every token this module mints is byte-identical
//!     in length.
//!   * The canonical CID as associated data, so a token minted while scanning for
//!     one CID does not authenticate when replayed against another.
//!
//! Every failure to open — wrong key, tampered bytes, wrong CID, expired, malformed
//! — returns the same `None`. The caller treats that as "no token" and starts at the
//! front, so no failure class is distinguishable and the token is no oracle.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;

/// Keyset position of the last row a truncated scan fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanPosition {
    /// The row's raw stored `created_at` text, the first half of the keyset cursor.
    pub created_at_key: String,
    /// The row's `id`, the tiebreaking half of the keyset cursor.
    pub id: String,
}

/// Plaintext version byte, so a future layout change is a clean open-failure
/// (treated as absent) rather than a misparse.
const VERSION: u8 = 1;

/// Byte width each variable-length field is padded to. Both halves of a scan
/// position are stored at this width regardless of content, which is what keeps
/// every minted token the same length. A repo id is `<owner-key>/<name>`, so 128
/// clears a `did:key` z-base58 owner plus a long name with room to spare; anything
/// past it fails the seal loudly rather than silently truncating a cursor (a
/// truncated cursor would resume at the wrong row and skip coverage).
const FIELD_WIDTH: usize = 128;

/// `version | created_len:u16 | created[FIELD_WIDTH] | id_len:u16 | id[FIELD_WIDTH] | expires:i64`
const PLAINTEXT_LEN: usize = 1 + 2 + FIELD_WIDTH + 2 + FIELD_WIDTH + 8;

/// Nonce width for XChaCha20-Poly1305.
const NONCE_LEN: usize = 24;

/// A fresh random 32-byte sealing key from the OS CSPRNG.
pub fn new_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

// The two halves below are deliberately separate and adjacent. The framing pair owns
// "every token is the same length"; the AEAD pair owns "the contents are confidential
// and CID-bound". Keeping them apart is what lets each property be exercised — and
// broken — without disturbing the other.

/// Encode a position into the FIXED-WIDTH plaintext:
/// `version | created_len:u16 | created[FIELD_WIDTH] | id_len:u16 | id[FIELD_WIDTH] | expires:i64`
///
/// The padding is the point. AEAD ciphertext is plaintext-length plus the tag, and both
/// halves of a scan position vary in length, so a length-prefixed encoding with no
/// padding would make token LENGTH a side channel for the sealed row.
fn encode_position(pos: &ScanPosition, expires_at_unix: i64) -> anyhow::Result<Vec<u8>> {
    let mut out = vec![0u8; PLAINTEXT_LEN];
    out[0] = VERSION;
    let mut at = 1;
    for field in [pos.created_at_key.as_bytes(), pos.id.as_bytes()] {
        if field.len() > FIELD_WIDTH {
            // Loud rather than truncating: a clipped cursor resumes at the wrong row and
            // silently skips coverage, which is the availability half of the bug this
            // token exists to fix.
            anyhow::bail!(
                "scan token field is {} bytes, over the {FIELD_WIDTH}-byte fixed width",
                field.len()
            );
        }
        out[at..at + 2].copy_from_slice(&(field.len() as u16).to_le_bytes());
        at += 2;
        out[at..at + field.len()].copy_from_slice(field);
        at += FIELD_WIDTH;
    }
    out[at..at + 8].copy_from_slice(&expires_at_unix.to_le_bytes());
    Ok(out)
}

/// Decode what [`encode_position`] wrote. `None` on any structural mismatch.
fn decode_position(bytes: &[u8]) -> Option<(ScanPosition, i64)> {
    if bytes.len() != PLAINTEXT_LEN || bytes[0] != VERSION {
        return None;
    }
    let mut at = 1;
    let mut fields = [const { String::new() }; 2];
    for slot in fields.iter_mut() {
        let len = u16::from_le_bytes([bytes[at], bytes[at + 1]]) as usize;
        at += 2;
        if len > FIELD_WIDTH {
            return None;
        }
        *slot = String::from_utf8(bytes[at..at + len].to_vec()).ok()?;
        at += FIELD_WIDTH;
    }
    let expires_at = i64::from_le_bytes(bytes[at..at + 8].try_into().ok()?);
    let [created_at_key, id] = fields;
    Some((ScanPosition { created_at_key, id }, expires_at))
}

/// AEAD-seal `plaintext` under `key`, bound to `cid`, framed as `nonce || ciphertext`.
fn seal_bytes(key: &[u8; 32], cid: &str, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("scan token key: {e}"))?;
    // A FRESH nonce per seal, from the OS CSPRNG. Under a stream cipher a repeated nonce
    // repeats the keystream, and two tokens sealed under one nonce XOR to the difference
    // of their plaintexts — which recovers a withheld row in full when the attacker can
    // force one of the two positions. This draw is the property the whole confidentiality
    // claim rests on.
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let sealed = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                // The canonical CID as associated data: a token minted while scanning for
                // one CID does not authenticate against another, so it cannot be replayed
                // to seed a different scan.
                aad: cid.as_bytes(),
            },
        )
        .map_err(|e| anyhow::anyhow!("scan token seal: {e}"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + sealed.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Open what [`seal_bytes`] framed. `None` on any failure, including a wrong `cid`.
fn open_bytes(key: &[u8; 32], cid: &str, raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() <= NONCE_LEN + 16 {
        return None;
    }
    let (nonce, sealed) = raw.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new_from_slice(key).ok()?;
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: sealed,
                aad: cid.as_bytes(),
            },
        )
        .ok()
}

/// Seal `pos` under `key`, bound to `cid`, expiring at `expires_at_unix`.
///
/// Returns the base64url (no pad) token. Errors only when a field exceeds
/// [`FIELD_WIDTH`] or the AEAD itself fails — never silently truncates.
pub fn seal_scan_token(
    key: &[u8; 32],
    cid: &str,
    pos: &ScanPosition,
    expires_at_unix: i64,
) -> anyhow::Result<String> {
    let plaintext = encode_position(pos, expires_at_unix)?;
    Ok(B64URL.encode(seal_bytes(key, cid, &plaintext)?))
}

/// Open a token minted by [`seal_scan_token`] under the same key and CID.
///
/// `None` for every failure class alike (wrong key, tampered, foreign CID, expired,
/// malformed, wrong version), so the caller can treat all of them as "absent" without
/// leaking which one occurred.
pub fn open_scan_token(
    key: &[u8; 32],
    cid: &str,
    token: &str,
    now_unix: i64,
) -> Option<ScanPosition> {
    let raw = B64URL.decode(token).ok()?;
    let plaintext = open_bytes(key, cid, &raw)?;
    let (pos, expires_at) = decode_position(&plaintext)?;
    if now_unix >= expires_at {
        return None;
    }
    Some(pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pos(created: &str, id: &str) -> ScanPosition {
        ScanPosition {
            created_at_key: created.to_string(),
            id: id.to_string(),
        }
    }

    #[test]
    fn round_trips_under_the_same_key_and_cid() {
        let key = new_key();
        let p = pos("2020-01-01T00:00:03+00:00", "z6MkOwner/private-repo");
        let t = seal_scan_token(&key, "bafkcid", &p, 1 << 40).unwrap();
        assert_eq!(open_scan_token(&key, "bafkcid", &t, 0), Some(p));
    }

    #[test]
    fn every_failure_class_opens_to_none() {
        let key = new_key();
        let other = new_key();
        let p = pos("2020-01-01T00:00:03+00:00", "z6MkOwner/private-repo");
        let t = seal_scan_token(&key, "bafkcid", &p, 1 << 40).unwrap();

        assert_eq!(open_scan_token(&other, "bafkcid", &t, 0), None, "wrong key");
        assert_eq!(
            open_scan_token(&key, "bafkOTHER", &t, 0),
            None,
            "foreign CID"
        );
        assert_eq!(
            open_scan_token(&key, "bafkcid", &t, 1 << 41),
            None,
            "expired"
        );
        assert_eq!(open_scan_token(&key, "bafkcid", "!!not b64", 0), None);
        assert_eq!(open_scan_token(&key, "bafkcid", "", 0), None);
        let mut flipped: Vec<u8> = t.bytes().collect();
        let last = flipped.len() - 1;
        flipped[last] = if flipped[last] == b'A' { b'B' } else { b'A' };
        assert_eq!(
            open_scan_token(&key, "bafkcid", &String::from_utf8(flipped).unwrap(), 0),
            None,
            "tampered"
        );
    }

    #[test]
    fn a_field_over_the_fixed_width_fails_loudly() {
        let key = new_key();
        let p = pos("2020-01-01T00:00:03+00:00", &"x".repeat(FIELD_WIDTH + 1));
        assert!(
            seal_scan_token(&key, "bafkcid", &p, 1 << 40).is_err(),
            "an over-wide field must fail the seal, never be truncated into a cursor \
             that resumes at the wrong row"
        );
    }
}
