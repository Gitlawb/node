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
//!     row's fields in full, strictly worse than emitting plaintext.
//!   * FIXED-WIDTH plaintext. AEAD ciphertext is plaintext-length plus the tag, and
//!     every field of a scan position varies in length, so a variable encoding would
//!     make token LENGTH a side channel for the sealed row (a short name under a
//!     short owner vs a long one) and for the candidate oid's width (40 hex on a
//!     sha1 repo, 64 on a sha256 one). Every token this module mints is byte-identical
//!     in length. Each field is padded to its own separate width, which is a per-field
//!     constant and so still leaks nothing about a given row or candidate.
//!   * The canonical CID as associated data, so a token minted while scanning for
//!     one CID does not authenticate when replayed against another.
//!
//! Every failure to open (wrong key, tampered bytes, wrong CID, expired, malformed)
//! returns the same `None`. The caller treats that as "no token" and starts at the
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
    /// The oid hex of the CANDIDATE this position resumes. One CID can map to several
    /// git oids, so a bare row cursor names a row without naming whose walk it belongs
    /// to. The candidate is named by IDENTITY rather than by position in the candidate
    /// list: that list is ordered by hex and mutates between rungs, so an index would
    /// name a different candidate the moment anything is pinned or unpinned.
    pub sha256_hex: String,
}

/// Plaintext version byte, so a future layout change is a clean open-failure
/// (treated as absent) rather than a misparse.
///
/// Bumped to 2 when the two halves stopped sharing one width (see [`ID_WIDTH`]), and
/// to 3 when the position gained the candidate oid it resumes (see [`OID_WIDTH`]).
/// A token minted under an earlier layout is a different length and a different
/// framing, so it opens to `None` and the caller restarts at the front, which is the
/// safe direction: a misparse would resume at a fabricated row and skip coverage.
const VERSION: u8 = 3;

/// Byte width the `created_at` half is padded to. Every value stored here is a
/// serialized timestamp, about 30 bytes, so 64 is roomy for the field's whole domain.
/// It is deliberately NOT widened to match [`ID_WIDTH`]: padding both halves to the id
/// width would nearly double every token for a field that can never use the space.
const CREATED_WIDTH: usize = 64;

/// Byte width the `id` half is padded to.
///
/// The bound is set by the WRITERS, not by what a typical id happens to look like.
/// `upsert_mirror_repo` builds `repos.id` as `{owner}/{name}`, and the slug validators
/// in the node's `repo_store` admit an owner of up to 255 bytes and a name of up to
/// 100, so 356 bytes is reachable through the ordinary write path and repo names are
/// peer-controllable. 384 clears that with margin.
///
/// Under-sizing this is not a cosmetic bug. A row at a truncation boundary whose id
/// exceeds the width fails the seal, the handler sheds a 503 with no continuation, and
/// a tokenless shed is byte-identical to the wrapped-scan response whose contract is
/// "the absence of a token means the ladder is over". The boundary row is deterministic
/// for a stable inventory, so every retry reproduces it and every row past it becomes
/// permanently unreachable. Anything past the width still fails loudly rather than
/// silently truncating a cursor into one that resumes at the wrong row.
const ID_WIDTH: usize = 384;

/// Byte width the candidate oid half is padded to.
///
/// Git mints exactly two oid widths and this field carries BOTH. A production repo is
/// created by `store::init_bare` with `git init --bare --object-format=sha1`, so its
/// oids are 40 hex; only the sha256 test fixtures mint 64. The field is therefore
/// length-prefixed like the two row halves rather than a bare fixed 64: a 64-only
/// field would fail every seal on a real deployment, and a failed seal sheds a
/// tokenless 503 that is byte-identical to "your ladder is over".
///
/// The padding to 64 is what keeps the WIDTH off the wire. Without it a 40-hex token
/// is 24 bytes shorter than a 64-hex one, and token length would say which object
/// format the holder's repo uses.
const OID_WIDTH: usize = 64;

/// `version | created_len:u16 | created[CREATED_WIDTH] | id_len:u16 | id[ID_WIDTH] | oid_len:u16 | oid[OID_WIDTH] | expires:i64`
const PLAINTEXT_LEN: usize = 1 + 2 + CREATED_WIDTH + 2 + ID_WIDTH + 2 + OID_WIDTH + 8;

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
// and CID-bound". Keeping them apart is what lets each property be exercised (and
// broken) without disturbing the other.

/// Encode a position into the FIXED-WIDTH plaintext:
/// `version | created_len:u16 | created[CREATED_WIDTH] | id_len:u16 | id[ID_WIDTH] | oid_len:u16 | oid[OID_WIDTH] | expires:i64`
///
/// The padding is the point. AEAD ciphertext is plaintext-length plus the tag, and every
/// field of a scan position varies in length, so a length-prefixed encoding with no
/// padding would make token LENGTH a side channel for the sealed row and for the
/// candidate's object format. Each field is padded to its OWN fixed width, which keeps
/// every minted token the same length while letting the id half carry the range the
/// write path actually admits.
fn encode_position(pos: &ScanPosition, expires_at_unix: i64) -> anyhow::Result<Vec<u8>> {
    let mut out = vec![0u8; PLAINTEXT_LEN];
    out[0] = VERSION;
    let mut at = 1;
    for (field, width) in [
        (pos.created_at_key.as_bytes(), CREATED_WIDTH),
        (pos.id.as_bytes(), ID_WIDTH),
        (pos.sha256_hex.as_bytes(), OID_WIDTH),
    ] {
        if field.len() > width {
            // Loud rather than truncating: a clipped cursor resumes at the wrong row and
            // silently skips coverage, which is the availability half of the bug this
            // token exists to fix.
            anyhow::bail!(
                "scan token field is {} bytes, over the {width}-byte fixed width",
                field.len()
            );
        }
        out[at..at + 2].copy_from_slice(&(field.len() as u16).to_le_bytes());
        at += 2;
        out[at..at + field.len()].copy_from_slice(field);
        at += width;
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
    let mut fields = [const { String::new() }; 3];
    for (slot, width) in fields.iter_mut().zip([CREATED_WIDTH, ID_WIDTH, OID_WIDTH]) {
        let len = u16::from_le_bytes([bytes[at], bytes[at + 1]]) as usize;
        at += 2;
        if len > width {
            return None;
        }
        *slot = String::from_utf8(bytes[at..at + len].to_vec()).ok()?;
        at += width;
    }
    let expires_at = i64::from_le_bytes(bytes[at..at + 8].try_into().ok()?);
    let [created_at_key, id, sha256_hex] = fields;
    // A zero-length candidate is a third state the encoder never mints. The front-of-table
    // sentinel is empty ROW halves with a real oid, so an empty oid would hand the resume
    // path a candidate that names nothing; refuse it like every other malformed frame.
    if sha256_hex.is_empty() {
        return None;
    }
    Some((
        ScanPosition {
            created_at_key,
            id,
            sha256_hex,
        },
        expires_at,
    ))
}

/// AEAD-seal `plaintext` under `key`, bound to `cid`, framed as `nonce || ciphertext`.
fn seal_bytes(key: &[u8; 32], cid: &str, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("scan token key: {e}"))?;
    // A FRESH nonce per seal, from the OS CSPRNG. Under a stream cipher a repeated nonce
    // repeats the keystream, and two tokens sealed under one nonce XOR to the difference
    // of their plaintexts, which recovers a withheld row in full when the attacker can
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
/// its own fixed width ([`CREATED_WIDTH`], [`ID_WIDTH`], [`OID_WIDTH`]) or the AEAD
/// itself fails, never silently truncates.
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

    /// A production-shaped candidate: `git init --bare --object-format=sha1`, so 40 hex.
    const OID_40: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
    /// A test-fixture-shaped candidate: the sha256 repos the suite creates mint 64 hex.
    const OID_64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn pos(created: &str, id: &str) -> ScanPosition {
        pos_for(created, id, OID_40)
    }

    fn pos_for(created: &str, id: &str, sha256_hex: &str) -> ScanPosition {
        ScanPosition {
            created_at_key: created.to_string(),
            id: id.to_string(),
            sha256_hex: sha256_hex.to_string(),
        }
    }

    /// Seal a hand-built plaintext through the AEAD half, so a test can frame bytes the
    /// encoder would never mint (an old version byte, a zero-length oid) and still exercise
    /// the real open path.
    fn seal_raw(key: &[u8; 32], cid: &str, plaintext: &[u8]) -> String {
        B64URL.encode(seal_bytes(key, cid, plaintext).unwrap())
    }

    /// Byte offset of the oid length prefix inside the plaintext, derived from the widths
    /// rather than hardcoded so a width change moves it with the layout.
    const OID_LEN_AT: usize = 1 + 2 + CREATED_WIDTH + 2 + ID_WIDTH;

    /// Scenario 1: both of git's oid widths round trip. The 40-hex case is the PRODUCTION
    /// shape (`git init --bare --object-format=sha1`), and an all-64 fixture suite would
    /// never exercise it, which is exactly how a fixed-64 field would ship broken.
    #[test]
    fn round_trips_at_both_oid_widths() {
        let key = new_key();
        for hex in [OID_40, OID_64] {
            let p = pos_for("2020-01-01T00:00:03+00:00", "z6MkOwner/private-repo", hex);
            let t =
                seal_scan_token(&key, "bafkcid", &p, 1 << 40).expect("both oid widths must seal");
            assert_eq!(
                open_scan_token(&key, "bafkcid", &t, 0),
                Some(p),
                "a {}-hex candidate must open to the identical position",
                hex.len()
            );
        }
    }

    /// Scenario 2: a token framed under the OLD version opens to `None`, never a misparse.
    /// Both legs matter: the version-2 plaintext was a different LENGTH, and a future
    /// same-length layout would only be caught by the version byte itself.
    #[test]
    fn a_prior_layout_version_opens_to_none() {
        let key = new_key();

        // The version-2 layout verbatim: no oid field, so 461 bytes.
        let mut old = vec![0u8; 1 + 2 + CREATED_WIDTH + 2 + ID_WIDTH + 8];
        old[0] = 2;
        assert_eq!(old.len(), 461, "the version-2 plaintext was 461 bytes");
        assert_eq!(
            open_scan_token(&key, "bafkcid", &seal_raw(&key, "bafkcid", &old), 0),
            None,
            "a version-2 token must open to None so the caller restarts at the front"
        );

        // Same length, stale version byte: only the version check can refuse this one.
        let mut stamped = encode_position(
            &pos("2020-01-01T00:00:03+00:00", "z6MkOwner/private-repo"),
            1 << 40,
        )
        .unwrap();
        stamped[0] = VERSION - 1;
        assert_eq!(
            open_scan_token(&key, "bafkcid", &seal_raw(&key, "bafkcid", &stamped), 0),
            None,
            "a stale version byte must open to None even at the current width"
        );
    }

    /// Scenario 3: token length is invariant across candidate VALUE and candidate WIDTH.
    /// The padding is what keeps the oid width off the wire: without it a 40-hex token is
    /// 24 bytes shorter than a 64-hex one and the length says which repo format the
    /// holder uses.
    #[test]
    fn token_length_is_invariant_across_oid_widths() {
        let key = new_key();
        let created = "2020-01-01T00:00:00+00:00";
        let id = "z6MkOwner/private-repo";
        let short =
            seal_scan_token(&key, "bafkcid", &pos_for(created, id, OID_40), 1 << 40).unwrap();
        let long =
            seal_scan_token(&key, "bafkcid", &pos_for(created, id, OID_64), 1 << 40).unwrap();
        assert_eq!(
            short.len(),
            long.len(),
            "a 40-hex and a 64-hex candidate must mint tokens of identical length, or the \
             oid width is a side channel"
        );

        // The absolute width, pinned by execution rather than by arithmetic on paper. The
        // gl client's mock fixtures hardcode this number (`TOKEN_LEN` in
        // crates/gl/src/ipfs_cmd.rs), and nothing in that crate seals a real token, so this
        // assertion is the only executable check that the two agree.
        assert_eq!(
            short.len(),
            756,
            "24 nonce + {PLAINTEXT_LEN} plaintext + 16 tag, base64url no pad"
        );
    }

    /// Scenario 4: the front-of-table sentinel. Empty row halves with a REAL candidate
    /// round trip, which is what lets a seal say "this candidate, no row cursor yet".
    #[test]
    fn empty_row_fields_round_trip_with_a_real_candidate() {
        let key = new_key();
        let p = pos_for("", "", OID_40);
        let t =
            seal_scan_token(&key, "bafkcid", &p, 1 << 40).expect("the front sentinel must seal");
        assert_eq!(open_scan_token(&key, "bafkcid", &t, 0), Some(p));
    }

    /// Scenario 6, third leg: a zero-length oid is a distinguishable third state that the
    /// encoder never mints, and accepting it would hand the sentinel machinery a candidate
    /// naming nothing. The decode path refuses it.
    #[test]
    fn a_zero_length_candidate_opens_to_none() {
        let key = new_key();
        let mut plaintext = encode_position(
            &pos("2020-01-01T00:00:03+00:00", "z6MkOwner/private-repo"),
            1 << 40,
        )
        .unwrap();
        plaintext[OID_LEN_AT..OID_LEN_AT + 2].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            open_scan_token(&key, "bafkcid", &seal_raw(&key, "bafkcid", &plaintext), 0),
            None,
            "a zero-length candidate must open to None, not to a position naming nothing"
        );
    }

    /// Scenario 6, second leg: an oid past the 64-byte width fails the seal loudly rather
    /// than being clipped into a hex that names a different candidate.
    #[test]
    fn an_oid_over_the_fixed_width_fails_loudly() {
        let key = new_key();
        let p = pos_for(
            "2020-01-01T00:00:03+00:00",
            "z6MkOwner/private-repo",
            &"a".repeat(OID_WIDTH + 1),
        );
        assert!(
            seal_scan_token(&key, "bafkcid", &p, 1 << 40).is_err(),
            "an over-wide candidate must fail the seal, never be truncated into a hex that \
             resumes the wrong candidate"
        );
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

    /// The id half must clear the LARGEST repo id the node's own write path admits,
    /// not merely a typical one. `upsert_mirror_repo` builds `repos.id` as
    /// `{owner}/{name}`, and the slug validators in `repo_store` admit 255 bytes of
    /// owner and 100 of name, so 356 is reachable. A width under that turns the
    /// boundary row into a seal failure, which sheds a tokenless 503 that is
    /// byte-identical to "your ladder is over" and strands every row past it forever.
    #[test]
    fn round_trips_a_repo_id_at_the_write_paths_maximum() {
        let key = new_key();
        let id = format!("{}/{}", "o".repeat(255), "n".repeat(100));
        assert_eq!(id.len(), 356, "255 owner + '/' + 100 name");
        let p = pos("2020-01-01T00:00:03+00:00", &id);
        let t = seal_scan_token(&key, "bafkcid", &p, 1 << 40)
            .expect("a repo id the write path admits must seal, never fail the width");
        assert_eq!(open_scan_token(&key, "bafkcid", &t, 0), Some(p));
    }

    #[test]
    fn a_field_over_the_fixed_width_fails_loudly() {
        let key = new_key();
        let p = pos("2020-01-01T00:00:03+00:00", &"x".repeat(ID_WIDTH + 1));
        assert!(
            seal_scan_token(&key, "bafkcid", &p, 1 << 40).is_err(),
            "an over-wide field must fail the seal, never be truncated into a cursor \
             that resumes at the wrong row"
        );
    }
}
