//! Envelope encryption for withheld blobs (Option B). A random content key
//! encrypts the blob (XChaCha20-Poly1305); the content key is wrapped to each
//! recipient via an X25519 box keyed from their Ed25519 `did:key`. The node
//! seals with public keys only; readers open with their own private key.

use crate::identity::Keypair;
use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use zeroize::Zeroizing;

/// X25519 public key (Montgomery u) for an Ed25519 verifying key.
fn x25519_public(vk: &VerifyingKey) -> Result<[u8; 32]> {
    use curve25519_dalek::edwards::CompressedEdwardsY;

    // Every X25519 shared secret derived from a small-order point is the
    // all-zero key: order-1 and order-2 convert to the all-zero Montgomery u
    // directly, order-4 and order-8 are annihilated by the scalar clamping in
    // x25519_secret_from_seed. Either way the per-recipient wrap could be
    // rebuilt by anyone. Resolution already refuses such a key (see
    // Did::to_verifying_key); this guard covers the SEAL side on its own terms
    // for a caller that obtained the key some other way. The open side
    // (open_blob's attacker-supplied `eph`) skips any entry whose exchange with
    // this reader yields the all-zero shared secret
    // (`yields_all_zero_shared_secret`), regardless of whether the bytes decode
    // to an Edwards point.
    if vk.is_weak() {
        return Err(anyhow::anyhow!("verifying key is a small-order point"));
    }

    let edwards = CompressedEdwardsY::from_slice(vk.as_bytes())
        .ok()
        .and_then(|c| c.decompress())
        .context("verifying key is not a valid edwards point")?;
    Ok(edwards.to_montgomery().to_bytes())
}

/// True when the X25519 exchange between an attacker-supplied `u` and this
/// reader's scalar yields the all-zero shared secret.
///
/// Asked of the RESULT, not of the encoding, and that distinction is the whole
/// guard. The previous version decompressed `u` to an Edwards point and asked
/// `is_small_order`, which reports "safe" for any low-order encoding that does
/// not decompress at all. Measured across the seven standard low-order
/// encodings, six were caught and `u = p - 1` was not: it fails to decompress,
/// so the check returned false, and the exchange is still the all-zero secret.
/// An entry built on it unwraps for every reader.
///
/// Enumerating encodings cannot be exhaustive, because the attack depends on the
/// shared secret rather than on the bytes that produced it, and twist and
/// non-canonical inputs keep arriving. Asking the result needs no list.
fn yields_all_zero_shared_secret(u: &[u8; 32], scalar: &[u8; 32]) -> bool {
    use curve25519_dalek::montgomery::MontgomeryPoint;

    MontgomeryPoint(*u).mul_clamped(*scalar).to_bytes() == [0u8; 32]
}

/// X25519 secret scalar for an Ed25519 seed (SHA-512 of seed, lower 32, clamped).
/// Returns the scalar wrapped in `Zeroizing`, and scrubs the intermediate
/// SHA-512 digest, so no copy of this secret material lingers in freed memory.
fn x25519_secret_from_seed(seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    use sha2::{Digest, Sha512};
    use zeroize::Zeroize;
    let mut h = Sha512::digest(seed);
    let mut s = Zeroizing::new([0u8; 32]);
    s.copy_from_slice(&h[..32]);
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
    h.as_mut_slice().zeroize();
    s
}

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use crypto_box::{
    aead::{AeadCore, OsRng},
    ChaChaBox, PublicKey as XPublic, SecretKey as XSecret,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

const MAGIC: &[u8] = b"GLENC";
const VERSION: u8 = 2;

#[derive(Serialize, Deserialize)]
struct Recipient {
    eph: String,   // base64 ephemeral x25519 pubkey (32B)
    nonce: String, // base64 box nonce (24B)
    wrap: String,  // base64 wrapped content key
}

#[derive(Serialize, Deserialize)]
struct Header {
    alg: String,
    nonce: String, // base64 body nonce (24B)
    recipients: Vec<Recipient>,
}

/// Encrypt `plaintext` so any of `recipients` (Ed25519 keys) can decrypt.
pub fn seal_blob(plaintext: &[u8], recipients: &[VerifyingKey]) -> Result<Vec<u8>> {
    if recipients.is_empty() {
        return Err(anyhow::anyhow!("seal_blob: no recipients"));
    }
    let mut content_key = [0u8; 32];
    OsRng.fill_bytes(&mut content_key);
    let body_cipher = XChaCha20Poly1305::new_from_slice(&content_key)
        .map_err(|e| anyhow::anyhow!("content key: {e}"))?;
    let mut body_nonce = [0u8; 24];
    OsRng.fill_bytes(&mut body_nonce);
    let body = body_cipher
        .encrypt(XNonce::from_slice(&body_nonce), plaintext)
        .map_err(|e| anyhow::anyhow!("body encrypt: {e}"))?;

    let mut wrapped = Vec::with_capacity(recipients.len());
    for vk in recipients {
        let recip_x = XPublic::from(x25519_public(vk)?);
        let eph = XSecret::generate(&mut OsRng);
        let abox = ChaChaBox::new(&recip_x, &eph);
        let nonce = ChaChaBox::generate_nonce(&mut OsRng);
        let ct = abox
            .encrypt(&nonce, &content_key[..])
            .map_err(|e| anyhow::anyhow!("wrap: {e}"))?;
        wrapped.push(Recipient {
            eph: B64.encode(eph.public_key().as_bytes()),
            nonce: B64.encode(nonce),
            wrap: B64.encode(ct),
        });
    }

    let header = Header {
        alg: "xchacha20poly1305".into(),
        nonce: B64.encode(body_nonce),
        recipients: wrapped,
    };
    let header_json = serde_json::to_vec(&header).context("encode header")?;

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_json);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decrypt an envelope with `keypair`. Errors if not a recipient or on auth fail.
pub fn open_blob(envelope: &[u8], keypair: &Keypair) -> Result<Vec<u8>> {
    let mut p = 0;
    if envelope.len() < MAGIC.len() + 1 + 4 || &envelope[..MAGIC.len()] != MAGIC {
        return Err(anyhow::anyhow!("bad envelope magic"));
    }
    p += MAGIC.len();
    if envelope[p] != VERSION {
        return Err(anyhow::anyhow!("unsupported envelope version"));
    }
    p += 1;
    let hlen = u32::from_le_bytes(envelope[p..p + 4].try_into().unwrap()) as usize;
    p += 4;
    let header: Header =
        serde_json::from_slice(envelope.get(p..p + hlen).context("truncated header")?)
            .context("decode header")?;
    let body = &envelope[p + hlen..];

    // The raw scalar is kept alongside the box secret so the exchange can be
    // tested BEFORE a box is built from an attacker-supplied ephemeral.
    let my_x_scalar = x25519_secret_from_seed(&keypair.to_seed());
    let my_x = XSecret::from(*my_x_scalar);

    // Identities are blinded: no entry says which recipient it belongs to, so
    // try each one. The ChaChaBox AEAD tag authenticates, so exactly the
    // reader's own entry unwraps; every other entry fails cleanly.
    let mut content_key: Option<Vec<u8>> = None;
    for entry in &header.recipients {
        let eph = match B64
            .decode(&entry.eph)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        {
            // An ephemeral whose exchange with this reader is the all-zero
            // shared secret would unwrap for anyone, so the entry is skipped.
            // Tested on the exchange itself: an encoding-shaped check misses
            // every low-order input that does not decompress to Edwards.
            Some(b) if !yields_all_zero_shared_secret(&b, &my_x_scalar) => XPublic::from(b),
            Some(_) => continue,
            None => continue,
        };
        // from_slice panics on a wrong length, and the envelope is attacker
        // controlled, so validate the 24-byte box nonce before using it.
        let nonce = match B64
            .decode(&entry.nonce)
            .ok()
            .and_then(|n| <[u8; 24]>::try_from(n.as_slice()).ok())
        {
            Some(n) => n,
            None => continue,
        };
        let wrap = match B64.decode(&entry.wrap) {
            Ok(w) => w,
            Err(_) => continue,
        };
        let abox = ChaChaBox::new(&eph, &my_x);
        if let Ok(ck) = abox.decrypt(
            crypto_box::aead::generic_array::GenericArray::from_slice(&nonce),
            wrap.as_slice(),
        ) {
            content_key = Some(ck);
            break;
        }
    }
    let content_key = content_key.context("not a recipient of this envelope")?;

    let body_cipher = XChaCha20Poly1305::new_from_slice(&content_key)
        .map_err(|e| anyhow::anyhow!("content key: {e}"))?;
    let body_nonce = B64
        .decode(&header.nonce)
        .ok()
        .and_then(|n| <[u8; 24]>::try_from(n.as_slice()).ok())
        .context("invalid body nonce")?;
    body_cipher
        .decrypt(XNonce::from_slice(&body_nonce), body)
        .map_err(|_| anyhow::anyhow!("body decrypt failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Keypair;

    #[test]
    fn ed25519_to_x25519_keypair_agrees() {
        // The X25519 public derived from the Ed25519 public must equal the
        // X25519 public of the X25519 secret derived from the same seed.
        let kp = Keypair::generate();
        let seed = kp.to_seed();
        let xpub_from_public = x25519_public(&kp.verifying_key()).unwrap();
        let xsec = x25519_secret_from_seed(&seed);
        let xpub_from_secret = crypto_box::SecretKey::from(*xsec).public_key().to_bytes();
        assert_eq!(xpub_from_public, xpub_from_secret);
    }

    #[test]
    fn seal_open_round_trip_for_recipients() {
        let owner = Keypair::generate();
        let reader_a = Keypair::generate();
        let reader_b = Keypair::generate();
        let msg = b"private blob contents";

        let env = seal_blob(msg, &[owner.verifying_key(), reader_a.verifying_key()]).unwrap();

        assert_eq!(open_blob(&env, &owner).unwrap(), msg);
        assert_eq!(open_blob(&env, &reader_a).unwrap(), msg);
        assert!(
            open_blob(&env, &reader_b).is_err(),
            "non-recipient must fail"
        );
    }

    #[test]
    fn tampered_envelope_fails() {
        let owner = Keypair::generate();
        let mut env = seal_blob(b"hi", &[owner.verifying_key()]).unwrap();
        let last = env.len() - 1;
        env[last] ^= 0x01;
        assert!(open_blob(&env, &owner).is_err());
    }

    #[test]
    fn v2_header_contains_no_recipient_pubkey() {
        // The blinded envelope header must not carry any recipient's public key.
        let reader = Keypair::generate();
        let env = seal_blob(b"private blob contents", &[reader.verifying_key()]).unwrap();

        // Slice out the header bytes using the envelope framing:
        // MAGIC | version(1B) | header_len(4B LE) | header_json | body
        let mut p = MAGIC.len() + 1; // skip MAGIC + version byte
        let hlen = u32::from_le_bytes(env[p..p + 4].try_into().unwrap()) as usize;
        p += 4;
        let header = &env[p..p + hlen];
        let header_str = String::from_utf8_lossy(header);

        let pubkey_b64 = B64.encode(reader.verifying_key().as_bytes());
        assert!(
            !header_str.contains(&pubkey_b64),
            "recipient public key must not appear in the blinded header"
        );
    }

    #[test]
    fn v1_envelope_is_rejected() {
        let reader = Keypair::generate();
        let mut env = seal_blob(b"hi", &[reader.verifying_key()]).unwrap();
        // Flip the version byte (immediately after MAGIC) from 2 to 1.
        env[MAGIC.len()] = 1;
        let err = open_blob(&env, &reader).unwrap_err();
        assert!(
            err.to_string().contains("unsupported envelope version"),
            "expected version-rejection error, got: {err}"
        );
    }

    #[test]
    fn malformed_nonce_returns_err_not_panic() {
        // from_slice panics on wrong-length input; a crafted envelope on the
        // public recovery path must surface an error, never panic.
        let reader = Keypair::generate();
        let env = seal_blob(b"private blob contents", &[reader.verifying_key()]).unwrap();

        // Split the envelope framing into header JSON and body.
        let mut p = MAGIC.len() + 1;
        let hlen = u32::from_le_bytes(env[p..p + 4].try_into().unwrap()) as usize;
        p += 4;
        let header_bytes = &env[p..p + hlen];
        let body = &env[p + hlen..];

        let reframe = |header: &serde_json::Value| -> Vec<u8> {
            let hj = serde_json::to_vec(header).unwrap();
            let mut out = Vec::new();
            out.extend_from_slice(MAGIC);
            out.push(VERSION);
            out.extend_from_slice(&(hj.len() as u32).to_le_bytes());
            out.extend_from_slice(&hj);
            out.extend_from_slice(body);
            out
        };
        let bad_nonce = serde_json::Value::String(B64.encode([0u8; 12]));

        // Corrupted per-recipient nonce: entry is skipped, no match.
        let mut header: serde_json::Value = serde_json::from_slice(header_bytes).unwrap();
        header["recipients"][0]["nonce"] = bad_nonce.clone();
        assert!(open_blob(&reframe(&header), &reader).is_err());

        // Corrupted body nonce: unwrap succeeds, body nonce is rejected.
        let mut header: serde_json::Value = serde_json::from_slice(header_bytes).unwrap();
        header["nonce"] = bad_nonce;
        assert!(open_blob(&reframe(&header), &reader).is_err());
    }

    /// Every standard low-order X25519 encoding must be detected by
    /// `yields_all_zero_shared_secret`, including encodings that do not
    /// decompress to an Edwards point (notably `u = p - 1`). The open side
    /// rejects on the exchange result, not on decode shape, because an
    /// encoding-shaped check misses non-decompressing low-order inputs while
    /// still yielding the all-zero shared secret.
    #[test]
    fn all_zero_shared_secret_is_detected_for_every_standard_low_order_encoding() {
        // The seven standard X25519 low-order encodings, driven as a set rather
        // than as the two that happen to decompress. The encoding-shaped check
        // this replaced reported `p - 1` as safe, and its exchange is all-zero.
        let mut one = [0u8; 32];
        one[0] = 1;
        let hex = |h: &str| -> [u8; 32] {
            let mut out = [0u8; 32];
            for i in 0..32 {
                out[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
            }
            out
        };
        let vectors = [
            ("u=0", [0u8; 32]),
            ("u=1", one),
            (
                "order8-a",
                hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
            ),
            (
                "order8-b",
                hex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
            ),
            (
                "p-1",
                hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            ),
            (
                "p",
                hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            ),
            (
                "p+1",
                hex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            ),
        ];
        let kp = Keypair::generate();
        let scalar = x25519_secret_from_seed(&kp.to_seed());
        for (name, u) in vectors {
            assert!(
                yields_all_zero_shared_secret(&u, &scalar),
                "{name} is a low-order encoding and must be detected"
            );
        }

        // And the other direction, or a guard that returned true always would
        // pass everything above while making the envelope unopenable.
        let real_u = x25519_public(&kp.verifying_key()).unwrap();
        assert!(
            !yields_all_zero_shared_secret(&real_u, &scalar),
            "a real key must not be treated as low-order"
        );
    }

    /// The open side must skip an entry whose header-supplied `eph` is a
    /// low-order point: such an entry forces the all-zero shared secret and
    /// would unwrap for any reader. A poisoned entry among honest ones must
    /// not DoS the envelope — the honest entry still opens.
    #[test]
    fn open_blob_skips_a_low_order_ephemeral_and_still_opens_honest_entry() {
        use curve25519_dalek::montgomery::MontgomeryPoint;
        let reader = Keypair::generate();
        let env = seal_blob(b"private blob contents", &[reader.verifying_key()]).unwrap();

        // Split the envelope framing into header JSON and body.
        let mut p = MAGIC.len() + 1;
        let hlen = u32::from_le_bytes(env[p..p + 4].try_into().unwrap()) as usize;
        p += 4;
        let header_bytes = &env[p..p + hlen];
        let body = &env[p + hlen..];

        // A low-order Montgomery u (u = 0) encoded as the entry's eph.
        let low_order_u = MontgomeryPoint([0u8; 32]).to_bytes();
        let poisoned = serde_json::json!({
            "eph": B64.encode(low_order_u),
            "nonce": B64.encode([0u8; 24]),
            "wrap": B64.encode([0u8; 32]),
        });

        let reframe = |header: &serde_json::Value| -> Vec<u8> {
            let hj = serde_json::to_vec(header).unwrap();
            let mut out = Vec::new();
            out.extend_from_slice(MAGIC);
            out.push(VERSION);
            out.extend_from_slice(&(hj.len() as u32).to_le_bytes());
            out.extend_from_slice(&hj);
            out.extend_from_slice(body);
            out
        };

        let mut header: serde_json::Value = serde_json::from_slice(header_bytes).unwrap();
        // Prepend the poisoned entry. The reader's honest entry must still
        // unwrap, so the envelope opens despite the low-order entry.
        let recipients = header["recipients"].as_array_mut().unwrap();
        recipients.insert(0, poisoned);
        assert_eq!(
            open_blob(&reframe(&header), &reader).unwrap(),
            b"private blob contents",
            "the honest entry must still open despite a low-order eph entry"
        );
    }

    /// Must-not for the open-side guard: an envelope whose ONLY entry is built
    /// on a low-order ephemeral must not open for any reader. Without the
    /// guard the all-zero shared secret unwraps for everyone, so the attacker
    /// controls the plaintext and the envelope's confidentiality is void.
    #[test]
    fn open_blob_rejects_a_poisoned_only_envelope() {
        use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
        use crypto_box::aead::AeadCore;
        use curve25519_dalek::montgomery::MontgomeryPoint;

        // Build a poisoned envelope from scratch: one recipient entry whose
        // eph is the low-order u = 0. The wrap is the encryption of a content
        // key under the all-zero shared secret, so without the guard any
        // reader's ChaChaBox against u = 0 decrypts it.
        let mut content_key = [0u8; 32];
        OsRng.fill_bytes(&mut content_key);
        let attacker_x = XSecret::generate(&mut OsRng);
        let zero_box = ChaChaBox::new(&XPublic::from([0u8; 32]), &attacker_x);
        let nonce = ChaChaBox::generate_nonce(&mut OsRng);
        let wrap = zero_box.encrypt(&nonce, &content_key[..]).unwrap();

        let body_nonce = [0x24u8; 24];
        let body_cipher = XChaCha20Poly1305::new_from_slice(&content_key).unwrap();
        let body = body_cipher
            .encrypt(
                XNonce::from_slice(&body_nonce),
                b"attacker-chosen plaintext".as_slice(),
            )
            .unwrap();

        let header = serde_json::json!({
            "alg": "xchacha20poly1305",
            "nonce": B64.encode(body_nonce),
            "recipients": [{
                "eph": B64.encode(MontgomeryPoint([0u8; 32]).to_bytes()),
                "nonce": B64.encode(nonce),
                "wrap": B64.encode(wrap),
            }],
        });
        let header_json = serde_json::to_vec(&header).unwrap();
        let mut env = Vec::new();
        env.extend_from_slice(MAGIC);
        env.push(VERSION);
        env.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
        env.extend_from_slice(&header_json);
        env.extend_from_slice(&body);

        let reader = Keypair::generate();
        let err = open_blob(&env, &reader).unwrap_err();
        assert!(
            err.to_string().contains("not a recipient"),
            "a poisoned-only envelope must not open for anyone, got: {err}"
        );
    }

    /// The same must-not, driven with the low-order encoding that does NOT map
    /// to an Edwards point.
    ///
    /// This is the case an encoding-shaped guard cannot see. `u = p - 1` is a
    /// legal X25519 input whose exchange is the all-zero secret for any scalar,
    /// and `MontgomeryPoint::to_edwards` returns None for it, so a check written
    /// as "decompress, then ask is_small_order" reports it as safe. Measured
    /// across the seven standard low-order encodings: six are caught that way
    /// and this one is not.
    ///
    /// Found by a cross-family review of the head that first added the guard,
    /// and the comment beside that guard asserted this case was already handled
    /// by a decode path that does not exist. That is why the fix rejects on the
    /// RESULT of the exchange rather than on a list of encodings: the result is
    /// what the attack actually depends on, and it needs no enumeration to be
    /// exhaustive.
    #[test]
    fn open_blob_rejects_a_non_edwards_low_order_ephemeral() {
        // No blanket `use ...::Aead` here. Two aead versions are reachable, and a
        // blanket import silently resolved the wrap through the one open_blob does
        // NOT decrypt with, producing a ciphertext that could never open. The test
        // then passed with the guard, without it, and with the original pre-fix
        // guard alike, proving nothing. Every call below names its trait.
        use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
        use crypto_box::aead::AeadCore;

        // u = p - 1 = 2^255 - 20, little endian.
        let mut eph = [0xffu8; 32];
        eph[0] = 0xec;
        eph[31] = 0x7f;

        let mut content_key = [0u8; 32];
        OsRng.fill_bytes(&mut content_key);
        let attacker_x = XSecret::generate(&mut OsRng);
        let zero_box = ChaChaBox::new(&XPublic::from([0u8; 32]), &attacker_x);
        let nonce = ChaChaBox::generate_nonce(&mut OsRng);
        let wrap = crypto_box::aead::Aead::encrypt(&zero_box, &nonce, &content_key[..]).unwrap();

        let body_nonce = [0x24u8; 24];
        let body_cipher = XChaCha20Poly1305::new_from_slice(&content_key).unwrap();
        let body = chacha20poly1305::aead::Aead::encrypt(
            &body_cipher,
            XNonce::from_slice(&body_nonce),
            b"attacker-chosen plaintext".as_slice(),
        )
        .unwrap();

        let header = serde_json::json!({
            "alg": "xchacha20poly1305",
            "nonce": B64.encode(body_nonce),
            "recipients": [{
                "eph": B64.encode(eph),
                "nonce": B64.encode(nonce),
                "wrap": B64.encode(wrap),
            }],
        });
        let header_json = serde_json::to_vec(&header).unwrap();
        let mut env = Vec::new();
        env.extend_from_slice(MAGIC);
        env.push(VERSION);
        env.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
        env.extend_from_slice(&header_json);
        env.extend_from_slice(&body);

        let reader = Keypair::generate();
        let err = open_blob(&env, &reader).unwrap_err();
        assert!(
            err.to_string().contains("not a recipient"),
            "an envelope whose only entry uses a non-Edwards low-order eph must not \
             open for anyone, got: {err}"
        );
    }

    /// The compressed identity point: a well-formed Ed25519 encoding that is
    /// small-order, so every shared secret derived from it is all-zero.
    fn weak_verifying_key() -> VerifyingKey {
        let mut weak = [0u8; 32];
        weak[0] = 1;
        let vk = VerifyingKey::from_bytes(&weak).expect("identity point decompresses");
        assert!(vk.is_weak(), "fixture precondition: key is small-order");
        vk
    }

    /// A small-order recipient key converts to Montgomery u = 0, and X25519
    /// against u = 0 is the all-zero shared secret for ANY scalar, so the
    /// wrapping box is reconstructable with no secret at all. Reject at the
    /// primitive so the seal side is safe regardless of how the caller
    /// obtained the key.
    #[test]
    fn x25519_public_rejects_a_small_order_key() {
        let weak_vk = weak_verifying_key();

        assert!(
            x25519_public(&weak_vk).is_err(),
            "a small-order key must not yield an x25519 public key"
        );
    }

    /// Control: a legitimate key still converts, and to a non-zero u.
    #[test]
    fn x25519_public_still_accepts_a_real_key() {
        let kp = Keypair::generate();
        let u = x25519_public(&kp.verifying_key()).expect("a real key must convert");
        assert_ne!(u, [0u8; 32], "a real key must not map to the zero point");
    }

    /// The guard has to propagate: no envelope may be produced for a weak
    /// recipient even when the DID choke point is bypassed entirely.
    #[test]
    fn seal_blob_refuses_a_small_order_recipient() {
        let weak_vk = weak_verifying_key();

        assert!(
            seal_blob(b"withheld", &[weak_vk]).is_err(),
            "sealing to a weak recipient must fail"
        );

        // And a mixed set must fail too: one weak recipient exposes the shared
        // content key, so a partial envelope is not an acceptable outcome.
        let honest = Keypair::generate();
        assert!(
            seal_blob(b"withheld", &[honest.verifying_key(), weak_vk]).is_err(),
            "a mixed honest+weak recipient set must fail closed, not seal partially"
        );
    }

    /// Control for the two above: the ordinary seal/open round trip is intact.
    #[test]
    fn legit_seal_open_round_trip_still_works() {
        let reader = Keypair::generate();
        let env = seal_blob(b"withheld blob", &[reader.verifying_key()]).expect("seal");
        assert_eq!(open_blob(&env, &reader).expect("open"), b"withheld blob");
    }

    /// The defect this fix exists to close, kept as an executable regression
    /// rather than an assertion about absence. It runs the real attack: craft a
    /// small-order did:key, get it into a recipient set alongside an honest
    /// reader, then rebuild the wrapping box from the all-zero shared secret
    /// that a small-order recipient forces. If any guard regresses, this does
    /// not merely fail, it fails printing the plaintext it recovered.
    #[test]
    fn attacker_cannot_recover_plaintext_via_a_weak_recipient() {
        use crate::did::Did;
        use std::str::FromStr;

        let weak_vk = weak_verifying_key();

        // Layer 1: the attacker's did:key string must not resolve at all.
        let weak_did = Did::from_verifying_key(&weak_vk).to_string();
        assert!(
            Did::from_str(&weak_did)
                .expect("still a well-formed did:key")
                .to_verifying_key()
                .is_err(),
            "a small-order did:key must not resolve"
        );

        // Layer 2: even handed the key directly, sealing must refuse. One weak
        // recipient would expose the single shared content key, so the honest
        // reader's blob would be readable by anyone.
        let honest = Keypair::generate();
        let secret_plaintext = b"WITHHELD BLOB CONTENTS";
        let envelope = match seal_blob(secret_plaintext, &[honest.verifying_key(), weak_vk]) {
            Err(_) => return, // no envelope exists, nothing to attack
            Ok(env) => env,
        };

        // Only reachable if a guard regressed. Run the attack and report what
        // it got, so the failure names the actual exposure.
        let mut p = MAGIC.len() + 1;
        let hlen = u32::from_le_bytes(envelope[p..p + 4].try_into().unwrap()) as usize;
        p += 4;
        let header: serde_json::Value = serde_json::from_slice(&envelope[p..p + hlen]).unwrap();
        let body = &envelope[p + hlen..];
        let body_nonce = B64.decode(header["nonce"].as_str().unwrap()).unwrap();

        // X25519 against u = 0 is the all-zero shared secret for any scalar, so
        // the sealer's box is reconstructable with a key the attacker picks.
        let zero_box = ChaChaBox::new(&XPublic::from([0u8; 32]), &XSecret::generate(&mut OsRng));
        for r in header["recipients"].as_array().unwrap() {
            let n = B64.decode(r["nonce"].as_str().unwrap()).unwrap();
            let w = B64.decode(r["wrap"].as_str().unwrap()).unwrap();
            if let Ok(content_key) = zero_box.decrypt(n.as_slice().into(), w.as_slice()) {
                let cipher = XChaCha20Poly1305::new_from_slice(&content_key).unwrap();
                let recovered = cipher
                    .decrypt(XNonce::from_slice(&body_nonce), body)
                    .expect("body decrypts once the content key is out");
                panic!(
                    "REGRESSION: attacker recovered plaintext with no private key: {:?}",
                    String::from_utf8_lossy(&recovered)
                );
            }
        }
        panic!("an envelope was sealed to a small-order recipient; the seal guard regressed");
    }
}
