//! Envelope encryption for withheld blobs (Option B). A random content key
//! encrypts the blob (XChaCha20-Poly1305); the content key is wrapped to each
//! recipient via an X25519 box keyed from their Ed25519 `did:key`. The node
//! seals with public keys only; readers open with their own private key.

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;

/// X25519 public key (Montgomery u) for an Ed25519 verifying key.
fn x25519_public(vk: &VerifyingKey) -> Result<[u8; 32]> {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    let edwards = CompressedEdwardsY::from_slice(vk.as_bytes())
        .ok()
        .and_then(|c| c.decompress())
        .context("verifying key is not a valid edwards point")?;
    Ok(edwards.to_montgomery().to_bytes())
}

/// X25519 secret scalar for an Ed25519 seed (SHA-512 of seed, lower 32, clamped).
fn x25519_secret_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha512};
    let h = Sha512::digest(seed);
    let mut s = [0u8; 32];
    s.copy_from_slice(&h[..32]);
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
    s
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
        let seed = kp.seed_bytes();
        let xpub_from_public = x25519_public(&kp.verifying_key()).unwrap();
        let xsec = x25519_secret_from_seed(&seed);
        let xpub_from_secret = crypto_box::SecretKey::from(xsec).public_key().to_bytes();
        assert_eq!(xpub_from_public, xpub_from_secret);
    }
}
