//! Proof-of-work solver for the iCaptcha answer step.
//!
//! iCaptcha requires a small proof-of-work with each answer so that minting a
//! proof costs CPU — a per-proof cost a distributed abuser cannot dodge by
//! rotating IPs. The work is bound to the per-challenge id: find a `nonce` such
//! that `sha256("{challenge}:{nonce}")` has at least `difficulty` leading zero
//! bits. This mirrors `icaptcha/src/pow.ts`.
//!
//! At the service default (~20 bits) this is well under a second for a single
//! solve; we still cap the search so a hostile/misconfigured difficulty can
//! never hang the client.

use sha2::{Digest, Sha256};

/// PoW parameters advertised by the service in a challenge (mirrors the
/// service's `PowChallenge`).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PowChallenge {
    /// Only `sha256-leading-zero-bits` is understood; other algorithms are
    /// rejected by [`solve`] rather than silently mis-solved.
    pub algorithm: String,
    /// The string to hash against (the per-challenge id).
    pub challenge: String,
    /// Required leading zero bits.
    pub difficulty: u32,
}

/// Hard cap on nonce search iterations. 2^26 ≈ 67M keeps a ~20-bit target (~1M
/// expected hashes) comfortably solvable while bounding worst-case work if the
/// service ever advertises an unexpectedly high difficulty.
const MAX_ITERS: u64 = 1 << 26;

const ALGORITHM: &str = "sha256-leading-zero-bits";

/// Leading zero bits of a byte slice.
fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut bits = 0;
    for &b in bytes {
        if b == 0 {
            bits += 8;
        } else {
            bits += b.leading_zeros();
            break;
        }
    }
    bits
}

/// sha256(`{challenge}:{nonce}`).
fn pow_hash(challenge: &str, nonce: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(challenge.as_bytes());
    hasher.update(b":");
    hasher.update(nonce.as_bytes());
    hasher.finalize().into()
}

/// Solve the PoW, returning a nonce whose hash meets the difficulty. Returns
/// `None` for an unknown algorithm or if no nonce is found within the cap (a
/// difficulty far above what the service uses in practice).
pub fn solve(pow: &PowChallenge) -> Option<String> {
    if pow.algorithm != ALGORITHM {
        tracing::warn!(algorithm = %pow.algorithm, "unknown iCaptcha PoW algorithm; cannot solve");
        return None;
    }
    if pow.difficulty == 0 {
        return Some("0".to_string());
    }
    for i in 0..MAX_ITERS {
        let nonce = format!("{i:x}");
        if leading_zero_bits(&pow_hash(&pow.challenge, &nonce)) >= pow.difficulty {
            return Some(nonce);
        }
    }
    tracing::warn!(
        difficulty = pow.difficulty,
        max_iters = MAX_ITERS,
        "iCaptcha PoW not solved within iteration cap"
    );
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pow(challenge: &str, difficulty: u32) -> PowChallenge {
        PowChallenge {
            algorithm: ALGORITHM.to_string(),
            challenge: challenge.to_string(),
            difficulty,
        }
    }

    #[test]
    fn leading_zero_bits_counts_across_bytes() {
        assert_eq!(leading_zero_bits(&[0xff]), 0);
        assert_eq!(leading_zero_bits(&[0x7f]), 1);
        assert_eq!(leading_zero_bits(&[0x01]), 7);
        assert_eq!(leading_zero_bits(&[0x00, 0xff]), 8);
        assert_eq!(leading_zero_bits(&[0x00, 0x01]), 15);
    }

    #[test]
    fn solves_and_the_solution_verifies() {
        let p = pow("challenge-abc", 12);
        let nonce = solve(&p).expect("should solve a 12-bit target");
        assert!(leading_zero_bits(&pow_hash(&p.challenge, &nonce)) >= 12);
    }

    #[test]
    fn solution_is_bound_to_the_challenge() {
        // A nonce solving one challenge should (overwhelmingly) not solve another
        // at the same difficulty — the work is challenge-specific.
        let nonce = solve(&pow("challenge-A", 12)).unwrap();
        assert!(leading_zero_bits(&pow_hash("challenge-B", &nonce)) < 12);
    }

    #[test]
    fn rejects_unknown_algorithm() {
        let mut p = pow("c", 8);
        p.algorithm = "scrypt".to_string();
        assert!(solve(&p).is_none());
    }

    #[test]
    fn zero_difficulty_is_trivially_solved() {
        assert_eq!(solve(&pow("c", 0)).as_deref(), Some("0"));
    }
}
