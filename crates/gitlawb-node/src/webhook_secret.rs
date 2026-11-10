//! At-rest protection for webhook HMAC secrets (#506).
//!
//! Webhook secrets are signing keys: whoever holds one can forge delivery
//! payloads to the receiver the hook points at. They are persisted in the
//! `webhooks.secret` column and used to compute the `X-Gitlawb-Signature-256`
//! header on each delivery. That secret needs two properties:
//!
//!   * It must never reach a log line or an API response. [`WebhookSecret`]
//!     redacts both `Debug` and `Serialize`, so no derived `{:?}` and no JSON
//!     body ever renders the value, whatever it contains.
//!   * It must not rest as plaintext where a database dump or backup can read
//!     it. The node seals the secret with a key derived from its persistent
//!     identity (see `AppState::derive_webhook_secret_key`), so a dump alone
//!     reveals nothing.
//!
//! Storage format: `enc:v1:<base64url(nonce || ciphertext)>` — a 24-byte
//! XChaCha20-Poly1305 nonce followed by the ciphertext (which carries the tag).
//! Anything without the `enc:v1:` prefix is a legacy plaintext value, written
//! before this protection shipped; the delivery path signs with those unchanged
//! and they are re-encrypted once at startup by
//! `Db::reencrypt_legacy_webhook_secrets`.

use std::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Prefix marking a sealed-at-rest secret. Legacy plaintext values lack it.
pub const SEAL_PREFIX: &str = "enc:v1:";

const NONCE_LEN: usize = 24;

/// An HMAC signing secret that never renders its contents in debug or JSON
/// output. Used as `Webhook.secret`, so that field is safe to `Debug`-print and
/// `Serialize` by construction rather than by discipline at each call site.
#[derive(Clone, PartialEq, Eq)]
pub struct WebhookSecret(String);

impl WebhookSecret {
    pub fn new(inner: String) -> Self {
        Self(inner)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the value is a sealed ciphertext (as opposed to legacy plaintext).
    pub fn is_sealed(&self) -> bool {
        self.0.starts_with(SEAL_PREFIX)
    }
}

impl fmt::Debug for WebhookSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"***\"")
    }
}

impl Serialize for WebhookSecret {
    /// Emit a fixed marker, never the contents. On the wire a set secret is
    /// `"secret": "***"` and an unset one is `"secret": null` (`Option`), which
    /// the CLI already reads as "is a secret set".
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("***")
    }
}

impl<'de> Deserialize<'de> for WebhookSecret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(WebhookSecret(String::deserialize(deserializer)?))
    }
}

/// Seal a plaintext secret under a node-held key. A fresh `OsRng` nonce on every
/// seal guarantees repeated seals of the same secret never collide.
pub fn seal(key: &[u8; 32], plaintext: &str) -> String {
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("webhook secret key is 32 bytes");
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .expect("XChaCha20-Poly1305 encryption is infallible for in-memory inputs");
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    format!("{SEAL_PREFIX}{}", B64URL.encode(out))
}

/// Open a sealed secret. Returns `None` for anything that is not a well-formed
/// sealed value — legacy plaintext, a foreign key, tampered or truncated bytes —
/// so a caller that needs the legacy path checks [`WebhookSecret::is_sealed`]
/// first (see [`reveal`]).
pub fn open(key: &[u8; 32], stored: &str) -> Option<String> {
    let raw = B64URL.decode(stored.strip_prefix(SEAL_PREFIX)?).ok()?;
    if raw.len() <= NONCE_LEN {
        return None;
    }
    let (nonce, ciphertext) = raw.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new_from_slice(key).ok()?;
    let plaintext = cipher.decrypt(XNonce::from_slice(nonce), ciphertext).ok()?;
    String::from_utf8(plaintext).ok()
}

/// Resolve a stored secret to its plaintext for signing. Sealed values are opened
/// with the node key; legacy plaintext is returned unchanged so a hook created
/// before this fix keeps signing until the startup re-encryption pass runs.
pub fn reveal(key: &[u8; 32], stored: &WebhookSecret) -> Option<String> {
    if stored.is_sealed() {
        open(key, stored.as_str())
    } else {
        Some(stored.as_str().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    /// Test keys need no secrecy, but they still come from the OS CSPRNG so no
    /// hard-coded key material sits in the tree. A wrong key fails XChaCha20-Poly1305
    /// authentication with overwhelming probability, so the "wrong key" case stays
    /// deterministic in practice.
    fn new_key() -> [u8; 32] {
        OsRng.gen()
    }

    fn other_key() -> [u8; 32] {
        OsRng.gen()
    }

    #[test]
    fn seal_open_round_trip() {
        let k = new_key();
        let sealed = seal(&k, "s3cr3t-value");
        assert!(sealed.starts_with(SEAL_PREFIX));
        assert_eq!(open(&k, &sealed).as_deref(), Some("s3cr3t-value"));
    }

    #[test]
    fn sealed_value_is_never_the_plaintext() {
        let k = new_key();
        let sealed = seal(&k, "s3cr3t-value");
        assert!(!sealed.contains("s3cr3t-value"));
    }

    #[test]
    fn wrong_key_does_not_open() {
        let sealed = seal(&new_key(), "s3cr3t-value");
        assert_eq!(open(&other_key(), &sealed), None);
    }

    #[test]
    fn tampered_or_truncated_value_does_not_open() {
        let k = new_key();
        let sealed = seal(&k, "s3cr3t-value");
        // Flip a byte inside the base64 payload.
        let mut chars: Vec<char> = sealed.chars().collect();
        let idx = SEAL_PREFIX.len();
        chars[idx] = if chars[idx] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert_eq!(open(&k, &tampered), None);
        // A value that is just the prefix (no nonce/ciphertext) is malformed.
        assert_eq!(open(&k, SEAL_PREFIX), None);
    }

    #[test]
    fn legacy_plaintext_is_revealed_unchanged() {
        let k = new_key();
        let legacy = WebhookSecret::new("plaintext-secret".into());
        assert!(!legacy.is_sealed());
        assert_eq!(reveal(&k, &legacy).as_deref(), Some("plaintext-secret"));
    }

    #[test]
    fn debug_is_redacted() {
        let s = WebhookSecret::new("s3cr3t-value".into());
        let rendered = format!("{s:?}");
        assert!(!rendered.contains("s3cr3t-value"));
        assert_eq!(rendered, "\"***\"");
    }

    #[test]
    fn serialize_is_redacted() {
        let s = WebhookSecret::new("s3cr3t-value".into());
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains("s3cr3t-value"));
        assert_eq!(json, "\"***\"");
    }

    #[test]
    fn deserialize_reads_the_underlying_string() {
        let s: WebhookSecret = serde_json::from_str("\"s3cr3t-value\"").unwrap();
        assert_eq!(s.as_str(), "s3cr3t-value");
    }
}
