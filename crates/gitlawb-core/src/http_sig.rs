```rust
//! HTTP Signatures (RFC 9421) for gitlawb.
//!
//! Every write request to a gitlawb node must be signed by the actor's
//! Ed25519 private key. The signature covers:
//!   - `@method`         — HTTP method (uppercase)
//!   - `@path`           — request path and query
//!   - `content-digest`  — SHA-256 of the request body (structured-field byte sequence)
//!
//! RFC 9421 headers produced by `sign_request`:
//!   Content-Digest:   sha-256=:base64hash:
//!   Signature-Input:  sig1=("@method" "@path" "content-digest");keyid="did:key:z6Mk...";alg="ed25519";created=<unix>
//!   Signature:        sig1=:base64signature:

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::did::Did;
use crate::identity::Keypair;
use crate::{Error, Result};

/// The component identifiers covered by every gitlawb signature.
pub const COVERED_COMPONENTS: &[&str] = &["@method", "@path", "content-digest"];

/// The three headers produced by RFC 9421 signing.
#[derive(Debug, Clone)]
pub struct SignedHeaders {
    /// `Content-Digest: sha-256=:base64:`
    pub content_digest: String,
    /// `Signature-Input: sig1=(...);keyid="...";alg="ed25519";created=<unix>`
    pub signature_input: String,
    /// `Signature: sig1=:base64:`
    pub signature: String,
}

/// A parsed RFC 9421 signature (from Signature-Input + Signature headers).
#[derive(Debug, Clone)]
pub struct HttpSignature {
    pub key_id: Did,
    pub alg: String,
    pub created: i64,
    pub components: Vec<String>,
    pub signature_bytes: Vec<u8>,
}

impl HttpSignature {
    /// Parse `Signature-Input` + `Signature` header values into an `HttpSignature`.
    ///
    /// `sig_input`  — value of the `Signature-Input` header
    /// `sig_header` — value of the `Signature` header
    pub fn parse(sig_input: &str, sig_header: &str) -> Result<Self> {
        let sig_input = sig_input.trim();

        // Expect: sig1=("@method" "@path" "content-digest");keyid="...";alg="...";created=...
        let rest = sig_input.strip_prefix("sig1=").ok_or_else(|| {
            Error::HttpSignature("Signature-Input must start with 'sig1='".into())
        })?;

        let open = rest
            .find('(')
            .ok_or_else(|| Error::HttpSignature("missing '(' in Signature-Input".into()))?;
        let close = rest
            .find(')')
            .ok_or_else(|| Error::HttpSignature("missing ')' in Signature-Input".into()))?;

        let components_str = &rest[open + 1..close];
        let params_str = &rest[close + 1..]; // starts with ';'

        // "\"@method\" \"@path\" \"content-digest\"" → ["@method", "@path", "content-digest"]
        let components: Vec<String> = components_str
            .split_whitespace()
            .map(|s| s.trim_matches('"').to_string())
            .collect();

        let params = parse_params(params_str)?;

        let key_id: Did = params
            .get("keyid")
            .ok_or_else(|| Error::HttpSignature("missing keyid param".into()))?
            .trim_matches('"')
            .parse()?;

        let alg = params
            .get("alg")
            .ok_or_else(|| Error::HttpSignature("missing alg param".into()))?
            .trim_matches('"')
            .to_string();

        let created: i64 = params
            .get("created")
            .ok_or_else(|| Error::HttpSignature("missing created param".into()))?
            .parse()
            .map_err(|_| Error::HttpSignature("invalid created timestamp".into()))?;

        // Signature: sig1=:base64bytes:
        let sig_b64 = sig_header
            .trim()
            .strip_prefix("sig1=:")
            .and_then(|s| s.strip_suffix(':'))
            .ok_or_else(|| Error::HttpSignature("Signature must be 'sig1=:base64:'".into()))?;

        let signature_bytes = STANDARD
            .decode(sig_b64)
            .map_err(|e| Error::HttpSignature(format!("invalid base64 in Signature: {e}")))?;

        Ok(Self {
            key_id,
            alg,
            created,
            components,
            signature_bytes,
        })
    }

    /// Reject if the `created` timestamp is more than 5 minutes from now.
    pub fn check_created(&self) -> Result<()> {
        let now = Utc::now().timestamp();
        let skew = (now - self.created).abs();
        if skew > 300 {
            return Err(Error::HttpSignature(format!(
                "clock skew too large: {skew}s (max 300s)"
           )));
        }
        Ok(())
    }

    /// Return the components that are required but absent from this signature.
    pub fn missing_components(&self) -> Vec<&str> {
        COVERED_COMPONENTS
            .iter()
            .filter(|c| !self.components.iter().any(|s| s.as_str() == **c))
            .copied()
            .collect()
    }

    /// Verify that the signature matches the request components.
    pub fn verify(&self, method: &str, path: &str, body: &[u8]) -> Result<()> {
        // Check method matches what was signed
        let signed_method = self.components.iter()
            .find(|c| c == "@method")
            .ok_or_else(|| Error::HttpSignature("missing @method in signature".into()))?;

        if signed_method != method {
            return Err(Error::HttpSignature(format!(
                "method mismatch: signed '{}' but got '{}'",
                signed_method, method
            )));
        }

        // Check path matches what was signed
        let signed_path = self.components.iter()
            .find(|c| c == "@path")
            .ok_or_else(|| Error::HttpSignature("missing @path in signature".into()))?;

        if signed_path != path {
            return Err(Error::HttpSignature(format!(
                "path mismatch: signed '{}' but got '{}'",
                signed_path, path
            )));
        }

        // Check content digest matches
        let content_digest = compute_content_digest(body);
        let signed_digest = self.components.iter()
            .find(|c| c == "content-digest")
            .ok_or_else(|| Error::HttpSignature("missing content-digest in signature".into()))?;

        if signed_digest != content_digest {
            return Err(Error::HttpSignature(format!(
                "content digest mismatch: signed '{}' but got '{}'",
                signed_digest, content_digest
            )));
        }

        Ok(())
    }
}

/// Build the RFC 9421 signing string (§2.5).
///
/// The signing string is a newline-separated list of:
///   `"component-name": value`  for each covered component, plus
///   `"@signature-params": <sig-params-value>`  as the final line.
pub fn build_sign