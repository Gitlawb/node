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
}

/// Build the RFC 9421 signing string (§2.5).
///
/// The signing string is a newline-separated list of:
///   `"component-name": value`  for each covered component, plus
///   `"@signature-params": <sig-params-value>`  as the final line.
pub fn build_signing_string(
    components: &[&str],
    sig_params_value: &str,
    request_values: &HashMap<String, String>,
) -> Result<String> {
    let mut lines = Vec::new();

    for comp in components {
        let value = request_values
            .get(*comp)
            .ok_or_else(|| Error::HttpSignature(format!("missing component '{comp}'")))?;
        lines.push(format!("\"{comp}\": {value}"));
    }

    lines.push(format!("\"@signature-params\": {sig_params_value}"));
    Ok(lines.join("\n"))
}

/// Sign an HTTP request per RFC 9421 and return the three headers to inject.
pub fn sign_request(
    keypair: &Keypair,
    method: &str,
    path_and_query: &str,
    body: &[u8],
) -> SignedHeaders {
    let created = Utc::now().timestamp();
    let content_digest = compute_content_digest(body);
    let did = keypair.did();

    // Full Signature-Input header value
    let signature_input = format!(
        r#"sig1=("@method" "@path" "content-digest");keyid="{did}";alg="ed25519";created={created}"#
    );

    // The @signature-params component value is the part after "sig1="
    let sig_params_value = &signature_input["sig1=".len()..];

    let mut request_values = HashMap::new();
    request_values.insert("@method".to_string(), method.to_uppercase());
    request_values.insert("@path".to_string(), path_and_query.to_string());
    request_values.insert("content-digest".to_string(), content_digest.clone());

    let signing_string =
        build_signing_string(COVERED_COMPONENTS, sig_params_value, &request_values)
            .expect("required components always present when building");

    let sig_bytes = keypair.sign(signing_string.as_bytes());
    let sig_b64 = STANDARD.encode(sig_bytes.to_bytes());

    SignedHeaders {
        content_digest,
        signature_input,
        signature: format!("sig1=:{sig_b64}:"),
    }
}

/// Compute RFC 9421 Content-Digest value: `sha-256=:base64(sha256(body)):`
pub fn compute_content_digest(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    format!("sha-256=:{}:", STANDARD.encode(hasher.finalize()))
}

/// Parse `;key="value";key2=value` parameter string into a map.
fn parse_params(s: &str) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    for part in s.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Keypair;

    #[test]
    fn sign_and_parse_roundtrip() {
        let kp = Keypair::generate();
        let headers = sign_request(&kp, "POST", "/api/register", b"{\"did\":\"test\"}");

        assert!(headers.signature_input.starts_with("sig1=("));
        assert!(headers.signature.starts_with("sig1=:"));
        assert!(headers.content_digest.starts_with("sha-256=:"));

        let sig = HttpSignature::parse(&headers.signature_input, &headers.signature).unwrap();
        assert_eq!(sig.key_id, kp.did());
        assert_eq!(sig.alg, "ed25519");
        assert!(sig.missing_components().is_empty());
        assert!(sig.check_created().is_ok());
    }

    #[test]
    fn content_digest_format() {
        let d = compute_content_digest(b"hello");
        assert!(d.starts_with("sha-256=:"));
        assert!(d.ends_with(':'));
    }

    #[test]
    fn signing_string_structure() {
        let mut vals = HashMap::new();
        vals.insert("@method".to_string(), "POST".to_string());
        vals.insert("@path".to_string(), "/api/test".to_string());
        vals.insert("content-digest".to_string(), "sha-256=:abc:".to_string());

        let s = build_signing_string(
            COVERED_COMPONENTS,
            r#"("@method" "@path" "content-digest");keyid="did:key:z6Mk";alg="ed25519";created=1000"#,
            &vals,
        ).unwrap();

        assert!(s.contains("\"@method\": POST"));
        assert!(s.contains("\"@path\": /api/test"));
        assert!(s.contains("\"@signature-params\":"));
    }

    #[test]
    fn missing_components_detected() {
        let kp = Keypair::generate();
        let did = kp.did();
        let sig_input = format!(r#"sig1=("@method");keyid="{did}";alg="ed25519";created=1000"#);
        let sig = HttpSignature::parse(&sig_input, "sig1=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:").unwrap();
        let missing = sig.missing_components();
        assert!(missing.contains(&"@path"));
        assert!(missing.contains(&"content-digest"));
    }

    #[test]
    fn verify_signature_end_to_end() {
        use crate::identity::verify;
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;

        let kp = Keypair::generate();
        let body = b"{\"did\":\"did:key:z6Mk\"}";
        let headers = sign_request(&kp, "POST", "/api/register", body);

        let sig = HttpSignature::parse(&headers.signature_input, &headers.signature).unwrap();

        let sig_params_value = headers.signature_input.strip_prefix("sig1=").unwrap();
        let mut request_values = HashMap::new();
        request_values.insert("@method".to_string(), "POST".to_string());
        request_values.insert("@path".to_string(), "/api/register".to_string());
        request_values.insert("content-digest".to_string(), headers.content_digest.clone());

        let components_ref: Vec<&str> = sig.components.iter().map(String::as_str).collect();
        let signing_string =
            build_signing_string(&components_ref, sig_params_value, &request_values).unwrap();

        let vk = sig.key_id.to_verifying_key().unwrap();
        let sig_b64 = headers
            .signature
            .strip_prefix("sig1=:")
            .unwrap()
            .strip_suffix(':')
            .unwrap();
        let sig_bytes: [u8; 64] = STANDARD.decode(sig_b64).unwrap().try_into().unwrap();

        assert!(verify(&vk, signing_string.as_bytes(), &sig_bytes).is_ok());
    }

    #[test]
    fn tampered_body_fails_digest_check() {
        let kp = Keypair::generate();
        let headers = sign_request(&kp, "POST", "/api/register", b"original body");
        let actual = compute_content_digest(b"tampered body");
        assert_ne!(headers.content_digest, actual);
    }

    #[test]
    fn empty_body_digest_is_valid() {
        let d = compute_content_digest(b"");
        assert!(d.starts_with("sha-256=:"));
        assert!(d.ends_with(':'));
        // SHA-256 of empty string is well-known
        assert!(d.len() > 12);
    }

    #[test]
    fn clock_skew_rejection() {
        let kp = Keypair::generate();
        let did = kp.did();
        // created=1 is way in the past — should fail clock skew check
        let sig_input = format!(
            r#"sig1=("@method" "@path" "content-digest");keyid="{did}";alg="ed25519";created=1"#
        );
        let sig = HttpSignature::parse(&sig_input, "sig1=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:").unwrap();
        assert!(sig.check_created().is_err());
    }

    #[test]
    fn fresh_signature_passes_clock_skew() {
        let kp = Keypair::generate();
        let headers = sign_request(&kp, "GET", "/api/v1/agents", b"");
        let sig = HttpSignature::parse(&headers.signature_input, &headers.signature).unwrap();
        assert!(sig.check_created().is_ok());
    }

    #[test]
    fn parse_error_missing_sig1_prefix() {
        let err = HttpSignature::parse(
            "badprefix=(\"@method\");keyid=\"did:key:z\";alg=\"ed25519\";created=1000",
            "sig1=:abc:",
        );
        assert!(err.is_err());
    }

    #[test]
    fn parse_error_missing_keyid() {
        let sig_input = r#"sig1=("@method");alg="ed25519";created=1000"#;
        let err = HttpSignature::parse(sig_input, "sig1=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:");
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("keyid"));
    }

    #[test]
    fn parse_error_bad_signature_format() {
        let kp = Keypair::generate();
        let did = kp.did();
        let sig_input = format!(r#"sig1=("@method");keyid="{did}";alg="ed25519";created=1000"#);
        // Missing trailing colon
        let err = HttpSignature::parse(&sig_input, "sig1=:abc");
        assert!(err.is_err());
    }

    #[test]
    fn digest_is_deterministic() {
        let d1 = compute_content_digest(b"same content");
        let d2 = compute_content_digest(b"same content");
        assert_eq!(d1, d2);
    }

    #[test]
    fn different_bodies_produce_different_digests() {
        let d1 = compute_content_digest(b"body one");
        let d2 = compute_content_digest(b"body two");
        assert_ne!(d1, d2);
    }

    #[test]
    fn method_uppercased_in_signing_string() {
        let kp = Keypair::generate();
        let headers = sign_request(&kp, "post", "/api/test", b"");
        let sig = HttpSignature::parse(&headers.signature_input, &headers.signature).unwrap();
        let sig_params_value = headers.signature_input.strip_prefix("sig1=").unwrap();
        let mut vals = HashMap::new();
        vals.insert("@method".to_string(), "POST".to_string());
        vals.insert("@path".to_string(), "/api/test".to_string());
        vals.insert("content-digest".to_string(), headers.content_digest.clone());
        let components_ref: Vec<&str> = sig.components.iter().map(String::as_str).collect();
        let s = build_signing_string(&components_ref, sig_params_value, &vals).unwrap();
        assert!(s.contains("\"@method\": POST"));
    }
}
