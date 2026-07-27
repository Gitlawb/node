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
//!   Signature-Input:  sig1=("@method" "@path" "content-digest");keyid="did:key:z6Mk...";alg="ed25519";created=<unix>;nonce="<32 hex chars>"
//!   Signature:        sig1=:base64signature:
//!
//! The `nonce` is a per-request 128-bit value. It sits in the parameter tail,
//! which is what `@signature-params` is built from, so it is covered by the
//! signature without appearing in the covered-component list.

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::did::Did;
use crate::identity::Keypair;
use crate::{Error, Result};

/// The component identifiers covered by every gitlawb signature.
pub const COVERED_COMPONENTS: &[&str] = &["@method", "@path", "content-digest"];

/// How old a signature may be and still verify.
///
/// Do not shrink this without measuring large-pack pushes: the verifier
/// buffers the entire request body before checking `created`, so a multi-GB
/// pack spends its upload time inside this budget.
pub const MAX_SIGNATURE_AGE_SECS: i64 = 300;

/// How far into the future a signature's `created` may sit. Absorbs ordinary
/// clock skew without letting a signer pre-date its way to a wider window.
pub const MAX_FUTURE_SKEW_SECS: i64 = 30;

/// The three headers produced by RFC 9421 signing.
#[derive(Debug, Clone)]
pub struct SignedHeaders {
    /// `Content-Digest: sha-256=:base64:`
    pub content_digest: String,
    /// `Signature-Input: sig1=(...);keyid="...";alg="ed25519";created=<unix>;nonce="..."`
    pub signature_input: String,
    /// `Signature: sig1=:base64:`
    pub signature: String,
    /// The per-request nonce carried in `Signature-Input`.
    pub nonce: String,
}

/// A parsed RFC 9421 signature (from Signature-Input + Signature headers).
#[derive(Debug, Clone)]
pub struct HttpSignature {
    pub key_id: Did,
    pub alg: String,
    pub created: i64,
    pub components: Vec<String>,
    pub signature_bytes: Vec<u8>,
    /// The `nonce` param, absent on signatures from a pre-nonce signer.
    pub nonce: Option<String>,
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

        // Optional: absent on signatures from a signer that predates the nonce.
        let nonce = params.get("nonce").map(|v| v.trim_matches('"').to_string());

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
            nonce,
        })
    }

    /// Reject a `created` timestamp outside the acceptance window.
    ///
    /// The window is deliberately asymmetric. A signature may be up to
    /// [`MAX_SIGNATURE_AGE_SECS`] old, because the verifier buffers the whole
    /// request body before this check runs and the git routes accept packs up
    /// to gigabytes, so upload time is charged against that budget. It may be
    /// only [`MAX_FUTURE_SKEW_SECS`] in the future, which is enough to absorb
    /// ordinary clock skew.
    ///
    /// This used to compare `(now - created).abs()` against a single bound,
    /// which let a signer pre-date `created` and hold a signature valid for
    /// twice the intended span (#253).
    pub fn check_created(&self) -> Result<()> {
        let now = Utc::now().timestamp();

        if self.created > now + MAX_FUTURE_SKEW_SECS {
            return Err(Error::HttpSignature(format!(
                "signature is dated {}s in the future (max {MAX_FUTURE_SKEW_SECS}s)",
                self.created - now
            )));
        }

        let age = now - self.created;
        if age > MAX_SIGNATURE_AGE_SECS {
            return Err(Error::HttpSignature(format!(
                "signature is {age}s old (max {MAX_SIGNATURE_AGE_SECS}s)"
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

/// Render `COVERED_COMPONENTS` as the parenthesised component list that goes
/// inside `Signature-Input`, e.g. `"@method" "@path" "content-digest"`.
///
/// Both the wire header and [`build_signing_string`]'s input are built from
/// this one source. Writing the list out by hand in the header while passing
/// the const to the signing-string builder lets a client sign over one set
/// while advertising another, which no verifier can reconcile.
fn covered_components_list() -> String {
    COVERED_COMPONENTS
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The request-derived value for every component this signer knows how to
/// cover. Kept alongside [`covered_components_list`] so the guard test can
/// check the two agree without signing anything.
fn request_values_for(
    method: &str,
    path_and_query: &str,
    content_digest: &str,
) -> HashMap<String, String> {
    let mut values = HashMap::new();
    values.insert("@method".to_string(), method.to_uppercase());
    values.insert("@path".to_string(), path_and_query.to_string());
    values.insert("content-digest".to_string(), content_digest.to_string());
    values
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

    // Full Signature-Input header value. The advertised component list is
    // derived from COVERED_COMPONENTS rather than written out, so the wire
    // header and the list we actually sign over cannot drift apart.
    let advertised = covered_components_list();
    // 128 bits from the OS CSPRNG, appended to the parameter tail. The tail is
    // sliced into `sig_params_value` below and so lands in the
    // `@signature-params` line, which puts the nonce under the signature
    // (RFC 9421 §2.3) without touching COVERED_COMPONENTS. Verifiers that
    // predate the nonce rebuild `@signature-params` from the received header
    // text, so they keep verifying an unknown parameter unchanged.
    let nonce = generate_nonce();
    let signature_input = format!(
        r#"sig1=({advertised});keyid="{did}";alg="ed25519";created={created};nonce="{nonce}""#
    );

    // The @signature-params component value is the part after "sig1="
    let sig_params_value = &signature_input["sig1=".len()..];

    let request_values = request_values_for(method, path_and_query, &content_digest);

    // Guarded by `sign_request_supplies_every_covered_component`: that test
    // fails cleanly if COVERED_COMPONENTS gains an entry `request_values_for`
    // cannot supply, which is the only way this could fail.
    let signing_string =
        build_signing_string(COVERED_COMPONENTS, sig_params_value, &request_values)
            .expect("request_values_for covers COVERED_COMPONENTS (see guard test)");

    let sig_bytes = keypair.sign(signing_string.as_bytes());
    let sig_b64 = STANDARD.encode(sig_bytes.to_bytes());

    SignedHeaders {
        content_digest,
        signature_input,
        signature: format!("sig1=:{sig_b64}:"),
        nonce,
    }
}

/// Draw a fresh 128-bit nonce from the OS CSPRNG, hex-encoded.
fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
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

    /// U1 guard: the component list on the wire must be exactly what we sign
    /// over. Load-bearing by mutation, not by red-then-green: adding a fourth
    /// entry to COVERED_COMPONENTS turns this red.
    #[test]
    fn signature_input_advertises_exactly_covered_components() {
        let kp = Keypair::generate();
        let headers = sign_request(&kp, "POST", "/api/test", b"body");
        let parsed = HttpSignature::parse(&headers.signature_input, &headers.signature)
            .expect("emitted Signature-Input must parse");
        assert_eq!(
            parsed.components, COVERED_COMPONENTS,
            "the advertised component list drifted from COVERED_COMPONENTS"
        );
    }

    /// U1 guard: every covered component must have a request-derived value.
    /// This is the check that fails *cleanly* when COVERED_COMPONENTS grows,
    /// instead of letting sign_request panic inside build_signing_string.
    #[test]
    fn sign_request_supplies_every_covered_component() {
        let values = request_values_for("POST", "/api/test", "sha-256=:abc:");
        let missing: Vec<&str> = COVERED_COMPONENTS
            .iter()
            .copied()
            .filter(|c| !values.contains_key(*c))
            .collect();
        assert!(
            missing.is_empty(),
            "COVERED_COMPONENTS entries with no value in request_values_for: {missing:?}. \
             sign_request would panic on every call; add the value or drop the component."
        );
    }

    /// U3 boundary: the forward bound is real and tight.
    #[test]
    fn future_dated_created_outside_skew_is_rejected() {
        let kp = Keypair::generate();
        let mut headers = sign_request(&kp, "GET", "/api/v1/agents", b"");
        let future = Utc::now().timestamp() + MAX_FUTURE_SKEW_SECS + 1;
        headers.signature_input = headers
            .signature_input
            .split(";created=")
            .next()
            .map(|head| format!("{head};created={future}"))
            .expect("signature_input carries created");
        let sig = HttpSignature::parse(&headers.signature_input, &headers.signature).unwrap();
        assert!(
            sig.check_created().is_err(),
            "created beyond the forward skew allowance must be rejected"
        );
    }

    /// U3 boundary: just inside the forward allowance still verifies, so the
    /// bound absorbs real clock skew rather than being effectively zero.
    #[test]
    fn future_dated_created_within_skew_is_accepted() {
        let kp = Keypair::generate();
        let mut headers = sign_request(&kp, "GET", "/api/v1/agents", b"");
        let future = Utc::now().timestamp() + MAX_FUTURE_SKEW_SECS - 1;
        headers.signature_input = headers
            .signature_input
            .split(";created=")
            .next()
            .map(|head| format!("{head};created={future}"))
            .expect("signature_input carries created");
        let sig = HttpSignature::parse(&headers.signature_input, &headers.signature).unwrap();
        assert!(sig.check_created().is_ok(), "within skew must be accepted");
    }

    /// U3 regression: the backward budget must not be narrowed. A large pack
    /// spends this long uploading before check_created ever runs.
    #[test]
    fn backward_budget_still_accepts_a_nearly_stale_signature() {
        let kp = Keypair::generate();
        let mut headers = sign_request(&kp, "POST", "/api/test", b"body");
        let old = Utc::now().timestamp() - (MAX_SIGNATURE_AGE_SECS - 20);
        headers.signature_input = headers
            .signature_input
            .split(";created=")
            .next()
            .map(|head| format!("{head};created={old}"))
            .expect("signature_input carries created");
        let sig = HttpSignature::parse(&headers.signature_input, &headers.signature).unwrap();
        assert!(
            sig.check_created().is_ok(),
            "a signature well inside the age budget must still verify"
        );
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

    /// U2: the nonce is per-call, so two signatures over an identical request
    /// differ and so do the `Signature-Input` values they were computed over.
    #[test]
    fn two_signatures_over_an_identical_request_differ() {
        let kp = Keypair::generate();
        let a = sign_request(&kp, "POST", "/api/register", b"same body");
        let b = sign_request(&kp, "POST", "/api/register", b"same body");

        assert_ne!(
            a.nonce, b.nonce,
            "each sign_request call must draw a fresh nonce"
        );
        assert_ne!(
            a.signature_input, b.signature_input,
            "the nonce must reach the wire header, not just the struct"
        );
        assert_ne!(
            a.signature, b.signature,
            "a covered nonce must change the signature bytes"
        );
    }

    /// U2: `parse` round-trips the nonce, and a nonce-less header still parses.
    #[test]
    fn parse_exposes_nonce_and_tolerates_its_absence() {
        let kp = Keypair::generate();
        let headers = sign_request(&kp, "POST", "/api/register", b"body");
        let parsed = HttpSignature::parse(&headers.signature_input, &headers.signature).unwrap();
        assert_eq!(
            parsed.nonce.as_deref(),
            Some(headers.nonce.as_str()),
            "the parsed nonce must be the one that was signed, unquoted"
        );

        let did = kp.did();
        let nonceless = format!(
            r#"sig1=("@method" "@path" "content-digest");keyid="{did}";alg="ed25519";created=1000"#
        );
        let parsed = HttpSignature::parse(&nonceless, &headers.signature).unwrap();
        assert_eq!(
            parsed.nonce, None,
            "a pre-U2 signer's header must parse with no nonce"
        );
    }

    /// U2: 128 bits of entropy, hex-encoded.
    #[test]
    fn nonce_is_128_bits() {
        let kp = Keypair::generate();
        let headers = sign_request(&kp, "GET", "/api/v1/agents", b"");
        let raw = hex::decode(&headers.nonce).expect("nonce must be hex");
        assert_eq!(raw.len(), 16, "nonce must carry exactly 128 bits");
    }

    /// U2 backward compatibility, the load-bearing one: a nonce-bearing
    /// signature still verifies through the same reconstruct-and-verify flow
    /// the node runs, with no verifier change.
    #[test]
    fn nonce_bearing_signature_verifies_through_the_unchanged_flow() {
        use crate::identity::verify;

        let kp = Keypair::generate();
        let body = b"{\"did\":\"did:key:z6Mk\"}";
        let headers = sign_request(&kp, "POST", "/api/register", body);
        assert!(
            headers.signature_input.contains(";nonce=\""),
            "this test is only meaningful once the header carries a nonce"
        );

        let sig = HttpSignature::parse(&headers.signature_input, &headers.signature).unwrap();
        assert_eq!(
            sig.components, COVERED_COMPONENTS,
            "the nonce must not disturb the covered-component list"
        );

        // Exactly what the node does: rebuild @signature-params from the
        // received header text and verify over it.
        let sig_params_value = headers.signature_input.strip_prefix("sig1=").unwrap();
        let mut request_values = HashMap::new();
        request_values.insert("@method".to_string(), "POST".to_string());
        request_values.insert("@path".to_string(), "/api/register".to_string());
        request_values.insert("content-digest".to_string(), headers.content_digest.clone());
        let components_ref: Vec<&str> = sig.components.iter().map(String::as_str).collect();
        let signing_string =
            build_signing_string(&components_ref, sig_params_value, &request_values).unwrap();

        let vk = sig.key_id.to_verifying_key().unwrap();
        let sig_bytes: [u8; 64] = sig.signature_bytes.clone().try_into().unwrap();
        assert!(
            verify(&vk, signing_string.as_bytes(), &sig_bytes).is_ok(),
            "a nonce-bearing signature must verify unchanged"
        );

        // And the nonce is genuinely covered: strip it and verification fails.
        let without_nonce = sig_params_value
            .split(";nonce=")
            .next()
            .unwrap()
            .to_string();
        let tampered =
            build_signing_string(&components_ref, &without_nonce, &request_values).unwrap();
        assert!(
            verify(&vk, tampered.as_bytes(), &sig_bytes).is_err(),
            "the nonce must be inside @signature-params, not decoration"
        );
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
