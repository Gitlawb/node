//! `gl cert` — ref certificate commands.
//!
//! Certificates are node-signed receipts proving that a push was accepted.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::Value;
use std::path::PathBuf;

use crate::http::NodeClient;
use crate::identity::load_keypair_from_dir;

fn signed_client(node: &str, dir: Option<&std::path::Path>) -> NodeClient {
    NodeClient::new(node, load_keypair_from_dir(dir).ok())
}

#[derive(Args)]
pub struct CertArgs {
    #[command(subcommand)]
    pub cmd: CertCmd,
}

#[derive(Subcommand)]
pub enum CertCmd {
    /// List ref certificates for a repository
    List {
        /// Repository in <owner>/<repo> or <repo> format
        repo: String,
        #[arg(
            long,
            default_value = "https://node.twigpine.com",
            env = "GITLAWB_NODE"
        )]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Show a specific ref certificate and verify its signature.
    ///
    /// `--verify` requires `--expect-node <did>`: the queried node's
    /// self-reported DID is not a trust anchor, because a node serving a
    /// forged certificate also controls its own self-report. Callers
    /// must name the issuer they trust.
    Show {
        /// Repository in <owner>/<repo> or <repo> format
        repo: String,
        /// Certificate ID
        id: String,
        #[arg(
            long,
            default_value = "https://node.twigpine.com",
            env = "GITLAWB_NODE"
        )]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Exit non-zero unless the Ed25519 signature verifies AND the
        /// issuing node matches --expect-node (which --verify requires:
        /// without a caller-supplied anchor there is no trusted issuer to
        /// verify against)
        #[arg(long)]
        verify: bool,
        /// Expected issuing node DID for --verify. A valid signature alone
        /// only proves the cert is internally consistent — signed by whatever
        /// key it names — so --verify also anchors the issuer to a DID you
        /// trust. The queried node's self-reported DID is deliberately NOT
        /// accepted as a fallback anchor: the node that served the cert can
        /// serve a matching self-report.
        #[arg(long, requires = "verify")]
        expect_node: Option<String>,
    },
}

pub async fn run(args: CertArgs) -> Result<()> {
    match args.cmd {
        CertCmd::List { repo, node, dir } => cmd_list(repo, node, dir).await,
        CertCmd::Show {
            repo,
            id,
            node,
            dir,
            verify,
            expect_node,
        } => cmd_show(repo, id, node, dir, verify, expect_node).await,
    }
}

/// Resolve "repo" into (owner, name) using the caller's DID when no slash is given.
async fn resolve_repo(
    repo: &str,
    node: &str,
    dir: Option<&std::path::Path>,
) -> Result<(String, String)> {
    if let Some((owner, name)) = repo.split_once('/') {
        Ok((owner.to_string(), name.to_string()))
    } else {
        let short = if let Ok(kp) = load_keypair_from_dir(dir) {
            let did = kp.did().to_string();
            did.split(':').next_back().unwrap_or(&did).to_string()
        } else {
            let client = signed_client(node, dir);
            let info = crate::http::read_json(client.get_authed("/").await?, "node info").await?;
            let did = info["did"].as_str().context("node info missing 'did'")?;
            did.split(':').next_back().unwrap_or(did).to_string()
        };
        Ok((short, repo.to_string()))
    }
}

async fn cmd_list(repo: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    let (owner, name) = resolve_repo(&repo, &node, dir.as_deref()).await?;

    let client = signed_client(&node, dir.as_deref());
    let path = format!("/api/v1/repos/{owner}/{name}/certs");
    let resp = crate::http::read_json(client.get_authed(&path).await?, "certificates").await?;

    let certs = resp["certificates"].as_array().cloned().unwrap_or_default();

    if certs.is_empty() {
        println!("No ref certificates for {owner}/{name}");
        return Ok(());
    }

    println!("Ref certificates for {owner}/{name}");
    println!();
    for cert in &certs {
        let id = cert["id"].as_str().unwrap_or("?");
        let ref_name = cert["ref_name"].as_str().unwrap_or("?");
        let new_sha = cert["new_sha"].as_str().unwrap_or("?");
        let issued_at = cert["issued_at"]
            .as_str()
            .map(|s| crate::text::truncate(s, 19))
            .unwrap_or("?");
        println!("  {id:.8}  {issued_at}  {ref_name}  {new_sha:.12}");
    }
    Ok(())
}

async fn cmd_show(
    repo: String,
    id: String,
    node: String,
    dir: Option<PathBuf>,
    require_valid: bool,
    expect_node: Option<String>,
) -> Result<()> {
    let (owner, name) = resolve_repo(&repo, &node, dir.as_deref()).await?;

    let client = signed_client(&node, dir.as_deref());
    let id = resolve_cert_id(&client, &owner, &name, &id).await?;

    // Fetch the certificate. read_json checks status first and surfaces the node's
    // capped+sanitized message on a non-2xx (a bounded error read, not the whole body).
    let path = format!("/api/v1/repos/{owner}/{name}/certs/{id}");
    let cert = crate::http::read_json(client.get_authed(&path).await?, "certificate").await?;

    let cert_id = cert["id"].as_str().unwrap_or("?");
    let ref_name = cert["ref_name"].as_str().unwrap_or("?");
    let old_sha = cert["old_sha"].as_str().unwrap_or("?");
    let new_sha = cert["new_sha"].as_str().unwrap_or("?");
    let pusher = cert["pusher_did"].as_str().unwrap_or("?");
    let node_did = cert["node_did"].as_str().unwrap_or("?");
    let signature = cert["signature"].as_str().unwrap_or("?");
    let issued_at = cert["issued_at"].as_str().unwrap_or("?");
    // #26 Split PR 3: read the wire-format version. A MISSING key
    // selects legacy v1 (an old server that predates the field).
    // A PRESENT value must be a JSON integer that fits in u32 and
    // names a version this client supports — otherwise the response
    // declares a format we cannot represent and we refuse to verify
    // rather than guess the payload shape. Reviewer 2 finding:
    // collapsing `null`, a string, a float, or an overflow integer
    // onto v1 would let a well-signed v1 signature pass `--verify`
    // against a server that explicitly said "version 2 (or 99, or
    // 4294967297)" — that is the exact mismatch the field exists
    // to prevent. parse_cert_version is the load-bearing parser
    // that distinguishes missing-key (legacy v1) from invalid-value
    // (unsupported).
    let parsed_version = parse_cert_version(cert.get("version"));
    let version_display: String = match &parsed_version {
        Ok(v) => v.to_string(),
        Err(reason) => format!("unsupported ({reason})"),
    };

    println!("Ref Certificate: {cert_id}");
    println!("  Ref:       {ref_name}");
    println!("  Old SHA:   {old_sha}");
    println!("  New SHA:   {new_sha}");
    println!("  Pusher:    {pusher}");
    println!("  Node DID:  {node_did}");
    println!("  Issued at: {issued_at}");
    println!("  Version:   {version_display}");
    println!("  Signature: {signature}");
    println!();

    // Verify the Ed25519 signature: rebuild the exact canonical payload the
    // node signed (see gitlawb-node/src/cert.rs::issue_ref_certificate) and
    // check it against the public key embedded in the certificate's node DID.
    // This proves the cert is internally authentic — signed by the key it
    // names; the node-DID comparison below covers *which* node that is.
    let repo_id = cert["repo_id"].as_str().unwrap_or("");
    let verdict = match parsed_version {
        // v1 is the only version this client verifies. The v1
        // signed payload is the 7-field canonical form with no
        // `version` key — see gitlawb-node/src/cert.rs. A future
        // v2+ cert has a different signed payload shape (the
        // version field becomes part of the signed JSON per
        // `v2_signing_payload`), so a v2+ cert from a server this
        // client does not know about must NOT be silently verified
        // as v1.
        // Reviewer 2: refuse rather than guess; the client and
        // server must agree on the version.
        // parse_cert_version admits exactly one Ok value: 1 (missing key and
        // integer 1 both land there; 2, floats, strings, overflow and every
        // other spelling come back Err with their own reason). A separate
        // `Ok(v != 1)` arm existed here and was DEAD CODE — a test aimed at it
        // could never catch drift in this match (review round 2) — so the
        // match now mirrors the parser's real contract, which the
        // `parse_cert_version_truth_table` test pins.
        Ok(_) => verify_signature(
            repo_id, ref_name, old_sha, new_sha, pusher, node_did, issued_at, signature,
        ),
        Err(ref reason) => Err(format!(
            "cert declared a version this client cannot represent ({reason}); refusing to verify"
        )),
    };

    println!("Signature verification:");
    match &verdict {
        Ok(()) => {
            println!(
                "  VALID — Ed25519 signature verified against the key the certificate names ({node_did})"
            );
        }
        Err(reason) => {
            // A version refusal means no cryptographic check ran, so it must
            // not print as an INVALID signature: operators and log scrapers
            // would read that as a failed Ed25519 verification. INVALID is
            // reserved for failures out of verify_signature itself.
            println!("  {} — {reason}", signature_verdict_label(&parsed_version));
        }
    }

    // Contextual only — the verdict above stands on its own, so a node-info
    // hiccup here must not turn a successfully displayed certificate into an
    // error exit. Route the lookup through read_json so a denial or a capped
    // error body yields a reportable reason instead of an opaque None, and keep
    // "carried no DID" distinct from "the lookup failed": an empty DID must not
    // reach the comparison and fabricate a mismatch warning.
    let current: std::result::Result<String, String> = match client.get("/").await {
        Ok(resp) => match crate::http::read_json(resp, "node info").await {
            Ok(info) => did_from_node_info(&info),
            Err(e) => Err(e.to_string()),
        },
        Err(e) => Err(e.to_string()),
    };
    for line in did_check_report(&current, node_did) {
        println!("{line}");
    }

    if require_valid {
        if let Err(reason) = verdict {
            // Round 3: do not claim the signature failed when it was
            // never checked. A version refusal means the payload
            // shape is unknown, so no signature verification ran.
            anyhow::bail!("certificate could not be verified: {reason}");
        }
        // A valid signature proves internal consistency only: the payload was
        // signed by whatever key the certificate itself names. A hostile
        // source can mint a keypair, put its DID in node_did, and self-sign.
        // --verify therefore also anchors the issuer — and the anchor must be
        // a DID the CALLER trusts, which is exactly what --expect-node is.
        // The DID the queried node reports at `/` is NOT an anchor: the same
        // node that served a forged certificate can serve a matching
        // self-report, and with that fallback a wholly forged cert printed
        // VALID and exited 0 (review round 2, demonstrated by execution). So
        // --verify without --expect-node refuses to claim a trusted issuer at
        // all, rather than laundering the server's self-assertion into one.
        match expect_node.as_deref() {
            Some(expected) if expected == node_did => {}
            Some(expected) => anyhow::bail!(
                "certificate is signed by {node_did}, but the expected issuer is {expected} — \
                 a valid signature alone proves internal consistency, not a trusted issuer"
            ),
            None => anyhow::bail!(
                "--verify needs --expect-node <did> to anchor the issuer: the signature is \
                 valid, but it only proves the cert is self-consistent with the DID it \
                 names ({node_did}); the queried node's self-reported DID is not a trust \
                 anchor"
            ),
        }
    }

    Ok(())
}

/// Pull the node's DID out of a `GET /` body for the comparison in `cmd_show`.
///
/// A missing OR empty `did` is a failure, not a value: letting `""` through
/// would reach the comparison and print a mismatch WARNING against a DID the
/// node never claimed, which reads as "issued by a different node" when the
/// truth is that the lookup told us nothing.
fn did_from_node_info(info: &serde_json::Value) -> std::result::Result<String, String> {
    match info["did"].as_str() {
        Some(did) if !did.is_empty() => Ok(did.to_string()),
        _ => Err("node info response carried no DID".to_string()),
    }
}

/// Select the report lines for the node-DID comparison in `cmd_show`.
///
/// `current` is the current node's DID, or the reason it could not be
/// determined. A comparison verdict (match or WARNING) is only produced when a
/// real DID was obtained; otherwise the report degrades to a could-not-compare
/// hint naming the reason, plus the offline-verification guidance. The signature
/// verdict printed above stands on its own either way — this block only answers
/// *which* node issued the certificate.
fn did_check_report(current: &std::result::Result<String, String>, node_did: &str) -> Vec<String> {
    match current {
        Ok(current) if current == node_did => {
            vec!["  Issuing node DID matches the node being queried.".to_string()]
        }
        Ok(current) => vec![
            format!("  WARNING: Certificate node DID ({node_did}) does not match"),
            format!("           current node DID ({current})."),
            "           This certificate was issued by a different node.".to_string(),
        ],
        Err(reason) => vec![
            format!("  Could not fetch the current node's DID ({reason}), so the comparison"),
            "  with the certificate's node DID is unavailable.".to_string(),
            "  To verify offline, use the node's Ed25519 public key derived from:".to_string(),
            format!("    did:key → {node_did}"),
        ],
    }
}

/// The stdout label for a failed verification verdict. A `parsed_version`
/// error means `verify_signature` never ran, so the refusal must print as
/// UNSUPPORTED VERSION rather than INVALID, which operators and log
/// scrapers would read as a failed Ed25519 check.
fn signature_verdict_label(parsed_version: &std::result::Result<u32, String>) -> &'static str {
    if parsed_version.is_err() {
        "UNSUPPORTED VERSION"
    } else {
        "INVALID"
    }
}

/// Rebuild the node's canonical signing payload (field order must match
/// gitlawb-node/src/cert.rs::issue_ref_certificate exactly) and verify the
/// certificate's Ed25519 signature against the key embedded in `node_did`.
#[allow(clippy::too_many_arguments)]
fn verify_signature(
    repo_id: &str,
    ref_name: &str,
    old_sha: &str,
    new_sha: &str,
    pusher: &str,
    node_did: &str,
    issued_at: &str,
    signature_b64: &str,
) -> std::result::Result<(), String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use std::str::FromStr;

    let payload = serde_json::json!({
        "repo_id": repo_id,
        "ref":     ref_name,
        "old":     old_sha,
        "new":     new_sha,
        "pusher":  pusher,
        "node":    node_did,
        "ts":      issued_at,
    });
    let payload_bytes =
        serde_json::to_vec(&payload).map_err(|e| format!("could not serialize payload: {e}"))?;

    let did =
        gitlawb_core::did::Did::from_str(node_did).map_err(|e| format!("bad node DID: {e}"))?;
    let verifying_key = did
        .to_verifying_key()
        .map_err(|e| format!("cannot derive a public key from {node_did}: {e}"))?;

    let sig_vec = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|e| format!("signature is not valid base64url: {e}"))?;
    let sig_bytes: [u8; 64] = sig_vec
        .try_into()
        .map_err(|_| "signature is not 64 bytes".to_string())?;

    gitlawb_core::identity::verify(&verifying_key, &payload_bytes, &sig_bytes)
        .map_err(|_| "Ed25519 signature does not match the signed payload".to_string())
}

/// Parse the wire-format `version` field of a certificate response.
///
/// Semantics (Reviewer 2):
///   - MISSING key (`None`) → `Ok(1)`. An old server predates the field, so
///     the cert is by definition the v1 (pre-versioning) shape; the v1
///     verify path is the only path that can possibly match the bytes.
///   - PRESENT key must be a JSON integer that fits losslessly in `u32`
///     and equals a version this client supports. `null`, a string,
///     a float, an overflow integer, or any version other than 1 all
///     yield `Err`. Collapsing any of these onto v1 would let a
///     well-signed v1 signature pass `--verify` against a response
///     that explicitly declared a format this client cannot represent
///     — which is exactly the mismatch the version field exists to
///     prevent.
///
/// The supported-version set is hard-coded to `{1}` because PR 3 ships
/// only v1 verification; bump this set (and the verdict branch) when
/// v2 verification lands.
fn parse_cert_version(value: Option<&Value>) -> Result<u32, String> {
    let v = match value {
        None => return Ok(1),
        Some(v) => v,
    };

    // serde_json::Value::as_u64 rejects strings, floats, booleans,
    // nulls, arrays, and objects — but it silently truncates floats
    // that are whole numbers (e.g. 2.0 → 2). We must reject floats
    // explicitly so a server cannot smuggle a v2 cert through the
    // float shape.
    if v.is_f64() {
        return Err(format!(
            "version is a JSON number with a fractional part ({v}); expected an integer"
        ));
    }

    let n = v.as_u64().ok_or_else(|| {
        // null / string / bool / array / object — anything that is
        // not a JSON integer.
        format!("version is {v}; expected a JSON integer")
    })?;

    // Lossy narrowing: refuse anything that does not fit in u32.
    // u32::MAX is 4_294_967_295; serde_json only goes up to u64.
    if n > u32::MAX as u64 {
        return Err(format!(
            "version {n} does not fit in u32 (max {})",
            u32::MAX
        ));
    }

    let n = n as u32;
    if n != 1 {
        return Err(format!(
            "this client supports cert version 1 only; server returned {n}"
        ));
    }
    Ok(1)
}

async fn resolve_cert_id(client: &NodeClient, owner: &str, name: &str, id: &str) -> Result<String> {
    if id.len() >= 36 {
        return Ok(id.to_string());
    }

    let path = format!("/api/v1/repos/{owner}/{name}/certs?prefix={id}");
    let resp = crate::http::read_json(client.get_authed(&path).await?, "certificates").await?;

    let certs = resp["certificates"].as_array().cloned().unwrap_or_default();
    let matches: Vec<String> = certs
        .iter()
        .filter_map(|cert| cert["id"].as_str())
        .map(ToString::to_string)
        .collect();

    match matches.as_slice() {
        [full_id] => Ok(full_id.to_string()),
        [] => Ok(id.to_string()),
        _ => anyhow::bail!("certificate prefix {id} matches multiple certificates"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins gl's payload reconstruction to the frozen canonical byte form the
    /// node signs (default serde_json maps = alphabetically ordered keys). If
    /// serialization drifts — a field added, or a preserve_order feature
    /// landing anywhere in the workspace (feature unification flips every
    /// crate at once) — this literal stops matching and the test fails,
    /// instead of every real certificate silently rendering INVALID.
    #[test]
    fn payload_serialization_matches_frozen_canonical_form() {
        let payload = serde_json::json!({
            "repo_id": "repo-1",
            "ref":     "refs/heads/main",
            "old":     "oldsha",
            "new":     "newsha",
            "pusher":  "did:key:z6MkPusher",
            "node":    "did:key:z6MkNode",
            "ts":      "2026-07-22T00:00:00+00:00",
        });
        let frozen = concat!(
            r#"{"new":"newsha","node":"did:key:z6MkNode","old":"oldsha","#,
            r#""pusher":"did:key:z6MkPusher","ref":"refs/heads/main","#,
            r#""repo_id":"repo-1","ts":"2026-07-22T00:00:00+00:00"}"#,
        );
        assert_eq!(serde_json::to_string(&payload).unwrap(), frozen);
    }

    /// Signing exactly as the node does must round-trip through
    /// verify_signature; any field tampering must fail it.
    #[test]
    fn verify_signature_round_trip_and_tamper() {
        let kp = gitlawb_core::identity::Keypair::generate();
        let node_did = kp.did().as_str().to_string();

        let payload = serde_json::json!({
            "repo_id": "repo-1",
            "ref":     "refs/heads/main",
            "old":     "0".repeat(40),
            "new":     "a".repeat(40),
            "pusher":  "did:key:z6MkPusher",
            "node":    node_did,
            "ts":      "2026-07-22T00:00:00+00:00",
        });
        let sig = kp.sign_b64(&serde_json::to_vec(&payload).unwrap());

        let ok = verify_signature(
            "repo-1",
            "refs/heads/main",
            &"0".repeat(40),
            &"a".repeat(40),
            "did:key:z6MkPusher",
            &node_did,
            "2026-07-22T00:00:00+00:00",
            &sig,
        );
        assert!(ok.is_ok(), "expected valid signature, got: {ok:?}");

        let tampered = verify_signature(
            "repo-1",
            "refs/heads/main",
            &"0".repeat(40),
            &"b".repeat(40), // new_sha changed after signing
            "did:key:z6MkPusher",
            &node_did,
            "2026-07-22T00:00:00+00:00",
            &sig,
        );
        assert!(tampered.is_err(), "tampered payload must not verify");

        let garbage = verify_signature(
            "repo-1",
            "refs/heads/main",
            &"0".repeat(40),
            &"a".repeat(40),
            "did:key:z6MkPusher",
            &node_did,
            "2026-07-22T00:00:00+00:00",
            "not-base64url!!!",
        );
        assert!(garbage.is_err(), "malformed signature must not verify");
    }

    #[tokio::test]
    async fn cmd_list_surfaces_denial_not_empty() {
        // A gated 404 on the repo-scoped certs read must Err, not print "No certificates".
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos/alice/secret/certs$".to_string()),
            )
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"repository 'alice/secret' not found"}"#)
            .expect(1)
            .create_async()
            .await;
        let result = cmd_list("alice/secret".to_string(), server.url(), None).await;
        assert!(result.is_err(), "cert list must Err on a gated 404");
        // Prove the gated certs path was actually requested: without this, an
        // unmatched route (mockito's 501, also non-2xx) would satisfy is_err().
        _m.assert_async().await;
    }

    #[tokio::test]
    async fn resolve_repo_surfaces_denial() {
        // A slash-free repo with an empty identity dir forces the GET / node-info
        // fetch. A gated 404 there must Err (surfacing the status), proving the
        // read_json conversion is load-bearing rather than silently ignored.
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap(); // empty, no identity.pem, forces the GET / branch
        let _m = server
            .mock("GET", "/")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"denied"}"#)
            .expect(1)
            .create_async()
            .await;
        let err = resolve_repo("noslash", &server.url(), Some(dir.path()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("404"), "got: {err}");
        _m.assert_async().await;
    }

    // The `GET /` node-info lookup after the cert loads is a fail-soft diagnostic:
    // a response-level failure degrades to a could-not-compare hint and the command
    // completes Ok, never a fabricated mismatch warning and never a fatal Err. The
    // cert fetch itself stays fail-closed. A >=36-char id skips resolve_cert_id so
    // only two mocks are needed.
    #[tokio::test]
    async fn cmd_show_completes_with_degraded_hint_when_node_info_denied() {
        let mut server = mockito::Server::new_async().await;
        let long_id = "a".repeat(36);
        let _cert = server
            .mock(
                "GET",
                format!("/api/v1/repos/alice/secret/certs/{long_id}").as_str(),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"id":"c1","ref_name":"refs/heads/main","old_sha":"0","new_sha":"1","pusher_did":"p","node_did":"n","signature":"s","issued_at":"2026-01-01T00:00:00Z"}"#,
            )
            .create_async()
            .await;
        let _root = server
            .mock("GET", "/")
            .with_status(403)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"denied"}"#)
            .expect(1)
            .create_async()
            .await;

        let result = cmd_show(
            "alice/secret".to_string(),
            long_id,
            server.url(),
            None,
            false,
            None,
        )
        .await;
        assert!(
            result.is_ok(),
            "cert show must complete despite a denied node-info lookup"
        );
        _cert.assert_async().await;
        _root.assert_async().await;
    }

    #[tokio::test]
    async fn cmd_show_degrades_on_malformed_node_info() {
        // A 2xx node-info body that fails to parse degrades the same way a denial
        // does: hint printed, command completes Ok.
        let mut server = mockito::Server::new_async().await;
        let long_id = "a".repeat(36);
        let _cert = server
            .mock(
                "GET",
                format!("/api/v1/repos/alice/secret/certs/{long_id}").as_str(),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"id":"c1","ref_name":"refs/heads/main","old_sha":"0","new_sha":"1","pusher_did":"p","node_did":"n","signature":"s","issued_at":"2026-01-01T00:00:00Z"}"#,
            )
            .create_async()
            .await;
        let _root = server
            .mock("GET", "/")
            .with_status(200)
            .with_body("not json")
            .expect(1)
            .create_async()
            .await;

        let result = cmd_show(
            "alice/secret".to_string(),
            long_id,
            server.url(),
            None,
            false,
            None,
        )
        .await;
        assert!(
            result.is_ok(),
            "cert show must complete despite malformed node info"
        );
        _cert.assert_async().await;
        _root.assert_async().await;
    }

    #[tokio::test]
    async fn cmd_show_degrades_when_node_info_lacks_did() {
        // A 2xx node-info body with no `did` routes to the degraded hint, not a
        // fabricated empty-DID mismatch warning; the command completes Ok.
        let mut server = mockito::Server::new_async().await;
        let long_id = "a".repeat(36);
        let _cert = server
            .mock(
                "GET",
                format!("/api/v1/repos/alice/secret/certs/{long_id}").as_str(),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"id":"c1","ref_name":"refs/heads/main","old_sha":"0","new_sha":"1","pusher_did":"p","node_did":"n","signature":"s","issued_at":"2026-01-01T00:00:00Z"}"#,
            )
            .create_async()
            .await;
        let _root = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .expect(1)
            .create_async()
            .await;

        let result = cmd_show(
            "alice/secret".to_string(),
            long_id,
            server.url(),
            None,
            false,
            None,
        )
        .await;
        assert!(
            result.is_ok(),
            "cert show must complete when node info lacks a DID"
        );
        _cert.assert_async().await;
        _root.assert_async().await;
    }

    // Must-not case: the certificate fetch itself stays fail-closed. A gated 404
    // aborts the command with the status surfaced, and the node-info lookup is
    // never reached (the expect(0) assert proves it never ran).
    #[tokio::test]
    async fn cmd_show_surfaces_denied_certificate() {
        let mut server = mockito::Server::new_async().await;
        let long_id = "a".repeat(36);
        let _cert = server
            .mock(
                "GET",
                format!("/api/v1/repos/alice/secret/certs/{long_id}").as_str(),
            )
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"repository not found"}"#)
            .expect(1)
            .create_async()
            .await;
        let _root = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"did":"n"}"#)
            .expect(0)
            .create_async()
            .await;

        let err = cmd_show(
            "alice/secret".to_string(),
            long_id,
            server.url(),
            None,
            false,
            None,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("404"), "got: {err}");
        _cert.assert_async().await;
        _root.assert_async().await;
    }

    #[tokio::test]
    async fn cmd_show_reports_matching_node_did() {
        // Pins the unchanged success path: node info fetched, DIDs compared, Ok.
        let mut server = mockito::Server::new_async().await;
        let long_id = "a".repeat(36);
        let _cert = server
            .mock(
                "GET",
                format!("/api/v1/repos/alice/secret/certs/{long_id}").as_str(),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"id":"c1","ref_name":"refs/heads/main","old_sha":"0","new_sha":"1","pusher_did":"p","node_did":"n","signature":"s","issued_at":"2026-01-01T00:00:00Z"}"#,
            )
            .create_async()
            .await;
        let _root = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"did":"n"}"#)
            .expect(1)
            .create_async()
            .await;

        let result = cmd_show(
            "alice/secret".to_string(),
            long_id,
            server.url(),
            None,
            false,
            None,
        )
        .await;
        assert!(result.is_ok(), "cert show must report a matching node DID");
        _cert.assert_async().await;
        _root.assert_async().await;
    }

    #[tokio::test]
    async fn cmd_show_warns_on_mismatching_node_did() {
        // A real, differing node DID drives the WARNING branch end to end; the
        // command still completes Ok.
        let mut server = mockito::Server::new_async().await;
        let long_id = "a".repeat(36);
        let _cert = server
            .mock(
                "GET",
                format!("/api/v1/repos/alice/secret/certs/{long_id}").as_str(),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"id":"c1","ref_name":"refs/heads/main","old_sha":"0","new_sha":"1","pusher_did":"p","node_did":"n","signature":"s","issued_at":"2026-01-01T00:00:00Z"}"#,
            )
            .create_async()
            .await;
        let _root = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"did":"did:key:other"}"#)
            .expect(1)
            .create_async()
            .await;

        let result = cmd_show(
            "alice/secret".to_string(),
            long_id,
            server.url(),
            None,
            false,
            None,
        )
        .await;
        assert!(
            result.is_ok(),
            "cert show must warn, not fail, on a mismatching node DID"
        );
        _cert.assert_async().await;
        _root.assert_async().await;
    }

    // ── --verify issuer anchoring ────────────────────────────────────────────
    //
    // Every other cmd_show test passes require_valid=false, so the whole
    // `if require_valid` block went unexecuted. It is the security-bearing half of
    // the command: a valid signature only proves the certificate is internally
    // consistent (a hostile node can mint a keypair, name it in node_did, and
    // self-sign), so --verify must additionally anchor the issuer to a DID the
    // caller trusts. These drive all four outcomes plus the must-not case.
    //
    // The certificate must carry a REAL signature over the canonical payload:
    // with a bogus one, --verify bails on the signature and never reaches the
    // anchoring, which would make every assertion below vacuous.
    fn signed_cert(node_kp: &gitlawb_core::identity::Keypair) -> (String, String) {
        let node_did = node_kp.did().as_str().to_string();
        let id = "a".repeat(36); // >= 36 chars skips resolve_cert_id's prefix lookup
        let payload = serde_json::json!({
            "repo_id": "repo-1",
            "ref":     "refs/heads/main",
            "old":     "0".repeat(40),
            "new":     "b".repeat(40),
            "pusher":  "did:key:z6MkPusher",
            "node":    node_did,
            "ts":      "2026-07-22T00:00:00+00:00",
        });
        let sig = node_kp.sign_b64(&serde_json::to_vec(&payload).unwrap());
        let body = serde_json::json!({
            "id": id,
            "repo_id": "repo-1",
            "ref_name": "refs/heads/main",
            "old_sha": "0".repeat(40),
            "new_sha": "b".repeat(40),
            "pusher_did": "did:key:z6MkPusher",
            "node_did": node_did,
            "signature": sig,
            "issued_at": "2026-07-22T00:00:00+00:00",
        })
        .to_string();
        (id, body)
    }

    /// Mount the cert fetch, plus a `GET /` answering with `node_info` (a JSON
    /// body) or a denial when `None`.
    async fn cert_server(
        server: &mut mockito::Server,
        id: &str,
        cert_body: &str,
        node_info: Option<&str>,
    ) -> (mockito::Mock, mockito::Mock) {
        let cert = server
            .mock("GET", format!("/api/v1/repos/alice/r/certs/{id}").as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(cert_body)
            .expect(1)
            .create_async()
            .await;
        let root = match node_info {
            Some(b) => {
                server
                    .mock("GET", "/")
                    .with_status(200)
                    .with_header("content-type", "application/json")
                    .with_body(b)
                    .create_async()
                    .await
            }
            None => {
                server
                    .mock("GET", "/")
                    .with_status(403)
                    .with_header("content-type", "application/json")
                    .with_body(r#"{"message":"denied"}"#)
                    .create_async()
                    .await
            }
        };
        (cert, root)
    }

    #[tokio::test]
    async fn verify_ok_when_issuing_node_is_the_queried_node() {
        let kp = gitlawb_core::identity::Keypair::generate();
        let (id, body) = signed_cert(&kp);
        let info = format!(r#"{{"did":"{}"}}"#, kp.did().as_str());
        let mut server = mockito::Server::new_async().await;
        let (cert, _root) = cert_server(&mut server, &id, &body, Some(&info)).await;

        let got = cmd_show(
            "alice/r".to_string(),
            id,
            server.url(),
            None,
            true,
            Some(kp.did().as_str().to_string()),
        )
        .await;
        assert!(got.is_ok(), "valid sig + matching issuer must pass");
        cert.assert_async().await;
    }

    #[tokio::test]
    async fn verify_bails_when_issuer_is_a_different_node() {
        // The self-signing-hostile-node case: the signature verifies against the
        // key the cert names, but that key is not the node we queried.
        let kp = gitlawb_core::identity::Keypair::generate();
        let (id, body) = signed_cert(&kp);
        let other = gitlawb_core::identity::Keypair::generate();
        let info = format!(r#"{{"did":"{}"}}"#, other.did().as_str());
        let mut server = mockito::Server::new_async().await;
        let (cert, _root) = cert_server(&mut server, &id, &body, Some(&info)).await;

        let err = cmd_show(
            "alice/r".to_string(),
            id,
            server.url(),
            None,
            true,
            Some(other.did().as_str().to_string()),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("expected issuer"), "got: {err}");
        cert.assert_async().await;
    }

    #[tokio::test]
    async fn verify_bails_when_node_info_denied_and_no_expect_node() {
        // Fail closed: with no trusted DID to anchor against, --verify must NOT
        // fall through to a pass just because the signature checked out.
        let kp = gitlawb_core::identity::Keypair::generate();
        let (id, body) = signed_cert(&kp);
        let mut server = mockito::Server::new_async().await;
        let (cert, _root) = cert_server(&mut server, &id, &body, None).await;

        let err = cmd_show("alice/r".to_string(), id, server.url(), None, true, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("--expect-node"), "got: {err}");
        cert.assert_async().await;
    }

    #[tokio::test]
    async fn verify_ok_when_expect_node_anchors_a_denied_lookup() {
        // --expect-node supplies the trust anchor the denied lookup could not, so
        // the same denial that fails the case above now passes.
        let kp = gitlawb_core::identity::Keypair::generate();
        let (id, body) = signed_cert(&kp);
        let mut server = mockito::Server::new_async().await;
        let (cert, _root) = cert_server(&mut server, &id, &body, None).await;

        let got = cmd_show(
            "alice/r".to_string(),
            id,
            server.url(),
            None,
            true,
            Some(kp.did().as_str().to_string()),
        )
        .await;
        assert!(got.is_ok(), "explicit anchor must pass");
        cert.assert_async().await;
    }

    #[tokio::test]
    async fn verify_bails_on_a_bad_signature_before_anchoring() {
        // The must-not: a forged certificate naming the queried node must fail on
        // the signature, even though its issuer would otherwise anchor cleanly.
        let kp = gitlawb_core::identity::Keypair::generate();
        let (id, body) = signed_cert(&kp);
        let forged = body.replace(&"b".repeat(40), &"c".repeat(40));
        let info = format!(r#"{{"did":"{}"}}"#, kp.did().as_str());
        let mut server = mockito::Server::new_async().await;
        let (cert, _root) = cert_server(&mut server, &id, &forged, Some(&info)).await;

        let err = cmd_show("alice/r".to_string(), id, server.url(), None, true, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match"), "got: {err}");
        cert.assert_async().await;
    }

    // The must-not case for the DID extraction: an empty or missing `did` has to
    // become a could-not-compare reason. If it leaks through as a value, the
    // comparison below fabricates a mismatch WARNING against a DID the node
    // never claimed.
    #[test]
    fn did_from_node_info_rejects_empty_and_missing() {
        assert!(did_from_node_info(&serde_json::json!({"did": "n"})).is_ok());
        for body in [
            serde_json::json!({"did": ""}),
            serde_json::json!({}),
            serde_json::json!({"did": 7}),
        ] {
            let got = did_from_node_info(&body);
            assert!(
                got.is_err(),
                "must not yield a comparable DID: {body} -> {got:?}"
            );
        }
        // And the reason it produces must route to the degraded hint, never a verdict.
        let report =
            did_check_report(&did_from_node_info(&serde_json::json!({"did": ""})), "n").join("\n");
        assert!(
            !report.contains("WARNING"),
            "fabricated a mismatch: {report}"
        );
        assert!(report.contains("Could not fetch"), "got: {report}");
    }

    // did_check_report is the three-way selector between the match text, the
    // mismatch WARNING, and the degraded could-not-compare hint. Substring
    // asserts (not full-line equality) so cosmetic wording edits don't break them.

    #[test]
    fn did_check_report_match() {
        let report = did_check_report(&Ok("n".to_string()), "n").join("\n");
        assert!(
            report.contains("matches the node being queried"),
            "got: {report}"
        );
        assert!(!report.contains("WARNING"), "got: {report}");
        assert!(!report.contains("Could not fetch"), "got: {report}");
    }

    #[test]
    fn did_check_report_mismatch() {
        let report = did_check_report(&Ok("did:key:other".to_string()), "n").join("\n");
        assert!(report.contains("WARNING"), "got: {report}");
        assert!(report.contains("does not match"), "got: {report}");
        assert!(report.contains("did:key:other"), "got: {report}");
        assert!(!report.contains("Could not fetch"), "got: {report}");
    }

    #[test]
    fn did_check_report_missing_did_reason() {
        let report =
            did_check_report(&Err("node info response carried no DID".to_string()), "n").join("\n");
        assert!(report.contains("Could not fetch"), "got: {report}");
        assert!(
            report.contains("node info response carried no DID"),
            "got: {report}"
        );
        assert!(report.contains("verify offline"), "got: {report}");
        // The must-not case: no real DID was obtained, so no comparison verdict
        // may be claimed in either direction.
        assert!(!report.contains("WARNING"), "got: {report}");
        assert!(
            !report.contains("matches the node being queried"),
            "got: {report}"
        );
    }

    #[test]
    fn did_check_report_lookup_error_reason() {
        let report =
            did_check_report(&Err("node info failed (403): denied".to_string()), "n").join("\n");
        assert!(report.contains("Could not fetch"), "got: {report}");
        assert!(report.contains("403"), "got: {report}");
        assert!(report.contains("verify offline"), "got: {report}");
        assert!(!report.contains("WARNING"), "got: {report}");
    }

    /// #26 Split PR 3: a missing `version` field on a cert defaults
    /// to 1, so an old server's response is forward-compatible with
    /// a new client. The v1 verify path is taken, and a
    /// well-signed v1 cert round-trips through `verify_signature`.
    ///
    /// Reviewer 1 finding: the previous shape only parsed the field
    /// and never called `verify_signature`, so the test could not
    /// fail if the verdict branch was wired to the wrong path. This
    /// version signs and verifies the full round-trip.
    #[test]
    fn missing_version_defaults_to_1_and_verifies() {
        let kp = gitlawb_core::identity::Keypair::generate();
        let node_did = kp.did().as_str().to_string();
        let payload = serde_json::json!({
            "repo_id": "repo-1",
            "ref":     "refs/heads/main",
            "old":     "0".repeat(40),
            "new":     "a".repeat(40),
            "pusher":  "did:key:z6MkPusher",
            "node":    node_did,
            "ts":      "2026-07-22T00:00:00+00:00",
        });
        let sig = kp.sign_b64(&serde_json::to_vec(&payload).unwrap());

        // Simulate the JSON a v1 server returns: no `version` key.
        let cert_json = serde_json::json!({
            "id":         "test-id",
            "repo_id":    "repo-1",
            "ref_name":   "refs/heads/main",
            "old_sha":    "0".repeat(40),
            "new_sha":    "a".repeat(40),
            "pusher_did": "did:key:z6MkPusher",
            "node_did":   node_did,
            "signature":  sig.clone(),
            "issued_at":  "2026-07-22T00:00:00+00:00",
            // no `version` field
        });

        // Forward-compat: the parse yields v1 (the only version this
        // client verifies), and the verdict arm matching Ok(1) feeds
        // the v1 payload through verify_signature end to end.
        assert_eq!(parse_cert_version(cert_json.get("version")).unwrap(), 1);
        let verdict = verify_signature(
            "repo-1",
            "refs/heads/main",
            &"0".repeat(40),
            &"a".repeat(40),
            "did:key:z6MkPusher",
            &node_did,
            "2026-07-22T00:00:00+00:00",
            &sig,
        );
        assert!(
            verdict.is_ok(),
            "missing version must take the v1 verify path: {verdict:?}"
        );
    }

    /// #26 Split PR 3: an explicit `version: 1` on a cert is the v1
    /// verify path. A v1 cert with an explicit version verifies the
    /// same as a v1 cert without one — round-trip through
    /// `verify_signature`.
    #[test]
    fn explicit_version_1_takes_v1_path() {
        let kp = gitlawb_core::identity::Keypair::generate();
        let node_did = kp.did().as_str().to_string();
        let payload = serde_json::json!({
            "repo_id": "repo-1",
            "ref":     "refs/heads/main",
            "old":     "0".repeat(40),
            "new":     "a".repeat(40),
            "pusher":  "did:key:z6MkPusher",
            "node":    node_did,
            "ts":      "2026-07-22T00:00:00+00:00",
        });
        let sig = kp.sign_b64(&serde_json::to_vec(&payload).unwrap());

        // Simulate a v1 cert with an explicit `version: 1` field.
        let cert_json = serde_json::json!({
            "id":         "test-id",
            "repo_id":    "repo-1",
            "ref_name":   "refs/heads/main",
            "old_sha":    "0".repeat(40),
            "new_sha":    "a".repeat(40),
            "pusher_did": "did:key:z6MkPusher",
            "node_did":   node_did,
            "signature":  sig.clone(),
            "issued_at":  "2026-07-22T00:00:00+00:00",
            "version":    1,
        });

        // The parse arms the Ok(1) verdict branch, which calls
        // verify_signature on the v1 payload. A signature mismatch
        // here would mean the verdict branch was wired to the
        // wrong path or the payload drifted.
        assert_eq!(parse_cert_version(cert_json.get("version")).unwrap(), 1);
        let verdict = verify_signature(
            "repo-1",
            "refs/heads/main",
            &"0".repeat(40),
            &"a".repeat(40),
            "did:key:z6MkPusher",
            &node_did,
            "2026-07-22T00:00:00+00:00",
            &sig,
        );
        assert!(
            verdict.is_ok(),
            "explicit version: 1 must take the v1 verify path: {verdict:?}"
        );
    }

    /// #26 Split PR 3 + Reviewer 2: parse_cert_version is the
    /// load-bearing gate that distinguishes a missing-key (legacy
    /// server) from a present-but-malformed value. The four cases
    /// below pin every cell of that truth table; collapsing any
    /// pair would let a server advertise "version 2" (or 99, or
    /// 4294967297, or "two") while the client runs the v1
    /// signature path on a different signed payload — a hostile
    /// misconfiguration that `--verify` must not silently accept.
    #[test]
    fn parse_cert_version_truth_table() {
        // MISSING key → legacy v1 (the v1 path is the only one that
        // could match pre-versioning bytes).
        assert_eq!(
            parse_cert_version(None).unwrap(),
            1,
            "a missing version field is the legacy v1 path"
        );

        // Explicit 1 → v1.
        assert_eq!(
            parse_cert_version(Some(&serde_json::json!(1))).unwrap(),
            1,
            "explicit version 1 is the v1 path"
        );

        // Explicit 2 → Err, NOT Ok(1). Reviewer 2: a v1 signature
        // must not verify against a server that said "version 2".
        assert!(
            parse_cert_version(Some(&serde_json::json!(2))).is_err(),
            "explicit version 2 must not collapse to v1"
        );

        // u32 overflow (2^32 + 1) → Err, NOT Ok(1). The previous
        // `.map(|v| v as u32)` silently truncated this to 1.
        let overflow = serde_json::json!(u64::from(u32::MAX) + 1);
        assert!(
            parse_cert_version(Some(&overflow)).is_err(),
            "a version that overflows u32 must not truncate to 1"
        );

        // Non-numeric: a string, a float, null, bool — every shape
        // that is not a JSON integer is rejected. None of these
        // may collapse to v1.
        for bad in [
            serde_json::json!("two"),
            serde_json::json!(2.0), // serde_json::Value::is_f64 is true for this
            serde_json::json!(2.5), // obviously fractional
            serde_json::json!(true),
            serde_json::json!(null),
            serde_json::json!([2]),
            serde_json::json!({"v": 2}),
        ] {
            assert!(
                parse_cert_version(Some(&bad)).is_err(),
                "non-integer version {bad} must not collapse to v1"
            );
        }
    }

    /// A version refusal must not print as INVALID — no cryptographic
    /// check ran, so labelling it INVALID would tell operators an Ed25519
    /// verification failed when the payload shape was the disqualifier.
    /// Removing the label branch fails this test.
    #[test]
    fn signature_verdict_label_distinguishes_refusal_from_bad_signature() {
        assert_eq!(
            signature_verdict_label(&Err("version 2 not supported".to_string())),
            "UNSUPPORTED VERSION"
        );
        assert_eq!(signature_verdict_label(&Ok(1)), "INVALID");
    }

    /// #26 Split PR 3, round 2: a `version: 2` certificate must fail
    /// `--verify` THROUGH `cmd_show` itself, not through a copy of its
    /// match. The prior form of this test duplicated the verdict match in
    /// the test body and aimed at an `Ok(v != 1)` arm the real parser can
    /// never produce, so gutting `cmd_show`'s rejection kept every test
    /// green (demonstrated by the reviewer by execution). Driving the
    /// command end to end is what makes this a guard: the mock serves a
    /// cert whose SIGNATURE IS VALID for v1 bytes but which declares
    /// version 2, and the command must exit Err with the version named —
    /// the v1 verify path must not launder it through.
    #[tokio::test]
    async fn cmd_show_verify_rejects_v2_even_with_valid_v1_signature() {
        let kp = gitlawb_core::identity::Keypair::generate();
        let node_did = kp.did().as_str().to_string();

        // Sign a v1-shaped payload so the ONLY disqualifier is the version.
        let payload = serde_json::json!({
            "repo_id": "repo-1",
            "ref":     "refs/heads/main",
            "old":     "0".repeat(40),
            "new":     "a".repeat(40),
            "pusher":  "did:key:z6MkPusher",
            "node":    node_did,
            "ts":      "2026-07-22T00:00:00+00:00",
        });
        let sig = kp.sign_b64(&serde_json::to_vec(&payload).unwrap());

        let cert_json = serde_json::json!({
            "id":         "0123456789abcdef0123456789abcdef0123",
            "repo_id":    "repo-1",
            "ref_name":   "refs/heads/main",
            "old_sha":    "0".repeat(40),
            "new_sha":    "a".repeat(40),
            "pusher_did": "did:key:z6MkPusher",
            "node_did":   node_did,
            "signature":  sig,
            "issued_at":  "2026-07-22T00:00:00+00:00",
            "version":    2,
        });

        let mut server = mockito::Server::new_async().await;
        // 36-char id short-circuits resolve_cert_id; "owner/repo" input
        // short-circuits resolve_repo — the cert GET is the only required
        // route. `/` may be probed for the contextual DID line; serving it
        // keeps the test about the verdict, not about network noise.
        let _cert = server
            .mock(
                "GET",
                "/api/v1/repos/o/r/certs/0123456789abcdef0123456789abcdef0123",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(cert_json.to_string())
            .create_async()
            .await;
        let _root = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::json!({ "did": node_did }).to_string())
            .create_async()
            .await;

        let err = cmd_show(
            "o/r".to_string(),
            "0123456789abcdef0123456789abcdef0123".to_string(),
            server.url(),
            None,
            true,
            Some(node_did.clone()),
        )
        .await
        .expect_err("a version-2 cert must fail --verify even with a valid v1 signature");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("version"),
            "the failure must name the version mismatch, not a generic invalid signature: {msg}"
        );
    }

    /// Round 2's second demonstrated escape: with no --expect-node, the old
    /// fallback anchored the issuer to the DID the QUERIED NODE reports at
    /// `/` — which a forger controls along with the cert, so a wholly forged
    /// self-signed certificate passed --verify with exit 0. `cmd_show` with
    /// --verify and no --expect-node must now refuse to claim a trusted
    /// issuer, even when the served cert's signature is valid and the node's
    /// self-report matches it.
    #[tokio::test]
    async fn cmd_show_verify_without_expect_node_refuses_self_asserted_anchor() {
        let kp = gitlawb_core::identity::Keypair::generate();
        let node_did = kp.did().as_str().to_string();
        let payload = serde_json::json!({
            "repo_id": "repo-1",
            "ref":     "refs/heads/main",
            "old":     "0".repeat(40),
            "new":     "a".repeat(40),
            "pusher":  "did:key:z6MkPusher",
            "node":    node_did,
            "ts":      "2026-07-22T00:00:00+00:00",
        });
        let sig = kp.sign_b64(&serde_json::to_vec(&payload).unwrap());
        let cert_json = serde_json::json!({
            "id":         "0123456789abcdef0123456789abcdef0123",
            "repo_id":    "repo-1",
            "ref_name":   "refs/heads/main",
            "old_sha":    "0".repeat(40),
            "new_sha":    "a".repeat(40),
            "pusher_did": "did:key:z6MkPusher",
            "node_did":   node_did,
            "signature":  sig,
            "issued_at":  "2026-07-22T00:00:00+00:00",
        });

        let mut server = mockito::Server::new_async().await;
        // P3 (reviewer round 2): both mocks are required to be
        // hit for the test to mean anything. `mockito 1.7`'s
        // `assert_on_drop` is off by default, so the previous
        // `_cert` and `_root` bindings would silently let a
        // regression that skipped the root fetch pass.
        // `.expect(2)` pins each mock's call count (the cert mock
        // is hit twice because the test runs `cmd_show` twice) and
        // `.assert_async()` at the end fires if any are unmet.
        let cert_mock = server
            .mock(
                "GET",
                "/api/v1/repos/o/r/certs/0123456789abcdef0123456789abcdef0123",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(cert_json.to_string())
            .expect(2)
            .create_async()
            .await;
        // The forger's matching self-report — the exact shape
        // that used to convert into a trust anchor. The guard's
        // whole point is to make the test FAIL if a future
        // regression stops calling `/` here: `.expect(2)` +
        // `.assert_async()` makes that dependency visible.
        let root_mock = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::json!({ "did": node_did }).to_string())
            .expect(2)
            .create_async()
            .await;

        let err = cmd_show(
            "o/r".to_string(),
            "0123456789abcdef0123456789abcdef0123".to_string(),
            server.url(),
            None,
            true,
            None,
        )
        .await
        .expect_err("--verify without --expect-node must not mint a trust anchor from the node's self-report");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("--expect-node"),
            "the refusal must tell the caller how to anchor trust: {msg}"
        );

        // Positive control: the same cert with the DID explicitly trusted
        // passes, so the guard is about the anchor, not the signature.
        cmd_show(
            "o/r".to_string(),
            "0123456789abcdef0123456789abcdef0123".to_string(),
            server.url(),
            None,
            true,
            Some(node_did),
        )
        .await
        .expect("explicitly anchored --verify of a valid v1 cert must pass");

        // P3 (reviewer round 2): confirm the mocks were actually
        // hit. Without this, a regression that skipped the cert or
        // root fetches would still produce a passing test (the
        // `expect_err` arm succeeds, the positive control succeeds)
        // and the test would mean nothing.
        cert_mock.assert_async().await;
        root_mock.assert_async().await;
    }
}
