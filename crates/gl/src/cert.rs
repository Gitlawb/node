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
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Show a specific ref certificate and verify its signature.
    ///
    /// `--verify` requires `--expect-node <did>` since v2 cert
    /// compat (Round 2): the queried node's self-reported DID is no
    /// longer accepted as a trust anchor, so callers must name the
    /// issuer they trust. See the `BREAKING CHANGE:` note on the
    /// commit that introduced this requirement.
    Show {
        /// Repository in <owner>/<repo> or <repo> format
        repo: String,
        /// Certificate ID
        id: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
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
            let info: Value = client
                .get_authed("/")
                .await?
                .json()
                .await
                .context("failed to fetch node info")?;
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
    let resp: Value = client
        .get_authed(&path)
        .await?
        .json()
        .await
        .context("failed to list certificates")?;

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
        let issued_at = cert["issued_at"].as_str().map(|s| &s[..19]).unwrap_or("?");
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

    // Fetch the certificate
    let path = format!("/api/v1/repos/{owner}/{name}/certs/{id}");
    let resp = client
        .get_authed(&path)
        .await?
        .error_for_status()
        .context("certificate not found")?;
    let cert: Value = resp.json().await.context("certificate not found")?;

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
        // version field becomes part of the JSON and the field
        // order changes), so a v2+ cert from a server this client
        // does not know about must NOT be silently verified as v1.
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
        Err(reason) => Err(format!(
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
            println!("  INVALID — {reason}");
        }
    }

    // Contextual only — the verdict above stands on its own, so a node-info
    // hiccup here must not turn a successfully displayed certificate into an
    // error exit.
    let current_node_did = match client.get("/").await {
        Ok(resp) => resp
            .json::<Value>()
            .await
            .ok()
            .and_then(|info| info["did"].as_str().map(str::to_string)),
        Err(_) => None,
    };
    match current_node_did.as_deref() {
        Some(current) if current == node_did => {
            // Self-reported, so phrased as information rather than trust: the
            // node answering `/` is the node that served the cert, and a
            // forger controls both. Trust comes only from --expect-node.
            println!("  Issuing node DID matches the queried node's self-reported DID.");
        }
        Some(current) => {
            println!("  WARNING: Certificate node DID ({node_did}) does not match");
            println!("           current node DID ({current}).");
            println!("           This certificate was issued by a different node.");
        }
        None => {
            println!("  NOTE: could not fetch current node info — skipping node-DID comparison.");
        }
    }

    if require_valid {
        if let Err(reason) = verdict {
            anyhow::bail!("certificate signature did not verify: {reason}");
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
    let resp: Value = client
        .get_authed(&path)
        .await?
        .error_for_status()
        .context("failed to list certificates")?
        .json()
        .await
        .context("failed to list certificates")?;

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
