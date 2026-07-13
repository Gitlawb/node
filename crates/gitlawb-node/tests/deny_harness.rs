//! Real-node deny harness: boots a real gitlawb-node over a bound TCP socket
//! and drives trust-boundary DENY paths through a real reqwest client,
//! asserting both the refusal status and that no withheld data leaks
//! (INV-1/INV-2/INV-8). Requires `--features test-harness`.
//!
//! Each `#[sqlx::test]` gets an ephemeral per-test database; `spawn_node` runs
//! the schema migrations and serves the real router on `127.0.0.1:0`.

mod support;

use std::process::Command;

use support::assert::assert_denied;
use support::probe::{probes_for, Expect, Fixture, Probe, Signer};
use support::routes::deny_bearing_routes;
use support::signing::signed_request;

use gitlawb_core::cid::Cid;
use gitlawb_core::identity::Keypair;
use gitlawb_node::test_harness::spawn_node;

/// Build the `/ipfs/{cid}` CID for a 64-hex sha2-256 git object id, matching the
/// node's own `Cid::from_sha256_bytes` (the value `get_by_cid` decodes back).
fn cid_for_oid(oid_hex: &str) -> String {
    let bytes = hex::decode(oid_hex).expect("hex oid");
    let arr: [u8; 32] = bytes.as_slice().try_into().expect("32-byte sha256 oid");
    Cid::from_sha256_bytes(&arr).to_string()
}

// ── U2: the signing client produces signatures require_signature accepts ─────

/// A validly signed receive-pack request clears `require_signature` (it does not
/// get a 401): it proceeds past the signature layer and is denied later for a
/// different reason (the repo does not exist). This proves the signing client
/// is producing signatures the real verifier accepts over the socket.
#[sqlx::test]
async fn signed_receive_pack_clears_signature_layer(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;
    let client = reqwest::Client::new();
    let kp = Keypair::generate();

    let resp = signed_request(
        &client,
        reqwest::Method::POST,
        &node.base_url,
        "/alice/repo/git-receive-pack",
        b"0000".to_vec(),
        &kp,
    )
    .send()
    .await
    .expect("request sends");

    assert_ne!(
        resp.status().as_u16(),
        401,
        "a valid signature must clear require_signature; got 401"
    );
}

/// Tampering the body after signing invalidates the content-digest, so the
/// server rejects with 400 `content_digest_mismatch` (distinct from the 401 a
/// missing/invalid signature gets). Proves the signature actually covers the
/// body: the digest is signed and the server re-checks it against the bytes it
/// received.
#[sqlx::test]
async fn tampered_body_after_signing_is_rejected(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;
    let client = reqwest::Client::new();
    let kp = Keypair::generate();

    // Sign one body, then replace it before sending.
    let mut req = signed_request(
        &client,
        reqwest::Method::POST,
        &node.base_url,
        "/alice/repo/git-receive-pack",
        b"0000".to_vec(),
        &kp,
    )
    .build()
    .expect("build request");
    *req.body_mut() = Some(reqwest::Body::from(b"tampered".to_vec()));

    let resp = client.execute(req).await.expect("request sends");
    assert_eq!(
        resp.status().as_u16(),
        400,
        "a body that no longer matches its content-digest must be rejected"
    );
}

// ── U5(a): INV-8 — an unsigned push is denied and leaks nothing ──────────────

/// An unauthenticated git-receive-pack (no signature headers) is rejected with
/// 401 before any handler runs, and the denial body carries no repo internals.
#[sqlx::test]
async fn unsigned_receive_pack_is_denied(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;
    let client = reqwest::Client::new();

    let url = format!("{}/alice/repo/git-receive-pack", node.base_url);
    let resp = client
        .post(&url)
        .header("content-type", "application/x-git-receive-pack-request")
        .body(b"0000".to_vec())
        .send()
        .await
        .expect("request sends");

    // No repo was seeded, so there are no OIDs to leak; the assertion still
    // enforces the 4xx-and-not-empty-200 INV-8 shape.
    assert_denied(resp, 401, &[]).await;
}

// ── U5(b): INV-8/INV-2 — anonymous /ipfs/{cid} of a withheld blob is denied ──

/// A public repo with a `/secret/**` withhold rule (readers = one allowed DID).
/// An anonymous content-addressed read of the withheld blob's CID is denied
/// (404) and leaks neither the secret bytes nor its OID; the sibling public
/// blob's CID is served anonymously, proving the withhold is blob-scoped.
#[sqlx::test]
async fn anon_ipfs_read_of_withheld_blob_is_denied(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;
    let client = reqwest::Client::new();

    let owner = Keypair::generate();
    let owner_did = owner.did().to_string();
    let reader = Keypair::generate();

    let repo_id = node.seed_repo(&owner_did, "u5b-repo", true).await;
    // sha256 object format: the /ipfs CID is the sha2-256 object id.
    let oids = node.seed_bare_repo(
        &owner_did,
        "u5b-repo",
        &[
            ("public/a.txt", "public bytes U5b"),
            ("secret/b.txt", "TOPSECRET-U5b"),
        ],
        "sha256",
    );
    node.withhold_path(
        &repo_id,
        "/secret/**",
        &[reader.did().to_string()],
        &owner_did,
    )
    .await;

    let secret_oid = oids["secret/b.txt"].clone();
    let secret_cid = cid_for_oid(&secret_oid);
    let public_cid = cid_for_oid(&oids["public/a.txt"]);

    // Anonymous read of the withheld blob's CID: denied, no leak of content or OID.
    let resp = client
        .get(format!("{}/ipfs/{secret_cid}", node.base_url))
        .send()
        .await
        .expect("request sends");
    assert_denied(
        resp,
        404,
        &["TOPSECRET-U5b", &secret_oid, &secret_oid[..12]],
    )
    .await;

    // The sibling public blob's CID is served to anon (withhold is blob-scoped).
    let resp = client
        .get(format!("{}/ipfs/{public_cid}", node.base_url))
        .send()
        .await
        .expect("request sends");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "public blob CID must be served to anon"
    );
    assert!(
        resp.text().await.unwrap().contains("public bytes U5b"),
        "the public blob content is returned"
    );
}

// ── U6: INV-1 — a validly signed NON-owner mutation is owner-gated (403) ──────

/// The case the in-crate `oneshot` suite cannot reach over the full stack: a
/// fully valid RFC-9421 signature from a non-owner DID hits a mutation and is
/// rejected by `require_owner` with 403, not merely "not authenticated". The
/// non-owner sends no `x-ucan` header, so `require_ucan_chain` passes through
/// and the request reaches the owner gate.
#[sqlx::test]
async fn wrong_owner_visibility_put_is_forbidden(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;
    let client = reqwest::Client::new();

    let owner = Keypair::generate();
    let owner_did = owner.did().to_string();
    let stranger = Keypair::generate();

    node.seed_repo(&owner_did, "harness-repo", true).await;

    let path = format!("/api/v1/repos/{owner_did}/harness-repo/visibility");
    let body = br#"{"path_glob":"/","reader_dids":[]}"#.to_vec();

    // Non-owner: valid signature, wrong identity -> 403 from the owner gate.
    let resp = signed_request(
        &client,
        reqwest::Method::PUT,
        &node.base_url,
        &path,
        body.clone(),
        &stranger,
    )
    .header("content-type", "application/json")
    .send()
    .await
    .expect("request sends");
    assert_denied(resp, 403, &[]).await;

    // Reachability proof: the same request signed by the OWNER is not 403 (it
    // reaches the handler). Without this, a 403 produced by an earlier layer or
    // a mis-seeded repo would masquerade as a passing INV-1 case.
    let resp = signed_request(
        &client,
        reqwest::Method::PUT,
        &node.base_url,
        &path,
        body,
        &owner,
    )
    .header("content-type", "application/json")
    .send()
    .await
    .expect("request sends");
    assert!(
        resp.status().is_success(),
        "owner's signed visibility PUT must reach the handler, got {}",
        resp.status()
    );
}

// ── U7: INV-2 — a read over a withheld path is denied and leaks nothing ───────

/// A public repo with a path-scoped withhold rule on `/secret/**`. An anonymous
/// blob read of the withheld path is denied (404 RepoNotFound) and the body
/// carries neither the secret content nor its blob OID; a read of a sibling
/// public path succeeds, proving the gate is path-scoped, not a blanket refusal.
#[sqlx::test]
async fn withheld_path_blob_read_is_denied(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;
    let client = reqwest::Client::new();

    let owner = Keypair::generate();
    let owner_did = owner.did().to_string();

    let repo_id = node.seed_repo(&owner_did, "u7-repo", true).await;
    let oids = node.seed_bare_repo(
        &owner_did,
        "u7-repo",
        &[
            ("public.txt", "hello public"),
            ("secret/data.txt", "TOPSECRET-CONTENT-U7"),
        ],
        "sha1",
    );
    node.withhold_path(&repo_id, "/secret/**", &[], &owner_did)
        .await;

    let secret_oid = oids["secret/data.txt"].clone();
    let short_oid = &secret_oid[..12];

    // Withheld path: denied, and neither the content nor the OID (full or short)
    // may appear in the denial body.
    let resp = client
        .get(format!(
            "{}/api/v1/repos/{owner_did}/u7-repo/blob/secret/data.txt",
            node.base_url
        ))
        .send()
        .await
        .expect("request sends");
    assert_denied(resp, 404, &["TOPSECRET-CONTENT-U7", &secret_oid, short_oid]).await;

    // Sibling public path: served, proving the withhold is path-scoped.
    let resp = client
        .get(format!(
            "{}/api/v1/repos/{owner_did}/u7-repo/blob/public.txt",
            node.base_url
        ))
        .send()
        .await
        .expect("request sends");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "public sibling path must be served"
    );
    assert!(
        resp.text().await.unwrap().contains("hello public"),
        "the public blob content is returned"
    );
}

// ── U8: INV-2 — an anonymous clone/fetch excludes withheld subtree blobs ──────

/// The replication/clone surface, the one `oneshot` cannot serve: a public repo
/// with a `/secret/**` withhold rule. A real anonymous `git clone` over
/// git-upload-pack must yield a packfile that omits the withheld blob's object
/// while keeping the sibling public blob. The assertion is packfile-aware: git
/// parsed the served pack, and `cat-file -e` checks object presence in it.
#[sqlx::test]
async fn anon_clone_excludes_withheld_subtree_blobs(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;

    let owner = Keypair::generate();
    let owner_did = owner.did().to_string();

    let repo_id = node.seed_repo(&owner_did, "u8-repo", true).await;
    let oids = node.seed_bare_repo(
        &owner_did,
        "u8-repo",
        &[
            ("public/a.txt", "public bytes U8"),
            ("secret/b.txt", "TOPSECRET-U8"),
        ],
        "sha1",
    );
    node.withhold_path(&repo_id, "/secret/**", &[], &owner_did)
        .await;

    let secret_oid = oids["secret/b.txt"].clone();
    let public_oid = oids["public/a.txt"].clone();
    let head = oids["HEAD"].clone();

    // Drive git-upload-pack directly (v0 stateless-RPC): a want for HEAD, a flush,
    // then done. No side-band capability, so the response is a raw packfile after
    // the NAK pkt-line. Vanilla `git clone` negotiates protocol v2 and deadlocks
    // against the node's v0 server; the POST is the real replication surface and,
    // via a bounded reqwest timeout, cannot wedge the suite.
    let pkt = |s: &str| format!("{:04x}{}", s.len() + 4, s).into_bytes();
    let mut req_body: Vec<u8> = Vec::new();
    req_body.extend(pkt(&format!("want {head}\n")));
    req_body.extend_from_slice(b"0000"); // flush after wants
    req_body.extend(pkt("done\n"));

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();
    let resp = client
        .post(format!(
            "{}/{owner_did}/u8-repo/git-upload-pack",
            node.base_url
        ))
        .header("content-type", "application/x-git-upload-pack-request")
        .body(req_body)
        .send()
        .await
        .expect("upload-pack POST sends");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "anon upload-pack POST must serve a pack"
    );
    let bytes = resp.bytes().await.expect("read pack response");

    // The packfile starts at the "PACK" magic (after the NAK pkt-line).
    let pack_start = bytes
        .windows(4)
        .position(|w| w == b"PACK")
        .expect("response must contain a packfile");
    let pack = &bytes[pack_start..];

    // Index the served pack and list its objects (packfile-aware: a raw byte scan
    // could not see an OID inside the zlib-compressed stream).
    let dir = std::env::temp_dir().join(format!("gl-u8-pack-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pack_path = dir.join("deny.pack");
    std::fs::write(&pack_path, pack).unwrap();
    let idx = Command::new("git")
        .args(["index-pack", pack_path.to_str().unwrap()])
        .output()
        .expect("git index-pack runs");
    assert!(
        idx.status.success(),
        "the served pack must index cleanly: {}",
        String::from_utf8_lossy(&idx.stderr)
    );
    let verify = Command::new("git")
        .args([
            "verify-pack",
            "-v",
            pack_path.with_extension("idx").to_str().unwrap(),
        ])
        .output()
        .expect("git verify-pack runs");
    let listing = String::from_utf8_lossy(&verify.stdout).to_string();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        !listing.contains(&secret_oid),
        "withheld blob {secret_oid} must be absent from the served pack; listing:\n{listing}"
    );
    assert!(
        listing.contains(&public_oid),
        "public blob {public_oid} must be present (withhold is subtree-scoped); listing:\n{listing}"
    );
}

// ── U3: drive the whole deny-bearing route registry over the real stack ───────

/// Send one [`Probe`] against the running node, signing as the probe's identity.
/// Anon requests are unsigned; Owner/Stranger requests carry a real RFC-9421
/// signature for the fixture's owner / stranger keypair.
async fn send_probe(
    client: &reqwest::Client,
    base_url: &str,
    fixture: &Fixture,
    probe: &Probe,
) -> reqwest::Response {
    let rb = match probe.signer {
        Signer::Anon => client
            .request(probe.method.clone(), format!("{base_url}{}", probe.path))
            .body(probe.body.clone()),
        Signer::Owner => signed_request(
            client,
            probe.method.clone(),
            base_url,
            &probe.path,
            probe.body.clone(),
            &fixture.owner,
        ),
        Signer::Stranger => signed_request(
            client,
            probe.method.clone(),
            base_url,
            &probe.path,
            probe.body.clone(),
            &fixture.stranger,
        ),
    };
    let rb = if probe.json {
        rb.header("content-type", "application/json")
    } else {
        rb
    };
    rb.send().await.unwrap_or_else(|e| {
        panic!(
            "probe failed to send: {} [{} {}]: {e}",
            probe.label, probe.method, probe.path
        )
    })
}

/// Walk every deny-bearing route (U1 registry), expand each into its hostile
/// probe plus positive twin (U2), and drive them against a real node: the
/// hostile request must return the exact deny status and leak nothing, and the
/// twin must reach the handler (owner-gate: not 403; read-gate: 2xx). This is
/// the runtime discharge of INV-1/INV-2/INV-8 across the whole registry, not one
/// hand-written case at a time.
///
/// Terminal anti-vacuous-green invariant: exactly one hostile probe per row is
/// driven and the count equals the registry size, so a row that silently
/// produced no probe fails here instead of the sweep passing by testing nothing.
#[sqlx::test]
async fn deny_bearing_registry_denies_hostile_and_admits_authorized(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;
    // A bounded timeout so a wedged route fails the suite rather than hanging it.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();
    let fixture = Fixture::seed(&node).await;

    let rows = deny_bearing_routes();
    assert!(
        !rows.is_empty(),
        "deny-bearing route registry is empty — nothing to sweep"
    );

    let mut hostile_driven = 0usize;
    let mut twins_driven = 0usize;

    for row in rows {
        let probes = probes_for(row, &fixture);
        assert!(
            !probes.is_empty(),
            "row {} {} produced no probes",
            row.method,
            row.path
        );
        for probe in &probes {
            let ctx = format!("{} [{} {}]", probe.label, probe.method, probe.path);
            let resp = send_probe(&client, &node.base_url, &fixture, probe).await;
            let status = resp.status();
            match &probe.expect {
                Expect::Deny(code) => {
                    hostile_driven += 1;
                    assert_eq!(
                        status.as_u16(),
                        *code,
                        "hostile probe must deny with {code}, got {status}: {ctx}"
                    );
                    // INV-8 shape guard: rechecks the status and that the body is
                    // neither an empty-200-as-success nor carrying withheld data.
                    assert_denied(resp, *code, &[]).await;
                }
                Expect::Not403 => {
                    twins_driven += 1;
                    assert_ne!(
                        status.as_u16(),
                        403,
                        "owner-reachability twin must reach the handler (not 403): {ctx}"
                    );
                }
                Expect::Ok2xx => {
                    twins_driven += 1;
                    assert!(
                        status.is_success(),
                        "read-reachability twin must be 2xx, got {status}: {ctx}"
                    );
                    // A 2xx with an empty body is a denial rendered as success:
                    // the authorized read must actually return the resource.
                    let body = resp.bytes().await.unwrap_or_default();
                    assert!(
                        !body.is_empty(),
                        "read-reachability twin returned an empty 2xx body (denial-as-success?): {ctx}"
                    );
                }
            }
        }
    }

    assert_eq!(
        hostile_driven,
        rows.len(),
        "expected exactly one hostile probe per deny-bearing row ({} rows), drove {hostile_driven}",
        rows.len()
    );
    assert!(
        twins_driven >= 1,
        "no positive twins were driven — the reachability proof is missing"
    );
}

// ── Additional INV-1 owner-gates over the real stack (fan-out of U6) ──────────

/// The remaining high-blast-radius owner-gated mutations that previously had
/// only the source-level authz-table guard and no runtime deny test: branch
/// protection, webhook create/delete, and visibility removal. Each rejects a
/// validly-signed non-owner with 403, and the owner reaches the handler (not
/// 403), proving the 403 is the owner gate. All share `did_matches` as the root
/// gate (see the mutation check in the harness commit).
#[sqlx::test]
async fn additional_owner_gates_reject_non_owner(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;
    let client = reqwest::Client::new();
    let owner = Keypair::generate();
    let owner_did = owner.did().to_string();
    let stranger = Keypair::generate();

    node.seed_repo(&owner_did, "gated-repo", true).await;
    let base = format!("/api/v1/repos/{owner_did}/gated-repo");

    // (method, path, body, needs-json-content-type)
    let cases: Vec<(reqwest::Method, String, Vec<u8>, bool)> = vec![
        (
            reqwest::Method::POST,
            format!("{base}/branches/main/protect"),
            Vec::new(),
            false,
        ),
        (
            reqwest::Method::DELETE,
            format!("{base}/branches/main/protect"),
            Vec::new(),
            false,
        ),
        (
            reqwest::Method::POST,
            format!("{base}/hooks"),
            br#"{"url":"https://example.com/hook","events":["*"]}"#.to_vec(),
            true,
        ),
        (
            reqwest::Method::DELETE,
            format!("{base}/hooks/deadbeef"),
            Vec::new(),
            false,
        ),
        (
            reqwest::Method::DELETE,
            format!("{base}/visibility"),
            br#"{"path_glob":"/"}"#.to_vec(),
            true,
        ),
    ];

    let send = |m: reqwest::Method, path: String, body: Vec<u8>, json: bool, kp: &Keypair| {
        let mut rb = signed_request(&client, m, &node.base_url, &path, body, kp);
        if json {
            rb = rb.header("content-type", "application/json");
        }
        rb.send()
    };

    for (method, path, body, json) in cases {
        // Non-owner: valid signature, wrong identity -> 403 owner gate, no leak.
        let resp = send(method.clone(), path.clone(), body.clone(), json, &stranger)
            .await
            .unwrap_or_else(|e| panic!("{method} {path} sends: {e}"));
        assert_denied(resp, 403, &[]).await;

        // Owner reaches the handler: NOT 403 (proves the 403 above was the gate,
        // not an earlier layer or a 415/404 masquerade).
        let resp = send(method.clone(), path.clone(), body, json, &owner)
            .await
            .unwrap_or_else(|e| panic!("{method} {path} owner sends: {e}"));
        assert_ne!(
            resp.status().as_u16(),
            403,
            "owner must reach {method} {path} (got 403)"
        );
    }
}

// ── U4: completeness cross-check (no DB) — the registry cannot silently drift ──
//
// The runtime sweep (U3) only proves the routes it is HANDED. This guard, a pure
// source scrape, keeps that hand-off honest against `server.rs`: no registry row
// points at a route that no longer mounts (stale row), and no owner-gated mount
// escapes the registry (orphan). It complements — does not duplicate — the
// in-crate `authz_guard` egress guard (`src/api/mod.rs`), which proves every
// repo-scoped API handler is *gated*; this proves the deny-bearing ones are
// *driven*, and it reaches the non-API git mounts `authz_guard` never sees.
mod completeness {
    use std::collections::HashSet;

    use super::deny_bearing_routes;
    use crate::support::routes::GateClass;

    /// Every `.route("<path>", <method>(<handler>)…)` mount in `src`, as
    /// (METHOD, path). Multiline-aware: most mounts put the path on the line after
    /// `.route(`, so a per-line scan false-greens. Walks balanced parens from each
    /// `.route(` so chained and multi-method (`put().delete().get()`) mounts are
    /// all captured.
    fn scrape_mounts(src: &str) -> Vec<(String, String)> {
        let bytes = src.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while let Some(rel) = src[i..].find(".route(") {
            let open = i + rel + ".route(".len();
            let mut depth = 1i32;
            let mut j = open;
            while j < src.len() && depth > 0 {
                match bytes[j] {
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            let call = &src[open..j.saturating_sub(1)];
            i = j;
            // The path is the first string literal in the call.
            let Some(qs) = call.find('"') else { continue };
            let Some(qe) = call[qs + 1..].find('"') else {
                continue;
            };
            let path = &call[qs + 1..qs + 1 + qe];
            for m in ["get", "post", "put", "delete", "patch"] {
                let needle = format!("{m}(");
                let mut k = 0;
                while let Some(mrel) = call[k..].find(&needle) {
                    let at = k + mrel;
                    // Reject a match that is the tail of a longer ident (e.g. the
                    // `get(` inside `budget(`): the char before must be a boundary.
                    let boundary = call[..at]
                        .chars()
                        .last()
                        .map(|c| !(c.is_alphanumeric() || c == '_'))
                        .unwrap_or(true);
                    if boundary {
                        out.push((m.to_uppercase(), path.to_string()));
                    }
                    k = at + needle.len();
                }
            }
        }
        out
    }

    /// Names of `fn`s in `src` whose body contains any `marker`. The body is the
    /// slice from a fn's `(` to the next top-level fn declaration — the same
    /// boundary set `authz_guard::fn_body` uses — so a marker can't leak across
    /// into the next handler.
    fn handlers_with_marker(src: &str, markers: &[&str]) -> HashSet<String> {
        let decls = [
            "\npub async fn ",
            "\npub(crate) async fn ",
            "\nasync fn ",
            "\npub(crate) fn ",
            "\npub fn ",
            "\nfn ",
        ];
        // Ordered start offsets of every fn declaration.
        let mut starts: Vec<usize> = Vec::new();
        for d in decls {
            let mut k = 0;
            while let Some(r) = src[k..].find(d) {
                starts.push(k + r + 1); // +1: skip the leading '\n'
                k = k + r + d.len();
            }
        }
        starts.sort_unstable();
        let mut out = HashSet::new();
        for (idx, &s) in starts.iter().enumerate() {
            let end = starts.get(idx + 1).copied().unwrap_or(src.len());
            let seg = &src[s..end];
            // The name is the ident after this decl's `fn ` (handles `pub(crate)`,
            // whose own `(` would otherwise be mistaken for the arg list).
            let Some(fnpos) = seg.find("fn ") else {
                continue;
            };
            let name: String = seg[fnpos + 3..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() {
                continue;
            }
            if markers.iter().any(|m| seg.contains(m)) {
                out.insert(name);
            }
        }
        out
    }

    fn short_handler(h: &str) -> &str {
        h.rsplit("::").next().unwrap_or(h)
    }

    #[test]
    fn deny_registry_is_not_stale_and_owner_gates_are_all_driven() {
        let server = include_str!("../src/server.rs");
        let mounts: HashSet<(String, String)> = scrape_mounts(server).into_iter().collect();

        // Scraper-integrity floor: if the parser silently stopped finding mounts,
        // the anti-stale check below would pass vacuously. The tree has ~95 mounts.
        assert!(
            mounts.len() >= 90,
            "mount scrape found only {} routes — the parser likely broke (floor 90)",
            mounts.len()
        );

        // ANTI-STALE: every deny-bearing row must still point at a live mount, so a
        // renamed/removed route can't leave a row that the sweep drives against a
        // 404 and calls a passing deny.
        for row in deny_bearing_routes() {
            assert!(
                mounts.contains(&(row.method.to_string(), row.path.to_string())),
                "stale registry row: {} {} is not mounted in server.rs (renamed or removed?)",
                row.method,
                row.path
            );
        }

        // ORPHAN GUARD: every handler carrying an unambiguous owner-gate marker
        // (`require_repo_owner` / `require_owner`) must be a registry owner-gate
        // row, so a newly added owner-gated mutation cannot escape the runtime
        // sweep. The api dir is read at test time (like authz_guard's completeness
        // scan) so a brand-new module is covered too. `did_matches` is deliberately
        // NOT a marker here: it is shared with the signer-self bucket and would
        // misclassify; close_pr/close_issue/protect are already covered as rows.
        let registry_owner_handlers: HashSet<&str> = deny_bearing_routes()
            .iter()
            .filter(|r| r.gate == GateClass::OwnerGate)
            .map(|r| short_handler(r.handler))
            .collect();

        let api_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/api");
        let mut owner_marked: HashSet<String> = HashSet::new();
        for entry in std::fs::read_dir(api_dir).expect("read api dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().is_some_and(|e| e == "rs") {
                let src = std::fs::read_to_string(&path).expect("read api file");
                owner_marked.extend(handlers_with_marker(
                    &src,
                    &["require_repo_owner(", "require_owner("],
                ));
            }
        }
        // The gate helpers' own definition lines contain the marker string; they
        // are helpers, not mounted handlers, so drop them.
        owner_marked.remove("require_owner");
        owner_marked.remove("require_repo_owner");

        // Non-vacuous floor: if the marker scan silently found nothing (a parser
        // regression), the orphan loop below would pass by checking zero handlers.
        // The tree has 10 owner-marker handlers today; 6 trips only on a real break.
        assert!(
            owner_marked.len() >= 6,
            "owner-gate marker scan found only {} handlers — the scan likely broke",
            owner_marked.len()
        );

        for h in &owner_marked {
            assert!(
                registry_owner_handlers.contains(h.as_str()),
                "handler `{h}` carries an owner-gate marker but is not an owner-gate \
                 row in deny_bearing_routes() — add it so the runtime sweep drives its 403"
            );
        }
    }
}
