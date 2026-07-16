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
use support::routes::{deny_bearing_routes, GateClass};
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

/// Build a minimal git-receive-pack request body: one ref-update pkt-line for
/// `refs/heads/<branch>` (dummy 40-hex old/new SHAs — the branch-protection gate
/// only reads the ref NAME) plus a flush. Enough to reach the ref-update parse
/// and the protection gate, not a real pack.
fn receive_pack_update_body(branch: &str) -> Vec<u8> {
    let old = "0".repeat(40);
    let new = "1".repeat(40);
    let line = format!("{old} {new} refs/heads/{branch}\0report-status\n");
    let pkt = format!("{:04x}{line}", line.len() + 4);
    let mut body = pkt.into_bytes();
    body.extend_from_slice(b"0000");
    body
}

/// #195 (F3): a signed NON-OWNER pushing to a PROTECTED branch is forbidden (403)
/// by the branch-protection gate (`repos.rs`), and the owner pushing to the same
/// branch is NOT blocked (control). git_receive_pack's registry row only drives the
/// unsigned-401 signature path, so without this probe inverting the 403 leaves the
/// sweep AND the completeness scan green. Drives the 403 so the gate can't rot.
#[sqlx::test]
async fn signed_stranger_protected_branch_push_is_forbidden(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;
    let client = reqwest::Client::new();
    let owner = Keypair::generate();
    let owner_did = owner.did().to_string();
    let stranger = Keypair::generate();

    let repo_id = node.seed_repo(&owner_did, "protrepo", true).await;
    node.seed_protected_branch(&repo_id, "main", &owner_did)
        .await;

    let path = format!("/{owner_did}/protrepo/git-receive-pack");
    let body = receive_pack_update_body("main");

    // Signed non-owner -> 403 branch protection; the denial leaks no repo internals.
    let resp = signed_request(
        &client,
        reqwest::Method::POST,
        &node.base_url,
        &path,
        body.clone(),
        &stranger,
    )
    .send()
    .await
    .expect("request sends");
    assert_eq!(
        resp.status().as_u16(),
        403,
        "a signed non-owner push to a protected branch must be forbidden (403)"
    );
    assert_denied(resp, 403, &[repo_id.as_str()]).await;

    // Owner control: the owner is NOT blocked by branch protection (it may fail
    // later on the dummy pack, but must not be the 403 the stranger got).
    let resp = signed_request(
        &client,
        reqwest::Method::POST,
        &node.base_url,
        &path,
        body,
        &owner,
    )
    .send()
    .await
    .expect("request sends");
    assert_ne!(
        resp.status().as_u16(),
        403,
        "the owner must not be blocked by their own branch protection (control)"
    );
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

// ── U3: get_pr_diff SECOND (per-path) gate — a diff touching a withheld path ──

/// Build a git v0 receive-pack body creating `refs/heads/<branch>` at a fresh
/// commit that adds `files` on top of the existing `main`, force-updating main to
/// a deterministic base so `<branch>` shares history with main. Returns the body
/// bytes plus the new feature tip. Shells out to the local `git`.
fn build_branch_push_body(server_main_tip: &str, branch: &str, files: &[(&str, &str)]) -> Vec<u8> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let work = std::env::temp_dir().join(format!(
        "gl-u3-prdiff-{}-{}",
        std::process::id(),
        server_main_tip
    ));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();
    let run = |args: &[&str]| -> String {
        let out = Command::new("git")
            .args(args)
            .current_dir(&work)
            .output()
            .expect("git runs");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    // Pin sha1 to match the served fixture repo; init.defaultObjectFormat=sha256 breaks the ref update.
    run(&["init", "-q", "-b", "main", "--object-format=sha1"]);
    run(&["config", "user.email", "t@t"]);
    run(&["config", "user.name", "t"]);
    std::fs::write(work.join("base.txt"), "prdiff base").unwrap();
    run(&["add", "base.txt"]);
    run(&["commit", "-q", "-m", "base"]);
    let new_main = run(&["rev-parse", "HEAD"]);
    run(&["checkout", "-q", "-b", branch]);
    for (p, c) in files {
        let full = work.join(p);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&full, c).unwrap();
        run(&["add", p]);
    }
    run(&["commit", "-q", "-m", "feature"]);
    let feature_tip = run(&["rev-parse", "HEAD"]);

    let mut child = Command::new("git")
        .args(["pack-objects", "--stdout", "--revs"])
        .current_dir(&work)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_ref()
        .unwrap()
        .write_all(format!("{new_main}\n{feature_tip}\n").as_bytes())
        .unwrap();
    let pack = child.wait_with_output().unwrap().stdout;

    let zero = "0".repeat(server_main_tip.len());
    let l1 = format!("{server_main_tip} {new_main} refs/heads/main\0report-status\n");
    let l2 = format!("{zero} {feature_tip} refs/heads/{branch}\n");
    let mut body: Vec<u8> = Vec::new();
    body.extend(format!("{:04x}{l1}", l1.len() + 4).into_bytes());
    body.extend(format!("{:04x}{l2}", l2.len() + 4).into_bytes());
    body.extend_from_slice(b"0000");
    body.extend_from_slice(&pack);
    let _ = std::fs::remove_dir_all(&work);
    body
}

/// get_pr_diff has a SECOND, path-scoped gate after the repo-root read: it
/// iterates the diff's touched paths and 404s if any is withheld (pulls.rs
/// visibility_check loop). On a PUBLIC repo with a `/secret/**` withhold rule and a
/// PR whose diff touches `secret/x.txt`, an anon caller PASSES the public repo-root
/// gate but must be DENIED by the per-path gate (404), leaking neither the withheld
/// content nor its OID; the owner sees the full diff. This drives the per-path gate
/// the private-repo registry row cannot reach (there, the root gate fires first for
/// every non-owner), so reverting the visibility_check Deny-return turns this RED.
#[sqlx::test]
async fn get_pr_diff_withheld_path_is_denied(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;
    let client = reqwest::Client::new();
    let owner = Keypair::generate();
    let owner_did = owner.did().to_string();

    let repo_id = node.seed_repo(&owner_did, "prdiff-repo", true).await;
    let oids = node.seed_bare_repo(
        &owner_did,
        "prdiff-repo",
        &[("public/a.txt", "public seed")],
        "sha1",
    );
    node.withhold_path(&repo_id, "/secret/**", &[], &owner_did)
        .await;

    // Push a `feature` branch whose diff vs main touches the withheld secret path.
    let body = build_branch_push_body(
        &oids["HEAD"],
        "feature",
        &[("secret/x.txt", "TOPSECRET-PRDIFF-PATH")],
    );
    let push = signed_request(
        &client,
        reqwest::Method::POST,
        &node.base_url,
        &format!("/{owner_did}/prdiff-repo/git-receive-pack"),
        body,
        &owner,
    )
    .header("content-type", "application/x-git-receive-pack-request")
    .send()
    .await
    .expect("push sends");
    assert_eq!(push.status().as_u16(), 200, "owner push must land");

    // Open a PR main <- feature (as owner, a reader of the public repo).
    let create = signed_request(
        &client,
        reqwest::Method::POST,
        &node.base_url,
        &format!("/api/v1/repos/{owner_did}/prdiff-repo/pulls"),
        br#"{"title":"prdiff","source_branch":"feature","target_branch":"main"}"#.to_vec(),
        &owner,
    )
    .header("content-type", "application/json")
    .send()
    .await
    .expect("create PR sends");
    assert_eq!(create.status().as_u16(), 201, "PR create must return 201");
    let pr: serde_json::Value = create.json().await.unwrap();
    let number = pr["number"].as_i64().expect("PR number");

    // Anon PASSES the public repo-root gate, then the per-path gate DENIES the diff
    // (it touches the withheld secret path): 404, leaking no content or OID.
    let secret_oid = oids.get("secret/x.txt").cloned().unwrap_or_default(); // seed_bare_repo didn't seed it; the pushed one is unknown here.
    let resp = client
        .get(format!(
            "{}/api/v1/repos/{owner_did}/prdiff-repo/pulls/{number}/diff",
            node.base_url
        ))
        .send()
        .await
        .expect("anon diff read sends");
    let mut withheld = vec!["TOPSECRET-PRDIFF-PATH"];
    if !secret_oid.is_empty() {
        withheld.push(secret_oid.as_str());
    }
    assert_denied(resp, 404, &withheld).await;

    // Owner sees the full diff (the per-path gate admits the reader).
    let resp = signed_request(
        &client,
        reqwest::Method::GET,
        &node.base_url,
        &format!("/api/v1/repos/{owner_did}/prdiff-repo/pulls/{number}/diff"),
        Vec::new(),
        &owner,
    )
    .send()
    .await
    .expect("owner diff read sends");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "owner must see the full PR diff (per-path gate admits the reader)"
    );
    assert!(
        resp.text().await.unwrap().contains("TOPSECRET-PRDIFF-PATH"),
        "the owner's diff returns the touched file content"
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
        // #195 (F1): each multi-principal arm signs with its own distinct fixture
        // identity, so reverting one arm in the handler turns only that arm's twin
        // RED.
        Signer::Author => signed_request(
            client,
            probe.method.clone(),
            base_url,
            &probe.path,
            probe.body.clone(),
            &fixture.author,
        ),
        Signer::Creator => signed_request(
            client,
            probe.method.clone(),
            base_url,
            &probe.path,
            probe.body.clone(),
            &fixture.creator,
        ),
        Signer::Claimant => signed_request(
            client,
            probe.method.clone(),
            base_url,
            &probe.path,
            probe.body.clone(),
            &fixture.claimant,
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

    // #195 (F1): every read-gate row is now probed by a signed non-reader too, so a
    // dropped stranger probe must fail loudly rather than being absorbed into the
    // total. Count the read-gate rows and the stranger hostiles separately.
    let readgate_rows = rows
        .iter()
        .filter(|r| matches!(r.gate, GateClass::ReadGate))
        .count();

    let mut hostile_driven = 0usize;
    let mut readgate_stranger_driven = 0usize;
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
                    // A signed-stranger 404 is the read-gate signed-non-reader probe
                    // (owner-gate strangers are 403, signature hostiles are anon 401).
                    if probe.signer == Signer::Stranger && *code == 404 {
                        readgate_stranger_driven += 1;
                    }
                    assert_eq!(
                        status.as_u16(),
                        *code,
                        "hostile probe must deny with {code}, got {status}: {ctx}"
                    );
                    // INV-8 shape guard: rechecks the status and that the body is
                    // neither an empty-200-as-success nor carrying withheld data. The
                    // probe's `withheld` tokens (the private repo's secret bytes and
                    // blob OID on read-gate probes) are passed through, so a 404 that
                    // spilled the private content fails here instead of being counted
                    // as a clean denial.
                    let tokens: Vec<&str> = probe.withheld.iter().map(String::as_str).collect();
                    assert_denied(resp, *code, &tokens).await;
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

    // One hostile per row (a signed stranger for the 403 gates, including the
    // #195 N2 status-gated bounty rows; anon for the signature and read-gate
    // rows), plus the EXTRA signed-stranger 404 each read-gate row drives.
    assert_eq!(
        hostile_driven,
        rows.len() + readgate_rows,
        "expected one hostile per row ({} rows) plus one signed-stranger hostile per read-gate row ({readgate_rows}), drove {hostile_driven}",
        rows.len()
    );
    // #195 (F1): every read-gate row must be probed by a signed non-reader — a
    // dropped stranger probe fails HERE rather than silently reducing coverage.
    assert_eq!(
        readgate_stranger_driven, readgate_rows,
        "every read-gate row must drive a signed-non-reader 404 probe ({readgate_rows} rows), drove {readgate_stranger_driven}"
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
    use crate::support::routes::{GateClass, Principal};

    /// The CLOSED set of structural reasons a read-gate handler may sit out of the
    /// runtime 404 sweep (#195, U4/R4). This replaces the free-text `reason`
    /// strings the old allowlist carried: a "deferred / needs seeding" prose excuse
    /// no longer type-checks. Every `READ_GATE_NOT_DRIVEN` entry must name one of
    /// these variants, so a reviewer sees a STRUCTURAL class (why the read is not a
    /// drivable 404-deny GET), never a soft deferral that hides an undriven private
    /// read. A drivable GET (the nine U3 reads) cannot be parked here because none
    /// of these classes fits it — and the driven-not-relabeled assertion below
    /// makes that a hard failure rather than a judgment call.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum NotDrivenReason {
        /// A create/write path that read-gates the caller before mutating, not a
        /// 404-deny GET. Its owner/author behaviour is covered by the mutation
        /// authz guard in `src/api/mod.rs`, not this GET-read sweep.
        ReadGatingMutation,
        /// A git smart-HTTP read (`info/refs`, `git-upload-pack`): its
        /// withheld-subtree 404/exclusion is driven by the U7/U8 real-clone cases,
        /// not the API GET sweep.
        GitSmartHttpRead,
        /// A content-addressed read (`/ipfs/{cid}`): its 404 deny + no-leak is
        /// driven by the U5b/U8 anon_ipfs/clone cases in this file.
        ContentAddressedRead,
        /// A global list-FILTER: returns 200 with unreadable rows removed, never a
        /// 404, so it is not a deny-bearing read at all.
        GlobalListFilter,
        /// The owner-2xx twin needs a live external dependency the harness lacks:
        /// `get_encrypted_blob` reads through `ipfs_pin::cat` with no harness stub,
        /// so it cannot be driven as a 2xx twin here. An honest exclusion, not a
        /// deferral (#195, KTD-5).
        ExternalDependencyUnavailable,
    }

    /// Read-gate handlers NOT driven as a `ReadGate` row, each carrying a CLOSED
    /// structural reason ([`NotDrivenReason`]) — never free-text. This is the
    /// enforced form of the prose that used to live in routes.rs; a handler leaving
    /// the sweep must be moved here under a structural class, never with a soft
    /// "deferred / needs seeding" excuse (which no longer type-checks).
    ///
    /// Single source of truth: both the marker-scan guard
    /// (`every_read_gate_handler_is_driven_or_explicitly_allowlisted`) and the
    /// route-table cross-check (`mounted_repo_gets_are_driven_excused_or_declared_public`)
    /// read this, so the two cannot drift.
    ///
    /// get_issue / get_pr / get_pr_diff / list_issue_comments / list_reviews /
    /// list_comments / get_cert / get_bounty / get_tree are DRIVEN as real ReadGate
    /// rows in deny_bearing_routes() (#195, U3); the driven-not-relabeled assertion
    /// bars any of them from being quietly re-parked here.
    const READ_GATE_NOT_DRIVEN: &[(&str, NotDrivenReason)] = &[
        // Owner-2xx twin needs a live IPFS backend (`ipfs_pin::cat`) the harness has
        // no stub for — an honest external-dependency exclusion (#195, KTD-5).
        (
            "get_encrypted_blob",
            NotDrivenReason::ExternalDependencyUnavailable,
        ),
        // Read-gates but is a mutation, not a 404-deny GET.
        ("create_review", NotDrivenReason::ReadGatingMutation),
        ("create_comment", NotDrivenReason::ReadGatingMutation),
        ("create_pr", NotDrivenReason::ReadGatingMutation),
        ("create_issue", NotDrivenReason::ReadGatingMutation),
        ("create_issue_comment", NotDrivenReason::ReadGatingMutation),
        ("create_bounty", NotDrivenReason::ReadGatingMutation),
        ("claim_bounty", NotDrivenReason::ReadGatingMutation),
        ("fork_repo", NotDrivenReason::ReadGatingMutation),
        ("star_repo", NotDrivenReason::ReadGatingMutation),
        ("unstar_repo", NotDrivenReason::ReadGatingMutation),
        // Content-addressed read: driven by the U5b/U8 anon_ipfs/clone cases.
        ("get_by_cid", NotDrivenReason::ContentAddressedRead),
        // Git smart-HTTP reads: driven by the U7/U8 real-clone cases.
        ("git_info_refs", NotDrivenReason::GitSmartHttpRead),
        ("git_upload_pack", NotDrivenReason::GitSmartHttpRead),
        // Global list-FILTER: 200 with unreadable rows removed, never a 404.
        ("list_all_bounties", NotDrivenReason::GlobalListFilter),
    ];

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

    /// Like [`handlers_with_marker`] but selects handlers whose body satisfies a
    /// PREDICATE rather than a substring — used for the inline owner-gate
    /// did_matches idiom (F3), whose "first arg is the caller, second is
    /// owner_did" shape a plain substring cannot express. Same fn-segmentation as
    /// `handlers_with_marker` so a match cannot leak across into the next handler.
    fn handlers_matching(src: &str, pred: fn(&str) -> bool) -> HashSet<String> {
        let decls = [
            "\npub async fn ",
            "\npub(crate) async fn ",
            "\nasync fn ",
            "\npub(crate) fn ",
            "\npub fn ",
            "\nfn ",
        ];
        let mut starts: Vec<usize> = Vec::new();
        for d in decls {
            let mut k = 0;
            while let Some(r) = src[k..].find(d) {
                starts.push(k + r + 1);
                k = k + r + d.len();
            }
        }
        starts.sort_unstable();
        let mut out = HashSet::new();
        for (idx, &s) in starts.iter().enumerate() {
            let end = starts.get(idx + 1).copied().unwrap_or(src.len());
            let seg = &src[s..end];
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
            if pred(seg) {
                out.insert(name);
            }
        }
        out
    }

    fn short_handler(h: &str) -> &str {
        h.rsplit("::").next().unwrap_or(h)
    }

    /// Like [`handlers_with_marker`] but ignores markers that appear only inside a
    /// full-line `//` comment. The owner-gate markers never show up in prose, but
    /// the read-gate markers (`authorize_repo_read(` / `visibility_check(`) do:
    /// several docstrings and a test comment name them (repos.rs's
    /// `owner_push_rejection` / `dedupe_canonical_repos` regions, the fork
    /// docstring), and a raw `contains` would misattribute those to the nearest
    /// preceding fn and force a phantom non-handler onto the read-gate allowlist.
    /// Mirrors `authz_guard::fn_body`'s comment-stripping so the scan sees code,
    /// not prose.
    fn handlers_with_code_marker(src: &str, markers: &[&str]) -> HashSet<String> {
        let stripped: String = src
            .lines()
            .map(|l| {
                if l.trim_start().starts_with("//") {
                    ""
                } else {
                    l
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        handlers_with_marker(&stripped, markers)
    }

    /// True when `body` contains an INLINE owner-gate `did_matches` call: one
    /// whose FIRST arg is the caller (`caller` / `&caller` / `&auth.0`) AND whose
    /// SECOND arg is `&record.owner_did`. That two-arg shape is the discriminator
    /// (F3): `require_owner`/`require_repo_owner` are the named markers, but
    /// protect_branch / unprotect_branch owner-gate with this raw idiom instead, so
    /// a plain marker misses them and a future owner-only handler using the same
    /// pattern could slip past the registry while U4 stayed green.
    ///
    /// It must NOT fire on the signer-self / author forms that share the helper:
    /// register_replica's `did_matches(replica_did, &record.owner_did)` (first arg
    /// is the replica, not the caller — signer-self by design), close_pr's
    /// `did_matches(&auth.0, &pr.author_did)`, and the bounty/task self forms
    /// (`&bounty.creator_did`, delegator/assignee dids). Whitespace and newlines
    /// inside the arg list are tolerated so a reformatted call still matches.
    fn has_owner_did_matches(body: &str) -> bool {
        let bytes = body.as_bytes();
        let mut i = 0;
        while let Some(rel) = body[i..].find("did_matches(") {
            let open = i + rel + "did_matches(".len();
            // Walk to the matching close paren, splitting the top-level args on the
            // first depth-0 comma (there are exactly two args).
            let mut depth = 1i32;
            let mut comma: Option<usize> = None;
            let mut j = open;
            while j < body.len() && depth > 0 {
                match bytes[j] {
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    b',' if depth == 1 && comma.is_none() => comma = Some(j),
                    _ => {}
                }
                j += 1;
            }
            i = j;
            let close = j.saturating_sub(1);
            let Some(comma) = comma else { continue };
            let arg1 = body[open..comma].split_whitespace().collect::<String>();
            let arg2 = body[comma + 1..close]
                .split_whitespace()
                .collect::<String>();
            let caller_first = arg1 == "caller" || arg1 == "&caller" || arg1 == "&auth.0";
            let owner_second = arg2 == "&record.owner_did";
            if caller_first && owner_second {
                return true;
            }
        }
        false
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

        // ORPHAN GUARD: every handler that owner-gates must be a registry owner-gate
        // row, so a newly added owner-gated mutation cannot escape the runtime
        // sweep. The api dir is read at test time (like authz_guard's completeness
        // scan) so a brand-new module is covered too. Two owner-gate shapes are
        // recognized:
        //   (1) the named markers `require_repo_owner(` / `require_owner(`, and
        //   (2) the INLINE `did_matches(caller, &record.owner_did)` idiom (F3) that
        //       protect_branch / unprotect_branch use instead of a named helper.
        // Only the SECOND-arg-is-owner_did form of did_matches is treated as an
        // owner gate; the signer-self / author forms (register_replica's
        // did_matches(replica_did, …), close_pr's did_matches(&auth.0, &author_did))
        // are deliberately NOT matched, so they don't false-orphan.
        // A handler satisfies the owner marker if it is a plain OwnerGate row OR a
        // MultiPrincipalGate row that declares the Owner arm (#195, F1: close_pr /
        // close_issue owner-gate via require_repo_owner but are owner-OR-author, so
        // they register as MultiPrincipalGate — their owner arm is still driven).
        let registry_owner_handlers: HashSet<&str> = deny_bearing_routes()
            .iter()
            .filter(|r| {
                r.gate == GateClass::OwnerGate
                    || (r.gate == GateClass::MultiPrincipalGate
                        && r.principals.contains(&Principal::Owner))
            })
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
                // Fold in the inline did_matches-owner idiom (F3).
                owner_marked.extend(handlers_matching(&src, has_owner_did_matches));
            }
        }
        // The gate helpers' own definitions carry the owner-gate idiom (the named
        // marker string, and visibility::require_owner's body is itself a
        // `did_matches(caller, &record.owner_did)` check); they are helpers, not
        // mounted handlers, so drop them.
        owner_marked.remove("require_owner");
        owner_marked.remove("require_repo_owner");
        // git_receive_pack also carries the inline did_matches-owner idiom, but for
        // a SECONDARY gate: its branch-protection push check (repos.rs), not a
        // whole-handler owner gate. Its 403 is DRIVEN by the dedicated
        // `signed_stranger_protected_branch_push_is_forbidden` test (#195, F3) — a
        // signed non-owner push to a protected branch, with an owner control — so
        // inverting the gate goes RED there. It is therefore not an owner-gate
        // orphan (the OwnerGate registry rows can't carry the protected-branch
        // substrate); drop it so the owner-orphan assert does not misflag a route
        // whose owner gate is already driven.
        owner_marked.remove("git_receive_pack");
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

    /// READ-GATE ORPHAN GUARD (F1). The owner-gate orphan guard above stops an
    /// owner-gated mount from escaping the sweep; this is its read-gate twin. Every
    /// handler carrying a read-gate marker (`authorize_repo_read(` /
    /// `visibility_check(` — the two markers repos.rs/issues.rs/pulls.rs/
    /// bounties.rs/certs.rs/labels.rs/changelog.rs/events.rs/encrypted.rs/stars.rs/
    /// visibility.rs all use, verified there is no third) must be EITHER a
    /// `ReadGate` row in `deny_bearing_routes()` (driven for its 404) OR an explicit
    /// entry in `READ_GATE_NOT_DRIVEN` with a reason. That enumerated allowlist
    /// REPLACES the old free-text "DEFERRED / EXCLUDED" prose in routes.rs: it is
    /// now enforced code, so removing or bypassing the read gate on any of these
    /// endpoints (or adding a brand-new read-gated handler) trips this instead of
    /// leaving the real-node sweep silently green. The api dir is read at test time,
    /// like the owner scan, so a new module is covered too.
    #[test]
    fn every_read_gate_handler_is_driven_or_explicitly_allowlisted() {
        // The allowlist is the module-level `READ_GATE_NOT_DRIVEN` (single source of
        // truth, shared with the route-table cross-check). Its entries carry a closed
        // `NotDrivenReason`, so a soft "deferred" excuse cannot be added.

        let driven_read_handlers: HashSet<&str> = deny_bearing_routes()
            .iter()
            .filter(|r| r.gate == GateClass::ReadGate)
            .map(|r| short_handler(r.handler))
            .collect();
        let allowlisted: HashSet<&str> = READ_GATE_NOT_DRIVEN.iter().map(|(h, _)| *h).collect();

        let api_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/api");
        let mut read_marked: HashSet<String> = HashSet::new();
        for entry in std::fs::read_dir(api_dir).expect("read api dir") {
            let path = entry.expect("dir entry").path();
            // Skip api/mod.rs: it holds the gate HELPERS themselves
            // (`authorize_repo_read`, `visibility_check`, `require_repo_owner`, …),
            // not mounted route handlers — every mounted read handler lives in a
            // sibling module (repos.rs, issues.rs, …). Scanning mod.rs would attach
            // the marker to helper definitions and force phantom allowlist entries.
            if path.file_name().is_some_and(|f| f == "mod.rs") {
                continue;
            }
            if path.extension().is_some_and(|e| e == "rs") {
                let src = std::fs::read_to_string(&path).expect("read api file");
                // Comment-stripped scan: the read-gate markers appear in several
                // docstrings, and a raw scan would allowlist phantom non-handlers.
                read_marked.extend(handlers_with_code_marker(
                    &src,
                    &["authorize_repo_read(", "visibility_check("],
                ));
            }
        }
        // The read-gate helper `visibility_check` is re-declared/aliased in
        // visibility.rs's own use-path; drop the helper name if the scan attaches
        // the marker to it (it is a helper, not a mounted handler) — the mirror of
        // the owner scan dropping require_owner / require_repo_owner.
        read_marked.remove("authorize_repo_read");
        read_marked.remove("visibility_check");

        // Non-vacuous floor: the tree has 41 read-gate-marked handlers today. If the
        // marker scan silently found far fewer, the orphan loop below would pass by
        // checking almost nothing; 30 trips only on a real parser break.
        assert!(
            read_marked.len() >= 30,
            "read-gate marker scan found only {} handlers — the scan likely broke (floor 30)",
            read_marked.len()
        );

        for h in &read_marked {
            let name = h.as_str();
            assert!(
                driven_read_handlers.contains(name) || allowlisted.contains(name),
                "handler `{name}` carries a read-gate marker but is neither a ReadGate \
                 row in deny_bearing_routes() nor in READ_GATE_NOT_DRIVEN — drive its \
                 404 or add it to the allowlist with a reason"
            );
        }

        // Staleness: every allowlist entry must still be a real read-gate handler,
        // so a rename/removal can't leave a dead exemption that masks a future gap.
        for (name, _reason) in READ_GATE_NOT_DRIVEN {
            assert!(
                read_marked.contains(*name),
                "READ_GATE_NOT_DRIVEN lists `{name}`, which no longer carries a \
                 read-gate marker (renamed, removed, or gate dropped?) — update the list"
            );
        }

        // DRIVEN-NOT-RELABELED (#195, U4/R5). The nine reads U3 drove must each be a
        // driven `ReadGate` row AND absent from `READ_GATE_NOT_DRIVEN`, so none can
        // be quietly re-parked under a mislabeled structural reason. A structural
        // class (mutation / git / content-addressed / list-filter / external-dep)
        // does not fit any of these nine, but a reviewer could still mistype one in;
        // this makes that a hard failure rather than a judgment call. Together with
        // the closed `NotDrivenReason` enum, a drivable private read cannot leave the
        // sweep: either the class does not compile, or this assertion fires.
        const U3_DRIVEN_READS: &[&str] = &[
            "get_issue",
            "get_pr",
            "get_pr_diff",
            "list_issue_comments",
            "list_reviews",
            "list_comments",
            "get_cert",
            "get_bounty",
            "get_tree",
        ];
        for name in U3_DRIVEN_READS {
            assert!(
                driven_read_handlers.contains(name),
                "U3 drove `{name}` as a private read, but it is no longer a ReadGate \
                 row in deny_bearing_routes() — a driven read was dropped or renamed"
            );
            assert!(
                !allowlisted.contains(name),
                "`{name}` is a U3-driven private read but was re-parked in \
                 READ_GATE_NOT_DRIVEN — a drivable 404-deny GET may not be excused \
                 under a structural reason; drive it, do not relabel it"
            );
        }
    }

    /// The repo-scoped GET mounts the [`scrape_mounts`] route-table walk does NOT
    /// treat as read-gated — genuinely public repo listings that fetch the repo and
    /// return metadata WITHOUT an `authorize_repo_read` / `visibility_check` call
    /// (verified in their handlers). They carry no read gate, so the cross-check
    /// below must not demand they be driven or structurally excused. Keyed by path
    /// (the unit `scrape_mounts` yields) so a new gate added to one of these later
    /// still surfaces via the marker scan; this list only says "no gate today".
    const PUBLIC_REPO_GETS: &[&str] = &[
        "/api/v1/repos/{owner}/{repo}/hooks", // list_webhooks
        "/api/v1/repos/{owner}/{repo}/branches/protected", // list_protected_branches
        "/api/v1/repos/{owner}/{repo}/replicas", // list_replicas
    ];

    /// True for a mounted path that is scoped to a single repo — the API form
    /// `/api/v1/repos/{owner}/{repo}/…` and the bare git form `/{owner}/{repo}/…`.
    /// These are the paths whose GET, if read-gated, must be driven or excused; a
    /// collection/global path (`/api/v1/repos`, `/api/v1/bounties`, `/api/v1/agents`
    /// …) is out of scope for the repo-read cross-check.
    fn is_repo_scoped_path(path: &str) -> bool {
        if let Some(rest) = path.strip_prefix("/api/v1/repos/") {
            // `.../{owner}/{repo}/…` — at least owner + repo + a trailing segment,
            // and NOT the `/api/v1/repos/federated` or bare `/api/v1/repos` forms
            // (those have no `{owner}` placeholder).
            return rest.starts_with("{owner}/{repo}/");
        }
        // Bare git form: `/{owner}/{repo}/info/refs` etc. It is repo-scoped when the
        // first two segments are the owner/repo placeholders.
        let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        segs.len() >= 3 && segs[0] == "{owner}" && segs[1] == "{repo}"
    }

    /// Extract the handler name from a single `.route("path", …get(handler)…)` mount
    /// body: the last `::`-tail ident inside the FIRST routing-method call for the
    /// requested HTTP method. Returns `None` if the method is not mounted on this
    /// route. Reuses the same balanced-paren mount slice `scrape_mounts` walks.
    fn handler_for_mount(call: &str, method: &str) -> Option<String> {
        let needle = format!("{}(", method.to_lowercase());
        let mut k = 0;
        while let Some(rel) = call[k..].find(&needle) {
            let at = k + rel;
            let boundary = call[..at]
                .chars()
                .last()
                .map(|c| !(c.is_alphanumeric() || c == '_'))
                .unwrap_or(true);
            if boundary {
                // The handler is the first path-expression after `get(`; take up to
                // the closing `)` and keep the final `::`-segment ident.
                let inner_start = at + needle.len();
                let inner = &call[inner_start..];
                let end = inner.find([')', ',']).unwrap_or(inner.len());
                let expr = inner[..end].trim();
                let name: String = expr
                    .rsplit("::")
                    .next()
                    .unwrap_or(expr)
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    return Some(name);
                }
            }
            k = at + needle.len();
        }
        None
    }

    /// Like [`scrape_mounts`] but also captures the handler name, so a mounted
    /// (METHOD, path) can be resolved to its handler for the read-gate cross-check.
    /// Same balanced-paren walk as `scrape_mounts`.
    fn scrape_mounts_with_handler(src: &str) -> Vec<(String, String, String)> {
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
                    let boundary = call[..at]
                        .chars()
                        .last()
                        .map(|c| !(c.is_alphanumeric() || c == '_'))
                        .unwrap_or(true);
                    if boundary {
                        if let Some(h) = handler_for_mount(call, m) {
                            out.push((m.to_uppercase(), path.to_string(), h));
                        }
                    }
                    k = at + needle.len();
                }
            }
        }
        out
    }

    /// SCRAPE-MOUNTS CROSS-CHECK (#195, U4/R5, INV-21b). The read-gate orphan guard
    /// above derives its required set from a SOURCE-MARKER scan of `src/api`; this
    /// derives it instead from the MOUNTED ROUTE TABLE (`server.rs`). Every mounted
    /// repo-scoped GET must be EITHER a driven `ReadGate` row, OR a deny-bearing GET
    /// of another class already in the registry (`list_visibility` is an owner-gated
    /// GET), OR structurally excused in `READ_GATE_NOT_DRIVEN`, OR a declared public
    /// repo-GET (`PUBLIC_REPO_GETS`). A mounted repo-GET that is none of these fails
    /// HERE — which catches a read that gates via a helper the marker scan does not
    /// recognize: it would still be mounted, so it must be classified rather than
    /// slipping past silently.
    #[test]
    fn mounted_repo_gets_are_driven_excused_or_declared_public() {
        let server = include_str!("../src/server.rs");
        let mounts = scrape_mounts_with_handler(server);

        // Integrity floor: the handler-aware walk must find roughly as many mounts
        // as the plain scrape; if it collapsed, the cross-check would pass vacuously.
        assert!(
            mounts.len() >= 90,
            "handler-aware mount scrape found only {} routes — the parser likely broke (floor 90)",
            mounts.len()
        );

        // Every path that is a driven ReadGate row, and every deny-bearing GET path
        // of any class (so the owner-gated `list_visibility` GET is accounted for).
        let driven_read_paths: HashSet<&str> = deny_bearing_routes()
            .iter()
            .filter(|r| r.gate == GateClass::ReadGate)
            .map(|r| r.path)
            .collect();
        let deny_bearing_get_paths: HashSet<&str> = deny_bearing_routes()
            .iter()
            .filter(|r| r.method == "GET")
            .map(|r| r.path)
            .collect();
        let excused_handlers: HashSet<&str> =
            READ_GATE_NOT_DRIVEN.iter().map(|(h, _)| *h).collect();
        let public_paths: HashSet<&str> = PUBLIC_REPO_GETS.iter().copied().collect();

        let mut repo_gets_seen = 0usize;
        for (method, path, handler) in &mounts {
            if method != "GET" || !is_repo_scoped_path(path) {
                continue;
            }
            repo_gets_seen += 1;
            let classified = driven_read_paths.contains(path.as_str())
                || deny_bearing_get_paths.contains(path.as_str())
                || excused_handlers.contains(handler.as_str())
                || public_paths.contains(path.as_str());
            assert!(
                classified,
                "mounted repo-scoped GET `{path}` (handler `{handler}`) is neither a \
                 driven ReadGate row, a deny-bearing GET row, structurally excused in \
                 READ_GATE_NOT_DRIVEN, nor a declared public repo-GET — classify it \
                 (it may gate via a helper the source-marker scan does not recognize)"
            );
        }

        // Non-vacuous floor: the tree mounts well over a dozen repo-scoped GETs; if
        // the filter found almost none, the loop above proved nothing.
        assert!(
            repo_gets_seen >= 15,
            "found only {repo_gets_seen} mounted repo-scoped GETs — the path filter \
             or the scrape likely broke (floor 15)"
        );
    }

    // ── F3 unit tests: the inline owner-gate did_matches discriminator ───────────
    //
    // These pin `has_owner_did_matches` against the EXACT real bodies (positive and
    // negative), so the two-arg discriminator can't silently regress into matching
    // the signer-self / author forms that share the helper.

    #[test]
    fn has_owner_did_matches_catches_the_protect_branch_owner_idiom() {
        // protect.rs:28 form: first arg the caller, second `&record.owner_did`.
        let body = "let caller = &auth.0;\n\
                    if !crate::api::did_matches(caller, &record.owner_did) {\n\
                        return Err(AppError::Forbidden(\"only the owner\".into()));\n\
                    }";
        assert!(
            has_owner_did_matches(body),
            "the protect_branch owner idiom must be recognized"
        );
    }

    #[test]
    fn has_owner_did_matches_catches_the_auth0_owner_form() {
        // The `&auth.0` first-arg spelling (repos.rs's branch-protection check),
        // tolerating a newline before the second arg.
        let body =
            "if x\n    && !crate::api::did_matches(&auth.0,\n        &record.owner_did)\n    {";
        assert!(
            has_owner_did_matches(body),
            "the &auth.0 / owner_did form must be recognized across a newline"
        );
    }

    #[test]
    fn has_owner_did_matches_ignores_register_replica_signer_self() {
        // replicas.rs:52: FIRST arg is `replica_did`, NOT the caller — signer-self
        // by design. The second arg is owner_did, so a naive "second arg is
        // owner_did" check would wrongly flag it. It must NOT match.
        let body = "if crate::api::did_matches(replica_did, &record.owner_did) {\n\
                        // the signer is registering itself as a replica\n\
                    }";
        assert!(
            !has_owner_did_matches(body),
            "register_replica's signer-self did_matches must NOT be treated as an owner gate"
        );
    }

    #[test]
    fn has_owner_did_matches_ignores_close_pr_author_form() {
        // pulls.rs:277: caller-first but SECOND arg is `&pr.author_did`, not
        // owner_did — the owner-or-author close gate. Must NOT match as owner-only.
        let body = "let is_author = crate::api::did_matches(&auth.0, &pr.author_did);";
        assert!(
            !has_owner_did_matches(body),
            "close_pr's author did_matches must NOT be treated as an owner gate"
        );
    }

    #[test]
    fn has_owner_did_matches_ignores_bounty_and_task_self_forms() {
        // bounties.rs / tasks.rs: caller-first, but the second arg is a
        // creator/delegator/assignee did, never owner_did.
        for body in [
            "if !crate::api::did_matches(&auth.0, &bounty.creator_did) {",
            "if !crate::api::did_matches(&auth.0, &body.delegator_did) {",
            "if !crate::api::did_matches(&auth.0, &body.assignee_did) {",
        ] {
            assert!(
                !has_owner_did_matches(body),
                "self/author did_matches form must NOT be treated as an owner gate: {body}"
            );
        }
    }
}
