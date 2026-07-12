//! Real-node deny harness: boots a real gitlawb-node over a bound TCP socket
//! and drives trust-boundary DENY paths through a real reqwest client,
//! asserting both the refusal status and that no withheld data leaks
//! (INV-1/INV-2/INV-8). Requires `--features test-harness`.
//!
//! Each `#[sqlx::test]` gets an ephemeral per-test database; `spawn_node` runs
//! the schema migrations and serves the real router on `127.0.0.1:0`.

mod support;

use support::assert::assert_denied;
use support::signing::signed_request;

use gitlawb_core::identity::Keypair;
use gitlawb_node::test_harness::spawn_node;

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
