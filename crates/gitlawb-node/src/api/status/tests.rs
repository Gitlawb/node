use axum::body::Body;
use axum::http::{Method, StatusCode};
use axum::routing::post;
use axum::Router;
use sqlx::PgPool;
use tower::ServiceExt;

use crate::db::RepoRecord;
use crate::test_support::{signed_request_as, test_state};

const OWNER: &str = "did:key:zSTATUSOWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const STRANGER: &str = "did:key:zSTATUSSTRANGERBBBBBBBBBBBBBBBBBBBBBBBBB";
const SHA_A: &str = "1111111111111111111111111111111111111111";
const SHA_B: &str = "2222222222222222222222222222222222222222";
const SHA_C: &str = "3333333333333333333333333333333333333333";

fn seed_repo(owner_did: &str, name: &str, is_public: bool) -> RepoRecord {
    let now = chrono::Utc::now();
    RepoRecord {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.to_string(),
        owner_did: owner_did.to_string(),
        description: None,
        is_public,
        default_branch: "main".to_string(),
        created_at: now,
        updated_at: now,
        disk_path: format!("/tmp/{name}"),
        forked_from: None,
        machine_id: None,
    }
}

fn router(state: crate::state::AppState) -> Router {
    Router::new()
        .route(
            "/api/v1/repos/{owner}/{repo}/statuses/{sha}",
            post(super::create_status),
        )
        .with_state(state)
}

fn body_of(state: &str, context: &str) -> Body {
    Body::from(format!(r#"{{"state":"{state}","context":"{context}"}}"#))
}

fn uri(owner: &str, repo: &str, sha: &str) -> String {
    format!("/api/v1/repos/{owner}/{repo}/statuses/{sha}")
}

/// `signed_request_as` plus the verified RFC 9421 material the signature
/// middleware injects in production, so a handler mounted bare still runs the
/// real path instead of a missing-material branch.
///
/// The body is buffered here rather than handed straight to the builder because
/// the material has to AGREE with it: the write path refuses a claim whose
/// signing string does not cover the digest of the body being stored, so a
/// stand-in built over some other bytes would take every bare-router test down
/// the refusal branch instead of the path it means to exercise.
async fn signed_with_material(did: &str, uri: &str, body: Body) -> axum::http::Request<Body> {
    let bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .expect("test body is already in memory");
    let material = sample_material_for(&bytes);
    let mut req = signed_request_as(did, Method::POST, uri, Body::from(bytes));
    req.extensions_mut().insert(material);
    req
}

/// Stand-in material over `{}`, for the cases that only need SOME well-formed
/// material to override one field of.
fn sample_material() -> crate::auth::SignatureMaterial {
    sample_material_for(b"{}")
}

/// Stand-in material for `body`, well inside every bound, and DISTINCT on every
/// call.
///
/// Distinct because that is what production looks like: a real signature covers
/// a `created` parameter and the body's own digest, so two genuine requests
/// never carry the same bytes. A constant stand-in would make the second write
/// of any test an exact replay of the first, and the write path answers a replay
/// with the row it already has. The replay tests below get their identical bytes
/// the honest way, by signing once and putting the same headers on the wire
/// twice through the production router.
///
/// The signing string carries a real `content-digest` line over `body`, the way
/// `build_signing_string` emits one, because the write path checks that line
/// against the bytes it is about to persist.
fn sample_material_for(body: &[u8]) -> crate::auth::SignatureMaterial {
    static NTH: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let nth = NTH.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let digest = gitlawb_core::http_sig::compute_content_digest(body);
    crate::auth::SignatureMaterial {
        signature: format!("sig1=:dGVzdA=={nth}:"),
        signature_input: "sig1=(\"@method\" \"@path\" \"content-digest\");alg=\"ed25519\""
            .to_string(),
        signing_string: format!("\"@method\": POST\n\"content-digest\": {digest}"),
        body: Some(axum::body::Bytes::copy_from_slice(body)),
    }
}

async fn post_as(
    state: &crate::state::AppState,
    did: &str,
    uri: &str,
    body: Body,
) -> axum::response::Response {
    router(state.clone())
        .oneshot(signed_with_material(did, uri, body).await)
        .await
        .unwrap()
}

/// Status plus the full response body, for the byte-identical deny comparison.
async fn status_and_bytes(resp: axum::response::Response) -> (StatusCode, Vec<u8>) {
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
}

/// The owner's claim is recorded with both DIDs and a server timestamp. The
/// repo is seeded with the BARE owner key while the caller presents the full
/// `did:key:` form, so the owner gate has to normalize (did_matches), not
/// compare raw strings.
#[sqlx::test]
async fn owner_writes_a_claim_recording_both_dids(pool: PgPool) {
    let state = test_state(pool).await;
    let bare = OWNER.strip_prefix("did:key:").unwrap();
    let repo = seed_repo(bare, "status-repo", true);
    let repo_id = repo.id.clone();
    state.db.create_repo(&repo).await.unwrap();

    let resp = post_as(
        &state,
        OWNER,
        &uri(OWNER, "status-repo", SHA_A),
        body_of("success", "ci/build"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let claims = state.db.list_status_claims(&repo_id, SHA_A).await.unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].state, "success");
    assert_eq!(claims[0].context, "ci/build");
    assert_eq!(claims[0].producer_did, OWNER);
    assert_eq!(claims[0].authorizing_did, OWNER);
    assert!(
        chrono::DateTime::parse_from_rfc3339(&claims[0].created_at).is_ok(),
        "created_at must be a server-assigned rfc3339 timestamp, got {:?}",
        claims[0].created_at
    );
    assert!(claims[0].seq > 0, "seq is assigned by the database");
    // The verified RFC 9421 material is persisted with the row: a claim that
    // cannot be re-verified after the request is gone is not history.
    assert!(claims[0].signature.starts_with("sig1=:dGVzdA=="));
    assert!(claims[0].signature_input.starts_with("sig1=("));
    assert_eq!(
        claims[0].request_body, br#"{"state":"success","context":"ci/build"}"#,
        "the stored body is the one the request carried"
    );
    assert_eq!(
        claims[0].signing_string,
        format!(
            "\"@method\": POST\n\"content-digest\": {}",
            gitlawb_core::http_sig::compute_content_digest(&claims[0].request_body)
        ),
        "the stored signing string is the verified material, digest line included"
    );
}

/// Covers AE1. Two claims for one context both survive: the history is
/// append-only and the later claim never overwrites the earlier row.
#[sqlx::test]
async fn ae1_pending_then_success_keeps_both_rows(pool: PgPool) {
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "history-repo", true);
    let repo_id = repo.id.clone();
    state.db.create_repo(&repo).await.unwrap();

    for st in ["pending", "success"] {
        let resp = post_as(
            &state,
            OWNER,
            &uri(OWNER, "history-repo", SHA_A),
            body_of(st, "ci/build"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED, "{st} claim");
    }

    let claims = state.db.list_status_claims(&repo_id, SHA_A).await.unwrap();
    let states: Vec<&str> = claims.iter().map(|c| c.state.as_str()).collect();
    assert_eq!(
        states,
        vec!["pending", "success"],
        "both claims must remain, ordered by seq"
    );
}

/// Covers AE5. A signed non-owner writing to a repo it CAN read is refused
/// with exactly 403 (existence is not secret on a public repo) and writes
/// nothing.
#[sqlx::test]
async fn ae5_non_owner_on_public_repo_is_forbidden(pool: PgPool) {
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "public-repo", true);
    let repo_id = repo.id.clone();
    state.db.create_repo(&repo).await.unwrap();

    let resp = post_as(
        &state,
        STRANGER,
        &uri(OWNER, "public-repo", SHA_A),
        body_of("success", "ci/build"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        state
            .db
            .list_status_claims(&repo_id, SHA_A)
            .await
            .unwrap()
            .is_empty(),
        "a refused write must leave no row"
    );
}

/// A non-owner writing to a private repo gets the response a MISSING repo
/// returns, byte for byte. The same URI is driven twice — once before the
/// repo exists, once after it is seeded private — so the two bodies are
/// comparable and the deny cannot pass vacuously on an absent row.
#[sqlx::test]
async fn non_owner_on_private_repo_is_indistinguishable_from_missing(pool: PgPool) {
    let state = test_state(pool).await;
    let target = uri(OWNER, "hidden-repo", SHA_A);

    let missing = post_as(&state, STRANGER, &target, body_of("success", "ci/build")).await;
    let missing = status_and_bytes(missing).await;

    let repo = seed_repo(OWNER, "hidden-repo", false);
    let repo_id = repo.id.clone();
    state.db.create_repo(&repo).await.unwrap();

    let denied = post_as(&state, STRANGER, &target, body_of("success", "ci/build")).await;
    let denied = status_and_bytes(denied).await;

    assert_eq!(missing.0, StatusCode::NOT_FOUND);
    assert_eq!(
        denied, missing,
        "a private-repo deny must be byte-identical to the missing-repo response"
    );
    assert!(
        state
            .db
            .list_status_claims(&repo_id, SHA_A)
            .await
            .unwrap()
            .is_empty(),
        "a refused write must leave no row"
    );
}

/// A quarantined repo denies before the visibility gate, so even a PUBLIC
/// quarantined repo answers with the missing-repo response. A plain repo load
/// plus owner comparison would answer 403 here, which is what makes this the
/// case that separates the two implementations.
#[sqlx::test]
async fn non_owner_on_quarantined_repo_is_indistinguishable_from_missing(pool: PgPool) {
    let state = test_state(pool).await;
    let target = uri(OWNER, "quarantined-repo", SHA_A);

    let missing = post_as(&state, STRANGER, &target, body_of("success", "ci/build")).await;
    let missing = status_and_bytes(missing).await;

    // Public on purpose: quarantine must deny independently of visibility.
    let repo = seed_repo(OWNER, "quarantined-repo", true);
    let repo_id = repo.id.clone();
    state.db.create_repo(&repo).await.unwrap();
    state.db.set_repo_quarantine(&repo_id, true).await.unwrap();

    let denied = post_as(&state, STRANGER, &target, body_of("success", "ci/build")).await;
    let denied = status_and_bytes(denied).await;

    assert_eq!(missing.0, StatusCode::NOT_FOUND);
    assert_eq!(
        denied, missing,
        "a quarantined-repo deny must be byte-identical to the missing-repo response"
    );
    assert!(
        state
            .db
            .list_status_claims(&repo_id, SHA_A)
            .await
            .unwrap()
            .is_empty(),
        "a refused write must leave no row"
    );
}

/// Every malformed field is exactly 400 and writes nothing. The two SHA cases
/// ride in the path, the rest in the body.
#[sqlx::test]
async fn malformed_claims_are_rejected_with_400(pool: PgPool) {
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "valid-repo", true);
    let repo_id = repo.id.clone();
    state.db.create_repo(&repo).await.unwrap();

    let long_description = "d".repeat(1025);
    let cases: Vec<(&str, String, String)> = vec![
        (
            "state outside the four-value set",
            uri(OWNER, "valid-repo", SHA_A),
            r#"{"state":"passed","context":"ci"}"#.into(),
        ),
        (
            "sha of 39 characters",
            uri(OWNER, "valid-repo", &"1".repeat(39)),
            r#"{"state":"success","context":"ci"}"#.into(),
        ),
        (
            "sha with a non-hex character",
            uri(OWNER, "valid-repo", &format!("{}z", "1".repeat(39))),
            r#"{"state":"success","context":"ci"}"#.into(),
        ),
        (
            "empty context",
            uri(OWNER, "valid-repo", SHA_A),
            r#"{"state":"success","context":"   "}"#.into(),
        ),
        (
            "control characters in context",
            uri(OWNER, "valid-repo", SHA_A),
            r#"{"state":"success","context":"ci\u0007build"}"#.into(),
        ),
        (
            "oversized description",
            uri(OWNER, "valid-repo", SHA_A),
            format!(r#"{{"state":"success","context":"ci","description":"{long_description}"}}"#),
        ),
        (
            "javascript: target url",
            uri(OWNER, "valid-repo", SHA_A),
            r#"{"state":"success","context":"ci","target_url":"javascript:alert(1)"}"#.into(),
        ),
    ];

    for (label, target, body) in cases {
        let resp = post_as(&state, OWNER, &target, Body::from(body)).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "{label} must be rejected with 400"
        );
    }

    for sha in [SHA_A, &"1".repeat(39), &format!("{}z", "1".repeat(39))] {
        assert!(
            state
                .db
                .list_status_claims(&repo_id, sha)
                .await
                .unwrap()
                .is_empty(),
            "a rejected claim must leave no row"
        );
    }
}

/// Seed one (repo, commit, producer, context) tuple to its cap; the next claim
/// on that tuple is exactly 429, while a fresh context on the same commit
/// still writes — proving the refusal came from the tuple cap and not from a
/// broader bound.
#[sqlx::test]
async fn per_tuple_cap_refuses_the_next_claim(pool: PgPool) {
    let state = test_state(pool.clone()).await;
    let repo = seed_repo(OWNER, "tuple-cap-repo", true);
    let repo_id = repo.id.clone();
    state.db.create_repo(&repo).await.unwrap();

    seed_claims(
        &pool,
        &repo_id,
        SHA_A,
        OWNER,
        "ci/build",
        super::MAX_CLAIMS_PER_TUPLE,
    )
    .await;

    let resp = post_as(
        &state,
        OWNER,
        &uri(OWNER, "tuple-cap-repo", SHA_A),
        body_of("success", "ci/build"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    let resp = post_as(
        &state,
        OWNER,
        &uri(OWNER, "tuple-cap-repo", SHA_A),
        body_of("success", "ci/lint"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "a different context on the same commit is under its own tuple cap"
    );
}

/// Seed the per-(repo, commit) context limit under distinct contexts; a claim
/// carrying a fresh context is exactly 429 even though its own tuple is empty.
#[sqlx::test]
async fn context_fanout_cap_refuses_a_fresh_context(pool: PgPool) {
    let state = test_state(pool.clone()).await;
    let repo = seed_repo(OWNER, "context-cap-repo", true);
    let repo_id = repo.id.clone();
    state.db.create_repo(&repo).await.unwrap();

    for i in 0..super::MAX_CONTEXTS_PER_COMMIT {
        seed_claims(&pool, &repo_id, SHA_A, OWNER, &format!("ci/{i}"), 1).await;
    }

    let resp = post_as(
        &state,
        OWNER,
        &uri(OWNER, "context-cap-repo", SHA_A),
        body_of("success", "ci/fresh"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    let resp = post_as(
        &state,
        OWNER,
        &uri(OWNER, "context-cap-repo", SHA_A),
        body_of("success", "ci/0"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "a context already present does not widen the fanout, so it still writes"
    );
}

/// Seed the per-repo limit across distinct well-formed SHAs, all inside the
/// window; a claim against a fresh SHA is exactly 429, which is the bound the
/// caller-chosen (never existence-checked) SHA would otherwise escape.
#[sqlx::test]
async fn repo_row_cap_refuses_a_fresh_sha(pool: PgPool) {
    let state = test_state(pool.clone()).await;
    let repo = seed_repo(OWNER, "repo-cap-repo", true);
    let repo_id = repo.id.clone();
    state.db.create_repo(&repo).await.unwrap();

    seed_claims_across_shas(
        &pool,
        &repo_id,
        OWNER,
        super::MAX_CLAIMS_PER_REPO_PER_WINDOW,
        &chrono::Utc::now().to_rfc3339(),
    )
    .await;

    let resp = post_as(
        &state,
        OWNER,
        &uri(OWNER, "repo-cap-repo", SHA_B),
        body_of("success", "ci/build"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

/// The per-repo bound is a rate, not a lifetime quota, and 429 says so
/// honestly: a client that waits and retries eventually gets through. The same
/// rows dated before the window admit a fresh claim, so a repo that once burst
/// to the limit is not permanently unable to accept a status while every CI
/// client retries a refusal that could never succeed.
#[sqlx::test]
async fn repo_cap_is_a_window_so_the_refusal_is_actually_retryable(pool: PgPool) {
    let state = test_state(pool.clone()).await;
    let repo = seed_repo(OWNER, "repo-window-repo", true);
    let repo_id = repo.id.clone();
    state.db.create_repo(&repo).await.unwrap();

    // Enough rows to blow a lifetime bound, every one of them older than the
    // window: this is the repo that reached the cap yesterday.
    let long_ago = (chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339();
    seed_claims_across_shas(
        &pool,
        &repo_id,
        OWNER,
        super::MAX_CLAIMS_PER_REPO_PER_WINDOW,
        &long_ago,
    )
    .await;

    let resp = post_as(
        &state,
        OWNER,
        &uri(OWNER, "repo-window-repo", SHA_B),
        body_of("success", "ci/build"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "claims outside the window must not count against it; a repo cannot be \
             permanently barred from accepting a status"
    );
}

/// A handler reached without the verified signature material writes NOTHING
/// and answers 500. The material is a server-side invariant (`require_signature`
/// always injects it), so its absence is a misconfiguration, not a client
/// error — and a claim stored without it is unverifiable history, which the
/// substrate cannot adopt. Failing open here would be silent: the row looks
/// fine and nothing goes red.
#[sqlx::test]
async fn missing_signature_material_fails_closed(pool: PgPool) {
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "material-repo", true);
    let repo_id = repo.id.clone();
    state.db.create_repo(&repo).await.unwrap();

    // Deliberately NOT signed_with_material: only the identity is injected.
    let resp = router(state.clone())
        .oneshot(signed_request_as(
            OWNER,
            Method::POST,
            &uri(OWNER, "material-repo", SHA_A),
            body_of("success", "ci/build"),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        state
            .db
            .list_status_claims(&repo_id, SHA_A)
            .await
            .unwrap()
            .is_empty(),
        "an unverifiable claim must never be stored"
    );
}

/// Every piece of signature material is bounded before it is persisted, and
/// an oversized one is exactly 400 with no row written.
///
/// The signing string is the one that actually grows: it carries a line per
/// covered component, and the component list comes from the caller's own
/// Signature-Input. The other three are bounded for the same reason, since
/// all four are caller-supplied bytes that the write path stores verbatim.
#[sqlx::test]
async fn oversized_signature_material_is_rejected_with_400(pool: PgPool) {
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "material-cap-repo", true);
    let repo_id = repo.id.clone();
    state.db.create_repo(&repo).await.unwrap();

    let cases: Vec<(&str, crate::auth::SignatureMaterial)> = vec![
        (
            "signature",
            crate::auth::SignatureMaterial {
                signature: "s".repeat(super::MAX_SIGNATURE_CHARS + 1),
                ..sample_material()
            },
        ),
        (
            "signature-input",
            crate::auth::SignatureMaterial {
                signature_input: "i".repeat(super::MAX_SIGNATURE_INPUT_CHARS + 1),
                ..sample_material()
            },
        ),
        (
            "signing string",
            crate::auth::SignatureMaterial {
                signing_string: "c".repeat(super::MAX_SIGNING_STRING_CHARS + 1),
                ..sample_material()
            },
        ),
        (
            "request body",
            crate::auth::SignatureMaterial {
                body: Some(vec![b'b'; super::MAX_REQUEST_BODY_BYTES + 1].into()),
                ..sample_material()
            },
        ),
    ];

    for (label, material) in cases {
        let mut req = signed_request_as(
            OWNER,
            Method::POST,
            &uri(OWNER, "material-cap-repo", SHA_A),
            body_of("success", "ci/build"),
        );
        req.extensions_mut().insert(material);
        let resp = router(state.clone()).oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "an oversized {label} must be rejected with 400"
        );
    }

    assert!(
        state
            .db
            .list_status_claims(&repo_id, SHA_A)
            .await
            .unwrap()
            .is_empty(),
        "a refused write must leave no row"
    );

    // The control: the same request with material inside every bound writes.
    let resp = post_as(
        &state,
        OWNER,
        &uri(OWNER, "material-cap-repo", SHA_A),
        body_of("success", "ci/build"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "material inside the bounds must still write, or the caps prove nothing"
    );
}

/// Material that reached this handler without the body is a refusal, not an
/// empty column.
///
/// The body is only captured on routes that mark themselves as persisting it,
/// so an absent body here means the status route lost that marker or the
/// marker layer was reordered behind the signature middleware. Writing the row
/// anyway would record a claim nobody can re-verify, with nothing going red:
/// the same absence-renders-as-success shape the missing-material branch
/// already refuses.
#[sqlx::test]
async fn material_without_the_body_is_refused_rather_than_stored_empty(pool: PgPool) {
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "no-body-repo", true);
    let repo_id = repo.id.clone();
    state.db.create_repo(&repo).await.unwrap();

    let mut req = signed_request_as(
        OWNER,
        Method::POST,
        &uri(OWNER, "no-body-repo", SHA_A),
        body_of("success", "ci/build"),
    );
    req.extensions_mut().insert(crate::auth::SignatureMaterial {
        body: None,
        ..sample_material()
    });
    let resp = router(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "a status write whose material carries no body must be refused"
    );
    assert!(
        state
            .db
            .list_status_claims(&repo_id, SHA_A)
            .await
            .unwrap()
            .is_empty(),
        "a refused write must leave no row"
    );

    // The control: the same request with the body present writes, so the
    // refusal above is about the missing body and not the route.
    let resp = post_as(
        &state,
        OWNER,
        &uri(OWNER, "no-body-repo", SHA_A),
        body_of("success", "ci/build"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "material carrying the body must still write"
    );
}

/// The 201 body carries exactly the client-facing fields and no signature
/// material. Asserted as the whole key set, not field by field, so a field
/// added to the response type later has to be added here deliberately
/// instead of leaking on the next serialize.
#[sqlx::test]
async fn create_response_carries_no_signature_material(pool: PgPool) {
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "response-repo", true);
    state.db.create_repo(&repo).await.unwrap();

    let resp = post_as(
            &state,
            OWNER,
            &uri(OWNER, "response-repo", SHA_A),
            Body::from(
                r#"{"state":"success","context":"ci/build","target_url":"https://ci.example/1","description":"ok"}"#,
            ),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body = body_json(resp).await;
    let mut keys: Vec<&str> = body
        .as_object()
        .expect("the 201 body must be a json object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "commit_sha",
            "context",
            "created_at",
            "description",
            "id",
            "producer_did",
            "repo_id",
            "seq",
            "state",
            "target_url",
        ],
        "the write response must carry exactly the client-facing fields"
    );

    assert_eq!(body["state"], "success");
    assert_eq!(body["context"], "ci/build");
    assert_eq!(body["commit_sha"], SHA_A);
    assert_eq!(body["producer_did"], OWNER);
    assert!(
        body["seq"].as_i64().unwrap() > 0,
        "the response must report the seq the database assigned"
    );
}

// ── Signed writes through the production router ───────────────────────
//
// Everything above injects a hand-built `SignatureMaterial` onto a bare
// router, which cannot see a middleware that populates the material wrongly.
// These drive a genuinely signed request through `build_router`.

/// Sign `body` for `path` with `kp` and POST it through the production
/// router, headers and all. Returns the headers that went on the wire
/// alongside the response, so a test can compare them against what the node
/// persisted.
async fn post_really_signed(
    state: &crate::state::AppState,
    kp: &gitlawb_core::identity::Keypair,
    path: &str,
    body: &[u8],
) -> (
    axum::response::Response,
    gitlawb_core::http_sig::SignedHeaders,
) {
    let signed = gitlawb_core::http_sig::sign_request(kp, "POST", path, body);
    let resp = post_signed_headers(state, path, body, &signed).await;
    (resp, signed)
}

/// POST `body` to `path` under signature headers that were produced earlier.
///
/// Splitting this out of [`post_really_signed`] is what makes a REPLAY
/// expressible: sign once, then put the identical bytes on the wire a second
/// time. Signing twice would not be a replay, because a fresh signature covers
/// a fresh `created` parameter.
async fn post_signed_headers(
    state: &crate::state::AppState,
    path: &str,
    body: &[u8],
    signed: &gitlawb_core::http_sig::SignedHeaders,
) -> axum::response::Response {
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header("content-digest", signed.content_digest.clone())
        .header("signature-input", signed.signature_input.clone())
        .header("signature", signed.signature.clone())
        .body(Body::from(body.to_vec()))
        .unwrap();
    crate::server::build_router(state.clone())
        .oneshot(req)
        .await
        .unwrap()
}

/// An oversized status body is refused at the transport, before the signature
/// middleware buffers it.
///
/// The 8 KiB bound the module advertises used to be checked only in the
/// handler, which runs after `require_signature` has collected and hashed the
/// entire body: the number bounded what was STORED, never what was ALLOCATED,
/// so a signed caller could make the node buffer a body of any size and only
/// then be told 400.
///
/// The unsigned arm is the one that pins the ORDERING rather than merely the
/// refusal. It carries no signature headers at all, so if anything ran ahead of
/// the limit it would be the auth middleware answering 401; a 413 means the
/// request was turned away before the layer that reads bodies ever saw it. The
/// signed arm shows the limit is not merely rejecting unauthenticated traffic,
/// the no-length arm shows a request that declares nothing is still bounded on
/// the read, and the control shows a body inside the bound still writes.
#[sqlx::test]
async fn an_oversized_status_body_is_refused_before_the_signature_middleware_buffers_it(
    pool: PgPool,
) {
    let state = test_state(pool.clone()).await;
    let kp = gitlawb_core::identity::Keypair::generate();
    let did = kp.did().to_string();
    let repo = seed_repo(&did, "body-limit-repo", true);
    let repo_id = repo.id.clone();
    state.db.create_repo(&repo).await.unwrap();
    let path = uri(&did, "body-limit-repo", SHA_A);

    let oversized = format!(
        r#"{{"state":"success","context":"ci/build","description":"{}"}}"#,
        "d".repeat(super::MAX_REQUEST_BODY_BYTES)
    );
    let signed = gitlawb_core::http_sig::sign_request(&kp, "POST", &path, oversized.as_bytes());

    // `Request::builder` does not stamp a Content-Length the way a real client
    // does, so the declared length is set explicitly wherever the test means to
    // exercise the declared-length branch.
    let post = |with_signature: bool, with_length: bool| {
        let mut b = axum::http::Request::builder()
            .method(Method::POST)
            .uri(&path)
            .header(axum::http::header::CONTENT_TYPE, "application/json");
        if with_signature {
            b = b
                .header("content-digest", signed.content_digest.clone())
                .header("signature-input", signed.signature_input.clone())
                .header("signature", signed.signature.clone());
        }
        if with_length {
            b = b.header(
                axum::http::header::CONTENT_LENGTH,
                oversized.len().to_string(),
            );
        }
        b.body(Body::from(oversized.clone())).unwrap()
    };
    let send = |req| async {
        crate::server::build_router(state.clone())
            .oneshot(req)
            .await
            .unwrap()
    };

    let resp = send(post(false, true)).await;
    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "an oversized body must be refused before anything reads or authenticates it"
    );

    let resp = send(post(true, true)).await;
    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "a signed oversized body must be refused by the transport bound, not by the handler"
    );

    // Nothing declared. The refusal moves to whoever reads the body — the
    // signature middleware, which cannot tell a truncated body from an
    // unreadable one and answers 400 — but the read still stops at the limit
    // rather than buffering whatever arrives.
    let resp = send(post(true, false)).await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "a body that declares no length must still be bounded on the read"
    );

    assert!(
        state
            .db
            .list_status_claims(&repo_id, SHA_A)
            .await
            .unwrap()
            .is_empty(),
        "a refused write must leave no row"
    );

    // The control: a body inside the bound still reaches the handler and writes.
    let ok_body = br#"{"state":"success","context":"ci/build"}"#;
    let (ok, _) = post_really_signed(&state, &kp, &path, ok_body).await;
    assert_eq!(
        ok.status(),
        StatusCode::CREATED,
        "the bound must not refuse an ordinary status write"
    );
}

/// A signature that covers an EMPTY content-digest cannot write a claim, even
/// though it is a genuine signature from the repository's own owner.
///
/// This is the whole attack, driven end to end through the production router.
/// `require_signature` rebuilds the covered component values from the request,
/// so a caller who omits the `Content-Digest` header makes the covered digest
/// the empty string on both the signing side and the verifying side. The
/// Ed25519 check therefore passes over method, path and nothing else, and any
/// body at all rides in underneath it. Every downstream check the write path
/// already had — owner, state, context, the four size bounds — passes too,
/// because none of them looks at whether the signature reaches the body.
///
/// If it wrote, the row would carry a valid signature, a signing string that
/// verifies under the owner's key, and a `request_body` that signing string
/// says nothing about: provenance that cannot be re-verified, which is the one
/// thing a claim is for. `re_verify` below is the procedure that would refuse
/// it after the fact; this is the same predicate applied before the insert.
///
/// The control at the end is what keeps the test honest: the same owner, repo,
/// commit and body, signed the ordinary way with the header present, writes.
#[sqlx::test]
async fn a_signature_over_an_empty_content_digest_cannot_write_a_claim(pool: PgPool) {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use gitlawb_core::http_sig::{build_signing_string, COVERED_COMPONENTS};

    let state = test_state(pool.clone()).await;
    let kp = gitlawb_core::identity::Keypair::generate();
    let did = kp.did().to_string();
    let repo = seed_repo(&did, "empty-digest-repo", true);
    let repo_id = repo.id.clone();
    state.db.create_repo(&repo).await.unwrap();

    let path = uri(&did, "empty-digest-repo", SHA_A);
    let created = chrono::Utc::now().timestamp();
    let signature_input = format!(
        r#"sig1=("@method" "@path" "content-digest");keyid="{did}";alg="ed25519";created={created}"#
    );
    let sig_params_value = signature_input
        .strip_prefix("sig1=")
        .expect("the header is built with the prefix");

    // Exactly the values the middleware derives when the header is absent.
    let mut values: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    values.insert("@method".into(), "POST".into());
    values.insert("@path".into(), path.clone());
    values.insert("content-digest".into(), String::new());
    let signing_string =
        build_signing_string(COVERED_COMPONENTS, sig_params_value, &values).unwrap();
    let signature = format!(
        "sig1=:{}:",
        STANDARD.encode(kp.sign(signing_string.as_bytes()).to_bytes())
    );

    // A body no signature covers, and no Content-Digest header to bind it.
    let smuggled = br#"{"state":"success","context":"ci/build"}"#;
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(&path)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header("signature-input", signature_input)
        .header("signature", signature)
        .body(Body::from(smuggled.to_vec()))
        .unwrap();
    let resp = crate::server::build_router(state.clone())
        .oneshot(req)
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "a signature that covers no digest of this body must not be accepted as provenance"
    );
    assert!(
        state
            .db
            .list_status_claims(&repo_id, SHA_A)
            .await
            .unwrap()
            .is_empty(),
        "a claim whose signature does not reach its body must never be stored"
    );

    // The control: the identical write, signed the ordinary way, is accepted —
    // so what refuses above is the missing binding and not the request shape.
    let (ok, _) = post_really_signed(&state, &kp, &path, smuggled).await;
    assert_eq!(ok.status(), StatusCode::CREATED);
    let claims = state.db.list_status_claims(&repo_id, SHA_A).await.unwrap();
    assert_eq!(claims.len(), 1);
    re_verify(&claims[0]).expect("the accepted claim must re-verify from the row alone");
}

/// Re-verify a stored claim from the row alone, the way a third party
/// adopting this history would have to:
///
///   1. the row's own fields are the ones the stored body carries,
///   2. the digest of the stored body is the one the signing string covers,
///   3. the stored signature verifies over that signing string under the
///      producer's key.
///
/// Returns the first broken link rather than panicking, so the negative case
/// can drive the same procedure and observe it refuse.
fn re_verify(claim: &crate::db::StatusClaim) -> std::result::Result<(), String> {
    let body: serde_json::Value = serde_json::from_slice(&claim.request_body)
        .map_err(|e| format!("stored body is not json: {e}"))?;
    if body["state"] != claim.state.as_str() {
        return Err(format!(
            "row state {:?} is not the state the signed body carries ({:?})",
            claim.state, body["state"]
        ));
    }
    if body["context"] != claim.context.as_str() {
        return Err(format!(
            "row context {:?} is not the context the signed body carries ({:?})",
            claim.context, body["context"]
        ));
    }

    let digest = gitlawb_core::http_sig::compute_content_digest(&claim.request_body);
    let covered = format!("\"content-digest\": {digest}");
    if !claim.signing_string.contains(&covered) {
        return Err(format!(
            "the signing string does not cover the stored body's digest ({covered})"
        ));
    }

    let did: gitlawb_core::did::Did = claim
        .producer_did
        .parse()
        .map_err(|e| format!("producer did does not parse: {e}"))?;
    let key = did
        .to_verifying_key()
        .map_err(|e| format!("producer did does not resolve to a key: {e}"))?;
    let parsed =
        gitlawb_core::http_sig::HttpSignature::parse(&claim.signature_input, &claim.signature)
            .map_err(|e| format!("stored signature headers do not parse: {e}"))?;
    let bytes: [u8; 64] = parsed
        .signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "stored signature is not 64 bytes".to_string())?;
    gitlawb_core::identity::verify(&key, claim.signing_string.as_bytes(), &bytes)
        .map_err(|e| format!("signature does not verify over the stored signing string: {e}"))
}

/// The stored row is re-verifiable end to end, and the chain closes: mutating
/// the row's `state` after the fact breaks it.
///
/// This is the property the whole write path exists for. Storing only the
/// signing string would pass the signature check and still leave step 1 and 2
/// unanswerable, because the signing string covers the body only through a
/// digest of bytes nobody kept.
#[sqlx::test]
async fn stored_claim_re_verifies_and_a_tampered_row_does_not(pool: PgPool) {
    let state = test_state(pool.clone()).await;
    let kp = gitlawb_core::identity::Keypair::generate();
    let did = kp.did().to_string();
    let repo = seed_repo(&did, "verify-repo", true);
    let repo_id = repo.id.clone();
    state.db.create_repo(&repo).await.unwrap();

    let path = uri(&did, "verify-repo", SHA_A);
    let body = br#"{"state":"success","context":"ci/build"}"#;
    let (resp, _) = post_really_signed(&state, &kp, &path, body).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let claims = state.db.list_status_claims(&repo_id, SHA_A).await.unwrap();
    assert_eq!(claims.len(), 1);
    re_verify(&claims[0]).expect("a stored claim must be re-verifiable from the row alone");

    // The negative: change the claim's verdict in place. Nothing about the
    // signature material changes, so this passes unless the stored body is
    // what ties the row to the signature.
    sqlx::query("UPDATE status_claims SET state='failure' WHERE id=$1")
        .bind(&claims[0].id)
        .execute(&pool)
        .await
        .unwrap();

    let tampered = state.db.list_status_claims(&repo_id, SHA_A).await.unwrap();
    assert_eq!(tampered[0].state, "failure");
    let err = re_verify(&tampered[0])
        .expect_err("a row whose state no longer matches the signed body must not re-verify");
    assert!(
        err.contains("row state"),
        "the mutated verdict must be what refuses, got: {err}"
    );
}

/// What `require_signature` puts in the extension is what the client sent,
/// field for field.
///
/// Every other 201-path test injects the material by hand onto a bare router,
/// so a middleware that swapped, truncated or corrupted these fields would
/// leave all of them green. This drives the real router and compares the
/// persisted row against the headers that went on the wire.
#[sqlx::test]
async fn middleware_persists_the_material_the_client_actually_sent(pool: PgPool) {
    use gitlawb_core::http_sig::{build_signing_string, COVERED_COMPONENTS};

    let state = test_state(pool).await;
    let kp = gitlawb_core::identity::Keypair::generate();
    let did = kp.did().to_string();
    let repo = seed_repo(&did, "material-wire-repo", true);
    let repo_id = repo.id.clone();
    state.db.create_repo(&repo).await.unwrap();

    let path = uri(&did, "material-wire-repo", SHA_A);
    let body = br#"{"state":"pending","context":"ci/wire","description":"in flight"}"#;
    let (resp, signed) = post_really_signed(&state, &kp, &path, body).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let claims = state.db.list_status_claims(&repo_id, SHA_A).await.unwrap();
    assert_eq!(claims.len(), 1);
    let claim = &claims[0];

    assert_eq!(
        claim.signature, signed.signature,
        "the stored Signature is the header the client sent"
    );
    assert_eq!(
        claim.signature_input, signed.signature_input,
        "the stored Signature-Input is the header the client sent"
    );
    assert_eq!(
        claim.request_body,
        body.to_vec(),
        "the stored body is the request body, whole and unaltered"
    );

    // The signing string the node verified must be the one the client signed,
    // rebuilt here independently rather than read back from the row.
    let mut values = std::collections::HashMap::new();
    values.insert("@method".to_string(), "POST".to_string());
    values.insert("@path".to_string(), path.clone());
    values.insert("content-digest".to_string(), signed.content_digest.clone());
    let expected = build_signing_string(
        COVERED_COMPONENTS,
        signed.signature_input.strip_prefix("sig1=").unwrap(),
        &values,
    )
    .unwrap();
    assert_eq!(
        claim.signing_string, expected,
        "the stored signing string is the canonical string the client signed"
    );

    assert_eq!(claim.producer_did, did);
    assert_eq!(claim.state, "pending");
    assert_eq!(claim.context, "ci/wire");
}

/// The status write route shows the persist marker to the signature
/// middleware, so the body is captured on the one route that stores it.
///
/// The marker is an extension layer on the status write group and the
/// middleware reads it when it decides whether to carry the body. That only
/// works if the marker layer is the OUTER of the two, and axum's layer order
/// is a property of how `build_router` is written, not something the type
/// system checks. Reordering the group, or dropping the layer, leaves a
/// handler that still passes every test driving a hand-built material onto a
/// bare router and stores nothing in production. This drives the real router.
#[sqlx::test]
async fn the_status_route_shows_the_persist_marker_to_the_signature_middleware(pool: PgPool) {
    let state = test_state(pool).await;
    let kp = gitlawb_core::identity::Keypair::generate();
    let did = kp.did().to_string();
    let repo = seed_repo(&did, "marker-order-repo", true);
    let repo_id = repo.id.clone();
    state.db.create_repo(&repo).await.unwrap();

    let path = uri(&did, "marker-order-repo", SHA_A);
    let body = br#"{"state":"success","context":"ci/marker"}"#;
    let (resp, _) = post_really_signed(&state, &kp, &path, body).await;
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "the status route must reach the signature middleware with the persist \
         marker already applied; a marker layer inside the auth layers is never seen"
    );

    let claims = state.db.list_status_claims(&repo_id, SHA_A).await.unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(
        claims[0].request_body,
        body.to_vec(),
        "the persist marker must make the middleware carry the body through to the row"
    );
}

/// A captured signed write, put on the wire a second time, returns the claim
/// it already recorded instead of appending a new one.
///
/// `require_signature` bounds only the clock skew on `created`, so the same
/// bytes are accepted again for as long as that window lasts. The row count is
/// asserted directly: a response that merely LOOKS right while a second row
/// landed is the failure this is written against.
#[sqlx::test]
async fn a_replayed_signed_write_returns_the_original_claim_and_writes_no_second_row(pool: PgPool) {
    let state = test_state(pool).await;
    let kp = gitlawb_core::identity::Keypair::generate();
    let did = kp.did().to_string();
    let repo = seed_repo(&did, "replay-repo", true);
    let repo_id = repo.id.clone();
    state.db.create_repo(&repo).await.unwrap();

    let path = uri(&did, "replay-repo", SHA_A);
    let body = br#"{"state":"success","context":"ci/build"}"#;

    let (first, signed) = post_really_signed(&state, &kp, &path, body).await;
    assert_eq!(first.status(), StatusCode::CREATED);
    let first_body = body_json(first).await;

    let replay = post_signed_headers(&state, &path, body, &signed).await;
    assert_eq!(
        replay.status(),
        StatusCode::OK,
        "an exact replay is already recorded, not newly created"
    );
    let replay_body = body_json(replay).await;
    assert_eq!(
        replay_body, first_body,
        "the replay must answer with the claim the first request wrote, id and \
         seq included"
    );

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM status_claims WHERE repo_id = $1")
        .bind(&repo_id)
        .fetch_one(state.db.pool())
        .await
        .unwrap();
    assert_eq!(
        rows, 1,
        "a replayed request must leave exactly one row; got {rows}"
    );
}

/// The consequence the replay actually buys an attacker: resurrecting a
/// superseded verdict.
///
/// The projection takes the latest claim per (producer, context) by `seq`, and
/// `seq` is assigned at insert. So a replay does not merely duplicate a row.
/// It earns a FRESH sequence number, which puts the stale `success` ahead of
/// the `failure` that superseded it and flips the commit's answer back.
#[sqlx::test]
async fn a_replayed_success_cannot_overturn_the_later_failure(pool: PgPool) {
    let state = test_state(pool).await;
    let kp = gitlawb_core::identity::Keypair::generate();
    let did = kp.did().to_string();
    let repo = seed_repo(&did, "replay-order-repo", true);
    state.db.create_repo(&repo).await.unwrap();

    let path = uri(&did, "replay-order-repo", SHA_A);
    let success = br#"{"state":"success","context":"ci/build"}"#;
    let failure = br#"{"state":"failure","context":"ci/build"}"#;

    let (resp, captured) = post_really_signed(&state, &kp, &path, success).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let (resp, _) = post_really_signed(&state, &kp, &path, failure).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let read = status_uri(&did, "replay-order-repo", SHA_A);
    let before = body_json(get_status(&state, Some(&did), &read).await).await;
    assert_eq!(before["state"], "failure", "the later claim is the verdict");

    // The capture, replayed inside the skew window. Accepted either way: which
    // status it carries is the previous test's business, and this one is about
    // what the commit reads afterwards.
    let replay = post_signed_headers(&state, &path, success, &captured).await;
    assert!(replay.status().is_success());

    let after = body_json(get_status(&state, Some(&did), &read).await).await;
    assert_eq!(
        after["state"], "failure",
        "a replayed success must not outrank the failure that superseded it"
    );
    assert_eq!(after["total_count"], 1);
    assert_eq!(after["statuses"][0]["state"], "failure");
}

/// The idempotency key is the request, not the tuple it writes about. Two
/// genuinely different signed requests for one producer and context both
/// record, and the append-only history keeps both.
#[sqlx::test]
async fn two_distinct_signed_writes_for_one_context_both_record(pool: PgPool) {
    let state = test_state(pool).await;
    let kp = gitlawb_core::identity::Keypair::generate();
    let did = kp.did().to_string();
    let repo = seed_repo(&did, "distinct-repo", true);
    let repo_id = repo.id.clone();
    state.db.create_repo(&repo).await.unwrap();

    let path = uri(&did, "distinct-repo", SHA_A);
    for body in [
        &br#"{"state":"pending","context":"ci/build"}"#[..],
        &br#"{"state":"success","context":"ci/build"}"#[..],
    ] {
        let (resp, _) = post_really_signed(&state, &kp, &path, body).await;
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "a distinct request is a new claim, not a replay"
        );
    }

    let claims = state.db.list_status_claims(&repo_id, SHA_A).await.unwrap();
    let states: Vec<&str> = claims.iter().map(|c| c.state.as_str()).collect();
    assert_eq!(
        states,
        vec!["pending", "success"],
        "both distinct claims must remain, ordered by seq"
    );
}

/// The route is registered on the production router AND its group reached the
/// merge chain: an unsigned request is refused by the signature layer with 401,
/// which a path axum never learned about would answer 404 instead.
#[sqlx::test]
async fn route_is_registered_behind_the_signature_layer(pool: PgPool) {
    let state = test_state(pool).await;
    let router = crate::server::build_router(state);
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(uri(OWNER, "any-repo", SHA_A))
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(body_of("success", "ci/build"))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "the status write route must exist and sit behind require_signature"
    );
}

// ── Read path (U4) ────────────────────────────────────────────────────

const NEW_OWNER: &str = "did:key:zSTATUSNEWOWNERCCCCCCCCCCCCCCCCCCCCCC";

fn read_router(state: crate::state::AppState) -> Router {
    Router::new()
        .route(
            "/api/v1/repos/{owner}/{repo}/commits/{sha}/status",
            axum::routing::get(super::commit_status),
        )
        .with_state(state)
}

fn status_uri(owner: &str, repo: &str, sha: &str) -> String {
    format!("/api/v1/repos/{owner}/{repo}/commits/{sha}/status")
}

/// GET the read surface as `did`, or anonymously when it is `None` (no
/// `AuthenticatedDid` extension at all, which is what an unsigned caller
/// looks like once `optional_signature` has passed it through).
async fn get_status(
    state: &crate::state::AppState,
    did: Option<&str>,
    uri: &str,
) -> axum::response::Response {
    let req = match did {
        Some(d) => signed_request_as(d, Method::GET, uri, Body::empty()),
        None => axum::http::Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .unwrap(),
    };
    read_router(state.clone()).oneshot(req).await.unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).expect("response body must be json")
}

/// One claim row with every field chosen by the caller, including the
/// authorizing DID and the display timestamp, so the projection's ordering
/// key and its current-authorization filter can both be driven directly.
#[allow(clippy::too_many_arguments)]
async fn seed_claim(
    pool: &PgPool,
    id: &str,
    repo_id: &str,
    sha: &str,
    producer: &str,
    authorizing: &str,
    context: &str,
    claim_state: &str,
    created_at: &str,
) {
    sqlx::query(
        "INSERT INTO status_claims
             (id, repo_id, commit_sha, state, context, producer_did, authorizing_did,
              signature, signature_input, signing_string, request_body, request_digest,
              created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,'','','',''::bytea,gen_random_uuid()::text,$8)",
    )
    .bind(id)
    .bind(repo_id)
    .bind(sha)
    .bind(claim_state)
    .bind(context)
    .bind(producer)
    .bind(authorizing)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("seed claim");
}

/// Covers AE1. A context reported pending then success reads as success with
/// exactly one entry: the projection takes the LATEST claim per (producer,
/// context), not every row in the history.
#[sqlx::test]
async fn ae1_latest_claim_per_context_reads_as_success(pool: PgPool) {
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "read-ae1", true);
    state.db.create_repo(&repo).await.unwrap();

    for st in ["pending", "success"] {
        let resp = post_as(
            &state,
            OWNER,
            &uri(OWNER, "read-ae1", SHA_A),
            body_of(st, "ci/build"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED, "{st} claim");
    }

    let resp = get_status(&state, Some(OWNER), &status_uri(OWNER, "read-ae1", SHA_A)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["state"], "success");
    assert_eq!(body["total_count"], 1);
    assert_eq!(body["statuses"].as_array().unwrap().len(), 1);
    assert_eq!(body["statuses"][0]["state"], "success");
    assert_eq!(body["statuses"][0]["context"], "ci/build");
    assert_eq!(body["statuses"][0]["producer_did"], OWNER);
    assert_eq!(
        body["reported_only"], true,
        "R19: the response marks that the state covers reported contexts only"
    );
}

/// The latest claim for a context is the highest server-assigned `seq`
/// (KTD-3), never the newest timestamp and never the largest row id. The two
/// rows are seeded so every other candidate key picks the LOSING row: the
/// earlier claim carries a far-future `created_at` and a lexically larger
/// uuid than the later one.
#[sqlx::test]
async fn latest_claim_is_highest_seq_not_newest_timestamp_or_id(pool: PgPool) {
    let state = test_state(pool.clone()).await;
    let repo = seed_repo(OWNER, "read-order", true);
    state.db.create_repo(&repo).await.unwrap();

    seed_claim(
        &pool,
        "zzzzzzzz-0000-0000-0000-000000000001",
        &repo.id,
        SHA_A,
        OWNER,
        OWNER,
        "ci/build",
        "pending",
        "2099-01-01T00:00:00Z",
    )
    .await;
    seed_claim(
        &pool,
        "aaaaaaaa-0000-0000-0000-000000000002",
        &repo.id,
        SHA_A,
        OWNER,
        OWNER,
        "ci/build",
        "success",
        "2000-01-01T00:00:00Z",
    )
    .await;

    let resp = get_status(&state, Some(OWNER), &status_uri(OWNER, "read-order", SHA_A)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(
        body["state"], "success",
        "the highest-seq claim wins; ordering on created_at or on the row id \
             would elect the stale pending claim"
    );
    assert_eq!(body["total_count"], 1);
}

/// Covers AE2. Two producers, two contexts, one success and one failure: the
/// combined state is failure and BOTH entries are present.
#[sqlx::test]
async fn ae2_two_producers_one_failure_reads_as_failure(pool: PgPool) {
    let state = test_state(pool.clone()).await;
    let repo = seed_repo(OWNER, "read-ae2", true);
    state.db.create_repo(&repo).await.unwrap();

    let resp = post_as(
        &state,
        OWNER,
        &uri(OWNER, "read-ae2", SHA_A),
        body_of("success", "ci/build"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    // A second producer, authorized by the same owner key.
    seed_claim(
        &pool,
        "11111111-0000-0000-0000-000000000001",
        &repo.id,
        SHA_A,
        STRANGER,
        OWNER,
        "ci/test",
        "failure",
        "2026-01-01T00:00:00Z",
    )
    .await;

    let resp = get_status(&state, Some(OWNER), &status_uri(OWNER, "read-ae2", SHA_A)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["state"], "failure");
    assert_eq!(body["total_count"], 2);
    let contexts: Vec<&str> = body["statuses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["context"].as_str().unwrap())
        .collect();
    assert!(contexts.contains(&"ci/build"), "contexts: {contexts:?}");
    assert!(contexts.contains(&"ci/test"), "contexts: {contexts:?}");
}

/// An error-state claim folds to the combined failure state (the error arm of
/// KTD-1, distinct from the failure arm the AE2 case covers).
#[sqlx::test]
async fn error_claim_folds_to_combined_failure(pool: PgPool) {
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "read-error", true);
    state.db.create_repo(&repo).await.unwrap();

    for (st, ctx) in [("success", "ci/build"), ("error", "ci/test")] {
        let resp = post_as(
            &state,
            OWNER,
            &uri(OWNER, "read-error", SHA_A),
            body_of(st, ctx),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED, "{st} claim");
    }

    let body =
        body_json(get_status(&state, Some(OWNER), &status_uri(OWNER, "read-error", SHA_A)).await)
            .await;
    assert_eq!(
        body["state"], "failure",
        "an error claim must fold to failure, never to success or pending"
    );
}

/// A pending claim alongside a success yields the combined pending state (the
/// middle arm of KTD-1).
#[sqlx::test]
async fn pending_alongside_success_reads_as_pending(pool: PgPool) {
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "read-pending", true);
    state.db.create_repo(&repo).await.unwrap();

    for (st, ctx) in [("success", "ci/build"), ("pending", "ci/test")] {
        let resp = post_as(
            &state,
            OWNER,
            &uri(OWNER, "read-pending", SHA_A),
            body_of(st, ctx),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED, "{st} claim");
    }

    let body = body_json(
        get_status(
            &state,
            Some(OWNER),
            &status_uri(OWNER, "read-pending", SHA_A),
        )
        .await,
    )
    .await;
    assert_eq!(body["state"], "pending");
    assert_eq!(body["total_count"], 2);
}

/// Covers AE3. A commit nobody reported on is exactly 200 with the pending
/// zero-count body. The WHOLE body is asserted, not just the status: a client
/// that renders this must not be able to arrive at green through a missing
/// field, an empty object, or a success state with an empty array.
#[sqlx::test]
async fn ae3_commit_with_no_claims_is_pending_zero(pool: PgPool) {
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "read-ae3", true);
    state.db.create_repo(&repo).await.unwrap();

    let resp = get_status(&state, Some(OWNER), &status_uri(OWNER, "read-ae3", SHA_A)).await;
    let (status, bytes) = status_and_bytes(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        format!(
            r#"{{"state":"pending","sha":"{SHA_A}","total_count":0,"statuses":[],"reported_only":true}}"#
        ),
        "absence must serialize as the explicit pending zero-count body"
    );
}

/// Covers AE4. An anonymous read of a PRIVATE repo that HAS a claim answers
/// byte for byte what the same caller gets for a repo that does not exist.
/// The claim is seeded first, so the deny cannot pass vacuously on an empty
/// projection.
#[sqlx::test]
async fn ae4_anon_private_repo_read_is_indistinguishable_from_missing(pool: PgPool) {
    let state = test_state(pool.clone()).await;
    let target = status_uri(OWNER, "read-ae4", SHA_A);

    let missing = status_and_bytes(get_status(&state, None, &target).await).await;

    let repo = seed_repo(OWNER, "read-ae4", false);
    state.db.create_repo(&repo).await.unwrap();
    seed_claim(
        &pool,
        "22222222-0000-0000-0000-000000000001",
        &repo.id,
        SHA_A,
        OWNER,
        OWNER,
        "ci/build",
        "success",
        "2026-01-01T00:00:00Z",
    )
    .await;

    let denied = status_and_bytes(get_status(&state, None, &target).await).await;

    assert_eq!(missing.0, StatusCode::NOT_FOUND);
    assert_eq!(
        denied, missing,
        "a private-repo deny must be byte-identical to the missing-repo response"
    );
    assert!(
        !String::from_utf8_lossy(&denied.1).contains("ci/build"),
        "the deny must carry no trace of the claim"
    );
}

/// The other half of the visibility pair: a PUBLIC repo's status is served to
/// an anonymous caller, so the gate above is a gate and not a blanket refusal.
#[sqlx::test]
async fn public_repo_status_served_to_anon(pool: PgPool) {
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "read-public", true);
    state.db.create_repo(&repo).await.unwrap();
    let resp = post_as(
        &state,
        OWNER,
        &uri(OWNER, "read-public", SHA_A),
        body_of("success", "ci/build"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = get_status(&state, None, &status_uri(OWNER, "read-public", SHA_A)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["state"], "success");
    assert_eq!(body["statuses"][0]["context"], "ci/build");
}

/// KTD-2 regression: the projection is computed per read, so tightening
/// visibility AFTER a claim was written retroactively hides it. A write-time
/// gated derived index kept serving a repo made private afterwards
/// (docs/solutions/security-issues/write-time-visibility-gate-leaves-derived-index-stale.md);
/// this is that shape on the status surface.
#[sqlx::test]
async fn tightening_visibility_hides_existing_claims_from_anon(pool: PgPool) {
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "read-tighten", true);
    state.db.create_repo(&repo).await.unwrap();
    let resp = post_as(
        &state,
        OWNER,
        &uri(OWNER, "read-tighten", SHA_A),
        body_of("success", "ci/secret-build"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let target = status_uri(OWNER, "read-tighten", SHA_A);
    let served = get_status(&state, None, &target).await;
    assert_eq!(
        served.status(),
        StatusCode::OK,
        "the claim is anonymously readable while the repo is public"
    );

    // Tighten: a root rule with an empty reader list denies everyone but the
    // owner, even though the repo row is still is_public.
    state
        .db
        .set_visibility_rule(&repo.id, "/", crate::db::VisibilityMode::B, &[], OWNER)
        .await
        .unwrap();

    let (status, bytes) = status_and_bytes(get_status(&state, None, &target).await).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a claim written while public must stop being served once visibility tightens"
    );
    assert!(
        !String::from_utf8_lossy(&bytes).contains("ci/secret-build"),
        "the deny must carry no trace of the claim"
    );
}

/// KTD-5: the projection filters on CURRENT authorization. After the repo
/// changes hands, the previous owner's claims drop out of the read, while the
/// append-only history keeps every row.
#[sqlx::test]
async fn claims_authorized_by_a_former_owner_leave_the_projection(pool: PgPool) {
    let state = test_state(pool.clone()).await;
    let repo = seed_repo(OWNER, "read-transfer", true);
    let repo_id = repo.id.clone();
    state.db.create_repo(&repo).await.unwrap();
    let resp = post_as(
        &state,
        OWNER,
        &uri(OWNER, "read-transfer", SHA_A),
        body_of("success", "ci/build"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    sqlx::query("UPDATE repos SET owner_did = $1 WHERE id = $2")
        .bind(NEW_OWNER)
        .bind(&repo_id)
        .execute(&pool)
        .await
        .expect("transfer the repo");

    let resp = get_status(
        &state,
        Some(NEW_OWNER),
        &status_uri(NEW_OWNER, "read-transfer", SHA_A),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(
        body["state"], "pending",
        "a claim the current owner never authorized must not decide the state"
    );
    assert_eq!(body["total_count"], 0);
    assert!(body["statuses"].as_array().unwrap().is_empty());

    assert_eq!(
        state
            .db
            .list_status_claims(&repo_id, SHA_A)
            .await
            .unwrap()
            .len(),
        1,
        "the history row survives the transfer; only the projection drops it"
    );
}

/// The current-authorization filter accepts the owner DID in either
/// representation, matching `did_matches`: a repo whose stored owner is the
/// BARE key still projects claims authorized under the full `did:key:` form.
#[sqlx::test]
async fn projection_matches_the_owner_in_either_did_form(pool: PgPool) {
    let state = test_state(pool).await;
    let bare = OWNER.strip_prefix("did:key:").unwrap();
    let repo = seed_repo(bare, "read-didform", true);
    state.db.create_repo(&repo).await.unwrap();
    let resp = post_as(
        &state,
        OWNER,
        &uri(OWNER, "read-didform", SHA_A),
        body_of("success", "ci/build"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body = body_json(
        get_status(
            &state,
            Some(OWNER),
            &status_uri(OWNER, "read-didform", SHA_A),
        )
        .await,
    )
    .await;
    assert_eq!(body["state"], "success");
    assert_eq!(body["total_count"], 1);
}

/// One identity spelled two ways is one producer. The owner reports the same
/// context first as `did:key:X` and then as the bare `X` — both pass the owner
/// gate, which normalizes — so the stored producer DID has to be normalized
/// too. Without that the projection's dedupe compares raw strings, leaves two
/// entries for one context, and the superseded claim keeps voting in the
/// combined state.
#[sqlx::test]
async fn one_identity_in_two_did_forms_projects_as_one_entry(pool: PgPool) {
    let state = test_state(pool).await;
    let bare = OWNER.strip_prefix("did:key:").unwrap();
    let repo = seed_repo(OWNER, "read-diddedupe", true);
    state.db.create_repo(&repo).await.unwrap();

    for (did, claim_state) in [(OWNER, "failure"), (bare, "success")] {
        let resp = post_as(
            &state,
            did,
            &uri(OWNER, "read-diddedupe", SHA_A),
            body_of(claim_state, "ci/build"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED, "claim as {did}");
    }

    let body = body_json(
        get_status(
            &state,
            Some(OWNER),
            &status_uri(OWNER, "read-diddedupe", SHA_A),
        )
        .await,
    )
    .await;
    assert_eq!(
        body["total_count"], 1,
        "the two spellings are one producer reporting one context"
    );
    assert_eq!(body["statuses"].as_array().unwrap().len(), 1);
    assert_eq!(
        body["state"], "success",
        "the newer claim supersedes the older one; a stale failure must not \
             keep voting because it was written under the other spelling"
    );
}

/// The lookup-failure path. With the claims table gone, the read is exactly
/// 500 carrying the stable `db_error` code — never a 200, and never an empty
/// statuses array. The message is the sqlx text and is not asserted; a
/// connectivity failure would take the separate 503 arm instead.
#[sqlx::test]
async fn claim_lookup_failure_is_500_never_empty_success(pool: PgPool) {
    let state = test_state(pool.clone()).await;
    let repo = seed_repo(OWNER, "read-dberr", true);
    state.db.create_repo(&repo).await.unwrap();
    let resp = post_as(
        &state,
        OWNER,
        &uri(OWNER, "read-dberr", SHA_A),
        body_of("success", "ci/build"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    sqlx::query("DROP TABLE status_claims")
        .execute(&pool)
        .await
        .expect("drop the claims table");

    let resp = get_status(&state, Some(OWNER), &status_uri(OWNER, "read-dberr", SHA_A)).await;
    let (status, bytes) = status_and_bytes(resp).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a failed projection query must not render as a served status"
    );
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"], "db_error");
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        !text.contains("statuses"),
        "an error must not carry an empty statuses array: {text}"
    );
}

/// The read route is registered on the production router AND its group kept
/// the `optional_signature` layer. A path axum never learned about answers
/// 404 for the anonymous case; a group missing the layer would ignore the
/// signature headers in the second case and serve 200 instead of 401.
#[sqlx::test]
async fn read_route_is_registered_with_optional_signature(pool: PgPool) {
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "read-wired", true);
    state.db.create_repo(&repo).await.unwrap();
    let target = status_uri(OWNER, "read-wired", SHA_A);

    let resp = crate::server::build_router(state.clone())
        .oneshot(
            axum::http::Request::builder()
                .method(Method::GET)
                .uri(&target)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the read route must exist on the production router and serve a public repo to anon"
    );

    let resp = crate::server::build_router(state)
        .oneshot(
            axum::http::Request::builder()
                .method(Method::GET)
                .uri(&target)
                .header("signature", "sig1=:bm90YXNpZw==:")
                .header("signature-input", "sig1=(\"@method\");alg=\"ed25519\"")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, bytes) = status_and_bytes(resp).await;
    // A presented signature is verified, and this one is unusable (no keyid,
    // required components missing), so the signature layer refuses it. Only
    // the layer can produce this: the same request against a group without it
    // is treated as anonymous and served 200 by the handler above.
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a presented signature must be verified, which only happens if the \
             read group still carries optional_signature"
    );
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        body["error"], "invalid_signature",
        "the refusal must come from the signature layer, not the handler"
    );
}

/// The `did:key` collapse is a security predicate, and it has exactly one
/// definition: `db::normalize_owner_key`, which the owner gate (`did_matches`)
/// and the projection's stored identity both go through. A second copy in this
/// module is how the two drift apart, one of them lagging a hardening, so the
/// production half is scanned for one.
#[test]
fn status_module_holds_no_second_copy_of_the_did_collapse() {
    let src = include_str!("mod.rs");
    let body_of_module =
        crate::test_support::scrape_source_region(src, None, Some("\n#[cfg(test)]\nmod tests;"))
            .expect("module has a tests module");
    assert!(
        body_of_module.contains("project_claims"),
        "the scan must cover the whole production half of the module"
    );
    assert!(
        !body_of_module.contains("did:key:"),
        "this module must not reimplement the did:key collapse — the \
             projection's identity comparison goes through db::normalize_owner_key"
    );
}

/// The must-not case the collapse exists to preserve: a bare base58 id must
/// never match across DID methods. A claim authorized by `did:gitlawb:X` is
/// not authorized by the owner `did:key:X`, so it stays out of the projection.
#[sqlx::test]
async fn a_cross_method_authorizing_did_never_projects(pool: PgPool) {
    let state = test_state(pool.clone()).await;
    let key_id = OWNER.strip_prefix("did:key:").unwrap();
    let repo = seed_repo(OWNER, "read-crossmethod", true);
    state.db.create_repo(&repo).await.unwrap();

    seed_claim(
        &pool,
        "cccccccc-0000-0000-0000-000000000001",
        &repo.id,
        SHA_A,
        &format!("did:gitlawb:{key_id}"),
        &format!("did:gitlawb:{key_id}"),
        "ci/build",
        "success",
        "2026-01-01T00:00:00Z",
    )
    .await;

    let body = body_json(
        get_status(
            &state,
            Some(OWNER),
            &status_uri(OWNER, "read-crossmethod", SHA_A),
        )
        .await,
    )
    .await;
    assert_eq!(
        body["total_count"], 0,
        "did:gitlawb:X and did:key:X share the base58 space and are different \
             identities; the projection must not treat one as the other"
    );
    assert_eq!(body["state"], "pending");
}

/// `n` claims on one (repo, commit, producer, context) tuple, inserted in one
/// statement so the cap tests stay fast.
async fn seed_claims(
    pool: &PgPool,
    repo_id: &str,
    sha: &str,
    producer: &str,
    context: &str,
    n: i64,
) {
    sqlx::query(
        "INSERT INTO status_claims
             (id, repo_id, commit_sha, state, context, producer_did, authorizing_did,
              signature, signature_input, signing_string, request_body, request_digest,
              created_at)
             SELECT md5(random()::text || g::text), $1, $2, 'success', $3, $4, $4,
                    '', '', '', ''::bytea, gen_random_uuid()::text,
                    '2026-01-01T00:00:00Z'
             FROM generate_series(1, $5) g",
    )
    .bind(repo_id)
    .bind(sha)
    .bind(context)
    .bind(producer)
    .bind(n)
    .execute(pool)
    .await
    .expect("seed claims");
}

/// `n` claims on one repo spread across `n` distinct 40-hex SHAs, one claim
/// each, so no tuple or context cap is reached before the per-repo one. The
/// timestamp is explicit because the per-repo bound is a rolling window: it
/// decides whether these rows are inside it.
async fn seed_claims_across_shas(
    pool: &PgPool,
    repo_id: &str,
    producer: &str,
    n: i64,
    created_at: &str,
) {
    sqlx::query(
        "INSERT INTO status_claims
             (id, repo_id, commit_sha, state, context, producer_did, authorizing_did,
              signature, signature_input, signing_string, request_body, request_digest,
              created_at)
             SELECT md5(random()::text || g::text), $1,
                    substr(md5(g::text) || md5((g + 1)::text), 1, 40),
                    'success', 'ci/build', $2, $2,
                    '', '', '', ''::bytea, gen_random_uuid()::text, $4
             FROM generate_series(1, $3) g",
    )
    .bind(repo_id)
    .bind(producer)
    .bind(n)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("seed claims across shas");
}

// ── Pull request rollup (U5) ──────────────────────────────────────────

fn rollup_router(state: crate::state::AppState) -> Router {
    Router::new()
        .route(
            "/api/v1/repos/{owner}/{repo}/pulls/{number}/status",
            axum::routing::get(super::pull_request_status),
        )
        .with_state(state)
}

fn rollup_uri(owner: &str, repo: &str, number: i64) -> String {
    format!("/api/v1/repos/{owner}/{repo}/pulls/{number}/status")
}

async fn get_rollup(
    state: &crate::state::AppState,
    did: Option<&str>,
    uri: &str,
) -> axum::response::Response {
    let req = match did {
        Some(d) => signed_request_as(d, Method::GET, uri, Body::empty()),
        None => axum::http::Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .unwrap(),
    };
    rollup_router(state.clone()).oneshot(req).await.unwrap()
}

fn seed_pr(repo_id: &str, number: i64, source_branch: &str) -> crate::db::PullRequest {
    let now = chrono::Utc::now().to_rfc3339();
    crate::db::PullRequest {
        id: uuid::Uuid::new_v4().to_string(),
        repo_id: repo_id.to_string(),
        number,
        title: format!("PR {number}"),
        body: None,
        author_did: OWNER.to_string(),
        source_branch: source_branch.to_string(),
        target_branch: "main".to_string(),
        status: "open".to_string(),
        merged_by_did: None,
        merged_at: None,
        head_commit: None,
        created_at: now.clone(),
        updated_at: now,
    }
}

/// Point a branch at a SHA the way the receive-pack path does: one
/// `repo_push_events` row, which is what the rollup's fallback resolves
/// through. Call order is what decides: the fallback reads the highest `seq`,
/// which the database assigns at insert, so a second call to the same branch
/// reads as a later push. The distinct timestamps are only there to keep two
/// fixture rows distinguishable in a failure message; changing them changes
/// nothing about which one wins.
async fn seed_branch_head(
    state: &crate::state::AppState,
    repo: &RepoRecord,
    branch: &str,
    sha: &str,
) {
    static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let created_at = format!("2026-01-01T00:00:00.{n:06}Z");
    seed_push_event(state, repo, branch, sha, &created_at).await;
}

/// One `repo_push_events` row, exactly the shape `record_push_events` writes
/// on the receive-pack path: a FULL ref name and the post-push SHA. The
/// timestamp is a caller-chosen display value, NOT the ordering key: the
/// fallback picks the row with the highest database-assigned `seq`, so the row
/// inserted last wins even if it carries the earlier stamp, and there is no
/// uuid tiebreak. `latest_push_sha_for_ref_follows_insertion_not_the_stamp`
/// pins that. A fixture reordered on the assumption the stamp decides will get
/// a different answer than it expects.
async fn seed_push_event(
    state: &crate::state::AppState,
    repo: &RepoRecord,
    branch: &str,
    sha: &str,
    created_at: &str,
) {
    state
        .db
        .insert_repo_push_event(&crate::db::RepoPushEvent {
            id: uuid::Uuid::new_v4().to_string(),
            // Ignored on insert; the database assigns the ordering key.
            seq: 0,
            repo_id: repo.id.clone(),
            ref_name: format!("refs/heads/{branch}"),
            after_sha: sha.to_string(),
            created_at: created_at.to_string(),
        })
        .await
        .expect("seed push event");
}

const PUSH_T1: &str = "2026-01-01T00:00:00.000000Z";
const PUSH_T2: &str = "2026-01-02T00:00:00.000000Z";

/// Serializes the tests that read [`super::BRANCH_RESOLVES`] and zeroes it, so
/// the counter measures one test's requests rather than whatever else the
/// harness is running in the same process. Held for the test's lifetime.
///
/// Every test that TRIGGERS a resolve takes it too, not only the ones that
/// read the count. The counter is process-global while the databases are
/// per-test, so an unguarded resolver running concurrently inflates a
/// guarded test's count and the failure looks like a bug in the fallback.
/// Async-aware on purpose: the guard is held across the test's awaits, which a
/// blocking `std` mutex must not be.
async fn resolve_count_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let guard = LOCK.lock().await;
    super::BRANCH_RESOLVES.store(0, std::sync::atomic::Ordering::SeqCst);
    guard
}

fn resolve_count() -> usize {
    super::BRANCH_RESOLVES.load(std::sync::atomic::Ordering::SeqCst)
}

/// The four wire states (KTD-1). The rollup never adds a fifth value, whatever
/// happened to the head.
fn assert_wire_state(body: &serde_json::Value) {
    let state = body["state"].as_str().expect("state must be a string");
    assert!(
        ["error", "failure", "pending", "success"].contains(&state),
        "rollup state {state:?} is outside the four-value wire set"
    );
}

/// R3/R11: the rollup is the SAME projection as the commit read. Asserted by
/// comparing the two responses on the head SHA, so the two surfaces cannot
/// drift into two answers.
#[sqlx::test]
async fn rollup_matches_the_commit_read_for_the_stored_head(pool: PgPool) {
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "rollup-same", true);
    state.db.create_repo(&repo).await.unwrap();
    let pr = seed_pr(&repo.id, 1, "feature");
    state.db.create_pr(&pr).await.unwrap();
    state
        .db
        .set_open_pr_heads(&repo.id, "feature", SHA_A)
        .await
        .unwrap();

    for (st, ctx) in [("success", "ci/build"), ("pending", "ci/test")] {
        let resp = post_as(
            &state,
            OWNER,
            &uri(OWNER, "rollup-same", SHA_A),
            body_of(st, ctx),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    let commit =
        body_json(get_status(&state, None, &status_uri(OWNER, "rollup-same", SHA_A)).await).await;
    let rollup =
        body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-same", 1)).await).await;

    assert_eq!(rollup["sha"], SHA_A);
    assert_eq!(rollup["head_resolved"], true);
    assert_eq!(rollup["pull_request_state"], "open");
    assert_eq!(rollup["reported_only"], true);
    assert_eq!(rollup["state"], commit["state"]);
    assert_eq!(rollup["total_count"], commit["total_count"]);
    assert_eq!(
        rollup["statuses"], commit["statuses"],
        "the rollup must serve the commit read's projection unchanged"
    );
}

/// Covers AE2 (rollup half). Two contexts on the head, one failing: the
/// rollup must not read as success.
#[sqlx::test]
async fn ae2_rollup_with_a_failing_context_does_not_read_as_success(pool: PgPool) {
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "rollup-ae2", true);
    state.db.create_repo(&repo).await.unwrap();
    let pr = seed_pr(&repo.id, 1, "feature");
    state.db.create_pr(&pr).await.unwrap();
    state
        .db
        .set_open_pr_heads(&repo.id, "feature", SHA_A)
        .await
        .unwrap();

    for (st, ctx) in [("success", "ci/build"), ("failure", "ci/test")] {
        let resp = post_as(
            &state,
            OWNER,
            &uri(OWNER, "rollup-ae2", SHA_A),
            body_of(st, ctx),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    let body = body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-ae2", 1)).await).await;
    assert_eq!(body["state"], "failure");
    assert_ne!(body["state"], "success");
    assert_eq!(body["total_count"], 2);
}

/// R12's first arm: a resolved head with nothing reported is pending-zero with
/// `head_resolved` TRUE. Pairs with the unresolvable case below, which differs
/// on that boolean alone.
#[sqlx::test]
async fn resolved_head_with_no_claims_is_pending_zero_and_head_resolved(pool: PgPool) {
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "rollup-silent", true);
    state.db.create_repo(&repo).await.unwrap();
    let pr = seed_pr(&repo.id, 1, "feature");
    state.db.create_pr(&pr).await.unwrap();
    state
        .db
        .set_open_pr_heads(&repo.id, "feature", SHA_A)
        .await
        .unwrap();

    let body =
        body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-silent", 1)).await).await;
    assert_wire_state(&body);
    assert_eq!(body["state"], "pending");
    assert_eq!(body["total_count"], 0);
    assert_eq!(body["statuses"].as_array().unwrap().len(), 0);
    assert_eq!(body["head_resolved"], true);
    assert_eq!(body["sha"], SHA_A);
}

/// R17: an open pull request whose source branch is gone has no resolvable
/// head. The answer is pending with zero contexts and `head_resolved` FALSE,
/// which is the ONLY field separating it from the reported-nothing case above.
#[sqlx::test]
async fn unresolvable_head_differs_from_silent_head_on_head_resolved_alone(pool: PgPool) {
    let _counting = resolve_count_guard().await;
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "rollup-gone", true);
    state.db.create_repo(&repo).await.unwrap();
    let pr = seed_pr(&repo.id, 1, "deleted-branch");
    state.db.create_pr(&pr).await.unwrap();

    let body =
        body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-gone", 1)).await).await;
    assert_wire_state(&body);
    assert_eq!(body["state"], "pending");
    assert_eq!(body["total_count"], 0);
    assert_eq!(body["statuses"].as_array().unwrap().len(), 0);
    assert_eq!(
        body["head_resolved"], false,
        "an unresolvable head must report head_resolved false, which is the \
             only field separating it from a resolved head nobody reported on"
    );
    assert!(
        body["sha"].is_null(),
        "an unresolved head must carry no target sha, got {:?}",
        body["sha"]
    );
    assert_eq!(body["pull_request_state"], "open");
    // Nothing was resolvable, so nothing was persisted either.
    assert_eq!(
        state
            .db
            .get_pr(&repo.id, 1)
            .await
            .unwrap()
            .unwrap()
            .head_commit,
        None
    );
}

/// R17's closed arm: a closed pull request with no stored head answers
/// unresolved and does NOT fall back to the branch, even when the branch still
/// has a head. Resolving there would hand a reader a commit the pull request
/// was never decided against.
#[sqlx::test]
async fn closed_pr_with_no_stored_head_does_not_resolve_the_branch(pool: PgPool) {
    let _counting = resolve_count_guard().await;
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "rollup-closed", true);
    state.db.create_repo(&repo).await.unwrap();
    let pr = seed_pr(&repo.id, 1, "feature");
    state.db.create_pr(&pr).await.unwrap();
    state.db.close_pr(&pr.id).await.unwrap();
    // The branch is alive and would resolve if the fallback ran.
    seed_branch_head(&state, &repo, "feature", SHA_B).await;

    let body =
        body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-closed", 1)).await).await;
    assert_wire_state(&body);
    assert_eq!(body["pull_request_state"], "closed");
    assert_eq!(
        body["head_resolved"], false,
        "a closed pull request with no stored head is unresolved, not back-filled"
    );
    assert!(body["sha"].is_null(), "no branch resolve on a closed PR");
    assert_eq!(body["total_count"], 0);
    assert_eq!(
        state
            .db
            .get_pr(&repo.id, 1)
            .await
            .unwrap()
            .unwrap()
            .head_commit,
        None,
        "a closed PR's head must not be back-filled from the live branch"
    );
    assert_eq!(
        resolve_count(),
        0,
        "a closed pull request must not trigger a branch resolve at all"
    );
}

/// R17's merged arm: the stored head is frozen at merge and its claims are
/// still served, with the pull request state named.
#[sqlx::test]
async fn merged_pr_serves_its_frozen_head(pool: PgPool) {
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "rollup-merged", true);
    state.db.create_repo(&repo).await.unwrap();
    let pr = seed_pr(&repo.id, 1, "feature");
    state.db.create_pr(&pr).await.unwrap();
    let resp = post_as(
        &state,
        OWNER,
        &uri(OWNER, "rollup-merged", SHA_A),
        body_of("success", "ci/build"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    state.db.merge_pr(&pr.id, OWNER, Some(SHA_A)).await.unwrap();
    // The branch moved on after the merge; the frozen head must win.
    seed_branch_head(&state, &repo, "feature", SHA_B).await;

    let body =
        body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-merged", 1)).await).await;
    assert_eq!(body["pull_request_state"], "merged");
    assert_eq!(body["head_resolved"], true);
    assert_eq!(body["sha"], SHA_A);
    assert_eq!(body["state"], "success");
    assert_eq!(body["total_count"], 1);
}

/// The force-push flow: a re-pointed head is a fresh target, so the rollup
/// goes back to pending-zero until something reports on the new SHA. A rollup
/// keyed to the OLD sha would keep showing a green that describes code nobody
/// is looking at any more.
#[sqlx::test]
async fn moving_the_stored_head_repoints_the_rollup(pool: PgPool) {
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "rollup-force", true);
    state.db.create_repo(&repo).await.unwrap();
    let pr = seed_pr(&repo.id, 1, "feature");
    state.db.create_pr(&pr).await.unwrap();
    state
        .db
        .set_open_pr_heads(&repo.id, "feature", SHA_A)
        .await
        .unwrap();
    let resp = post_as(
        &state,
        OWNER,
        &uri(OWNER, "rollup-force", SHA_A),
        body_of("success", "ci/build"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let before =
        body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-force", 1)).await).await;
    assert_eq!(before["state"], "success");

    state
        .db
        .set_open_pr_heads(&repo.id, "feature", SHA_B)
        .await
        .unwrap();

    let after =
        body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-force", 1)).await).await;
    assert_eq!(after["sha"], SHA_B);
    assert_eq!(after["state"], "pending");
    assert_eq!(after["total_count"], 0);
}

/// The open-PR fallback: no stored head, a live source branch, so the branch
/// head is resolved from the database, served, AND persisted as the stored
/// head for the next read.
#[sqlx::test]
async fn open_pr_without_a_stored_head_resolves_and_persists_the_branch_head(pool: PgPool) {
    let _counting = resolve_count_guard().await;
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "rollup-fallback", true);
    state.db.create_repo(&repo).await.unwrap();
    let pr = seed_pr(&repo.id, 1, "feature");
    state.db.create_pr(&pr).await.unwrap();
    seed_branch_head(&state, &repo, "feature", SHA_A).await;

    let body =
        body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-fallback", 1)).await).await;
    assert_eq!(body["head_resolved"], true);
    assert_eq!(body["sha"], SHA_A);
    assert_eq!(body["state"], "pending");
    assert_eq!(
        state
            .db
            .get_pr(&repo.id, 1)
            .await
            .unwrap()
            .unwrap()
            .head_commit,
        Some(SHA_A.to_string()),
        "the resolved head must be persisted as the stored head"
    );
}

/// The fallback must resolve on a node with no object-storage pinning at all.
///
/// `branch_cids` has exactly one production writer, and it only fires for a
/// ref whose objects came back with a pin CID, so on a node with no Pinata JWT
/// the table stays empty forever. `repo_push_events` is written unconditionally
/// for every ref update on the receive-pack path, which is why it is the
/// fallback's source. Nothing here seeds `branch_cids`: if the resolve still
/// went through it, this open pull request would answer `head_resolved: false`
/// permanently.
#[sqlx::test]
async fn fallback_resolves_from_push_events_with_no_pin_recorded(pool: PgPool) {
    let _counting = resolve_count_guard().await;
    let state = test_state(pool.clone()).await;
    let repo = seed_repo(OWNER, "rollup-nopin", true);
    state.db.create_repo(&repo).await.unwrap();
    let pr = seed_pr(&repo.id, 1, "feature");
    state.db.create_pr(&pr).await.unwrap();
    seed_push_event(&state, &repo, "feature", SHA_A, PUSH_T1).await;

    let pinned: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM branch_cids")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pinned, 0, "the unpinned node premise must hold");

    let body =
        body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-nopin", 1)).await).await;
    assert_eq!(
        body["head_resolved"], true,
        "a pushed branch must resolve on a node that pins nothing"
    );
    assert_eq!(body["sha"], SHA_A);
    assert_eq!(
        state
            .db
            .get_pr(&repo.id, 1)
            .await
            .unwrap()
            .unwrap()
            .head_commit,
        Some(SHA_A.to_string()),
        "the resolved head must still be persisted"
    );
}

/// The fallback takes the LATEST push for the branch, not any push, and it
/// takes it for the right ref: a tag sharing the branch's name and a push to a
/// different branch are both seeded ahead of the real one, so a query missing
/// either predicate returns the wrong SHA rather than passing vacuously.
#[sqlx::test]
async fn fallback_takes_the_latest_push_for_that_exact_branch(pool: PgPool) {
    let _counting = resolve_count_guard().await;
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "rollup-latest", true);
    state.db.create_repo(&repo).await.unwrap();
    let pr = seed_pr(&repo.id, 1, "feature");
    state.db.create_pr(&pr).await.unwrap();

    seed_push_event(&state, &repo, "feature", SHA_A, PUSH_T1).await;
    seed_push_event(&state, &repo, "other", SHA_C, PUSH_T2).await;
    // A tag named like the branch, written the way the push path would.
    state
        .db
        .insert_repo_push_event(&crate::db::RepoPushEvent {
            id: uuid::Uuid::new_v4().to_string(),
            // Ignored on insert; the database assigns the ordering key.
            seq: 0,
            repo_id: repo.id.clone(),
            ref_name: "refs/tags/feature".to_string(),
            after_sha: SHA_C.to_string(),
            created_at: PUSH_T2.to_string(),
        })
        .await
        .unwrap();
    seed_push_event(&state, &repo, "feature", SHA_B, PUSH_T2).await;

    let body =
        body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-latest", 1)).await).await;
    assert_eq!(
        body["sha"], SHA_B,
        "the newest push to refs/heads/feature is the head"
    );
}

/// A push recorded for a DIFFERENT repository must never resolve this one's
/// branch. Same branch name, same timestamp, no row for this repo.
#[sqlx::test]
async fn fallback_does_not_cross_repositories(pool: PgPool) {
    let _counting = resolve_count_guard().await;
    let state = test_state(pool).await;
    let mine = seed_repo(OWNER, "rollup-mine", true);
    let theirs = seed_repo(OWNER, "rollup-theirs", true);
    state.db.create_repo(&mine).await.unwrap();
    state.db.create_repo(&theirs).await.unwrap();
    let pr = seed_pr(&mine.id, 1, "feature");
    state.db.create_pr(&pr).await.unwrap();
    seed_push_event(&state, &theirs, "feature", SHA_A, PUSH_T1).await;

    let body =
        body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-mine", 1)).await).await;
    assert_eq!(
        body["head_resolved"], false,
        "another repository's push must not resolve this pull request's head"
    );
}

/// The comment on `rollup_head` claims the PERSIST is once-per-pull-request,
/// not the resolve. This is what keeps that claim honest: an open pull request
/// whose branch never resolves runs the lookup again on every read, forever,
/// because there is nothing to store and therefore nothing to short-circuit on.
#[sqlx::test]
async fn an_unresolvable_head_re_runs_the_resolve_on_every_read(pool: PgPool) {
    let _counting = resolve_count_guard().await;
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "rollup-retry", true);
    state.db.create_repo(&repo).await.unwrap();
    let pr = seed_pr(&repo.id, 1, "never-pushed");
    state.db.create_pr(&pr).await.unwrap();

    let first =
        body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-retry", 1)).await).await;
    assert_eq!(first["head_resolved"], false);
    assert_eq!(resolve_count(), 1, "the first read attempts the resolve");

    let second =
        body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-retry", 1)).await).await;
    assert_eq!(second["head_resolved"], false);
    assert_eq!(
        resolve_count(),
        2,
        "with nothing stored there is nothing to short-circuit on, so the \
             second read attempts the resolve again"
    );
}

/// The fallback writes on an UNAUTHENTICATED read, so it has to be
/// self-limiting: it fires only while `head_commit` is absent, and it sets it.
///
/// Proven two ways, because the output alone would not show it. The response
/// says the second read returned the STORED sha after the branch moved
/// underneath it, which it could not do if it had re-resolved; and the resolve
/// counter says the branch lookup RAN once across two reads, which is the
/// work-done bound rather than the results-emitted one — a fallback that
/// re-read the branch on every call and then discarded the answer would leave
/// the response identical and the cost doubled.
#[sqlx::test]
async fn head_fallback_resolves_once_and_later_reads_use_the_stored_head(pool: PgPool) {
    let _counting = resolve_count_guard().await;
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "rollup-once", true);
    state.db.create_repo(&repo).await.unwrap();
    let pr = seed_pr(&repo.id, 1, "feature");
    state.db.create_pr(&pr).await.unwrap();
    seed_branch_head(&state, &repo, "feature", SHA_A).await;

    let first =
        body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-once", 1)).await).await;
    assert_eq!(first["sha"], SHA_A, "the first read resolves the branch");
    assert_eq!(
        resolve_count(),
        1,
        "the first read must perform exactly one branch-head lookup"
    );
    assert_eq!(
        state
            .db
            .get_pr(&repo.id, 1)
            .await
            .unwrap()
            .unwrap()
            .head_commit,
        Some(SHA_A.to_string()),
        "the first read persists what it resolved"
    );

    // Move the branch WITHOUT going through the push path, so nothing updates
    // the stored head. A second read that resolved again would return SHA_B.
    seed_branch_head(&state, &repo, "feature", SHA_B).await;

    let second =
        body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-once", 1)).await).await;
    assert_eq!(
        second["sha"], SHA_A,
        "the second read must be served from the stored head, not a fresh branch resolve"
    );
    assert_eq!(
        state
            .db
            .get_pr(&repo.id, 1)
            .await
            .unwrap()
            .unwrap()
            .head_commit,
        Some(SHA_A.to_string()),
        "the stored head must not be rewritten by a later read"
    );
    assert_eq!(
        resolve_count(),
        1,
        "the branch resolve must not run again once a head is stored"
    );
}

/// The write-back is a cache fill, so its failure must not destroy an answer
/// the read already has. The head is resolved BEFORE the persist is attempted,
/// and the persist is the only thing that fails here.
///
/// The failure is induced with a CHECK constraint that rejects any non-null
/// `head_commit`: the UPDATE errors while every read in the request path
/// (`repos`, `pull_requests`, `repo_push_events`) still works, which is what
/// isolates the write. Dropping a table would take the read down with it and
/// the test would pass for the wrong reason.
#[sqlx::test]
async fn a_failed_head_write_back_still_serves_the_resolved_head(pool: PgPool) {
    let _counting = resolve_count_guard().await;
    let state = test_state(pool.clone()).await;
    let repo = seed_repo(OWNER, "rollup-wbfail", true);
    state.db.create_repo(&repo).await.unwrap();
    let pr = seed_pr(&repo.id, 1, "feature");
    state.db.create_pr(&pr).await.unwrap();
    seed_push_event(&state, &repo, "feature", SHA_A, PUSH_T1).await;

    sqlx::query(
        "ALTER TABLE pull_requests
             ADD CONSTRAINT no_head_commit_writes CHECK (head_commit IS NULL)",
    )
    .execute(&pool)
    .await
    .expect("install the write-blocking constraint");
    // The premise: this exact call is the one the rollup makes, and it errors.
    state
        .db
        .set_pr_head_if_absent(&pr.id, SHA_A)
        .await
        .expect_err("the persist must fail for this test to mean anything");

    let resp = get_rollup(&state, None, &rollup_uri(OWNER, "rollup-wbfail", 1)).await;
    let (status, bytes) = status_and_bytes(resp).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a failed best-effort cache fill must not turn a resolved read into an \
             error: {}",
        String::from_utf8_lossy(&bytes)
    );
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["head_resolved"], true);
    assert_eq!(body["sha"], SHA_A);
    assert_eq!(body["state"], "pending");
    assert_eq!(
        resolve_count(),
        1,
        "the read resolved the branch itself rather than reading a stored head"
    );
    assert_eq!(
        state
            .db
            .get_pr(&repo.id, 1)
            .await
            .unwrap()
            .unwrap()
            .head_commit,
        None,
        "nothing was persisted, which is the point: the answer was served anyway"
    );
}

/// The rollup's deny is the repo's own not-found, byte for byte what a caller
/// gets for a repo that does not exist. The pull request and its claims are
/// seeded first, so the deny cannot pass vacuously.
#[sqlx::test]
async fn anon_rollup_on_private_repo_is_indistinguishable_from_missing(pool: PgPool) {
    let state = test_state(pool.clone()).await;
    let target = rollup_uri(OWNER, "rollup-private", 1);

    let missing = status_and_bytes(get_rollup(&state, None, &target).await).await;

    let repo = seed_repo(OWNER, "rollup-private", false);
    state.db.create_repo(&repo).await.unwrap();
    let pr = seed_pr(&repo.id, 1, "feature");
    state.db.create_pr(&pr).await.unwrap();
    state
        .db
        .set_open_pr_heads(&repo.id, "feature", SHA_A)
        .await
        .unwrap();
    seed_claim(
        &pool,
        "33333333-0000-0000-0000-000000000001",
        &repo.id,
        SHA_A,
        OWNER,
        OWNER,
        "ci/build",
        "success",
        "2026-01-01T00:00:00Z",
    )
    .await;

    let denied = status_and_bytes(get_rollup(&state, None, &target).await).await;

    assert_eq!(missing.0, StatusCode::NOT_FOUND);
    assert_eq!(
        denied, missing,
        "a private-repo deny must be byte-identical to the missing-repo response"
    );
    assert!(
        !String::from_utf8_lossy(&denied.1).contains("ci/build"),
        "the deny must carry no trace of the claim"
    );
}

/// A pull request number that does not exist on a repo the caller CAN read is
/// the plain not-found: existence is not secret once the read gate passed.
#[sqlx::test]
async fn unknown_pr_number_on_a_visible_repo_is_404(pool: PgPool) {
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "rollup-missing-pr", true);
    state.db.create_repo(&repo).await.unwrap();

    let resp = get_rollup(&state, None, &rollup_uri(OWNER, "rollup-missing-pr", 99)).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// R18's endpoint boundary: the rollup lives ONLY on the per-pull-request
/// endpoint. The list response must gain no rollup field and do no status
/// work, or one list call becomes N projections.
///
/// Asserted on the ABSENCE of the named rollup fields, never on the full field
/// set: `head_commit` already surfaces on this response through the pull
/// request's own Serialize, and `status` is the pull request's own open/closed
/// state, so neither is evidence either way.
#[sqlx::test]
async fn pr_list_response_carries_no_rollup_fields(pool: PgPool) {
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "rollup-boundary", true);
    state.db.create_repo(&repo).await.unwrap();
    let pr = seed_pr(&repo.id, 1, "feature");
    state.db.create_pr(&pr).await.unwrap();
    state
        .db
        .set_open_pr_heads(&repo.id, "feature", SHA_A)
        .await
        .unwrap();
    let resp = post_as(
        &state,
        OWNER,
        &uri(OWNER, "rollup-boundary", SHA_A),
        body_of("success", "ci/build"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let router = Router::new()
        .route(
            "/api/v1/repos/{owner}/{repo}/pulls",
            axum::routing::get(crate::api::pulls::list_prs),
        )
        .with_state(state.clone());
    let resp = router
        .oneshot(
            axum::http::Request::builder()
                .method(Method::GET)
                .uri(format!("/api/v1/repos/{OWNER}/rollup-boundary/pulls"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let entry = &body["pulls"][0];
    assert_eq!(
        entry["number"], 1,
        "the list must still serve the pull request"
    );
    for field in [
        "combined_state",
        "head_resolved",
        "reported_only",
        "rollup",
        "statuses",
        "total_count",
    ] {
        assert!(
            entry.get(field).is_none(),
            "the pull request list response must not carry `{field}`"
        );
        assert!(
            body.get(field).is_none(),
            "the pull request list envelope must not carry `{field}`"
        );
    }
}

/// R18's cost bound, by source read: no path in this module acquires the
/// repository. `repo_store.acquire` downloads the whole repository from object
/// storage on a cold node, and this read group carries no rate limiter, so an
/// anonymous caller could drive repeated downloads. The ref helper that needs
/// an acquired path is named here too, since reaching for it is how the
/// acquire gets reintroduced.
#[test]
fn status_module_never_acquires_the_repo_or_lists_refs_from_disk() {
    let src = include_str!("mod.rs");
    // The module's production half is now the whole of `status/mod.rs`, which
    // ends at the declaration of the tests file. Anchoring on that declaration
    // rather than on any `#[cfg(test)]` attribute still matters: the
    // production half carries test-only instrumentation of its own, and
    // stopping at the first attribute would leave most of the module unscanned.
    let body_of_module =
        crate::test_support::scrape_source_region(src, None, Some("\n#[cfg(test)]\nmod tests;"))
            .expect("module has a tests module");
    assert!(
        body_of_module.contains("pull_request_status"),
        "the scan must cover the whole production half of the module"
    );
    for banned in ["repo_store.acquire", "store::list_refs"] {
        assert!(
            !body_of_module.contains(banned),
            "the status module must not call `{banned}` — the rollup's branch \
                 resolve is a database read, not a repository acquire"
        );
    }
    assert!(
        body_of_module.contains("latest_push_sha_for_ref("),
        "the fallback's branch lookup must be the database-backed \
             latest_push_sha_for_ref over repo_push_events"
    );
    assert!(
        !body_of_module.contains("list_branch_cids("),
        "the fallback must not read branch_cids — that table has one writer \
             and it only fires when the pushed objects came back with a pin CID, \
             so on a node with no pinning configured it is never written"
    );
}

/// The rollup route exists on the production router and its group kept
/// `optional_signature`: a group that is never merged is not a route, and a
/// group without the layer reads every caller as anonymous.
#[sqlx::test]
async fn rollup_route_is_registered_with_optional_signature(pool: PgPool) {
    let _counting = resolve_count_guard().await;
    let state = test_state(pool).await;
    let repo = seed_repo(OWNER, "rollup-wired", true);
    state.db.create_repo(&repo).await.unwrap();
    let pr = seed_pr(&repo.id, 1, "feature");
    state.db.create_pr(&pr).await.unwrap();
    let target = rollup_uri(OWNER, "rollup-wired", 1);

    let resp = crate::server::build_router(state.clone())
        .oneshot(
            axum::http::Request::builder()
                .method(Method::GET)
                .uri(&target)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the rollup route must exist on the production router and serve a public repo to anon"
    );

    let resp = crate::server::build_router(state)
        .oneshot(
            axum::http::Request::builder()
                .method(Method::GET)
                .uri(&target)
                .header("signature", "sig1=:bm90YXNpZw==:")
                .header("signature-input", "sig1=(\"@method\");alg=\"ed25519\"")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, bytes) = status_and_bytes(resp).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a presented signature must be verified, which only happens if the \
             rollup's group still carries optional_signature"
    );
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"], "invalid_signature");
}
