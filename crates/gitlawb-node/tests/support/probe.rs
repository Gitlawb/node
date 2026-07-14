//! U2: fixture state matrix + per-gate-class probe generators.
//!
//! The fixture is a STATE MATRIX, not one repo: owner-gate rows need a repo the
//! signed stranger can REACH (so the request hits the owner gate, not an
//! existence-hiding 404), and read-gate rows need a repo the caller CANNOT see.
//! A single repo cannot be both, so we seed a public repo (owner-gate substrate)
//! and a private repo with content (read-gate substrate).
//!
//! Each deny-bearing row expands to probes: the hostile request (asserting the
//! exact deny) plus a positive twin (owner-reachability for owner-gate,
//! reader/sibling-public read for read-gate) so a 403/404 for the wrong reason
//! cannot false-pass.

use gitlawb_core::identity::Keypair;
use gitlawb_node::test_harness::TestNode;

use super::routes::{GateClass, IdSource, Principal, Reach, Row};

/// A seeded two-repo state matrix plus the owner and stranger identities.
pub struct Fixture {
    pub owner: Keypair,
    pub stranger: Keypair,
    /// The PR/issue author — distinct from owner and stranger — so the
    /// owner-OR-author close gates (#195, F1) drive their author arm with an
    /// identity that is NOT the owner (the original bug seeded author == owner).
    pub author: Keypair,
    /// The bounty creator, distinct from every other identity.
    pub creator: Keypair,
    /// The bounty claimant, distinct from every other identity.
    pub claimant: Keypair,
    pub owner_did: String,
    pub author_did: String,
    pub creator_did: String,
    pub claimant_did: String,
    /// The id (UUID) of the seeded disputable bounty, filled into the
    /// `dispute_bounty` row's `{id}` placeholder (IdSource::BountyId).
    pub bounty_id: String,
    /// The id (UUID) of the seeded issue (authored by `author`), filled into the
    /// `close_issue` row's `{id}` placeholder (IdSource::IssueId).
    pub issue_id: String,
    /// The id (UUID) of an issue seeded in the PRIVATE repo (marker in its title),
    /// filled into the get_issue / list_issue_comments read-gate rows
    /// (IdSource::PrivIssueId). Distinct from `issue_id` (the public close issue).
    pub priv_issue_id: String,
    /// The id (UUID) of a bounty seeded against the PRIVATE repo (marker in its
    /// title), filled into the get_bounty read-gate row (IdSource::PrivBountyId).
    pub priv_bounty_id: String,
    /// The id (UUID) of a ref-certificate issued by a real owner push to the
    /// private repo, filled into the get_cert read-gate row (IdSource::CertId).
    pub cert_id: String,
    /// Per-read secret markers seeded into the private sub-entities (issue title,
    /// PR title, cert signature, bounty title). Each read's own marker is added to
    /// that read's withheld set so a 404 leaking THAT read's private content fails
    /// (#195, R3/KTD-4). A union is used so every seeded marker is withheld from
    /// every read-gate hostile — a per-read withheld token, never a status-only
    /// 404 check.
    pub priv_markers: Vec<String>,
    /// Public repo: owner-gate rows run against this so the stranger reaches the
    /// owner gate rather than a hidden-repo 404.
    pub public_repo: String,
    /// The public repo's id, needed to seed the PR the close-gate rows require.
    pub public_repo_id: String,
    /// Private repo (is_public=false) with seeded content: read-gate rows run
    /// against this so an anon caller gets the existence-hiding 404 and the owner
    /// twin gets 2xx.
    pub private_repo: String,
    /// The private repo's internal id (UUID). A read-gate denial body must never
    /// echo it: a 404 that serializes the private record's internal id has leaked
    /// repository metadata just as much as the blob content (#195, F4).
    pub private_repo_id: String,
    /// A seeded blob path present in both repos, for `{*path}` reads.
    pub content_path: String,
    /// The DISTINCTIVE secret bytes seeded into the private repo's blob. A
    /// read-gate denial body must never echo this (INV-8: the sweep claims the
    /// denial "leaks nothing", so it must actually check for the private content).
    pub private_secret: String,
    /// The private blob's full sha1 object id, and its short prefix. Neither may
    /// appear in a read-gate denial body — a 404 that names the withheld object's
    /// OID has leaked its existence.
    pub private_blob_oid: String,
    pub private_blob_oid_short: String,
}

impl Fixture {
    pub async fn seed(node: &TestNode) -> Fixture {
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let stranger = Keypair::generate();
        // #195 (F1): distinct identities for each authorizing arm of the
        // multi-principal gates. All four must differ from owner and stranger and
        // from each other, or an arm silently collapses onto another and reverting
        // it stays invisible (the original author == owner bug).
        let author = Keypair::generate();
        let author_did = author.did().to_string();
        let creator = Keypair::generate();
        let creator_did = creator.did().to_string();
        let claimant = Keypair::generate();
        let claimant_did = claimant.did().to_string();
        let content_path = "public/a.txt".to_string();

        let pub_repo = "prober-pub";
        let public_repo_id = node.seed_repo(&owner_did, pub_repo, true).await;
        node.seed_bare_repo(
            &owner_did,
            pub_repo,
            &[("public/a.txt", "pub content")],
            "sha1",
        );
        // The author-or-owner close gates load the PR/issue before they run, so
        // the close rows need the entity to exist. Seed both authored by `author`
        // (NOT the owner) so the author arm is granted by a non-owner identity and
        // reverting either arm is observable. The PR seeds via the DB (author_did
        // is a real column). The issue is seeded over HTTP as `author` (below):
        // close_issue deserializes the WHOLE git-JSON IssueRecord before reading
        // its author, so a bare `{"author":..}` DB-seed fails to deserialize and
        // the author falls back to None — the author arm would then 403.
        node.seed_pr(&public_repo_id, 1, &author_did).await;
        let issue_id = seed_authored_issue(node, &owner_did, pub_repo, &author).await;

        // Seed a DISPUTABLE bounty (status "claimed", creator + claimant set) so the
        // dispute_bounty creator/claimant arms reach their auth check. dispute_bounty
        // gates on creator/claimant, NOT the repo, so the bounty is created on the
        // public repo (both signers can read it). Seeded over HTTP through the real
        // handlers — create (creator) then claim (claimant) — because the DB seam is
        // private to TestNode and a test-only seed method would be a src/ change.
        let bounty_id = seed_disputable_bounty(
            node,
            &owner_did,
            pub_repo,
            &creator,
            &creator_did,
            &claimant,
        )
        .await;

        let priv_repo = "prober-priv";
        // Seed the private blob with an UNMISTAKABLE marker (not "priv content"),
        // so a read-gate denial body that echoes the content is caught as a leak
        // rather than blending into generic prose. The OID is captured so the OID
        // (full + short) is withheld too — a 404 naming the object's id has leaked
        // its existence just as much as its bytes.
        let private_secret = "TOPSECRET-PRIVREAD-U3".to_string();
        let private_repo_id = node.seed_repo(&owner_did, priv_repo, false).await;
        let priv_oids = node.seed_bare_repo(
            &owner_did,
            priv_repo,
            &[("public/a.txt", &private_secret)],
            "sha1",
        );
        let private_blob_oid = priv_oids["public/a.txt"].clone();
        let private_blob_oid_short = private_blob_oid[..12].to_string();
        // The private repo's current `main` commit tip, needed as the `old` oid of
        // the ref-update that force-points main at the deterministic push below.
        let private_main_tip = priv_oids["HEAD"].clone();

        // #195 (F2/U3): seed the private sub-entities the deferred reads return, each
        // carrying its OWN distinctive marker so the per-read leak assertion is
        // load-bearing. All are seeded as the OWNER (the only reader of the private
        // repo), so anon/stranger get the existence-hiding 404 and the owner twin
        // gets a 2xx that actually returns the entity.
        //
        // A real owner push to the private repo advances a `feature` branch with a
        // marker file (so get_pr_diff's branch_diff_names(main, feature) is
        // NON-EMPTY) AND issues a ref-certificate (get_cert). Do it first so the PR's
        // source branch exists before create_pr and the cert id is captured.
        let pr_diff_marker = "TOPSECRET-PRDIFF-U3".to_string();
        let cert_id = seed_private_push_and_cert(
            node,
            &owner,
            &owner_did,
            priv_repo,
            &private_main_tip,
            &private_secret,
            &private_blob_oid,
            &pr_diff_marker,
        )
        .await;

        let issue_marker = "TOPSECRET-ISSUE-U3".to_string();
        let priv_issue_id =
            seed_private_issue(node, &owner, &owner_did, priv_repo, &issue_marker).await;

        let pr_marker = "TOPSECRET-PRTITLE-U3".to_string();
        seed_private_pr(node, &owner, &owner_did, priv_repo, &pr_marker).await;

        let bounty_marker = "TOPSECRET-BOUNTY-U3".to_string();
        let priv_bounty_id =
            seed_private_bounty(node, &owner, &owner_did, priv_repo, &bounty_marker).await;

        let priv_markers = vec![
            issue_marker,
            pr_marker,
            pr_diff_marker,
            bounty_marker,
        ];

        Fixture {
            owner,
            stranger,
            author,
            creator,
            claimant,
            owner_did,
            author_did,
            creator_did,
            claimant_did,
            bounty_id,
            issue_id,
            priv_issue_id,
            priv_bounty_id,
            cert_id,
            priv_markers,
            public_repo: pub_repo.to_string(),
            public_repo_id,
            private_repo: priv_repo.to_string(),
            private_repo_id,
            content_path,
            private_secret,
            private_blob_oid,
            private_blob_oid_short,
        }
    }
}

/// Seed an issue authored by `author` through the real `create_issue` handler
/// and return its minted UUID id. Written as a full git-JSON `IssueRecord` (the
/// handler serializes the whole record), so `close_issue`'s deserialize-then-read
/// author path finds the author — which a bare-field DB seed cannot satisfy.
async fn seed_authored_issue(
    node: &TestNode,
    owner_did: &str,
    repo: &str,
    author: &Keypair,
) -> String {
    use super::signing::signed_request;

    let client = reqwest::Client::new();
    let path = format!("/api/v1/repos/{owner_did}/{repo}/issues");
    let body = br#"{"title":"prober close issue"}"#.to_vec();
    let resp = signed_request(
        &client,
        reqwest::Method::POST,
        &node.base_url,
        &path,
        body,
        author,
    )
    .header("content-type", "application/json")
    .send()
    .await
    .expect("create issue sends");
    assert_eq!(
        resp.status().as_u16(),
        201,
        "seeding: issue create must return 201 (author can read the public repo)"
    );
    let created: serde_json::Value = resp.json().await.expect("issue create returns JSON");
    created["id"]
        .as_str()
        .expect("created issue carries an id")
        .to_string()
}

/// Seed a bounty in the `claimed` state (creator + claimant set) so the
/// dispute_bounty creator/claimant arms reach their auth check, and return its id.
///
/// Driven through the real HTTP handlers rather than the DB: `create_bounty` mints
/// a UUID id we read back from the response, and `claim_bounty` sets the claimant.
/// Both read-gate the (public) repo, which the creator/claimant can read. The
/// bounty lands `status = "claimed"`; because its deadline has not been exceeded,
/// a creator/claimant dispute returns 400 (not 403) after passing auth — which is
/// still a Not403 twin — while a stranger is denied 403 at the auth check first.
async fn seed_disputable_bounty(
    node: &TestNode,
    owner_did: &str,
    repo: &str,
    creator: &Keypair,
    creator_did: &str,
    claimant: &Keypair,
) -> String {
    use super::signing::signed_request;

    let client = reqwest::Client::new();

    // create_bounty (creator) -> 201 with the minted BountyRecord (carries the id).
    let create_path = format!("/api/v1/repos/{owner_did}/{repo}/bounties");
    let body = br#"{"title":"prober dispute bounty","amount":1}"#.to_vec();
    let resp = signed_request(
        &client,
        reqwest::Method::POST,
        &node.base_url,
        &create_path,
        body,
        creator,
    )
    .header("content-type", "application/json")
    .send()
    .await
    .expect("create bounty sends");
    assert_eq!(
        resp.status().as_u16(),
        201,
        "seeding: bounty create must return 201 (creator can read the public repo)"
    );
    let created: serde_json::Value = resp.json().await.expect("bounty create returns JSON");
    let bounty_id = created["id"]
        .as_str()
        .expect("created bounty carries an id")
        .to_string();
    assert_eq!(
        created["creator_did"].as_str(),
        Some(creator_did),
        "seeded bounty creator must be the fixture creator"
    );

    // claim_bounty (claimant) -> 200, status becomes "claimed", claimant recorded.
    let claim_path = format!("/api/v1/bounties/{bounty_id}/claim");
    let resp = signed_request(
        &client,
        reqwest::Method::POST,
        &node.base_url,
        &claim_path,
        br#"{}"#.to_vec(),
        claimant,
    )
    .header("content-type", "application/json")
    .send()
    .await
    .expect("claim bounty sends");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "seeding: bounty claim must return 200 (claimant can read the public repo)"
    );

    bounty_id
}

/// Seed an issue in the PRIVATE repo (as the owner, the only reader) whose title
/// carries `marker`, and return its id. get_issue returns the whole IssueRecord,
/// so a 404 that echoes the title has leaked private content; the marker is added
/// to the withheld set.
async fn seed_private_issue(
    node: &TestNode,
    owner: &Keypair,
    owner_did: &str,
    repo: &str,
    marker: &str,
) -> String {
    use super::signing::signed_request;

    let client = reqwest::Client::new();
    let path = format!("/api/v1/repos/{owner_did}/{repo}/issues");
    let body = format!(r#"{{"title":"{marker}"}}"#).into_bytes();
    let resp = signed_request(&client, reqwest::Method::POST, &node.base_url, &path, body, owner)
        .header("content-type", "application/json")
        .send()
        .await
        .expect("create private issue sends");
    assert_eq!(
        resp.status().as_u16(),
        201,
        "seeding: private issue create must return 201 (owner reads its own private repo)"
    );
    let created: serde_json::Value = resp.json().await.expect("issue create returns JSON");
    created["id"]
        .as_str()
        .expect("created private issue carries an id")
        .to_string()
}

/// Seed a PR in the PRIVATE repo (as the owner) with `marker` in its title and
/// `feature` as its source branch (which the prior push created). get_pr returns
/// the whole PullRequest and get_pr_diff a real non-empty diff, so both the title
/// marker and the diff marker are withheld. Lands at PR number 1 (first PR).
async fn seed_private_pr(
    node: &TestNode,
    owner: &Keypair,
    owner_did: &str,
    repo: &str,
    marker: &str,
) {
    use super::signing::signed_request;

    let client = reqwest::Client::new();
    let path = format!("/api/v1/repos/{owner_did}/{repo}/pulls");
    let body = format!(
        r#"{{"title":"{marker}","source_branch":"feature","target_branch":"main"}}"#
    )
    .into_bytes();
    let resp = signed_request(&client, reqwest::Method::POST, &node.base_url, &path, body, owner)
        .header("content-type", "application/json")
        .send()
        .await
        .expect("create private PR sends");
    assert_eq!(
        resp.status().as_u16(),
        201,
        "seeding: private PR create must return 201 (owner reads its own private repo)"
    );
    let created: serde_json::Value = resp.json().await.expect("PR create returns JSON");
    assert_eq!(
        created["number"].as_i64(),
        Some(1),
        "seeded private PR must be number 1 (the read-gate rows fill {{number}} = 1)"
    );
}

/// Seed a bounty against the PRIVATE repo (as the owner) with `marker` in its
/// title, and return its id. get_bounty read-gates the bounty's own repo, so
/// anon/stranger get a 404 while the owner gets the bounty JSON (title marker
/// withheld from the 404).
async fn seed_private_bounty(
    node: &TestNode,
    owner: &Keypair,
    owner_did: &str,
    repo: &str,
    marker: &str,
) -> String {
    use super::signing::signed_request;

    let client = reqwest::Client::new();
    let path = format!("/api/v1/repos/{owner_did}/{repo}/bounties");
    let body = format!(r#"{{"title":"{marker}","amount":1}}"#).into_bytes();
    let resp = signed_request(&client, reqwest::Method::POST, &node.base_url, &path, body, owner)
        .header("content-type", "application/json")
        .send()
        .await
        .expect("create private bounty sends");
    assert_eq!(
        resp.status().as_u16(),
        201,
        "seeding: private bounty create must return 201 (owner reads its own private repo)"
    );
    let created: serde_json::Value = resp.json().await.expect("bounty create returns JSON");
    created["id"]
        .as_str()
        .expect("created private bounty carries an id")
        .to_string()
}

/// Point the PRIVATE repo's `main` at a deterministic commit and add a `feature`
/// branch (a marker file on top of it) via a real owner git-receive-pack push,
/// which also makes the node issue a ref-certificate. Returns the issued cert's
/// id, read back from the owner's list_certs.
///
/// seed_bare_repo's `main` tip is non-deterministic (its commit dates are ambient),
/// so we cannot build a `feature` that descends from it without the parent objects.
/// Instead we push a full (non-thin) history: a fresh `main` commit and `feature`
/// on top, force-updating the served `main` (the ref-update carries the server's
/// current tip as its `old` oid; receive.denyNonFastForwards is off by default, so
/// the non-fast-forward update applies). After the push, `feature` descends from
/// the new `main`, so get_pr_diff's `git diff main...feature` has a merge base and
/// returns the marker file. The push is signed as the owner (require_signature) and,
/// on a non-protected branch of an owner-owned repo, lands cleanly and issues a cert.
#[allow(clippy::too_many_arguments)]
async fn seed_private_push_and_cert(
    node: &TestNode,
    owner: &Keypair,
    owner_did: &str,
    repo: &str,
    server_main_tip: &str,
    blob_contents: &str,
    expected_blob_oid: &str,
    marker_file_contents: &str,
) -> String {
    use super::signing::signed_request;
    use std::process::Command;

    let work = std::env::temp_dir().join(format!(
        "gl-u3-certpush-{}-{}",
        std::process::id(),
        server_main_tip
    ));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).expect("create cert-push workdir");
    let run = |args: &[&str], cwd: &std::path::Path| -> String {
        let out = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .expect("git runs");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };

    run(&["init", "-q", "-b", "main"], &work);
    run(&["config", "user.email", "t@t"], &work);
    run(&["config", "user.name", "t"], &work);
    // Keep `public/a.txt` (the seeded blob) on the new main so the get_blob /
    // get_tree owner twins still resolve it — the blob OID depends only on content,
    // so preserving the bytes preserves `private_blob_oid`.
    std::fs::create_dir_all(work.join("public")).expect("mk public dir");
    std::fs::write(work.join("public/a.txt"), blob_contents).expect("seed blob file");
    run(&["add", "public/a.txt"], &work);
    run(&["commit", "-q", "-m", "u3 main"], &work);
    let new_main = run(&["rev-parse", "HEAD"], &work);
    let new_blob = run(&["rev-parse", "HEAD:public/a.txt"], &work);
    assert_eq!(
        new_blob, expected_blob_oid,
        "the pushed public/a.txt blob OID must equal the fixture's private_blob_oid"
    );

    // feature = new main + a marker file.
    run(&["checkout", "-q", "-b", "feature"], &work);
    std::fs::write(work.join("feature.txt"), marker_file_contents).expect("seed marker file");
    run(&["add", "feature.txt"], &work);
    run(&["commit", "-q", "-m", "feature commit"], &work);
    let feature_tip = run(&["rev-parse", "HEAD"], &work);

    // Full (non-thin) pack of both branches' objects — the server keeps its old
    // main objects but needs all of the new ones since feature does not descend
    // from the server's current main.
    let pack = {
        let out = Command::new("git")
            .args(["pack-objects", "--stdout", "--revs"])
            .current_dir(&work)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn pack-objects");
        use std::io::Write;
        out.stdin
            .as_ref()
            .expect("pack-objects stdin")
            .write_all(format!("{new_main}\n{feature_tip}\n").as_bytes())
            .expect("write revs");
        let done = out.wait_with_output().expect("pack-objects completes");
        assert!(done.status.success(), "pack-objects must succeed");
        done.stdout
    };

    // git v0 receive-pack body: two ref-update pkt-lines — force-update main
    // (old = the server's current tip) and create feature — the first carrying the
    // capabilities after a NUL, a flush, then the packfile.
    let zero = "0".repeat(server_main_tip.len());
    let l1 = format!("{server_main_tip} {new_main} refs/heads/main\0report-status\n");
    let l2 = format!("{zero} {feature_tip} refs/heads/feature\n");
    let mut body: Vec<u8> = Vec::new();
    body.extend(format!("{:04x}{l1}", l1.len() + 4).into_bytes());
    body.extend(format!("{:04x}{l2}", l2.len() + 4).into_bytes());
    body.extend_from_slice(b"0000");
    body.extend_from_slice(&pack);

    let client = reqwest::Client::new();
    let push_path = format!("/{owner_did}/{repo}/git-receive-pack");
    let resp = signed_request(
        &client,
        reqwest::Method::POST,
        &node.base_url,
        &push_path,
        body,
        owner,
    )
    .header("content-type", "application/x-git-receive-pack-request")
    .send()
    .await
    .expect("receive-pack push sends");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "seeding: owner push to a non-protected feature branch must return 200 so a cert issues"
    );

    let _ = std::fs::remove_dir_all(&work);

    // Read the issued cert id back from the owner's list_certs on the private repo.
    let certs_path = format!("/api/v1/repos/{owner_did}/{repo}/certs");
    let resp = signed_request(
        &client,
        reqwest::Method::GET,
        &node.base_url,
        &certs_path,
        Vec::new(),
        owner,
    )
    .send()
    .await
    .expect("list_certs sends");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "seeding: owner list_certs must return 200"
    );
    let listed: serde_json::Value = resp.json().await.expect("list_certs returns JSON");
    listed["certificates"][0]["id"]
        .as_str()
        .expect("a ref-certificate must have been issued by the push")
        .to_string()
}

/// Who signs a probe request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signer {
    Anon,
    Owner,
    Stranger,
    /// The PR/issue author arm of a multi-principal close gate.
    Author,
    /// The bounty creator arm of dispute_bounty.
    Creator,
    /// The bounty claimant arm of dispute_bounty.
    Claimant,
}

/// The signer identity that grants a given multi-principal arm. The runtime sweep
/// resolves each to its fixture keypair; the structural consistency test uses it
/// to confirm every declared arm has a twin signed by ITS identity.
pub fn signer_for_principal(p: Principal) -> Signer {
    match p {
        Principal::Owner => Signer::Owner,
        Principal::Author => Signer::Author,
        Principal::Creator => Signer::Creator,
        Principal::Claimant => Signer::Claimant,
    }
}

/// What a probe expects.
#[derive(Debug, Clone)]
pub enum Expect {
    /// Hostile request: the exact deny status, body leaking none of `withheld`.
    Deny(u16),
    /// Owner-gate twin: the owner reaches the handler, so NOT 403.
    Not403,
    /// Read-gate twin: an authorized read returns a non-empty 2xx (an empty 2xx
    /// would be a denial rendered as success).
    Ok2xx,
}

/// A single request to drive against the node.
#[derive(Debug, Clone)]
pub struct Probe {
    pub label: String,
    pub method: reqwest::Method,
    /// Path used both for the URL and for RFC-9421 `@path` signing.
    pub path: String,
    pub body: Vec<u8>,
    pub signer: Signer,
    pub json: bool,
    pub expect: Expect,
    /// Private tokens (secret content, blob OID) that the DENY body must not echo.
    /// Non-empty only for read-gate hostile probes, where a private repo/blob is
    /// actually seeded; the owner-gate (403) and signature (401) hostile probes
    /// fire on NO_ENTITY repos before any entity lookup, so there is genuinely
    /// nothing seeded to leak and an empty list is the honest assertion there.
    pub withheld: Vec<String>,
}

/// Substitute path-template placeholders from the fixture. `repo` is the public
/// repo for owner-gate rows and the private repo for read-gate rows.
///
/// `id_source` selects what `{id}` resolves to: `Fixed` uses the static seed id
/// `"1"` (entities seeded at #1), while a per-row source such as `BountyId`
/// injects a UUID minted at seed time. This is the general id-threading hook U3
/// reuses for the other id-keyed reads (a cert id, etc.): add an `IdSource`
/// variant + fixture field and map it here.
fn fill(path: &str, fixture: &Fixture, repo: &str, id_source: IdSource) -> String {
    let id = match id_source {
        IdSource::Fixed => "1",
        IdSource::BountyId => fixture.bounty_id.as_str(),
        IdSource::IssueId => fixture.issue_id.as_str(),
        IdSource::PrivIssueId => fixture.priv_issue_id.as_str(),
        IdSource::PrivBountyId => fixture.priv_bounty_id.as_str(),
        IdSource::CertId => fixture.cert_id.as_str(),
    };
    path.replace("{owner}", &fixture.owner_did)
        .replace("{repo}", repo)
        .replace("{number}", "1")
        .replace("{id}", id)
        .replace("{label}", "bug")
        .replace("{branch}", "main")
        .replace("{*path}", &fixture.content_path)
        .replace("{path}", &fixture.content_path)
}

/// Expand one deny-bearing row into its hostile probe plus positive twin.
pub fn probes_for(row: &Row, fixture: &Fixture) -> Vec<Probe> {
    let method: reqwest::Method = row.method.parse().expect("valid method");
    let body = row.body.map(|b| b.as_bytes().to_vec()).unwrap_or_default();
    let json = row.body.is_some();

    match row.gate {
        GateClass::OwnerGate => {
            let path = fill(row.path, fixture, &fixture.public_repo, row.id_source);
            vec![
                Probe {
                    label: format!("{} owner-gate hostile", row.handler),
                    method: method.clone(),
                    path: path.clone(),
                    body: body.clone(),
                    signer: Signer::Stranger,
                    json,
                    expect: Expect::Deny(403),
                    // No entity is seeded on the public owner-gate substrate before
                    // the 403 fires, so there is nothing private to leak here.
                    withheld: Vec::new(),
                },
                Probe {
                    label: format!("{} owner-reachability twin", row.handler),
                    method,
                    path,
                    body,
                    signer: Signer::Owner,
                    json,
                    expect: Expect::Not403,
                    withheld: Vec::new(),
                },
            ]
        }
        GateClass::MultiPrincipalGate => {
            // #195 (F1): a single stranger-403 hostile plus one Not403 twin PER
            // declared arm. Each arm is signed by ITS distinct fixture identity, so
            // reverting any single arm in the handler turns that arm's twin RED
            // while the others (and the stranger 403) stay green.
            let path = fill(row.path, fixture, &fixture.public_repo, row.id_source);
            let mut v = vec![Probe {
                label: format!("{} multi-principal hostile (stranger)", row.handler),
                method: method.clone(),
                path: path.clone(),
                body: body.clone(),
                signer: Signer::Stranger,
                json,
                expect: Expect::Deny(403),
                // The gate fires before returning any entity; nothing private is
                // seeded to leak on this substrate.
                withheld: Vec::new(),
            }];
            for arm in row.principals {
                let signer = signer_for_principal(*arm);
                v.push(Probe {
                    label: format!("{} arm twin ({:?})", row.handler, arm),
                    method: method.clone(),
                    path: path.clone(),
                    body: body.clone(),
                    signer,
                    json,
                    expect: Expect::Not403,
                    withheld: Vec::new(),
                });
            }
            v
        }
        GateClass::ReadGate => {
            let path = fill(row.path, fixture, &fixture.private_repo, row.id_source);
            // INV-8: the private repo's blob and its OID are actually seeded here, so
            // the 404 body must echo neither the secret content nor the blob OID
            // (full or short) nor the private repo's internal id (#195, F4). An empty
            // withheld list would let a 404 that spilled the private content pass as
            // a clean denial.
            // #195 (R3/KTD-4): the fixed blob-scoped withheld set PLUS every seeded
            // sub-entity marker. The new reads (get_issue/get_pr/get_pr_diff/get_cert
            // /get_bounty and the list rows off them) return their OWN private
            // content, whose markers are NOT in the blob set — a 404 that leaks an
            // issue title or PR diff must fail, so the per-read markers are withheld
            // from every read-gate hostile. A status-only 404 check would be vacuous.
            let mut withheld = vec![
                fixture.private_secret.clone(),
                fixture.private_blob_oid.clone(),
                fixture.private_blob_oid_short.clone(),
                fixture.private_repo_id.clone(),
            ];
            withheld.extend(fixture.priv_markers.iter().cloned());
            let mut v = vec![
                Probe {
                    label: format!("{} read-gate hostile (anon)", row.handler),
                    method: method.clone(),
                    path: path.clone(),
                    body: body.clone(),
                    signer: Signer::Anon,
                    json,
                    expect: Expect::Deny(404),
                    withheld: withheld.clone(),
                },
                // #195 (F1): a signed NON-READER must also get the existence-hiding
                // 404 — a signature is not access (INV-12). Without this probe, a
                // regression that treats any valid signature as authorized would leak
                // the private repo while the anon probe stayed green.
                Probe {
                    label: format!("{} read-gate hostile (signed non-reader)", row.handler),
                    method: method.clone(),
                    path: path.clone(),
                    body: body.clone(),
                    signer: Signer::Stranger,
                    json,
                    expect: Expect::Deny(404),
                    withheld: withheld.clone(),
                },
            ];
            // Positive twin: prove the 404 is the gate, not an absent entity.
            let twin = match row.reach {
                Reach::ReaderReads => Probe {
                    label: format!("{} read-reachability twin (owner)", row.handler),
                    method,
                    path,
                    body,
                    signer: Signer::Owner,
                    json,
                    expect: Expect::Ok2xx,
                    // The twin is a GRANTED read; it is expected to return the
                    // content, so nothing is withheld from it.
                    withheld: Vec::new(),
                },
                Reach::SiblingPublic(sibling) => Probe {
                    label: format!("{} read-reachability twin (sibling public)", row.handler),
                    method,
                    path: fill(sibling, fixture, &fixture.private_repo, row.id_source),
                    body,
                    signer: Signer::Anon,
                    json,
                    expect: Expect::Ok2xx,
                    withheld: Vec::new(),
                },
                Reach::None => panic!(
                    "read-gate row {} {} has no Reach twin (U1 consistency should have caught this)",
                    row.method, row.path
                ),
            };
            v.push(twin);
            v
        }
        GateClass::SignatureRequired => {
            let path = fill(row.path, fixture, &fixture.public_repo, row.id_source);
            vec![Probe {
                label: format!("{} signature-required hostile", row.handler),
                method,
                path,
                body,
                signer: Signer::Anon,
                json,
                expect: Expect::Deny(401),
                // The 401 fires at the signature layer before any repo/entity is
                // looked up (NO_ENTITY substrate), so nothing private is in scope.
                withheld: Vec::new(),
            }]
        }
    }
}

/// A DB-less `Fixture` for the pure-generator unit tests (here and the structural
/// consistency test in `routes.rs`). No node is seeded, so the identities are
/// generated keypairs with placeholder repo/secret metadata; only the arm DIDs
/// and the injected `{id}` matter to `probes_for`. Shared so both test modules
/// build the same shape.
#[cfg(test)]
pub mod tests_support {
    use super::*;

    pub fn fx() -> Fixture {
        let author = Keypair::generate();
        let creator = Keypair::generate();
        let claimant = Keypair::generate();
        Fixture {
            author_did: author.did().to_string(),
            creator_did: creator.did().to_string(),
            claimant_did: claimant.did().to_string(),
            author,
            creator,
            claimant,
            bounty_id: "bounty-uuid-1234".to_string(),
            issue_id: "issue-uuid-1234".to_string(),
            priv_issue_id: "priv-issue-uuid-1234".to_string(),
            priv_bounty_id: "priv-bounty-uuid-1234".to_string(),
            cert_id: "cert-uuid-1234".to_string(),
            priv_markers: vec![
                "TOPSECRET-ISSUE-U3".to_string(),
                "TOPSECRET-PRTITLE-U3".to_string(),
                "TOPSECRET-PRDIFF-U3".to_string(),
                "TOPSECRET-BOUNTY-U3".to_string(),
            ],
            owner: Keypair::generate(),
            stranger: Keypair::generate(),
            owner_did: "did:key:zOWNER".to_string(),
            public_repo: "prober-pub".to_string(),
            public_repo_id: "pub-id".to_string(),
            private_repo: "prober-priv".to_string(),
            private_repo_id: "priv-repo-uuid-0BADF00D".to_string(),
            content_path: "public/a.txt".to_string(),
            private_secret: "TOPSECRET-PRIVREAD-U3".to_string(),
            private_blob_oid: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            private_blob_oid_short: "deadbeefdead".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::routes::{GateClass, Reach, Row};

    use super::tests_support::fx;

    #[test]
    fn owner_gate_row_yields_stranger_403_and_owner_twin() {
        let row = Row {
            method: "PUT",
            path: "/api/v1/repos/{owner}/{repo}/visibility",
            gate: GateClass::OwnerGate,
            handler: "visibility::set_visibility",
            body: Some(r#"{"path_glob":"/"}"#),
            needs: &[],
            reach: Reach::None,
            principals: &[],
            id_source: crate::support::routes::IdSource::Fixed,
        };
        let ps = probes_for(&row, &fx());
        assert_eq!(ps.len(), 2);
        assert_eq!(ps[0].signer, Signer::Stranger);
        assert!(ps[0].json);
        assert!(matches!(ps[0].expect, Expect::Deny(403)));
        assert!(
            ps[0].path.contains("prober-pub"),
            "owner-gate uses the public repo"
        );
        assert_eq!(ps[1].signer, Signer::Owner);
        assert!(matches!(ps[1].expect, Expect::Not403));
        // Owner-gate hostile fires on a NO_ENTITY public repo before any lookup, so
        // there is nothing private seeded to leak: an empty withheld list is honest.
        assert!(
            ps[0].withheld.is_empty(),
            "owner-gate hostile probe seeds no private entity, so withholds nothing"
        );
    }

    #[test]
    fn read_gate_row_yields_anon_and_stranger_404_and_positive_twin() {
        let row = Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/blob/{*path}",
            gate: GateClass::ReadGate,
            handler: "repos::get_blob",
            body: None,
            needs: &[],
            reach: Reach::ReaderReads,
            principals: &[],
            id_source: crate::support::routes::IdSource::Fixed,
        };
        let f = fx();
        let ps = probes_for(&row, &f);
        // anon hostile, signed-stranger hostile (#195 F1), owner twin.
        assert_eq!(ps.len(), 3);
        assert_eq!(ps[0].signer, Signer::Anon);
        assert!(matches!(ps[0].expect, Expect::Deny(404)));
        // #195 (F1): the signed non-reader hostile must also expect a 404 no-leak.
        assert_eq!(ps[1].signer, Signer::Stranger);
        assert!(matches!(ps[1].expect, Expect::Deny(404)));
        assert!(
            !ps[1].withheld.is_empty(),
            "the signed-stranger hostile must carry the same withheld tokens"
        );
        assert!(
            ps[0].path.contains("prober-priv"),
            "read-gate uses the private repo"
        );
        assert!(ps[0].path.contains("public/a.txt"), "{{*path}} substituted");
        // F2 belt-and-suspenders: the read-gate hostile probe MUST carry the private
        // tokens, so a future refactor that drops them (reverting F2 to a vacuous
        // empty-withheld 404 check) fails loudly here.
        assert!(
            !ps[0].withheld.is_empty(),
            "read-gate hostile probe must carry withheld private tokens"
        );
        assert!(
            ps[0].withheld.contains(&f.private_secret),
            "the seeded secret content must be a withheld token"
        );
        assert!(
            ps[0].withheld.contains(&f.private_blob_oid),
            "the private blob OID must be a withheld token"
        );
        assert!(
            ps[0].withheld.contains(&f.private_blob_oid_short),
            "the short blob OID prefix must be a withheld token"
        );
        assert_eq!(ps[2].signer, Signer::Owner);
        assert!(matches!(ps[2].expect, Expect::Ok2xx));
        // The granted twin returns the content, so it withholds nothing.
        assert!(
            ps[2].withheld.is_empty(),
            "the granted read twin must not carry withheld tokens"
        );
    }

    #[test]
    fn signature_row_yields_unsigned_401_no_twin() {
        let row = Row {
            method: "POST",
            path: "/{owner}/{repo}/git-receive-pack",
            gate: GateClass::SignatureRequired,
            handler: "repos::git_receive_pack",
            body: None,
            needs: &[],
            reach: Reach::None,
            principals: &[],
            id_source: crate::support::routes::IdSource::Fixed,
        };
        let ps = probes_for(&row, &fx());
        assert_eq!(ps.len(), 1);
        assert_eq!(ps[0].signer, Signer::Anon);
        assert!(matches!(ps[0].expect, Expect::Deny(401)));
        // The 401 fires before any entity lookup, so nothing private is in scope.
        assert!(
            ps[0].withheld.is_empty(),
            "signature-required hostile probe withholds nothing (fires pre-lookup)"
        );
    }

    #[test]
    fn read_gate_sibling_public_twin_reads_the_sibling_path_anon() {
        let row = Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/blob/secret/x.txt",
            gate: GateClass::ReadGate,
            handler: "repos::get_blob",
            body: None,
            needs: &[],
            reach: Reach::SiblingPublic("/api/v1/repos/{owner}/{repo}/blob/{*path}"),
            principals: &[],
            id_source: crate::support::routes::IdSource::Fixed,
        };
        let ps = probes_for(&row, &fx());
        // anon hostile, signed-stranger hostile (#195 F1), sibling-public twin.
        assert_eq!(ps.len(), 3);
        // Hostile: anon on the withheld path -> 404.
        assert_eq!(ps[0].signer, Signer::Anon);
        assert!(matches!(ps[0].expect, Expect::Deny(404)));
        assert!(ps[0].path.ends_with("/blob/secret/x.txt"));
        // Signed non-reader on the withheld path -> 404 too.
        assert_eq!(ps[1].signer, Signer::Stranger);
        assert!(matches!(ps[1].expect, Expect::Deny(404)));
        assert!(ps[1].path.ends_with("/blob/secret/x.txt"));
        // Twin: anon on the sibling PUBLIC path -> non-empty 2xx (proves the 404
        // is path-scoped withholding, not a blanket refusal).
        assert_eq!(ps[2].signer, Signer::Anon);
        assert!(matches!(ps[2].expect, Expect::Ok2xx));
        assert!(
            ps[2].path.contains("public/a.txt"),
            "sibling template's {{*path}} is filled from the fixture content path"
        );
    }

    // F2 RED proof at the check_denied level (no DB): feed a synthetic denial body
    // that DOES contain the private secret through the SAME withheld tokens the
    // read-gate probe carries. If the tokens are truly threaded and non-empty, the
    // deny check must reject it as a leak. This is the fail case a real node's
    // clean 404 avoids; it proves the sweep would actually catch a leaking 404.
    #[test]
    fn read_gate_withheld_tokens_reject_a_leaking_denial_body() {
        use crate::support::assert::check_denied;

        let row = Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}",
            gate: GateClass::ReadGate,
            handler: "repos::get_repo",
            body: None,
            needs: &[],
            reach: Reach::ReaderReads,
            principals: &[],
            id_source: crate::support::routes::IdSource::Fixed,
        };
        let f = fx();
        let ps = probes_for(&row, &f);
        let tokens: Vec<&str> = ps[0].withheld.iter().map(String::as_str).collect();
        assert!(
            !tokens.is_empty(),
            "precondition: read-gate probe carries tokens"
        );

        // A hostile 404 that spilled the secret content: must be rejected as a leak.
        let leaking = format!(
            r#"{{"error":"blob {} at {}"}}"#,
            f.private_secret, f.private_blob_oid
        );
        let r = check_denied(404, &leaking, 404, &tokens);
        assert!(
            r.is_err(),
            "a 404 body echoing the secret must be flagged: {r:?}"
        );
        assert!(
            r.unwrap_err().contains(&f.private_secret),
            "the failure must name the leaked secret token"
        );

        // #195 (F4): a 404 that serialized the private repo's internal id (UUID) is
        // a repository-metadata leak and must be flagged too — proving the UUID is a
        // load-bearing withheld token, not just the blob content.
        let leaking_meta = format!(r#"{{"error":"repo {} not found"}}"#, f.private_repo_id);
        let rm = check_denied(404, &leaking_meta, 404, &tokens);
        assert!(
            rm.is_err(),
            "a 404 body echoing the private repo id must be flagged: {rm:?}"
        );
        assert!(
            rm.unwrap_err().contains(&f.private_repo_id),
            "the failure must name the leaked private repo id token"
        );

        // A clean 404 (no private tokens) with the same tokens passes: the tokens do
        // not spuriously trip on an honest denial.
        let clean = check_denied(404, r#"{"error":"repository not found"}"#, 404, &tokens);
        assert!(
            clean.is_ok(),
            "a clean 404 must pass the withheld check: {clean:?}"
        );
    }

    #[test]
    #[should_panic(expected = "has no Reach twin")]
    fn read_gate_row_without_a_reach_twin_panics() {
        // A read-gate row with Reach::None is a registry bug the U1 consistency
        // test rejects; if one slips through, the probe generator must fail loud
        // rather than silently emit a hostile probe with no positive twin.
        let row = Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/issues",
            gate: GateClass::ReadGate,
            handler: "issues::list_issues",
            body: None,
            needs: &[],
            reach: Reach::None,
            principals: &[],
            id_source: crate::support::routes::IdSource::Fixed,
        };
        let _ = probes_for(&row, &fx());
    }
}
