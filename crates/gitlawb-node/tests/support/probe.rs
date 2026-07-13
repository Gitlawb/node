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

use super::routes::{GateClass, Reach, Row};

/// A seeded two-repo state matrix plus the owner and stranger identities.
pub struct Fixture {
    pub owner: Keypair,
    pub stranger: Keypair,
    pub owner_did: String,
    /// Public repo: owner-gate rows run against this so the stranger reaches the
    /// owner gate rather than a hidden-repo 404.
    pub public_repo: String,
    /// The public repo's id, needed to seed the PR the close-gate rows require.
    pub public_repo_id: String,
    /// Private repo (is_public=false) with seeded content: read-gate rows run
    /// against this so an anon caller gets the existence-hiding 404 and the owner
    /// twin gets 2xx.
    pub private_repo: String,
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
        // the `.../pulls/1/close` and `.../issues/1/close` rows need entity #1 to
        // exist (owner-authored) or a stranger 404s (absent) instead of 403.
        node.seed_pr(&public_repo_id, 1, &owner_did).await;
        node.seed_issue(&owner_did, pub_repo, "1", &owner_did);

        let priv_repo = "prober-priv";
        // Seed the private blob with an UNMISTAKABLE marker (not "priv content"),
        // so a read-gate denial body that echoes the content is caught as a leak
        // rather than blending into generic prose. The OID is captured so the OID
        // (full + short) is withheld too — a 404 naming the object's id has leaked
        // its existence just as much as its bytes.
        let private_secret = "TOPSECRET-PRIVREAD-U3".to_string();
        node.seed_repo(&owner_did, priv_repo, false).await;
        let priv_oids = node.seed_bare_repo(
            &owner_did,
            priv_repo,
            &[("public/a.txt", &private_secret)],
            "sha1",
        );
        let private_blob_oid = priv_oids["public/a.txt"].clone();
        let private_blob_oid_short = private_blob_oid[..12].to_string();

        Fixture {
            owner,
            stranger,
            owner_did,
            public_repo: pub_repo.to_string(),
            public_repo_id,
            private_repo: priv_repo.to_string(),
            content_path,
            private_secret,
            private_blob_oid,
            private_blob_oid_short,
        }
    }
}

/// Who signs a probe request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signer {
    Anon,
    Owner,
    Stranger,
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
fn fill(path: &str, fixture: &Fixture, repo: &str) -> String {
    path.replace("{owner}", &fixture.owner_did)
        .replace("{repo}", repo)
        .replace("{number}", "1")
        .replace("{id}", "1")
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
            let path = fill(row.path, fixture, &fixture.public_repo);
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
        GateClass::ReadGate => {
            let path = fill(row.path, fixture, &fixture.private_repo);
            let mut v = vec![Probe {
                label: format!("{} read-gate hostile", row.handler),
                method: method.clone(),
                path: path.clone(),
                body: body.clone(),
                signer: Signer::Anon,
                json,
                expect: Expect::Deny(404),
                // INV-8: the private repo's blob and its OID are actually seeded
                // here, so the 404 body must echo neither the secret content nor the
                // blob OID (full or short). An empty withheld list would let a 404
                // that spilled the private content pass as a clean denial.
                withheld: vec![
                    fixture.private_secret.clone(),
                    fixture.private_blob_oid.clone(),
                    fixture.private_blob_oid_short.clone(),
                ],
            }];
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
                    path: fill(sibling, fixture, &fixture.private_repo),
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
            let path = fill(row.path, fixture, &fixture.public_repo);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::routes::{GateClass, Reach, Row};

    fn fx() -> Fixture {
        Fixture {
            owner: Keypair::generate(),
            stranger: Keypair::generate(),
            owner_did: "did:key:zOWNER".to_string(),
            public_repo: "prober-pub".to_string(),
            public_repo_id: "pub-id".to_string(),
            private_repo: "prober-priv".to_string(),
            content_path: "public/a.txt".to_string(),
            private_secret: "TOPSECRET-PRIVREAD-U3".to_string(),
            private_blob_oid: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            private_blob_oid_short: "deadbeefdead".to_string(),
        }
    }

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
    fn read_gate_row_yields_anon_404_and_positive_twin() {
        let row = Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/blob/{*path}",
            gate: GateClass::ReadGate,
            handler: "repos::get_blob",
            body: None,
            needs: &[],
            reach: Reach::ReaderReads,
        };
        let f = fx();
        let ps = probes_for(&row, &f);
        assert_eq!(ps.len(), 2);
        assert_eq!(ps[0].signer, Signer::Anon);
        assert!(matches!(ps[0].expect, Expect::Deny(404)));
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
        assert_eq!(ps[1].signer, Signer::Owner);
        assert!(matches!(ps[1].expect, Expect::Ok2xx));
        // The granted twin returns the content, so it withholds nothing.
        assert!(
            ps[1].withheld.is_empty(),
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
        };
        let ps = probes_for(&row, &fx());
        assert_eq!(ps.len(), 2);
        // Hostile: anon on the withheld path -> 404.
        assert_eq!(ps[0].signer, Signer::Anon);
        assert!(matches!(ps[0].expect, Expect::Deny(404)));
        assert!(ps[0].path.ends_with("/blob/secret/x.txt"));
        // Twin: anon on the sibling PUBLIC path -> non-empty 2xx (proves the 404
        // is path-scoped withholding, not a blanket refusal).
        assert_eq!(ps[1].signer, Signer::Anon);
        assert!(matches!(ps[1].expect, Expect::Ok2xx));
        assert!(
            ps[1].path.contains("public/a.txt"),
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
        };
        let _ = probes_for(&row, &fx());
    }
}
