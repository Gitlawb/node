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
        node.seed_repo(&owner_did, priv_repo, false).await;
        node.seed_bare_repo(
            &owner_did,
            priv_repo,
            &[("public/a.txt", "priv content")],
            "sha1",
        );

        Fixture {
            owner,
            stranger,
            owner_did,
            public_repo: pub_repo.to_string(),
            public_repo_id,
            private_repo: priv_repo.to_string(),
            content_path,
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
    /// Read-gate twin: an authorized read returns 2xx (optionally containing a token).
    Ok2xx(Option<String>),
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
                },
                Probe {
                    label: format!("{} owner-reachability twin", row.handler),
                    method,
                    path,
                    body,
                    signer: Signer::Owner,
                    json,
                    expect: Expect::Not403,
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
                    expect: Expect::Ok2xx(None),
                },
                Reach::SiblingPublic(sibling) => Probe {
                    label: format!("{} read-reachability twin (sibling public)", row.handler),
                    method,
                    path: fill(sibling, fixture, &fixture.private_repo),
                    body,
                    signer: Signer::Anon,
                    json,
                    expect: Expect::Ok2xx(None),
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
        let ps = probes_for(&row, &fx());
        assert_eq!(ps.len(), 2);
        assert_eq!(ps[0].signer, Signer::Anon);
        assert!(matches!(ps[0].expect, Expect::Deny(404)));
        assert!(
            ps[0].path.contains("prober-priv"),
            "read-gate uses the private repo"
        );
        assert!(ps[0].path.contains("public/a.txt"), "{{*path}} substituted");
        assert_eq!(ps[1].signer, Signer::Owner);
        assert!(matches!(ps[1].expect, Expect::Ok2xx(_)));
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
    }
}
