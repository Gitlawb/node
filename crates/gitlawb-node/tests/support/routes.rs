//! U1: the deny-bearing route set for the invariant deny-prober.
//!
//! ONLY the routes that carry a runtime deny to assert live here: owner-gate
//! (403), read-gate (404), and signature-required (401). Everything else on the
//! surface (positive-only / public / signer-self) is NOT listed here; U4's
//! completeness cross-check discharges those against the existing `authz_guard`
//! classification in `crates/gitlawb-node/src/api/mod.rs`.
//!
//! Each row is classified by READING its handler, never inferred from the route
//! name, and records the handler fn name so a reviewer can spot-check. Guessing
//! is how a false test enters the sweep (the register_replica lesson: it looks
//! like an owner-gate, it is signer-self; and list_visibility is a 403
//! owner-gate despite being a GET).
//!
//! Rows are declarative (gate class + entities + reachability), not prebuilt
//! requests, so Flavor B (the cross-surface differential prober) can reuse them
//! (R9).

/// The gate class of a deny-bearing route and the exact status its deny emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateClass {
    /// `require_repo_owner` / `require_owner` / inline `did_matches(caller, owner)`
    /// -> `AppError::Forbidden` == 403. Probed with a validly-signed non-owner.
    OwnerGate,
    /// A 403 gate with MORE THAN ONE authorizing principal (owner-OR-author,
    /// creator-OR-claimant, …). Probed with a validly-signed stranger (403) plus
    /// one Not403 twin per declared arm (`Row.principals`), so reverting ANY
    /// single arm turns that arm's twin RED. A single-arm `OwnerGate` cannot
    /// express this: it tests one identity, so the untested arm is invisible
    /// (#195, F1).
    MultiPrincipalGate,
    /// `authorize_repo_read` / `visibility_check` -> `RepoNotFound` == 404
    /// (existence-hiding). Probed with a non-reader against a private/withheld
    /// target. A 404 alone is ambiguous (a missing entity also 404s), so every
    /// read-gate row carries a `Reach` positive twin.
    ReadGate,
    /// `require_signature` layer -> 401 on the git write routes. Probed unsigned.
    SignatureRequired,
}

impl GateClass {
    pub fn expected_status(self) -> u16 {
        match self {
            GateClass::OwnerGate | GateClass::MultiPrincipalGate => 403,
            GateClass::ReadGate => 404,
            GateClass::SignatureRequired => 401,
        }
    }
}

/// An authorizing principal (arm) of a multi-principal 403 gate. Each maps to a
/// distinct fixture identity in `probe.rs` so reverting one arm cannot silently
/// re-collapse onto another (the original bug seeded `author == owner`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Principal {
    /// The repo owner (`require_repo_owner` / `did_matches(caller, owner)`).
    Owner,
    /// The PR/issue author (`did_matches(caller, author_did)`).
    Author,
    /// The bounty creator (`did_matches(caller, creator_did)`).
    Creator,
    /// The bounty claimant (`did_matches(caller, claimant_did)`).
    Claimant,
}

/// How a read-gate row's positive twin proves the 404 is the gate and not a
/// merely-absent entity/repo. Owner-gate and signature rows use `None`
/// (the owner-gate twin is the same request re-signed as the owner, handled by
/// the probe generator from the class, not a path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Not a read-gate row; no read-twin.
    None,
    /// The authorized reader/owner issues the same request and gets 2xx.
    ReaderReads,
    /// A sibling PUBLIC path on the same repo returns 2xx-with-content, proving
    /// the 404 is path-scoped withholding, not a blanket/absent 404. Mirrors the
    /// existing U7/U8/anon_ipfs cases in `tests/deny_harness.rs`.
    SiblingPublic(&'static str),
}

/// How a row's `{id}` placeholder is filled. Most id-keyed paths use a fixed
/// seed id (`"1"`), but some entities are keyed by a UUID minted at seed time
/// (a bounty, a cert), so the fixture must inject the captured id per row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdSource {
    /// `{id}` -> the fixed seed id `"1"` (static-template entities seeded at #1).
    Fixed,
    /// `{id}` -> the fixture's seeded disputable bounty id (UUID).
    BountyId,
    /// `{id}` -> the fixture's seeded issue id (UUID). The issue is stored as a
    /// full git-JSON `IssueRecord` (authored by the fixture author), which a
    /// bare `{"author":..}` seed cannot satisfy — close_issue deserializes the
    /// whole record before reading its author, so the author arm needs the
    /// complete record.
    IssueId,
    /// `{id}` -> the fixture's seeded PRIVATE-repo issue id (UUID). Distinct from
    /// `IssueId` (the public-repo close-gate issue): the get_issue /
    /// list_issue_comments read-gate rows run against the PRIVATE repo, so their
    /// `{id}` must be an issue that actually exists there (#195, F2/U3).
    PrivIssueId,
    /// `{id}` -> the fixture's seeded PRIVATE-repo bounty id (UUID). get_bounty is
    /// NOT repo-scoped in its path (`/api/v1/bounties/{id}`) but read-gates on the
    /// bounty's own repo; the bounty is seeded against the private repo so anon /
    /// stranger get the existence-hiding 404 and the owner gets 2xx (#195, U3).
    PrivBountyId,
    /// `{id}` -> the fixture's seeded ref-certificate id (UUID), issued by a real
    /// owner push to the private repo. get_cert read-gates the private repo on "/"
    /// then fetches the cert by id, so the owner-2xx twin needs a real cert whose
    /// repo_id is the private repo's (#195, U3).
    CertId,
}

/// One deny-bearing route. `path` is a template with `{owner}`/`{repo}`/`{id}`
/// /`{number}`/`{*path}` placeholders the probe generator (U2) fills from the
/// fixture. `needs` names the seeded sub-entities the path requires (empty for
/// owner-gate rows: the gate fires before the entity lookup).
#[derive(Debug, Clone, Copy)]
pub struct Row {
    pub method: &'static str,
    pub path: &'static str,
    pub gate: GateClass,
    /// Handler fn name, recorded for review spot-check (per-row verification).
    pub handler: &'static str,
    /// Sample request body (JSON) or `None`. JSON bodies drive the
    /// `Content-Type: application/json` the probe attaches to clear the extractor.
    pub body: Option<&'static str>,
    /// Seeded sub-entities the path template consumes.
    pub needs: &'static [&'static str],
    /// Positive-twin strategy for read-gate rows.
    pub reach: Reach,
    /// For `MultiPrincipalGate` rows, the authorizing arms this gate must drive
    /// (one Not403 twin each). Empty for every other class — only meaningful for
    /// `MultiPrincipalGate`, and the consistency test enforces that pairing.
    pub principals: &'static [Principal],
    /// How the `{id}` placeholder is filled for this row (see [`IdSource`]).
    pub id_source: IdSource,
}

const NO_ENTITY: &[&str] = &[];
const NO_PRINCIPAL: &[Principal] = &[];

/// The deny-bearing route set. Owner-gate and signature-required tranches are
/// fully verified against their handlers this session; the read-gate tranche is
/// populated as each handler's deny path (404-deny vs list-filter) is verified.
pub fn deny_bearing_routes() -> &'static [Row] {
    &[
        // ── Owner-gate (403) — verified: each calls require_repo_owner /
        //    require_owner / inline did_matches against the repo owner. ──────────
        Row {
            method: "POST",
            path: "/api/v1/repos/{owner}/{repo}/pulls/{number}/merge",
            gate: GateClass::OwnerGate,
            handler: "pulls::merge_pr",
            body: None,
            needs: &["pr_number"],
            reach: Reach::None,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        // #195 (F1): close_pr / close_issue are owner-OR-author gates (pulls.rs:276,
        // issues.rs:255). A plain OwnerGate tests only the owner arm, so reverting
        // the author arm is invisible. MultiPrincipalGate drives BOTH arms.
        Row {
            method: "POST",
            path: "/api/v1/repos/{owner}/{repo}/pulls/{number}/close",
            gate: GateClass::MultiPrincipalGate,
            handler: "pulls::close_pr",
            body: None,
            needs: &["pr_number"],
            reach: Reach::None,
            principals: &[Principal::Owner, Principal::Author],
            id_source: IdSource::Fixed,
        },
        Row {
            method: "POST",
            path: "/api/v1/repos/{owner}/{repo}/issues/{id}/close",
            gate: GateClass::MultiPrincipalGate,
            handler: "issues::close_issue",
            body: None,
            needs: &["issue_id"],
            reach: Reach::None,
            principals: &[Principal::Owner, Principal::Author],
            id_source: IdSource::IssueId,
        },
        // #195 (F1): dispute_bounty is creator-OR-claimant (bounties.rs:425). Not
        // repo-scoped: it gates on the bounty's creator/claimant, so the row is
        // id-keyed by the seeded disputable bounty's UUID (IdSource::BountyId).
        Row {
            method: "POST",
            path: "/api/v1/bounties/{id}/dispute",
            gate: GateClass::MultiPrincipalGate,
            handler: "bounties::dispute_bounty",
            body: None,
            needs: &["bounty_id"],
            reach: Reach::None,
            principals: &[Principal::Creator, Principal::Claimant],
            id_source: IdSource::BountyId,
        },
        Row {
            method: "POST",
            path: "/api/v1/repos/{owner}/{repo}/hooks",
            gate: GateClass::OwnerGate,
            handler: "webhooks::create_webhook",
            body: Some(r#"{"url":"https://e.example/h","events":["*"]}"#),
            needs: NO_ENTITY,
            reach: Reach::None,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        Row {
            method: "DELETE",
            path: "/api/v1/repos/{owner}/{repo}/hooks/{id}",
            gate: GateClass::OwnerGate,
            handler: "webhooks::delete_webhook",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::None,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        Row {
            method: "POST",
            path: "/api/v1/repos/{owner}/{repo}/labels",
            gate: GateClass::OwnerGate,
            handler: "labels::add_label",
            body: Some(r#"{"label":"bug"}"#),
            needs: NO_ENTITY,
            reach: Reach::None,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        Row {
            method: "DELETE",
            path: "/api/v1/repos/{owner}/{repo}/labels/{label}",
            gate: GateClass::OwnerGate,
            handler: "labels::remove_label",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::None,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        Row {
            method: "POST",
            path: "/api/v1/repos/{owner}/{repo}/branches/{branch}/protect",
            gate: GateClass::OwnerGate,
            handler: "protect::protect_branch",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::None,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        Row {
            method: "DELETE",
            path: "/api/v1/repos/{owner}/{repo}/branches/{branch}/protect",
            gate: GateClass::OwnerGate,
            handler: "protect::unprotect_branch",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::None,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        Row {
            method: "PUT",
            path: "/api/v1/repos/{owner}/{repo}/visibility",
            gate: GateClass::OwnerGate,
            handler: "visibility::set_visibility",
            body: Some(r#"{"path_glob":"/","reader_dids":[]}"#),
            needs: NO_ENTITY,
            reach: Reach::None,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        Row {
            method: "DELETE",
            path: "/api/v1/repos/{owner}/{repo}/visibility",
            gate: GateClass::OwnerGate,
            handler: "visibility::remove_visibility",
            body: Some(r#"{"path_glob":"/"}"#),
            needs: NO_ENTITY,
            reach: Reach::None,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        // list_visibility is a 403 owner-gate despite being a GET (calls
        // require_owner); the /visibility mount chains put+delete+get, all gated.
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/visibility",
            gate: GateClass::OwnerGate,
            handler: "visibility::list_visibility",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::None,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        // ── Signature-required (401) — verified: git write route wrapped by the
        //    require_signature layer (add_auth_layers in server.rs). ─────────────
        Row {
            method: "POST",
            path: "/{owner}/{repo}/git-receive-pack",
            gate: GateClass::SignatureRequired,
            handler: "repos::git_receive_pack",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::None,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        // ── Read-gate (404) — verified: each handler calls
        //    authorize_repo_read / visibility_check on "/" which returns
        //    AppError::RepoNotFound (404) when a non-reader hits a private repo
        //    (api/mod.rs:44-62). The Reach twin is the owner issuing the same
        //    request against the private repo and getting 2xx, proving the 404 is
        //    the gate and not a merely-absent entity/repo. Every row here gates on
        //    the whole repo ("/"), so ReaderReads (owner re-read) is the twin;
        //    the fully-private fixture repo needs no per-row sub-entity seeding
        //    because these reads either return the seeded repo/blob or an empty
        //    2xx list.
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}",
            gate: GateClass::ReadGate,
            handler: "repos::get_repo",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        // #195 (F2): repo-root reads that gate on "/" — driven as real ReadGate rows
        // rather than source-only exemptions, so a runtime bypass that keeps the
        // authorize_repo_read/visibility_check marker but leaks is caught.
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/star",
            gate: GateClass::ReadGate,
            handler: "stars::get_star_status",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/icaptcha-proof",
            gate: GateClass::ReadGate,
            handler: "repos::get_icaptcha_proof",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/encrypted-blobs/replicate",
            gate: GateClass::ReadGate,
            handler: "encrypted::replicate_encrypted_blobs",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/commits",
            gate: GateClass::ReadGate,
            handler: "repos::list_commits",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/tree",
            gate: GateClass::ReadGate,
            handler: "repos::get_tree_root",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        // Path-scoped read: get_blob gates on "/{path}" (repos.rs:390). The
        // fully-private fixture repo denies any path to anon (404); the owner
        // reads the seeded blob at content_path and gets 2xx bytes. (Path-scoped
        // subtree WITHHOLDING on a *public* repo — the SiblingPublic twin — is
        // already covered by the U7/U8 cases in deny_harness.rs.)
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/blob/{*path}",
            gate: GateClass::ReadGate,
            handler: "repos::get_blob",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/refs",
            gate: GateClass::ReadGate,
            handler: "repos::list_refs",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/issues",
            gate: GateClass::ReadGate,
            handler: "issues::list_issues",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/labels",
            gate: GateClass::ReadGate,
            handler: "labels::list_labels",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/certs",
            gate: GateClass::ReadGate,
            handler: "certs::list_certs",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/events",
            gate: GateClass::ReadGate,
            handler: "events::list_repo_events",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/pulls",
            gate: GateClass::ReadGate,
            handler: "pulls::list_prs",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/changelog",
            gate: GateClass::ReadGate,
            handler: "changelog::get_changelog",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/bounties",
            gate: GateClass::ReadGate,
            handler: "bounties::list_repo_bounties",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/withheld-paths",
            gate: GateClass::ReadGate,
            handler: "visibility::withheld_paths",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/encrypted-blobs",
            gate: GateClass::ReadGate,
            handler: "encrypted::list_encrypted_blobs",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        // #195 (F2, U3): sub-entity reads that gate on "/" (the private repo) but
        // require the entity to EXIST at the request path for the owner-2xx twin.
        // Each carries its own distinctive marker (seeded in probe.rs) added to the
        // per-read withheld set, so a 404 that echoes THAT read's private content
        // (issue title, PR title, PR diff, bounty title) fails — a status-
        // only 404 check would be vacuous. These were source-only exemptions in
        // READ_GATE_NOT_DRIVEN before; they are now driven as real ReadGate rows.
        // get_issue: id-keyed by the seeded PRIVATE issue (marker in its title).
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/issues/{id}",
            gate: GateClass::ReadGate,
            handler: "issues::get_issue",
            body: None,
            needs: &["priv_issue_id"],
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::PrivIssueId,
        },
        // list_issue_comments: parent issue must exist (private); child list may be
        // empty — an empty `{"comments":[]}` is a non-empty 2xx body.
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/issues/{id}/comments",
            gate: GateClass::ReadGate,
            handler: "issues::list_issue_comments",
            body: None,
            needs: &["priv_issue_id"],
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::PrivIssueId,
        },
        // get_pr: the seeded PRIVATE PR #1 (marker in its title).
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/pulls/{number}",
            gate: GateClass::ReadGate,
            handler: "pulls::get_pr",
            body: None,
            needs: &["priv_pr"],
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        // get_pr_diff: the PRIVATE PR #1 has a real `feature` source branch with a
        // marker file, so branch_diff_names(main, feature) is NON-EMPTY and the
        // owner twin returns a real diff (a bail!/500 if the source ref were
        // missing). The per-path visibility_check Deny-return is additionally
        // driven by the hand-written get_pr_diff_withheld_path_is_denied test.
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/pulls/{number}/diff",
            gate: GateClass::ReadGate,
            handler: "pulls::get_pr_diff",
            body: None,
            needs: &["priv_pr"],
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        // list_reviews / list_comments: parent PR #1 must exist (private); child
        // lists may be empty.
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/pulls/{number}/reviews",
            gate: GateClass::ReadGate,
            handler: "pulls::list_reviews",
            body: None,
            needs: &["priv_pr"],
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/pulls/{number}/comments",
            gate: GateClass::ReadGate,
            handler: "pulls::list_comments",
            body: None,
            needs: &["priv_pr"],
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        // get_cert: id-keyed by a real ref-certificate issued by an owner push to
        // the private repo. No cert-content marker is seeded: get_cert read-gates
        // the repo on "/" and 404s a non-reader BEFORE fetching the cert, so cert
        // fields cannot reach the deny body — the repo-scoped tokens (private_repo_id,
        // private_secret) plus the status check carry the no-leak assertion here.
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/certs/{id}",
            gate: GateClass::ReadGate,
            handler: "certs::get_cert",
            body: None,
            needs: &["cert_id"],
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::CertId,
        },
        // get_bounty: NOT repo-scoped in its path, read-gates on the bounty's repo.
        // Seeded against the PRIVATE repo (marker in its title), id-keyed.
        Row {
            method: "GET",
            path: "/api/v1/bounties/{id}",
            gate: GateClass::ReadGate,
            handler: "bounties::get_bounty",
            body: None,
            needs: &["priv_bounty_id"],
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::PrivBountyId,
        },
        // get_tree (path-scoped): genuinely ADDITIONAL to get_tree_root (Q1). Root
        // gates on "/"; get_tree gates on the REQUESTED subtree (N3,
        // authorize_repo_read(&gate_path)), a distinct path-scoped Deny surface. The
        // {*path} fills to the private content path, so a non-reader is denied the
        // subtree listing and the owner gets a non-empty 2xx.
        Row {
            method: "GET",
            path: "/api/v1/repos/{owner}/{repo}/tree/{*path}",
            gate: GateClass::ReadGate,
            handler: "repos::get_tree",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::ReaderReads,
            principals: NO_PRINCIPAL,
            id_source: IdSource::Fixed,
        },
        // The read-gate handlers NOT driven here (deferred GET reads, read-gating
        // mutations, git smart-HTTP reads, the content-addressed read, and the
        // global list-filters) are no longer tracked by free-text prose: they are
        // ENFORCED in deny_harness.rs's `READ_GATE_NOT_DRIVEN` allowlist, which the
        // `every_read_gate_handler_is_driven_or_explicitly_allowlisted` guard checks
        // against a live scan of every read-gate marker in src/api. That is the
        // single source of truth — adding/removing a driven read row here without
        // updating the allowlist trips the guard.
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_internal_consistency() {
        let rows = deny_bearing_routes();

        // No duplicate method+path.
        let mut seen = std::collections::HashSet::new();
        for r in rows {
            assert!(
                seen.insert((r.method, r.path)),
                "duplicate deny-bearing row: {} {}",
                r.method,
                r.path
            );
        }

        for r in rows {
            // Every row records its handler fn (review spot-check anchor).
            assert!(
                !r.handler.is_empty(),
                "row {} {} has no handler",
                r.method,
                r.path
            );

            match r.gate {
                // Every read-gate row must carry a positive twin, or a 404 from a
                // merely-absent entity is indistinguishable from the gate's 404.
                GateClass::ReadGate => assert_ne!(
                    r.reach,
                    Reach::None,
                    "read-gate row {} {} needs a Reach positive twin",
                    r.method,
                    r.path
                ),
                // Owner-gate/signature rows use the class's own twin (owner re-sign)
                // or none, never a read-path twin.
                _ => assert_eq!(
                    r.reach,
                    Reach::None,
                    "non-read-gate row {} {} must not carry a read twin",
                    r.method,
                    r.path
                ),
            }

            // `principals` is meaningful ONLY on MultiPrincipalGate rows: it must
            // be non-empty there (a gate with no declared arm drives nothing) and
            // empty everywhere else (a stray arm set on a non-multi row is a bug).
            match r.gate {
                GateClass::MultiPrincipalGate => assert!(
                    !r.principals.is_empty(),
                    "multi-principal row {} {} declares no authorizing arms",
                    r.method,
                    r.path
                ),
                _ => assert!(
                    r.principals.is_empty(),
                    "non-multi-principal row {} {} must not declare arms",
                    r.method,
                    r.path
                ),
            }
        }
    }

    /// STRUCTURAL enforcement (#195, F1): every `MultiPrincipalGate` row's
    /// generator output must carry exactly one Not403 twin PER declared arm plus
    /// the single stranger hostile, so a row that registered an arm but never
    /// emits its twin (the vacuous-guard failure) fails HERE rather than in a
    /// runtime sweep nobody re-runs. Invokes `probes_for` directly — the same
    /// generator the real sweep drives — so the two cannot drift.
    #[test]
    fn multi_principal_rows_emit_one_twin_per_arm() {
        use crate::support::probe::{probes_for, tests_support::fx, Expect, Signer};

        let fixture = fx();
        let mut checked = 0usize;
        for r in deny_bearing_routes() {
            if r.gate != GateClass::MultiPrincipalGate {
                continue;
            }
            checked += 1;
            let ps = probes_for(r, &fixture);

            let hostile = ps
                .iter()
                .filter(|p| p.signer == Signer::Stranger && matches!(p.expect, Expect::Deny(403)))
                .count();
            assert_eq!(
                hostile, 1,
                "multi-principal row {} {} must drive exactly one stranger-403 hostile, drove {hostile}",
                r.method, r.path
            );

            let twins = ps
                .iter()
                .filter(|p| matches!(p.expect, Expect::Not403))
                .count();
            assert_eq!(
                twins,
                r.principals.len(),
                "multi-principal row {} {} declares {} arms but emits {twins} Not403 twins",
                r.method,
                r.path,
                r.principals.len(),
            );

            // Each declared arm maps to a distinct signer, and every twin's signer
            // is one of the declared arms (no phantom / wrong-arm twin).
            for arm in r.principals {
                let want = crate::support::probe::signer_for_principal(*arm);
                let present = ps
                    .iter()
                    .any(|p| p.signer == want && matches!(p.expect, Expect::Not403));
                assert!(
                    present,
                    "multi-principal row {} {} declares arm {:?} but emits no Not403 twin for it",
                    r.method, r.path, arm
                );
            }

            // The twins' signers must be DISTINCT and number the declared arms. The
            // per-arm any() check above is satisfied by a single twin when two arms
            // map to the same Signer (a signer_for_principal collision), so without
            // this a wrong mapping would pass with one arm silently untested.
            let mut twin_signers: Vec<Signer> = ps
                .iter()
                .filter(|p| matches!(p.expect, Expect::Not403))
                .map(|p| p.signer)
                .collect();
            twin_signers.sort_by_key(|s| format!("{s:?}"));
            twin_signers.dedup();
            assert_eq!(
                twin_signers.len(),
                r.principals.len(),
                "multi-principal row {} {} emits twins with {} DISTINCT signers but declares {} arms \
                 (Principal->Signer collision?)",
                r.method,
                r.path,
                twin_signers.len(),
                r.principals.len(),
            );
        }
        assert!(
            checked >= 3,
            "expected at least the three known multi-principal rows, checked {checked}"
        );
    }
}
