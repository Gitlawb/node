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
            GateClass::OwnerGate => 403,
            GateClass::ReadGate => 404,
            GateClass::SignatureRequired => 401,
        }
    }
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
}

const NO_ENTITY: &[&str] = &[];

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
        },
        Row {
            method: "POST",
            path: "/api/v1/repos/{owner}/{repo}/pulls/{number}/close",
            gate: GateClass::OwnerGate,
            handler: "pulls::close_pr",
            body: None,
            needs: &["pr_number"],
            reach: Reach::None,
        },
        Row {
            method: "POST",
            path: "/api/v1/repos/{owner}/{repo}/issues/{id}/close",
            gate: GateClass::OwnerGate,
            handler: "issues::close_issue",
            body: None,
            needs: &["issue_id"],
            reach: Reach::None,
        },
        Row {
            method: "POST",
            path: "/api/v1/repos/{owner}/{repo}/hooks",
            gate: GateClass::OwnerGate,
            handler: "webhooks::create_webhook",
            body: Some(r#"{"url":"https://e.example/h","events":["*"]}"#),
            needs: NO_ENTITY,
            reach: Reach::None,
        },
        Row {
            method: "DELETE",
            path: "/api/v1/repos/{owner}/{repo}/hooks/{id}",
            gate: GateClass::OwnerGate,
            handler: "webhooks::delete_webhook",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::None,
        },
        Row {
            method: "POST",
            path: "/api/v1/repos/{owner}/{repo}/labels",
            gate: GateClass::OwnerGate,
            handler: "labels::add_label",
            body: Some(r#"{"label":"bug"}"#),
            needs: NO_ENTITY,
            reach: Reach::None,
        },
        Row {
            method: "DELETE",
            path: "/api/v1/repos/{owner}/{repo}/labels/{label}",
            gate: GateClass::OwnerGate,
            handler: "labels::remove_label",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::None,
        },
        Row {
            method: "POST",
            path: "/api/v1/repos/{owner}/{repo}/branches/{branch}/protect",
            gate: GateClass::OwnerGate,
            handler: "protect::protect_branch",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::None,
        },
        Row {
            method: "DELETE",
            path: "/api/v1/repos/{owner}/{repo}/branches/{branch}/protect",
            gate: GateClass::OwnerGate,
            handler: "protect::unprotect_branch",
            body: None,
            needs: NO_ENTITY,
            reach: Reach::None,
        },
        Row {
            method: "PUT",
            path: "/api/v1/repos/{owner}/{repo}/visibility",
            gate: GateClass::OwnerGate,
            handler: "visibility::set_visibility",
            body: Some(r#"{"path_glob":"/","reader_dids":[]}"#),
            needs: NO_ENTITY,
            reach: Reach::None,
        },
        Row {
            method: "DELETE",
            path: "/api/v1/repos/{owner}/{repo}/visibility",
            gate: GateClass::OwnerGate,
            handler: "visibility::remove_visibility",
            body: Some(r#"{"path_glob":"/"}"#),
            needs: NO_ENTITY,
            reach: Reach::None,
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
        },
        // ── Read-gate (404) — TODO(U1 continuation): populate per-handler-verified
        //    rows for the repo-scoped 404-reads (get_repo, get_blob, get_tree,
        //    get_by_cid, git_info_refs, git_upload_pack, get_cert, get_issue,
        //    get_pr, list_certs, list_issues, ...), each with a Reach twin, and
        //    keep the global list-filter surfaces (list_repos, list_all_bounties)
        //    OUT (they filter, they do not 404 — a different class, Flavor B).
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
        }
    }
}
