use crate::db::{RepoRecord, VisibilityRule};
use crate::error::{AppError, Result};
use crate::state::AppState;
use crate::visibility::{visibility_check, Decision};

pub mod agents;
pub mod arweave;
pub mod bounties;
pub mod certs;
pub mod changelog;
pub mod encrypted;
pub mod events;
pub mod ipfs;
pub mod issues;
pub mod labels;
pub mod peers;
pub mod profiles;
pub mod protect;
pub mod pulls;
pub mod register;
pub mod replicas;
pub mod repos;
pub mod resolve;
pub mod stars;
pub mod tasks;
pub mod visibility;
pub mod webhooks;

/// Resolve a repo for a read request and enforce path-scoped visibility.
///
/// Returns 404 (`RepoNotFound`) if the repo does not exist or the caller may not
/// read `path`, using the same opaque response the git serve path returns so
/// existence is not confirmed. Returns the record and its visibility rules so a
/// content handler can apply an extra per-path check without a second DB query.
///
/// Callers pass `"/"` for repo-level reads (listings); content endpoints pass the
/// specific path so a withheld subtree is denied even on an otherwise-public repo.
pub(crate) async fn authorize_repo_read(
    state: &AppState,
    owner: &str,
    name: &str,
    caller: Option<&str>,
    path: &str,
) -> Result<(RepoRecord, Vec<VisibilityRule>)> {
    let record = state
        .db
        .get_repo(owner, name)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;
    let rules = state.db.list_visibility_rules(&record.id).await?;
    if visibility_check(&rules, record.is_public, &record.owner_did, caller, path) == Decision::Deny
    {
        return Err(AppError::RepoNotFound(format!("{owner}/{name}")));
    }
    Ok((record, rules))
}

/// Match a presented DID against a stored DID that may be the full `did:key:<id>`
/// form or the bare `<id>` short form (mirror rows store the bare key). Collapse
/// representation only within `did:key`; never let a bare id match across methods —
/// `did:web` / `did:gitlawb` share the base58 space with `did:key`, so a
/// trailing-segment compare would treat `did:key:X` and `did:gitlawb:X` as equal.
pub(crate) fn did_matches(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    fn key_id(d: &str) -> &str {
        d.strip_prefix("did:key:").unwrap_or(d)
    }
    let (ka, kb) = (key_id(a), key_id(b));
    // After stripping `did:key:`, a value still containing ':' is a non-key full
    // DID — do not let it match a bare `did:key` id.
    !ka.contains(':') && !kb.contains(':') && ka == kb
}

/// 403 unless `caller` is the repo owner. Uses [`did_matches`] so the owner check
/// and the author check (close policy) share one normalization.
pub(crate) fn require_repo_owner(record: &RepoRecord, caller: &str) -> Result<()> {
    if did_matches(caller, &record.owner_did) {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "only the repo owner can perform this action".into(),
        ))
    }
}

#[cfg(test)]
mod did_tests {
    use super::did_matches;

    #[test]
    fn full_matches_bare_same_key() {
        assert!(did_matches("did:key:zABC", "zABC"));
        assert!(did_matches("zABC", "did:key:zABC"));
    }

    #[test]
    fn rejects_cross_method_collision() {
        assert!(!did_matches("did:key:zABC", "did:gitlawb:zABC"));
        assert!(!did_matches("did:key:zABC", "did:web:zABC"));
    }

    #[test]
    fn exact_match_and_distinct_keys() {
        assert!(did_matches("did:key:zABC", "did:key:zABC"));
        assert!(!did_matches("did:key:zABC", "did:key:zXYZ"));
        assert!(!did_matches("zABC", "zXYZ"));
    }
}

/// Drift guard (plan 002 §Gate-type table, Step 5). Every in-scope mutation
/// handler must contain its expected gate marker in its own body; removing a
/// gate fails this test. Source-level (no DB), so it runs everywhere. When a new
/// route is added to an in-scope group, add its row here with a deliberate gate
/// type — that forced decision is the point.
///
/// Markers are gate-SHAPED — a call (`require_repo_owner(`, `did_matches(`) or a
/// binding/comparison expression (`caller != &record.owner_did`,
/// `let owner_did = auth.0`) — never a bare identifier that could also appear in
/// a log line. Full-line comments are stripped before matching, so a marker that
/// survives only as a comment above a deleted gate does NOT satisfy a row.
#[cfg(test)]
mod authz_guard {
    /// The body of `func` with full-line comments removed. Bounds the slice at the
    /// next top-level fn item so a marker in a later handler can't leak in,
    /// tolerating `pub async`, `pub(crate) async`, `async`, `pub`, and bare `fn`
    /// declarations (the old single-`pub async fn` delimiter over-ran on any other
    /// form).
    fn fn_body(src: &str, func: &str) -> String {
        let needle = format!("fn {func}(");
        let start = src
            .find(&needle)
            .unwrap_or_else(|| panic!("handler `{func}` not found (renamed or removed?)"));
        let rest = &src[start..];
        let end = [
            "\npub async fn ",
            "\npub(crate) async fn ",
            "\nasync fn ",
            "\npub fn ",
            "\nfn ",
        ]
        .iter()
        .filter_map(|p| rest[1..].find(p).map(|i| i + 1))
        .min()
        .unwrap_or(rest.len());
        rest[..end]
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn every_in_scope_mutation_has_its_gate() {
        let pulls = include_str!("pulls.rs");
        let webhooks = include_str!("webhooks.rs");
        let labels = include_str!("labels.rs");
        let issues = include_str!("issues.rs");
        let bounties = include_str!("bounties.rs");
        let replicas = include_str!("replicas.rs");
        let tasks = include_str!("tasks.rs");
        let stars = include_str!("stars.rs");
        let protect = include_str!("protect.rs");
        let visibility = include_str!("visibility.rs");
        let profiles = include_str!("profiles.rs");
        let repos = include_str!("repos.rs");
        let register = include_str!("register.rs");
        let ipfs = include_str!("ipfs.rs");

        // (source, handler, expected gate marker)
        let rows: &[(&str, &str, &str)] = &[
            // Bucket A — owner-gate (require_repo_owner -> 403)
            (pulls, "merge_pr", "require_repo_owner("),
            (webhooks, "create_webhook", "require_repo_owner("),
            (webhooks, "delete_webhook", "require_repo_owner("),
            (labels, "add_label", "require_repo_owner("),
            (labels, "remove_label", "require_repo_owner("),
            // Bucket A' — owner OR author (did_matches against the author)
            (pulls, "close_pr", "did_matches("),
            (issues, "close_issue", "did_matches("),
            // Bucket B — read-gate (authorize_repo_read)
            (pulls, "create_review", "authorize_repo_read("),
            (pulls, "create_comment", "authorize_repo_read("),
            (pulls, "create_pr", "authorize_repo_read("),
            (issues, "create_issue_comment", "authorize_repo_read("),
            (issues, "create_issue", "authorize_repo_read("),
            (bounties, "create_bounty", "authorize_repo_read("),
            (repos, "fork_repo", "authorize_repo_read("),
            // get_by_cid gates each iterated repo row directly via visibility_check
            // (KTD2a: it must NOT route through authorize_repo_read's fuzzy re-resolve).
            (ipfs, "get_by_cid", "visibility_check("),
            // Bucket C — signer-self: the acting DID is matched/bound to auth.0
            (tasks, "create_task", "did_matches("),
            (tasks, "claim_task", "did_matches("),
            (tasks, "complete_task", "did_matches("),
            (tasks, "fail_task", "did_matches("),
            (repos, "create_repo", "let owner_did = auth.0"),
            (profiles, "set_profile", "let did = auth.0"),
            (register, "register", "did_matches("),
            (stars, "star_repo", "caller = &auth.0"),
            (stars, "unstar_repo", "caller = &auth.0"),
            // Bucket D — non-owner-by-design, positive per-route marker
            (bounties, "claim_bounty", "claim_bounty(&id, &auth.0"),
            (bounties, "submit_bounty", "did_matches("),
            (bounties, "approve_bounty", "did_matches("),
            (bounties, "cancel_bounty", "did_matches("),
            (bounties, "dispute_bounty", "did_matches("),
            (replicas, "register_replica", "did_matches("),
            (replicas, "unregister_replica", "replica_did = &auth.0"),
            // PRE-GATED — already owner-gated, in-scope group; guard the gate itself
            (protect, "protect_branch", "did_matches("),
            (protect, "unprotect_branch", "did_matches("),
            (visibility, "set_visibility", "require_owner("),
            (visibility, "remove_visibility", "require_owner("),
            (visibility, "list_visibility", "require_owner("),
        ];

        // The visibility rows prove require_owner is CALLED; this proves the helper
        // itself does DID-safe matching, not a raw/trailing-segment compare.
        assert!(
            fn_body(visibility, "require_owner").contains("did_matches("),
            "visibility::require_owner must use did_matches for DID-safe owner matching"
        );

        for (src, func, marker) in rows {
            let body = fn_body(src, func);
            assert!(
                body.contains(marker),
                "handler `{func}` is missing its gate marker `{marker}` — gate removed or route reclassified"
            );
        }
    }

    /// Proves the comment-stripping that GUARD-1 added: a marker that appears only
    /// in a full-line comment (the real `replicas.rs` false-pass shape) must NOT
    /// satisfy a row.
    #[test]
    fn comment_only_marker_does_not_satisfy_a_row() {
        let src = "pub async fn demo() {\n    // did_matches( handles the owner form\n    do_thing();\n}\n";
        assert!(
            !fn_body(src, "demo").contains("did_matches("),
            "a marker present only in a comment must not count as an enforced gate"
        );
    }
}
