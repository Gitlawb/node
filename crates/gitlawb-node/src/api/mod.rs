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
    // A quarantined mirror (admitted by the iCaptcha propagation gate but not
    // validated) is hidden from every reader — serve/clone and fork alike — as if
    // it did not exist, until an operator releases it. Checked before the
    // visibility gate so its existence is never disclosed.
    if state.db.is_repo_quarantined(&record.id).await? {
        return Err(AppError::RepoNotFound(format!("{owner}/{name}")));
    }
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
            // list_webhooks layers authorize_repo_read (404 hides a private repo)
            // before the owner gate; the require_repo_owner marker guards the 403.
            (webhooks, "list_webhooks", "require_repo_owner("),
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
            // #94 sibling read surfaces: gate private-repo metadata on read
            // visibility (public repos stay anonymous; private repos 404).
            (replicas, "list_replicas", "authorize_repo_read("),
            (protect, "list_protected_branches", "authorize_repo_read("),
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

    /// All `pub async fn` / `pub(crate) async fn` handler names declared in `src`.
    /// Verb-agnostic on purpose: a repo-scoped read of any name is in scope, so a
    /// handler named `fetch_*` / `replicate_*` / `info_refs` cannot escape the gate
    /// check by not being called `list_*` / `get_*`.
    fn handler_names(src: &str) -> Vec<String> {
        ["pub async fn ", "pub(crate) async fn "]
            .iter()
            .flat_map(|decl| {
                src.match_indices(decl).map(move |(i, _)| {
                    src[i + decl.len()..]
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect::<String>()
                })
            })
            .collect()
    }

    /// True when the handler's signature takes an owner+repo path
    /// (`Path<(String, String...)>`), i.e. it is a repo-scoped read rather than a
    /// node-wide aggregate (`/stats`, `/ipfs/pins`, the global feeds).
    fn is_repo_scoped(body: &str) -> bool {
        let header = &body[..body.find('{').unwrap_or(body.len())];
        header.contains("Path<(String, String")
    }

    /// True when at least one gate marker runs for EVERY service — i.e. some
    /// marker sits outside any `if service == ...` discriminator block. A gate
    /// that appears ONLY inside such a block (as the info/refs advertisement gate
    /// did before #119: `visibility_check` ran under `if service ==
    /// "git-upload-pack"`, leaving `git-receive-pack` ungated) covers a subset of
    /// services and must NOT count as a full gate. Other handlers carry no
    /// `service ==` discriminator, so for them this matches the plain
    /// substring check. NOTE: only `if service ==` is detected — a
    /// `match service { .. }` discriminator is NOT tracked and a gate inside one
    /// arm would pass as full; avoid that shape, or extend the span loop below.
    fn gate_runs_unconditionally(body: &str, markers: &[&str]) -> bool {
        // Brace-matched spans of each `if service == ...` block.
        let mut cond_spans: Vec<(usize, usize)> = Vec::new();
        let mut search = 0;
        while let Some(rel) = body[search..].find("if service ==") {
            let cond_start = search + rel;
            let Some(brace_rel) = body[cond_start..].find('{') else {
                break;
            };
            let open = cond_start + brace_rel;
            let mut depth = 0i32;
            let mut end = body.len();
            for (i, c) in body[open..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = open + i;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            cond_spans.push((open, end));
            // On an unclosed block `end` stays at body.len() (the fail-safe
            // direction: treat the rest as conditional rather than mask a gate);
            // clamp so the next slice can't index past the end and panic.
            search = (end + 1).min(body.len());
        }
        markers.iter().any(|m| {
            body.match_indices(m)
                .any(|(pos, _)| !cond_spans.iter().any(|(s, e)| pos >= *s && pos <= *e))
        })
    }

    /// Egress gate guard: every repo-scoped handler (`Path<(String, String..)>`)
    /// must carry an authz marker — a read gate (`authorize_repo_read` /
    /// `visibility_check`), or a write gate (`require_repo_owner` / `require_owner`
    /// / `did_matches` / a `&auth.0` self-binding) — or be listed in KNOWN_UNGATED
    /// (the tracked, ungated reads). A new ungated handler of ANY verb trips this,
    /// and a completeness scan over `src/api/` trips it for a whole new module that
    /// adds a repo-scoped handler without being wired into `sources`. Mutations are
    /// also checked precisely, per handler, by the mutation guard above; here they
    /// only need *some* binding so the net stays verb-agnostic.
    ///
    /// Scope and limits (this is a source scrape; the runtime route guard covers
    /// behaviour):
    /// - It proves a gate is CALLED, not that it runs on the requested path: a
    ///   content handler gating `"/"` instead of the subtree still passes here.
    /// - It sees handlers taking the owner+repo tuple `Path<(String, String..)>`; a
    ///   repo identified by a struct/custom extractor would be missed (the helper
    ///   unit tests pin these boundaries).
    /// - KNOWN_UNGATED entries need a real open issue and review; the staleness
    ///   assert removes one only once its gate lands.
    #[test]
    fn every_repo_scoped_handler_is_gated() {
        let sources: &[(&str, &str)] = &[
            (include_str!("bounties.rs"), "bounties.rs"),
            (include_str!("certs.rs"), "certs.rs"),
            (include_str!("changelog.rs"), "changelog.rs"),
            (include_str!("encrypted.rs"), "encrypted.rs"),
            (include_str!("events.rs"), "events.rs"),
            (include_str!("issues.rs"), "issues.rs"),
            (include_str!("labels.rs"), "labels.rs"),
            (include_str!("protect.rs"), "protect.rs"),
            (include_str!("pulls.rs"), "pulls.rs"),
            (include_str!("replicas.rs"), "replicas.rs"),
            (include_str!("repos.rs"), "repos.rs"),
            (include_str!("stars.rs"), "stars.rs"),
            (include_str!("visibility.rs"), "visibility.rs"),
            (include_str!("webhooks.rs"), "webhooks.rs"),
        ];
        let listed: std::collections::HashSet<&str> = sources.iter().map(|(_, f)| *f).collect();
        assert!(!listed.is_empty(), "read-guard `sources` is empty");

        // Completeness: every api/*.rs NOT already in `sources` must declare no
        // repo-scoped handler, so a brand-new module cannot add an ungated handler
        // the scrape never looks at. Reads the directory at test time (so the list
        // cannot silently drift from the filesystem) and only inspects unlisted
        // files — listed files are covered by the per-handler loop below.
        let api_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/api");
        for (_, f) in sources {
            assert!(
                std::path::Path::new(api_dir).join(f).exists(),
                "read-guard `sources` lists {f} but the file does not exist"
            );
        }
        for entry in std::fs::read_dir(api_dir).expect("read src/api") {
            let path = entry.expect("dir entry").path();
            let fname = path.file_name().unwrap().to_string_lossy().into_owned();
            if !fname.ends_with(".rs") || fname == "mod.rs" || listed.contains(fname.as_str()) {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("read api file");
            let has_repo_handler = handler_names(&src)
                .iter()
                .any(|n| is_repo_scoped(&fn_body(&src, n)));
            assert!(
                !has_repo_handler,
                "api/{fname} declares a repo-scoped handler but is not in the egress \
                 guard `sources` list — add it so its handlers are gate-checked"
            );
        }

        // Repo-scoped reads known to be ungated today, each tracked by an issue.
        // Remove an entry the moment its gate lands (the staleness assert enforces it).
        let known_ungated: &[(&str, &str)] = &[
            // info/refs gates only git-upload-pack today; git-receive-pack
            // advertisement is ungated until #119 makes the gate unconditional.
            ("git_info_refs", "#119"),
            ("list_certs", "#120"),
            ("get_cert", "#120"),
            ("list_issues", "#120"),
            ("get_issue", "#120"),
            ("list_issue_comments", "#120"),
            ("list_labels", "#120"),
            ("list_repo_bounties", "#120"),
            ("get_star_status", "#120"),
            ("list_repo_events", "#94 (PR #113)"),
            ("list_webhooks", "#94 (PR #113)"),
            ("list_replicas", "PR #113"),
            ("list_protected_branches", "PR #113"),
        ];
        let is_known = |n: &str| known_ungated.iter().any(|(k, _)| *k == n);
        // Any one of these = the handler binds the caller to an authz decision: the
        // first two are read gates, the rest are the write/owner/self-binding forms.
        // A repo-scoped mutation passes here on its write gate; the mutation guard
        // above additionally verifies the exact gate type per handler. NOTE: a local
        // rename of `caller`/`replica_did` must be paired with a marker update here.
        let markers = [
            "authorize_repo_read(",
            "visibility_check(",
            "require_repo_owner(",
            "require_owner(",
            "did_matches(",
            "caller = &auth.0",
            "replica_did = &auth.0",
        ];

        // Every KNOWN_UNGATED name must be a real handler (catch typos / renames).
        let all: std::collections::HashSet<String> =
            sources.iter().flat_map(|(s, _)| handler_names(s)).collect();
        for (n, _) in known_ungated {
            assert!(
                all.contains(*n),
                "KNOWN_UNGATED lists `{n}`, which is not a real handler (renamed or removed?)"
            );
        }

        let mut checked = 0usize;
        for (src, file) in sources {
            for name in handler_names(src) {
                let body = fn_body(src, &name);
                if !is_repo_scoped(&body) {
                    continue; // node-wide aggregate, not a repo-scoped surface
                }
                checked += 1;
                let gated = gate_runs_unconditionally(&body, &markers);
                assert!(
                    gated || is_known(&name),
                    "repo-scoped handler `{name}` ({file}) has no authz gate and is \
                     not in KNOWN_UNGATED — add the visibility/owner gate with the \
                     caller, or track it there"
                );
                assert!(
                    !(gated && is_known(&name)),
                    "handler `{name}` ({file}) is now gated — remove it from \
                     KNOWN_UNGATED so the allowlist stays an accurate gap list"
                );
            }
        }
        // Tripwire: if the scrape silently stopped finding handlers (e.g. a parser
        // regression in handler_names/is_repo_scoped), this floor fails loudly
        // instead of the guard passing vacuously. Current count is ~54 repo-scoped
        // handlers; 20 is a deliberate floor that trips only on a gross regression.
        assert!(
            checked >= 20,
            "egress guard only checked {checked} repo-scoped handlers — the scrape likely broke"
        );
    }

    /// Pins the `handler_names` boundary: it collects every `pub`/`pub(crate)
    /// async fn` regardless of verb (so a `fetch_*` read cannot escape), and skips
    /// private `async fn` and sync `fn` helpers.
    #[test]
    fn handler_names_finds_all_pub_async_and_skips_others() {
        let src = "pub async fn list_things() {}\n\
                   pub async fn fetch_thing() {}\n\
                   pub(crate) async fn get_crate_thing() {}\n\
                   async fn private_helper() {}\n\
                   fn sync_helper() {}\n";
        let names = handler_names(src);
        // Verb-agnostic: a non-list/get read verb is still seen.
        assert!(names.contains(&"list_things".to_string()));
        assert!(names.contains(&"fetch_thing".to_string()));
        // pub(crate) routed handlers are in scope too.
        assert!(names.contains(&"get_crate_thing".to_string()));
        // Private/sync helpers are not routed handlers and are skipped.
        assert!(!names
            .iter()
            .any(|n| n == "private_helper" || n == "sync_helper"));
    }

    /// Pins the `is_repo_scoped` boundary: an owner+repo tuple Path is repo-scoped;
    /// a single-segment or absent Path is a node-wide aggregate.
    #[test]
    fn is_repo_scoped_requires_owner_repo_path() {
        let repo =
            "fn get_x(s: State, Path((owner, name)): Path<(String, String)>) {\n  body();\n}";
        let three = "fn get_y(Path((o, n, id)): Path<(String, String, String)>) {\n  body();\n}";
        let node_wide = "fn list_z(s: State<AppState>) {\n  body();\n}";
        let single = "fn get_w(Path(cid): Path<String>) {\n  body();\n}";
        assert!(is_repo_scoped(repo), "owner+repo tuple is repo-scoped");
        assert!(is_repo_scoped(three), "owner+repo+id tuple is repo-scoped");
        assert!(!is_repo_scoped(node_wide), "no Path is node-wide");
        assert!(
            !is_repo_scoped(single),
            "single-segment Path is not repo-scoped"
        );
    }

    /// Pins `gate_runs_unconditionally`: a gate nested only inside an
    /// `if service == ...` block is conditional (does NOT count), while the same
    /// gate at the top level — or an additional unconditional one — does.
    #[test]
    fn conditional_service_gate_is_not_a_full_gate() {
        let markers = ["visibility_check("];
        // Gate runs only for one service: not a full gate.
        let conditional = "fn f() {\n  \
            if service == \"git-upload-pack\" {\n    \
                visibility_check(rules, caller);\n  \
            }\n  \
            if service == \"git-receive-pack\" { acquire_fresh(); }\n}";
        assert!(
            !gate_runs_unconditionally(conditional, &markers),
            "a gate only inside `if service ==` covers a subset of services"
        );
        // Same gate at top level: full gate.
        let unconditional = "fn f() {\n  \
            visibility_check(rules, caller);\n  \
            if service == \"git-receive-pack\" { acquire_fresh(); }\n}";
        assert!(
            gate_runs_unconditionally(unconditional, &markers),
            "an unconditional gate runs for every service"
        );
        // A gate inside EACH of two service blocks, none outside: still a
        // subset (no service clears it unconditionally), so not a full gate.
        let both_conditional = "fn f() {\n  \
            if service == \"git-upload-pack\" { visibility_check(a); }\n  \
            if service == \"git-receive-pack\" { visibility_check(b); }\n}";
        assert!(
            !gate_runs_unconditionally(both_conditional, &markers),
            "a gate inside every service block is still conditional"
        );
        // A marker inside one block AND again unconditionally: the
        // unconditional occurrence makes it a full gate (exercises the
        // match_indices scan past the in-block hit).
        let inside_and_outside = "fn f() {\n  \
            if service == \"git-upload-pack\" { visibility_check(a); }\n  \
            visibility_check(b);\n}";
        assert!(
            gate_runs_unconditionally(inside_and_outside, &markers),
            "an unconditional occurrence counts even when another is conditional"
        );
        // No marker at all: not gated.
        assert!(!gate_runs_unconditionally(
            "fn f() { do_thing(); }",
            &markers
        ));
        // An unclosed `if service ==` block (e.g. phantom brace from a string
        // literal) must not panic on the slice advance; the span runs to EOF, so
        // the in-block marker reads as conditional. Real Rust source is balanced,
        // so this only guards the scraper against a future pathological body.
        let unclosed = "fn f() { if service == \"x\" { visibility_check(a);";
        assert!(
            !gate_runs_unconditionally(unclosed, &markers),
            "an unclosed service block must not panic and stays conditional"
        );
    }
}
