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

    #[test]
    fn empty_did_matches() {
        assert!(did_matches("", ""));
        assert!(did_matches("", "did:key:"));
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

    /// Completeness fence over the GraphQL mutation surface: the mirror of
    /// `every_in_scope_mutation_has_its_gate` for `graphql/mutation.rs`. Kept a
    /// SEPARATE guard with its own table (never folded into the REST rows above):
    /// a guard over a heterogeneous set must classify per member, and these
    /// same-named task rows belong to the GraphQL surface, not `api/tasks.rs`.
    ///
    /// COMPLETENESS comes from the engine's own SDL (`schema.sdl()`), parsed as a
    /// structured AST (#219), NOT introspection and NOT a text parse of source.
    /// This matters: async-graphql OMITS `#[graphql(visible = false)]` fields from
    /// introspection while leaving them executable, so an introspection-sourced fence
    /// could be defeated by a hidden mutation. SDL includes those fields, so no
    /// visibility flag (and, via the AST parse, no brace-in-description quirk) can hide
    /// a live mutation. The SDL field set must equal the registered set: a new field with
    /// no row fails (a repo-write cannot slip in unlisted); a registered name absent from
    /// the schema fails (renamed or removed). The set is also cross-checked against
    /// introspection, so any field present in SDL but hidden from introspection fails
    /// named as a forbidden hidden mutation.
    ///
    /// The MARKER check is the only source-scraped part, and it is not the
    /// completeness guarantee. Three honest limits, so a green check is not misread
    /// as full authorization coverage:
    ///   1. A present marker is not load-bearingness (the gate may not redden on a
    ///      hostile probe: the #203 present-but-vacuous case). The adversarial tests
    ///      in `graphql/mutation.rs` are the load-bearing layer.
    ///   2. A present marker is not gate-correctness (it may be the wrong bucket for
    ///      the operation's resource: a repo-write registered as signer-self would
    ///      pass, so INV-1 review remains the defense).
    ///   3. The marker check scrapes the comment-masked, brace-bounded resolver body;
    ///      a `{`/`}` or a `did_matches(` inside a STRING literal is not masked, so it
    ///      could mis-slice that body or satisfy the marker vacuously (the same
    ///      vacuous-marker class as limit 1). Completeness is unaffected: it comes
    ///      from the SDL AST, not from this scrape.
    #[test]
    fn every_graphql_mutation_has_its_gate() {
        // (Rust snake name, schema field in camelCase, expected gate marker). The
        // four are Bucket C signer-self (`did_matches(`); a repo-write would be
        // Bucket A (`require_repo_owner(`). Same-named REST rows live in the guard
        // above against `api/tasks.rs`.
        let registered: &[(&str, &str, &str)] = &[
            ("create_task", "createTask", "did_matches("),
            ("claim_task", "claimTask", "did_matches("),
            ("complete_task", "completeTask", "did_matches("),
            ("fail_task", "failTask", "did_matches("),
        ];

        // Completeness source is the SDL (#219): it includes visible=false mutations,
        // which introspection omits. Cross-check against introspection first so a hidden
        // mutation fails with a specific, actionable message rather than a generic
        // "unclassified".
        let fields = graphql_mutation_fields_from_sdl();
        let introspected = graphql_mutation_fields_from_schema();
        for f in &fields {
            assert!(
                introspected.iter().any(|i| i == f),
                "GraphQL mutation `{f}` is in the schema but hidden from introspection \
                 (a `#[graphql(visible = false)]` field): hidden mutations are forbidden \
                 by this fence — make it visible so its classification is enforceable, or \
                 remove it"
            );
        }

        // Completeness both directions against the authoritative (SDL) field set.
        for f in &fields {
            assert!(
                registered.iter().any(|(_, camel, _)| camel == f),
                "unclassified GraphQL mutation `{f}`: add it to \
                 every_graphql_mutation_has_its_gate with a deliberate gate \
                 (`require_repo_owner(` for a repo-write, `did_matches(` for a task op)"
            );
        }
        for (_, camel, _) in registered {
            assert!(
                fields.iter().any(|f| f == camel),
                "registered GraphQL mutation `{camel}` is not in the schema \
                 (renamed or removed); update the table"
            );
        }

        // Marker present (source scrape; the vacuity limit, backstopped by the
        // adversarial tests): each resolver body carries its bucket marker.
        let masked = mask_comments(include_str!("../graphql/mutation.rs"));
        for (snake, _, marker) in registered {
            let body = resolver_body(&masked, snake);
            assert!(
                body.contains(marker),
                "GraphQL mutation `{snake}` is missing its gate marker `{marker}`: gate removed"
            );
        }
    }

    /// Version-safety self-check (#219, INV-21): the fence's completeness guarantee rests
    /// on `schema.sdl()` INCLUDING `visible = false` fields while introspection omits
    /// them. That is observed async-graphql behavior, not a documented contract, so pin
    /// it here: a synthetic schema with a hidden mutation must have that field in its
    /// SDL-derived set and NOT in its introspection-derived set. If a future
    /// async-graphql upgrade ever filters SDL by visibility, the first assertion flips
    /// RED — the assumption is load-bearing, not trusted.
    #[test]
    fn sdl_source_sees_hidden_mutations_that_introspection_omits() {
        use async_graphql::{EmptySubscription, Object, Schema, Value};
        struct Q;
        #[Object]
        impl Q {
            async fn ping(&self) -> i32 {
                0
            }
        }
        struct M;
        #[Object]
        impl M {
            async fn visible_mut(&self) -> i32 {
                1
            }
            #[graphql(visible = false)]
            async fn hidden_mut(&self) -> i32 {
                2
            }
        }
        let schema = Schema::build(Q, M, EmptySubscription).finish();

        // SDL source (the fix): includes the hidden field.
        let sdl_fields = mutation_field_names_from_sdl(&schema.sdl());
        assert!(
            sdl_fields.iter().any(|f| f == "hiddenMut"),
            "SDL-sourced set MUST include the visible=false mutation; if this is RED, \
             async-graphql started filtering SDL by visibility and the fence's \
             completeness guarantee is broken: {sdl_fields:?}"
        );

        // Introspection (the OLD source): omits the hidden field. This is the exact gap
        // the fix closes — an introspection-sourced fence never sees `hiddenMut`.
        let resp = tokio::runtime::Runtime::new()
            .expect("tokio runtime")
            .block_on(schema.execute("{ __schema { mutationType { fields { name } } } }"));
        let mut introspected = Vec::new();
        if let Value::Object(root) = &resp.data {
            if let Some(Value::Object(sc)) = root.get("__schema") {
                if let Some(Value::Object(mt)) = sc.get("mutationType") {
                    if let Some(Value::List(fl)) = mt.get("fields") {
                        for fo in fl {
                            if let Value::Object(o) = fo {
                                if let Some(Value::String(n)) = o.get("name") {
                                    introspected.push(n.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
        assert!(
            !introspected.iter().any(|f| f == "hiddenMut"),
            "introspection is expected to OMIT the visible=false mutation (that is the \
             gap the SDL source closes); got {introspected:?}"
        );

        // The exact diff the fence computes: hidden ∈ (sdl \ introspection).
        let hidden: Vec<&String> = sdl_fields
            .iter()
            .filter(|f| !introspected.iter().any(|i| i == *f))
            .collect();
        assert_eq!(
            hidden,
            vec!["hiddenMut"],
            "the SDL-vs-introspection diff must surface exactly the hidden mutation"
        );
    }

    /// The mutation field names (camelCase, as async-graphql exposes them) via the
    /// engine's own introspection. STRUCTURED: the names arrive as data, so nothing in
    /// the resolver source or the serialized SDL (a brace in a doc description, a
    /// comment, a string) can hide a field. The schema builds with no data and
    /// introspection runs no resolver, so this stays a plain DB-free unit test. A
    /// navigation miss yields an empty list, which fails loud via the set-equality
    /// above (a registered name reads as "not in the schema"), never vacuously.
    fn graphql_mutation_fields_from_schema() -> Vec<String> {
        use crate::graphql::mutation::MutationRoot;
        use crate::graphql::query::QueryRoot;
        use crate::graphql::subscription::SubscriptionRoot;
        use async_graphql::Value;
        let schema =
            async_graphql::Schema::build(QueryRoot, MutationRoot, SubscriptionRoot).finish();
        let resp = tokio::runtime::Runtime::new()
            .expect("tokio runtime")
            .block_on(schema.execute("{ __schema { mutationType { fields { name } } } }"));
        assert!(
            resp.errors.is_empty(),
            "schema introspection failed: {:?}",
            resp.errors
        );
        let mut names = Vec::new();
        if let Value::Object(root) = &resp.data {
            if let Some(Value::Object(sc)) = root.get("__schema") {
                if let Some(Value::Object(mt)) = sc.get("mutationType") {
                    if let Some(Value::List(field_list)) = mt.get("fields") {
                        for field in field_list {
                            if let Value::Object(fo) = field {
                                if let Some(Value::String(n)) = fo.get("name") {
                                    names.push(n.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
        names
    }

    /// The mutation field names sourced from the built schema's SDL — the completeness
    /// source (#219). Builds the same DB-free schema as the introspection helper and runs
    /// its `.sdl()` (sync, no runtime needed) through [`mutation_field_names_from_sdl`].
    /// SDL includes `#[graphql(visible = false)]` fields, so this source cannot be
    /// defeated by hiding a mutation from introspection.
    fn graphql_mutation_fields_from_sdl() -> Vec<String> {
        use crate::graphql::mutation::MutationRoot;
        use crate::graphql::query::QueryRoot;
        use crate::graphql::subscription::SubscriptionRoot;
        let schema =
            async_graphql::Schema::build(QueryRoot, MutationRoot, SubscriptionRoot).finish();
        mutation_field_names_from_sdl(&schema.sdl())
    }

    /// The mutation type's field names extracted from an async-graphql SDL string via
    /// the engine's OWN parser AST (`async_graphql::parser::parse_schema`), NOT
    /// introspection. This is the completeness source (#219): unlike introspection,
    /// which async-graphql filters by `visible` (a `#[graphql(visible = false)]`
    /// mutation is executable but ABSENT from introspection), `schema.sdl()` includes
    /// every registered field, so a hidden mutation still appears here and must carry a
    /// classified row. Parsing the AST (not a brace/line text scan) means a `}` inside a
    /// field description cannot mis-slice the type block. camelCase, as async-graphql
    /// emits. An empty result on a navigation miss is safe: the set-equality in
    /// `every_graphql_mutation_has_its_gate` turns "no fields" into a loud failure for
    /// every registered name, never a vacuous pass.
    fn mutation_field_names_from_sdl(sdl: &str) -> Vec<String> {
        use async_graphql::parser::parse_schema;
        use async_graphql::parser::types::{TypeKind, TypeSystemDefinition};

        let doc = parse_schema(sdl).expect("async-graphql SDL must parse");
        // The mutation root type name: from the `schema { mutation: X }` block if
        // present, else the GraphQL default "Mutation".
        let mutation_type = doc
            .definitions
            .iter()
            .find_map(|def| match def {
                TypeSystemDefinition::Schema(s) => s
                    .node
                    .mutation
                    .as_ref()
                    .map(|m| m.node.as_str().to_string()),
                _ => None,
            })
            .unwrap_or_else(|| "Mutation".to_string());
        // The fields of that object type.
        doc.definitions
            .iter()
            .find_map(|def| match def {
                TypeSystemDefinition::Type(t) if t.node.name.node.as_str() == mutation_type => {
                    match &t.node.kind {
                        TypeKind::Object(obj) => Some(
                            obj.fields
                                .iter()
                                .map(|f| f.node.name.node.as_str().to_string())
                                .collect::<Vec<_>>(),
                        ),
                        _ => None,
                    }
                }
                _ => None,
            })
            .unwrap_or_default()
    }

    #[test]
    fn sdl_extractor_includes_a_hidden_visible_false_field() {
        // A field that would be hidden from introspection must still be listed from SDL.
        let sdl = "schema { query: QueryRoot mutation: MutationRoot }\n\
                   type QueryRoot { ping: Int! }\n\
                   type MutationRoot { createTask: Int! hiddenMut: Int! }\n";
        let fields = mutation_field_names_from_sdl(sdl);
        assert!(
            fields.iter().any(|f| f == "createTask"),
            "visible field must be listed: {fields:?}"
        );
        assert!(
            fields.iter().any(|f| f == "hiddenMut"),
            "a visible=false field (present in SDL, hidden from introspection) MUST be \
             listed by the completeness source: {fields:?}"
        );
    }

    #[test]
    fn sdl_extractor_is_not_fooled_by_a_brace_in_a_field_description() {
        // A `}` inside a field description must not truncate the type block (the AST
        // parse is immune to the text-parse quirk the old design feared).
        let sdl = "schema { query: QueryRoot mutation: MutationRoot }\n\
                   type QueryRoot { ping: Int! }\n\
                   type MutationRoot {\n\
                     \"\"\"a description with a } brace and { another\"\"\"\n\
                     createTask: Int!\n\
                     claimTask: Int!\n\
                   }\n";
        let fields = mutation_field_names_from_sdl(sdl);
        assert!(
            fields.iter().any(|f| f == "createTask") && fields.iter().any(|f| f == "claimTask"),
            "both fields must be extracted despite a brace in a description: {fields:?}"
        );
    }

    #[test]
    fn sdl_extractor_returns_empty_for_a_query_only_schema() {
        let sdl = "schema { query: QueryRoot }\ntype QueryRoot { ping: Int! }\n";
        assert!(
            mutation_field_names_from_sdl(sdl).is_empty(),
            "a schema with no mutation root yields no mutation fields (no panic)"
        );
    }

    /// The comment-masked body of `async fn <snake>` in `graphql/mutation.rs`, bounded
    /// to the resolver's OWN braces (its `{ .. }`), for the marker check. Brace-matching
    /// on the comment-masked source means a `}` in a trailing helper cannot extend the
    /// body and a comment marker does not count. A `{`/`}` inside a STRING literal is
    /// not masked, a documented marker-check-only residual (limit 3); completeness does
    /// not use this.
    fn resolver_body(masked_src: &str, snake: &str) -> String {
        let needle = format!("async fn {snake}(");
        let start = masked_src.find(&needle).unwrap_or_else(|| {
            panic!("resolver `async fn {snake}(` not found in graphql/mutation.rs")
        });
        let open = start
            + masked_src[start..]
                .find('{')
                .expect("resolver body opening brace");
        let mut depth = 0i32;
        let mut end = masked_src.len();
        for (i, c) in masked_src[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        masked_src[open..end].to_string()
    }

    /// `src` with `//` line comments and `/* */` block comments (nested) blanked to
    /// spaces, WITHOUT opening a comment inside a `"..."` string (so a `"https://"` does
    /// not erase the rest of its line). String CONTENTS are left intact, so a brace or
    /// a gate marker inside a string is not masked; for the marker check that is a
    /// documented vacuity residual (limit 3), and completeness does not use this at
    /// all. Char literals and raw/byte strings are not tracked (absent in resolver
    /// bodies); a `'"'` char or a raw string is the remaining narrow residual.
    fn mask_comments(src: &str) -> String {
        let chars: Vec<char> = src.chars().collect();
        let mut out = String::with_capacity(src.len());
        let mut i = 0;
        let mut block_depth = 0usize;
        let mut in_string = false;
        while i < chars.len() {
            let c = chars[i];
            let next = chars.get(i + 1).copied();
            if block_depth > 0 {
                if c == '/' && next == Some('*') {
                    block_depth += 1;
                    out.push_str("  ");
                    i += 2;
                } else if c == '*' && next == Some('/') {
                    block_depth -= 1;
                    out.push_str("  ");
                    i += 2;
                } else {
                    out.push(if c == '\n' { '\n' } else { ' ' });
                    i += 1;
                }
            } else if in_string {
                out.push(c);
                if c == '\\' {
                    if let Some(n) = next {
                        out.push(n);
                        i += 2;
                    } else {
                        i += 1;
                    }
                } else {
                    if c == '"' {
                        in_string = false;
                    }
                    i += 1;
                }
            } else if c == '"' {
                in_string = true;
                out.push('"');
                i += 1;
            } else if c == '/' && next == Some('/') {
                while i < chars.len() && chars[i] != '\n' {
                    out.push(' ');
                    i += 1;
                }
            } else if c == '/' && next == Some('*') {
                block_depth = 1;
                out.push_str("  ");
                i += 2;
            } else {
                out.push(c);
                i += 1;
            }
        }
        out
    }

    /// The introspection field set (the completeness source of truth) is exactly the
    /// registered mutations. If async-graphql adds or renames a field, this reddens
    /// and forces the `every_graphql_mutation_has_its_gate` table to be updated.
    #[test]
    fn schema_lists_exactly_the_registered_mutations() {
        let mut fields = graphql_mutation_fields_from_schema();
        fields.sort();
        assert_eq!(
            fields,
            vec!["claimTask", "completeTask", "createTask", "failTask"],
            "the introspected mutation field set is the authoritative discovered set"
        );
    }

    /// The marker check is bounded to a resolver's OWN body and is comment- and
    /// string-aware: a `//` inside a `"https://"` string does not erase a real gate on
    /// that line (no false-red), and a trailing module helper's `did_matches(` does not
    /// rescue a resolver whose own gate was removed (no false-green).
    #[test]
    fn resolver_body_is_bounded_and_comment_and_string_aware() {
        let src = "\
impl MutationRoot {
    async fn ok(&self) -> Result<u32> {
        let _ = (\"see https://x/y\", did_matches(a, b)); // URL string then gate, one line
        Ok(0)
    }
    async fn last(&self) -> Result<u32> {
        // did_matches( only in a comment
        Ok(0)
    }
}
fn helper() { let _ = did_matches(z, z); }
#[cfg(test)]
mod tests { async fn t() { let _ = did_matches(x, y); } }
";
        let masked = mask_comments(src);
        assert!(
            resolver_body(&masked, "ok").contains("did_matches("),
            "a `//` inside a string must not erase the real gate on that line"
        );
        assert!(
            !resolver_body(&masked, "last").contains("did_matches("),
            "the marker check must be bounded to the resolver's own body (a trailing \
             helper's marker must not rescue a resolver whose gate was removed)"
        );
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

    /// Collect `.rs` source files under `dir`. Recursive so the completeness scan
    /// covers nested API modules (`api/<module>/mod.rs` and deeper), not only the
    /// immediate `api/*.rs` children.
    fn collect_rs_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).expect("read api dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                out.extend(collect_rs_files(&path));
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
        out
    }

    /// The `.rs` files under `api_root` (as paths RELATIVE to it) that the
    /// completeness scan must inspect: everything except the top-level `mod.rs` (the
    /// guard file itself) and the top-level files already covered by the per-handler
    /// `sources` loop. A nested `api/<module>/<name>.rs` is a distinct source file
    /// even when its basename matches a listed top-level file, so it stays in scope.
    fn unlisted_source_files(
        api_root: &std::path::Path,
        listed: &std::collections::HashSet<&str>,
    ) -> Vec<String> {
        collect_rs_files(api_root)
            .iter()
            .filter_map(|path| {
                let rel = path
                    .strip_prefix(api_root)
                    .ok()?
                    .to_string_lossy()
                    .replace('\\', "/");
                if rel == "mod.rs" || listed.contains(rel.as_str()) {
                    None
                } else {
                    Some(rel)
                }
            })
            .collect()
    }

    #[test]
    fn collect_rs_files_recurses_subdirs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("a.rs"), "").unwrap();
        std::fs::write(root.join("note.txt"), "").unwrap();
        std::fs::create_dir_all(root.join("sub/deep")).unwrap();
        std::fs::write(root.join("sub/mod.rs"), "").unwrap();
        std::fs::write(root.join("sub/deep/c.rs"), "").unwrap();
        let names: std::collections::HashSet<String> = collect_rs_files(root)
            .iter()
            .map(|p| {
                p.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert!(names.contains("a.rs"));
        assert!(
            names.contains("sub/mod.rs"),
            "nested module file must be collected"
        );
        assert!(
            names.contains("sub/deep/c.rs"),
            "deeply nested file must be collected"
        );
        assert!(
            !names.iter().any(|n| n.ends_with(".txt")),
            "non-rs files excluded"
        );
        assert_eq!(names.len(), 3);
    }

    // P3 (#119): the completeness scan must skip already-covered files by their path
    // RELATIVE to api_root, not by basename. A nested api/<module>/repos.rs is a
    // distinct source file from the covered top-level repos.rs and must still be
    // scanned, or a new nested module could smuggle in an ungated repo-scoped handler
    // behind a colliding filename.
    #[test]
    fn unlisted_source_files_scans_nested_file_with_colliding_basename() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("repos.rs"), "").unwrap();
        std::fs::write(root.join("mod.rs"), "").unwrap();
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/repos.rs"), "").unwrap();
        std::fs::write(root.join("sub/fresh.rs"), "").unwrap();
        let listed: std::collections::HashSet<&str> = ["repos.rs"].into_iter().collect();

        let unlisted = unlisted_source_files(root, &listed);

        assert!(
            unlisted.contains(&"sub/repos.rs".to_string()),
            "a nested file whose basename matches a listed top-level file must still be scanned"
        );
        assert!(
            unlisted.contains(&"sub/fresh.rs".to_string()),
            "a nested file with a unique name must be scanned"
        );
        assert!(
            !unlisted.contains(&"repos.rs".to_string()),
            "the listed top-level file is covered by the per-handler loop"
        );
        assert!(
            !unlisted.contains(&"mod.rs".to_string()),
            "the top-level guard file is skipped"
        );
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
        let api_root = std::path::Path::new(api_dir);
        for rel in unlisted_source_files(api_root, &listed) {
            let src = std::fs::read_to_string(api_root.join(&rel)).expect("read api file");
            let has_repo_handler = handler_names(&src)
                .iter()
                .any(|n| is_repo_scoped(&fn_body(&src, n)));
            assert!(
                !has_repo_handler,
                "api/{rel} declares a repo-scoped handler but is not in the egress \
                 guard `sources` list — add it so its handlers are gate-checked"
            );
        }

        // Repo-scoped reads known to be ungated today, each tracked by an issue.
        // Remove an entry the moment its gate lands (the staleness assert enforces it).
        let known_ungated: &[(&str, &str)] = &[
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
