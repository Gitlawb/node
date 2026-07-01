//! Pure read-authorization logic for path-scoped visibility.
//!
//! `visibility_check` decides whether a caller may read a given path in a repo,
//! based on the repo's visibility rules with a fallback to the legacy
//! `is_public` flag. It performs no I/O so it is exhaustively unit tested.

use crate::db::{RepoRecord, VisibilityRule};
use std::collections::HashMap;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

/// NFC-normalize a glob prefix or path so the matcher compares canonically
/// equivalent strings byte-for-byte. Without this, a deny rule authored NFC
/// (`é` = U+00E9) byte-compares unequal to a path committed NFD (`e` + U+0301)
/// and the blob slips past the rule on the replication path (#101). NFC, not
/// NFKC: compatibility folding (ligatures, full-width forms) would merge paths
/// the filesystem treats as distinct and over-withhold. Both sides of every
/// comparison must pass through this, or the skew just moves.
fn nfc(s: &str) -> String {
    s.nfc().collect()
}

/// True if `caller` is the repo owner (matches full did:key or its short form),
/// mirroring the owner-match idiom in `api/protect.rs`.
fn is_owner(owner_did: &str, caller: &str) -> bool {
    let owner_short = owner_did.split(':').next_back().unwrap_or(owner_did);
    caller == owner_did || caller == owner_short
}

/// The match prefix for a glob: "/" stays "/", "/secret/**" becomes "/secret".
fn glob_prefix(glob: &str) -> &str {
    let p = glob.trim_end_matches("**").trim_end_matches('/');
    if p.is_empty() {
        "/"
    } else {
        p
    }
}

/// Does `glob` match `path`? "/" matches everything; "/secret" matches
/// "/secret" and any "/secret/..." descendant.
fn glob_matches(glob: &str, path: &str) -> bool {
    let prefix = glob_prefix(glob);
    if prefix == "/" {
        return true;
    }
    // Compare in NFC so an NFC rule matches a canonically-equivalent NFD path
    // (and vice versa). Both sides normalized here — the single matcher seam.
    let prefix = nfc(prefix);
    let path = nfc(path);
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

/// Specificity = length of the (normalized) match prefix; longer is more
/// specific. Normalized so ranking stays consistent with `glob_matches`.
fn specificity(glob: &str) -> usize {
    nfc(glob_prefix(glob)).len()
}

/// Decide whether `caller` (None = anonymous) may read `path` in a repo.
/// `path` is "/" for a whole-repo clone/fetch.
///
/// Reader DIDs in a rule are matched exactly, so they must be stored in full
/// `did:key:...` form. The owner is the only identity matched in both full and
/// short form.
pub fn visibility_check(
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
    caller: Option<&str>,
    path: &str,
) -> Decision {
    // The owner can always read everything.
    if let Some(c) = caller {
        if is_owner(owner_did, c) {
            return Decision::Allow;
        }
    }

    // Most-specific matching rule wins. On equal specificity the last rule in
    // DB order is chosen; `list_visibility_rules` orders by `path_glob`, so this
    // is deterministic.
    let best = rules
        .iter()
        .filter(|r| glob_matches(&r.path_glob, path))
        .max_by_key(|r| specificity(&r.path_glob));

    match best {
        Some(rule) => {
            // Phase 1 treats every matching rule as an allow-list keyed by
            // `reader_dids`. `rule.mode` (A vs B) is stored from day one but not
            // acted on here; it governs replication behavior in Phases 2-3.
            let allowed = caller
                .map(|c| rule.reader_dids.iter().any(|d| d == c))
                .unwrap_or(false);
            if allowed {
                Decision::Allow
            } else {
                Decision::Deny
            }
        }
        None => {
            if is_public {
                Decision::Allow
            } else {
                Decision::Deny
            }
        }
    }
}

/// Whether `caller` (None = anonymous) may see a repo in a listing — the `"/"`
/// visibility decision, shared by every repo-listing surface (REST list,
/// federated list, GraphQL `repos`) so they enforce one rule, not three drifting
/// copies. Not a bare `is_public` test: a repo can be `is_public=false` with a
/// root rule granting readers, or `is_public=true` with a root deny (#97).
pub fn listable_at_root(
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
    caller: Option<&str>,
) -> bool {
    visibility_check(rules, is_public, owner_did, caller, "/") == Decision::Allow
}

/// Whether a single `received_ref_updates` row (identified by its peer-supplied
/// `row_repo` slug) should be shown to `caller` (None = anonymous) on the
/// cross-repo ref-updates feeds (#112 GraphQL, #114 REST).
///
/// Pure and I/O-free: both call sites load the deduped local repo set and its
/// visibility rules once per request and pass them in, so the gate logic lives
/// here and visibility.rs keeps its "no I/O" property.
///
/// The slug is written verbatim from the inbound gossip/notify message, so it is
/// untrusted input, not a canonical key. The decision is fail-closed by
/// construction: the only KEEP paths are (a) a slug with no `/` (cannot name a
/// local `owner/name` pair, so remote by definition), (b) all matched local
/// records are readable, and (c) no local record matches (remote/gossip-only).
/// Any local match the caller cannot read at root DROPs the row. There is no
/// catch-all keep on unexpected state.
///
/// Slug/record owner keys are matched prefix-tolerantly (one is a prefix of the
/// other), covering the exact short-key, the full `did:key:` form, and the
/// URL-truncated 8-char form. Prefix over-match can only over-drop a genuinely
/// remote row (fail-safe), never over-serve a private local one.
///
/// The live call sites are the #112 (GraphQL) and #114 (REST) feed handlers,
/// added in the following units; exercised by the unit tests below meanwhile.
pub fn ref_update_row_visible(
    deduped: &[RepoRecord],
    rules_by_repo: &HashMap<String, Vec<VisibilityRule>>,
    caller: Option<&str>,
    row_repo: &str,
) -> bool {
    // No '/': the slug cannot name a local owner/name pair. Remote by
    // definition (same branch as "matches nothing local") → KEEP.
    let Some((owner_part, name)) = row_repo.rsplit_once('/') else {
        return true;
    };

    // Normalize the slug's owner to the same short-key form the dedup grouping
    // and `did_matches` use: strip a leading `did:key:` only when the remainder
    // is a bare key id (no further ':').
    let row_key = match owner_part.strip_prefix("did:key:") {
        Some(rest) if !rest.contains(':') => rest,
        _ => owner_part,
    };

    // A record matches the slug when its name is equal and one owner key is a
    // prefix of the other (prefix-tolerant per the doc comment above).
    for record in deduped {
        if record.name != name {
            continue;
        }
        let record_key = record
            .owner_did
            .split(':')
            .next_back()
            .unwrap_or(&record.owner_did);
        if !(record_key.starts_with(row_key) || row_key.starts_with(record_key)) {
            continue;
        }
        let rules = rules_by_repo
            .get(&record.id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        // Fail closed: any matched local record the caller cannot read at root
        // drops the row.
        if !listable_at_root(rules, record.is_public, &record.owner_did, caller) {
            return false;
        }
    }

    // Reached only if every matched local record is readable, or nothing local
    // matched (remote/gossip-only). Both are the KEEP paths; there is no
    // default-keep on unexpected state — an unreadable match already returned.
    true
}

/// The subtree path globs that `caller` (None = anonymous) may NOT read, given
/// the repo's rules. Whole-repo ("/") rules are excluded: a denied whole-repo
/// read is handled by the 404 gate before a clone ever starts. Each remaining
/// rule is reported when `visibility_check` denies the caller at the glob's
/// representative path. Used by the clean-clone client to sparse-exclude the
/// private paths from checkout.
pub fn withheld_globs(
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
    caller: Option<&str>,
) -> Vec<String> {
    rules
        .iter()
        .filter(|r| r.path_glob != "/")
        .filter(|r| {
            let probe = glob_prefix(&r.path_glob);
            visibility_check(rules, is_public, owner_did, caller, probe) == Decision::Deny
        })
        .map(|r| r.path_glob.clone())
        .collect()
}

/// The allowed globs that sit strictly underneath a denied glob. A clean-clone
/// client sparse-excludes everything in `withheld_globs`, which would also hide
/// these nested allowed paths; re-including them restores the caller's access.
/// Example: with `/secret/**` denied and `/secret/public/**` allowed for the
/// same caller, `/secret/public/**` is returned here so the client re-includes
/// it after excluding `/secret/`.
pub fn reincluded_globs(
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
    caller: Option<&str>,
) -> Vec<String> {
    let denied: Vec<&str> = rules
        .iter()
        .filter(|r| r.path_glob != "/")
        .filter(|r| {
            visibility_check(
                rules,
                is_public,
                owner_did,
                caller,
                glob_prefix(&r.path_glob),
            ) == Decision::Deny
        })
        .map(|r| glob_prefix(&r.path_glob))
        .collect();

    rules
        .iter()
        .filter(|r| r.path_glob != "/")
        .filter(|r| {
            visibility_check(
                rules,
                is_public,
                owner_did,
                caller,
                glob_prefix(&r.path_glob),
            ) == Decision::Allow
        })
        .filter(|r| {
            let p = glob_prefix(&r.path_glob);
            denied
                .iter()
                .any(|d| *d != p && p.starts_with(&format!("{d}/")))
        })
        .map(|r| r.path_glob.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::VisibilityMode;
    use chrono::Utc;

    fn rule(path_glob: &str, mode: VisibilityMode, readers: &[&str]) -> VisibilityRule {
        VisibilityRule {
            id: "x".into(),
            repo_id: "r1".into(),
            path_glob: path_glob.into(),
            mode,
            reader_dids: readers.iter().map(|s| s.to_string()).collect(),
            created_by: "did:key:z6MkOwner".into(),
            created_at: Utc::now(),
        }
    }

    const OWNER: &str = "did:key:z6MkOwner";

    #[test]
    fn withheld_globs_lists_only_denied_subtrees() {
        let rules = [
            rule("/secret/**", VisibilityMode::B, &["did:key:z6MkFriend"]),
            rule("/docs/**", VisibilityMode::B, &["did:key:z6MkStranger"]),
        ];
        // Stranger is denied /secret but allowed /docs.
        let mut got = withheld_globs(&rules, true, OWNER, Some("did:key:z6MkStranger"));
        got.sort();
        assert_eq!(got, vec!["/secret/**".to_string()]);
        // Owner is denied nothing.
        assert!(withheld_globs(&rules, true, OWNER, Some(OWNER)).is_empty());
        // Anonymous is denied both.
        let mut anon = withheld_globs(&rules, true, OWNER, None);
        anon.sort();
        assert_eq!(anon, vec!["/docs/**".to_string(), "/secret/**".to_string()]);
    }

    #[test]
    fn reincluded_globs_restores_allowed_nested_path() {
        let rules = [
            rule("/secret/**", VisibilityMode::B, &["did:key:z6MkFriend"]),
            rule(
                "/secret/public/**",
                VisibilityMode::B,
                &["did:key:z6MkFriend", "did:key:z6MkStranger"],
            ),
        ];
        // Stranger is denied /secret/** but allowed the nested /secret/public/**.
        let withheld = withheld_globs(&rules, true, OWNER, Some("did:key:z6MkStranger"));
        assert_eq!(withheld, vec!["/secret/**".to_string()]);
        let reinc = reincluded_globs(&rules, true, OWNER, Some("did:key:z6MkStranger"));
        assert_eq!(reinc, vec!["/secret/public/**".to_string()]);
        // Owner is denied nothing, so there is nothing to re-include.
        assert!(reincluded_globs(&rules, true, OWNER, Some(OWNER)).is_empty());
    }

    #[test]
    fn no_rules_public_allows_anonymous() {
        assert_eq!(
            visibility_check(&[], true, OWNER, None, "/"),
            Decision::Allow
        );
    }

    #[test]
    fn no_rules_private_denies_anonymous() {
        assert_eq!(
            visibility_check(&[], false, OWNER, None, "/"),
            Decision::Deny
        );
    }

    #[test]
    fn root_rule_denies_anonymous() {
        let rules = [rule("/", VisibilityMode::A, &[])];
        assert_eq!(
            visibility_check(&rules, true, OWNER, None, "/"),
            Decision::Deny
        );
    }

    #[test]
    fn root_rule_allows_owner() {
        let rules = [rule("/", VisibilityMode::A, &[])];
        assert_eq!(
            visibility_check(&rules, true, OWNER, Some(OWNER), "/"),
            Decision::Allow
        );
    }

    #[test]
    fn root_rule_allows_owner_short_form() {
        let rules = [rule("/", VisibilityMode::A, &[])];
        assert_eq!(
            visibility_check(&rules, true, OWNER, Some("z6MkOwner"), "/"),
            Decision::Allow
        );
    }

    #[test]
    fn root_rule_allows_listed_reader() {
        let rules = [rule("/", VisibilityMode::A, &["did:key:z6MkFriend"])];
        assert_eq!(
            visibility_check(&rules, true, OWNER, Some("did:key:z6MkFriend"), "/"),
            Decision::Allow
        );
    }

    #[test]
    fn root_rule_denies_unlisted_reader() {
        let rules = [rule("/", VisibilityMode::A, &["did:key:z6MkFriend"])];
        assert_eq!(
            visibility_check(&rules, true, OWNER, Some("did:key:z6MkStranger"), "/"),
            Decision::Deny
        );
    }

    #[test]
    fn subtree_rule_matches_descendant_path() {
        let rules = [rule(
            "/secret/**",
            VisibilityMode::B,
            &["did:key:z6MkFriend"],
        )];
        assert_eq!(
            visibility_check(
                &rules,
                true,
                OWNER,
                Some("did:key:z6MkStranger"),
                "/secret/a.rs"
            ),
            Decision::Deny
        );
        assert_eq!(
            visibility_check(
                &rules,
                true,
                OWNER,
                Some("did:key:z6MkFriend"),
                "/secret/a.rs"
            ),
            Decision::Allow
        );
    }

    #[test]
    fn subtree_rule_does_not_affect_root_clone() {
        // A subtree rule must not gate a whole-repo (path "/") read: the public
        // fallback applies because the subtree glob does not match "/".
        let rules = [rule("/secret/**", VisibilityMode::B, &[])];
        assert_eq!(
            visibility_check(&rules, true, OWNER, None, "/"),
            Decision::Allow
        );
    }

    #[test]
    fn most_specific_rule_wins() {
        // Public repo, but /secret is locked. A stranger reading /secret is denied
        // by the more specific rule even though "/" would allow.
        let rules = [
            rule("/", VisibilityMode::A, &["did:key:z6MkStranger"]),
            rule("/secret/**", VisibilityMode::B, &["did:key:z6MkFriend"]),
        ];
        // stranger is a root reader but not a /secret reader
        assert_eq!(
            visibility_check(
                &rules,
                true,
                OWNER,
                Some("did:key:z6MkStranger"),
                "/secret/a.rs"
            ),
            Decision::Deny
        );
        // stranger can still read root
        assert_eq!(
            visibility_check(&rules, true, OWNER, Some("did:key:z6MkStranger"), "/"),
            Decision::Allow
        );
    }

    // Mirrors the gossip-announce gate in git_receive_pack: announce iff an
    // anonymous caller can read "/".
    #[test]
    fn announce_gate_matches_public_readability() {
        let announce = |rules: &[VisibilityRule], is_public: bool| {
            visibility_check(rules, is_public, OWNER, None, "/") == Decision::Allow
        };
        // Public repo, no rules → announce.
        assert!(announce(&[], true));
        // Legacy private repo (is_public false, no rules) → silent.
        assert!(!announce(&[], false));
        // Mode A whole-repo rule with no public readers → silent.
        assert!(!announce(&[rule("/", VisibilityMode::A, &[])], true));
        // Mode B public repo with a private subtree → still announce.
        assert!(announce(
            &[rule("/secret/**", VisibilityMode::B, &[])],
            true
        ));
    }

    // ── ref_update_row_visible (feed gate) ──────────────────────────────────

    fn rec(id: &str, owner_did: &str, name: &str, is_public: bool) -> RepoRecord {
        RepoRecord {
            id: id.into(),
            name: name.into(),
            owner_did: owner_did.into(),
            description: None,
            is_public,
            default_branch: "main".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            disk_path: format!("/srv/{id}"),
            forked_from: None,
            machine_id: None,
        }
    }

    fn rules_for(entries: &[(&str, &[VisibilityRule])]) -> HashMap<String, Vec<VisibilityRule>> {
        entries
            .iter()
            .map(|(id, rs)| (id.to_string(), rs.to_vec()))
            .collect()
    }

    #[test]
    fn feed_public_local_repo_kept_for_anon() {
        let deduped = [rec("r1", "did:key:z6MkOwner", "widget", true)];
        let rules = HashMap::new();
        assert!(ref_update_row_visible(
            &deduped,
            &rules,
            None,
            "z6MkOwner/widget"
        ));
    }

    #[test]
    fn feed_private_local_repo_dropped_for_anon_kept_for_owner() {
        let deduped = [rec("r1", "did:key:z6MkOwner", "widget", false)];
        let rules = HashMap::new();
        // Anonymous → drop.
        assert!(!ref_update_row_visible(
            &deduped,
            &rules,
            None,
            "z6MkOwner/widget"
        ));
        // Owner (full DID) → keep.
        assert!(ref_update_row_visible(
            &deduped,
            &rules,
            Some("did:key:z6MkOwner"),
            "z6MkOwner/widget"
        ));
    }

    #[test]
    fn feed_root_rule_reader_reincluded() {
        // Private repo (is_public=false) with a root rule granting a named
        // reader. Delegates to listable_at_root: anon and non-reader denied,
        // named reader allowed.
        let deduped = [rec("r1", OWNER, "widget", false)];
        let root = [rule("/", VisibilityMode::A, &["did:key:z6MkFriend"])];
        let rules = rules_for(&[("r1", &root)]);
        assert!(!ref_update_row_visible(
            &deduped,
            &rules,
            None,
            "z6MkOwner/widget"
        ));
        assert!(!ref_update_row_visible(
            &deduped,
            &rules,
            Some("did:key:z6MkStranger"),
            "z6MkOwner/widget"
        ));
        assert!(ref_update_row_visible(
            &deduped,
            &rules,
            Some("did:key:z6MkFriend"),
            "z6MkOwner/widget"
        ));
    }

    #[test]
    fn feed_alias_full_did_slug_dropped_for_anon() {
        // Owner stored full-DID; slug also carries the full-DID form. Still
        // matches (row_key normalizes to the short key) → drop. Round 1's
        // string-match would have leaked this.
        let deduped = [rec("r1", "did:key:zABC", "widget", false)];
        let rules = HashMap::new();
        assert!(!ref_update_row_visible(
            &deduped,
            &rules,
            None,
            "did:key:zABC/widget"
        ));
    }

    #[test]
    fn feed_truncated_key_slug_dropped_for_anon() {
        // Slug carries an 8-char URL-truncated prefix of the owner key; still
        // matches via prefix tolerance → drop. Round 2's get_repo path leaked.
        let deduped = [rec("r1", "did:key:zABCDEFGH", "widget", false)];
        let rules = HashMap::new();
        assert!(!ref_update_row_visible(
            &deduped,
            &rules,
            None,
            "zABCDEF/widget"
        ));
    }

    #[test]
    fn feed_mirror_coexistence_private_canonical_dropped_for_anon() {
        // Pure-level mirror-coexistence: the deduped set contains only the
        // private canonical record for (owner,name). A matching slug drops for
        // anon. (DB-level dedup survivor property is pinned separately.)
        let deduped = [rec("uuid-canonical", "did:key:z6Mkwbud", "nipmod", false)];
        let rules = HashMap::new();
        assert!(!ref_update_row_visible(
            &deduped,
            &rules,
            None,
            "z6Mkwbud/nipmod"
        ));
    }

    #[test]
    fn feed_empty_owner_slug_matches_and_drops() {
        // Slug "/name": empty owner_part → row_key "" → starts_with("") matches
        // every same-named record. Fail-safe pin for a private repo.
        let deduped = [rec("r1", "did:key:z6MkOwner", "widget", false)];
        let rules = HashMap::new();
        assert!(!ref_update_row_visible(&deduped, &rules, None, "/widget"));
    }

    #[test]
    fn feed_one_char_owner_slug_matches_and_drops() {
        // 1-char owner prefix that the private repo's key starts with → match.
        let deduped = [rec("r1", "did:key:z6MkOwner", "widget", false)];
        let rules = HashMap::new();
        assert!(!ref_update_row_visible(&deduped, &rules, None, "z/widget"));
    }

    #[test]
    fn feed_remote_slug_no_match_kept() {
        // Different owner key, no prefix relation → no local match → keep.
        let deduped = [rec("r1", "did:key:z6MkOwner", "widget", false)];
        let rules = HashMap::new();
        assert!(ref_update_row_visible(
            &deduped,
            &rules,
            None,
            "zZZZOTHER/widget"
        ));
    }

    #[test]
    fn feed_malformed_slug_no_slash_kept_no_panic() {
        let deduped = [rec("r1", "did:key:z6MkOwner", "widget", false)];
        let rules = HashMap::new();
        assert!(ref_update_row_visible(&deduped, &rules, None, "noslug"));
    }

    #[test]
    fn feed_empty_deduped_set_keeps_any_slug() {
        let deduped: [RepoRecord; 0] = [];
        let rules = HashMap::new();
        assert!(ref_update_row_visible(
            &deduped,
            &rules,
            None,
            "z6MkOwner/widget"
        ));
        assert!(ref_update_row_visible(&deduped, &rules, None, "anything"));
    }

    // #101: a deny rule must withhold a path that denotes the same characters in
    // a different Unicode normalization form. Without NFC normalization at the
    // matcher seam, an NFC-authored rule byte-compares unequal to an NFD-stored
    // path and the blob leaks on the replication path.
    #[test]
    fn matcher_withholds_across_nfc_nfd_normalization_skew() {
        // "é" composed (NFC, U+00E9) in the rule; decomposed (NFD, e + U+0301)
        // in the committed path.
        let nfc_rule = "/s\u{00e9}cret/**";
        let nfd_path = "/se\u{0301}cret/key.pem";
        let rules = [rule(nfc_rule, VisibilityMode::B, &["did:key:z6MkFriend"])];
        assert_eq!(
            visibility_check(&rules, true, OWNER, None, nfd_path),
            Decision::Deny,
            "NFC-authored deny rule must withhold the canonically-equivalent NFD path"
        );

        // Mirror: rule authored NFD, path committed NFC.
        let nfd_rule = "/se\u{0301}cret/**";
        let nfc_path = "/s\u{00e9}cret/key.pem";
        let rules2 = [rule(nfd_rule, VisibilityMode::B, &["did:key:z6MkFriend"])];
        assert_eq!(
            visibility_check(&rules2, true, OWNER, None, nfc_path),
            Decision::Deny,
            "NFD-authored deny rule must withhold the canonically-equivalent NFC path"
        );

        // A genuinely different path is still allowed (no over-withholding).
        assert_eq!(
            visibility_check(&rules, true, OWNER, None, "/public/x.txt"),
            Decision::Allow
        );
    }
}
