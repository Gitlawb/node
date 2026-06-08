//! Pure read-authorization logic for path-scoped visibility.
//!
//! `visibility_check` decides whether a caller may read a given path in a repo,
//! based on the repo's visibility rules with a fallback to the legacy
//! `is_public` flag. It performs no I/O so it is exhaustively unit tested.

use crate::db::VisibilityRule;

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
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
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

/// Specificity = length of the match prefix; longer is more specific.
fn specificity(glob: &str) -> usize {
    glob_prefix(glob).len()
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
}
