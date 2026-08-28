//! #26 Split PR 4 — `GITLAWB_ENFORCE_OWNER_PUSH` default is consistent across surfaces.
//!
//! Reviewer 2 (2026-08-28) closed PR #224 with a P2 finding: SECURITY.md and
//! README.md both stated the default was `false`, while `Config::enforce_owner_push`
//! declared `default_value_t = true` and the runtime, .env.example, and the env
//! var table on the README all agreed with the code. Two operator-facing
//! surfaces lied about the authorization policy. PR #330 flipped the code
//! default and updated .env.example / README env table / docs/RUN-A-NODE.md,
//! but missed these two prose mentions.
//!
//! This guard pins the four surfaces together. Each one is read off the
//! working tree at test time, not a copy in the binary, so a revert of the doc
//! edit or a flip of the clap default turns it red:
//!
//! 1. `Config::enforce_owner_push` declares `default_value_t = true` (the
//!    `enforce_owner_push_is_declared_true_independent_of_the_environment`
//!    unit test in `config.rs` already covers this; this guard re-asserts
//!    it at the integration layer so a future removal of the unit test is
//!    caught).
//! 2. `.env.example` sets `GITLAWB_ENFORCE_OWNER_PUSH=true`.
//! 3. `README.md` says the default is `true` in both the known-limitations
//!    prose and the env-var table.
//! 4. `SECURITY.md` says the default is `true`.
//!
//! The four are checked independently. A check that just verified "at least
//! one surface says true" would pass while a stale SECURITY.md lied; a check
//! that only verified the binary would not catch the doc drift that
//! produced this finding in the first place.

use std::path::Path;

fn read(rel: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Pin the prose mentions of `GITLAWB_ENFORCE_OWNER_PUSH` so a future doc
/// edit cannot reintroduce the "defaults to false" wording the reviewer
/// flagged. The wording in the test is what the docs MUST say about the
/// default; absence of any prose mention is also a fail because operators
/// rely on the docs to learn the default.
#[test]
fn security_md_states_owner_push_default_is_true() {
    let security = read("SECURITY.md");
    let section = section_after(&security, "### Repository write authorization defaults")
        .unwrap_or_else(|| panic!("SECURITY.md is missing the owner-push section"));

    assert!(
        section.contains("defaults to `true`"),
        "SECURITY.md owner-push section must state the default is true. \
         Found:\n{section}"
    );
    assert!(
        !section_claims_default_is_false(&section),
        "SECURITY.md owner-push section must not claim the default is false. \
         Found:\n{section}"
    );
}

#[test]
fn readme_known_limitations_states_owner_push_default_is_true() {
    let readme = read("README.md");
    let limitations = section_after(&readme, "Known limitations:")
        .unwrap_or_else(|| panic!("README.md is missing the Known limitations: section"));

    // The owner-push line is one bullet in the limitations list. Pull the
    // single line that mentions the env var so the assertion is local to
    // the claim, not a substring of unrelated text.
    let line = limitations
        .lines()
        .find(|l| l.contains("GITLAWB_ENFORCE_OWNER_PUSH"))
        .unwrap_or_else(|| {
            panic!(
                "README.md Known limitations must mention GITLAWB_ENFORCE_OWNER_PUSH.\n\
                 Got:\n{limitations}"
            )
        });

    assert!(
        line.contains("defaults to `true`") || line.contains("defaults to true"),
        "README Known-limitations owner-push bullet must state the default is true. \
         Found:\n{line}"
    );
    assert!(
        !section_claims_default_is_false(line),
        "README Known-limitations owner-push bullet must not claim the default is false. \
         Found:\n{line}"
    );
}

#[test]
fn readme_env_var_table_states_owner_push_default_is_true() {
    let readme = read("README.md");
    let line = readme
        .lines()
        .find(|l| l.contains("GITLAWB_ENFORCE_OWNER_PUSH") && l.contains("|"))
        .unwrap_or_else(|| {
            panic!("README.md is missing the env-var-table row for GITLAWB_ENFORCE_OWNER_PUSH")
        });

    assert!(
        line.contains("Defaults to `true`") || line.contains("defaults to `true`"),
        "README env-var-table row for GITLAWB_ENFORCE_OWNER_PUSH must state the default is true. \
         Found:\n{line}"
    );
    assert!(
        !section_claims_default_is_false(line),
        "README env-var-table row for GITLAWB_ENFORCE_OWNER_PUSH must not claim the default is false. \
         Found:\n{line}"
    );
}

#[test]
fn env_example_sets_owner_push_true() {
    let env = read(".env.example");
    let line = env
        .lines()
        .find(|l| l.trim_start().starts_with("GITLAWB_ENFORCE_OWNER_PUSH"))
        .unwrap_or_else(|| panic!(".env.example is missing GITLAWB_ENFORCE_OWNER_PUSH"));

    assert!(
        line.contains("=true"),
        ".env.example GITLAWB_ENFORCE_OWNER_PUSH must be set to true. Found:\n{line}"
    );
}

/// A claim that the default is false can hide in many phrasings. Match the
/// forms that have appeared in the wild on this branch: "defaults to `false`",
/// "defaults to false", "default is false", "is `false` for compatibility",
/// "is false for compatibility". The match is intentionally narrow — false
/// positives would suppress a real doc edit.
fn section_claims_default_is_false(section: &str) -> bool {
    let lower = section.to_ascii_lowercase();
    lower.contains("defaults to `false`")
        || lower.contains("defaults to false")
        || lower.contains("default is `false`")
        || lower.contains("default is false")
        || (lower.contains("`false`") && lower.contains("for compatibility"))
}

/// Return the prose after a markdown heading up to the next heading of the
/// same or higher level. Used to scope a search to one section without
/// pulling in later sections that happen to mention the same term.
fn section_after(doc: &str, heading: &str) -> Option<String> {
    let start = doc.find(heading)?;
    let after = &doc[start..];
    let header_level = heading.chars().take_while(|c| *c == '#').count();

    // Skip past the heading line itself.
    let body_start = after.find('\n')? + 1;
    let body = &after[body_start..];

    // Stop at the next heading of the same or higher level.
    let mut end = body.len();
    for line in body.lines() {
        let level = line.chars().take_while(|c| *c == '#').count();
        if level > 0 && level <= header_level {
            end = line.as_ptr() as usize - body.as_ptr() as usize;
            break;
        }
    }

    Some(body[..end].to_string())
}
