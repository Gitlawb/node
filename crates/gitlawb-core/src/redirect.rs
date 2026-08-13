//! Redirect policy shared by every gitlawb HTTP client that signs its requests.
//!
//! Both `gl` (async) and `git-remote-gitlawb` (blocking) attach RFC 9421
//! `Signature` and `Signature-Input` headers, and reqwest strips only
//! `Authorization`, `Cookie`, `Proxy-Authorization` and `WWW-Authenticate` when a
//! redirect crosses hosts. A signature would survive that hop, and it binds
//! `@method`, `@path` and `content-digest` with no authority component, so a node
//! answering 302 could hand a working credential to a host of its choosing and read
//! as the caller anywhere until the clock-skew window closes. On a 307/308 the
//! request body goes along with it, which for the remote helper is the pack.
//!
//! The decision lives here rather than in either client because the two used to
//! disagree: `gl` was scoped to the origin while the remote helper, the binary that
//! actually runs `git clone gitlawb://`, still ran reqwest's default and followed
//! anywhere. One predicate is what keeps a future third client from repeating that.
//!
//! The type is `url::Url`, which is what `reqwest::Url` re-exports, so both clients
//! pass their attempt URLs straight in.

/// Longest redirect chain followed. `reqwest::redirect::Policy::custom` replaces
/// reqwest's built-in limit, so the bound has to be restated by every client that
/// installs a custom policy; the value is reqwest's own default.
///
/// This counts FOLLOWS, matching `Policy::limited`: reqwest pushes the redirecting
/// URL onto `previous` before consulting the policy, and `Limit(max)` refuses once
/// `previous.len() > max`, so a caller comparing against this constant must use `>`
/// too or it permits one hop fewer than it says.
pub const MAX_REDIRECTS: usize = 10;

/// Follow a redirect only when it stays on the origin that issued it.
///
/// `Policy::none()` would have been the simpler answer, but same-origin redirects
/// are legitimate here (a node fronted by a proxy that upgrades http to https, or
/// normalizes a trailing slash), so the policy is scoped to the origin rather than
/// switched off.
///
/// Host and port must match exactly. Port is compared as `Url::port`, which is
/// `None` for a scheme's default port, so http -> https on the same host compares
/// equal while http -> http on a different port does not. A downgrade from https to
/// http is refused as well: the target is the same host, but the signature would go
/// out in cleartext, which is the same credential leak by a slower route.
///
/// Host comparison rides on `url`'s parse-time normalization (lowercasing and IDN
/// -> punycode), so the spellings an attacker reaches for do not open a gap. That
/// is a property of the parsed `Url`, not of this function, which is why the test
/// matrix pins it: a move to raw string comparison would silently lose it.
pub fn may_follow(previous: &url::Url, next: &url::Url) -> bool {
    let same_origin = next.host_str() == previous.host_str() && next.port() == previous.port();
    let downgraded = previous.scheme() == "https" && next.scheme() != "https";
    same_origin && !downgraded
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every branch of the decision, both ways, plus the spellings that would slip
    /// past a comparison less careful than `Url`'s own normalization.
    #[test]
    fn may_follow_covers_each_origin_branch() {
        let url = |s: &str| url::Url::parse(s).unwrap();
        let cases: &[(&str, &str, bool, &str)] = &[
            (
                "http://node.example/a",
                "http://node.example/b",
                true,
                "same origin, different path",
            ),
            (
                "http://node.example/a",
                "https://node.example/a",
                true,
                "http to https on one host: both ports are the scheme default",
            ),
            (
                "https://node.example/a",
                "https://node.example/a/",
                true,
                "trailing-slash normalization",
            ),
            (
                "https://node.example:8443/a",
                "https://node.example:8443/b",
                true,
                "same explicit port",
            ),
            (
                "http://node.example/a",
                "http://attacker.example/a",
                false,
                "different host",
            ),
            (
                "http://node.example/a",
                "http://node.example:8080/a",
                false,
                "same host, different port",
            ),
            (
                "https://node.example/a",
                "http://node.example/a",
                false,
                "https downgraded to cleartext on the same host",
            ),
            (
                "https://node.example/a",
                "http://node.example:443/a",
                false,
                "a downgrade dressed up as the https port",
            ),
            // The rows below pass today because `Url::parse` normalizes the host, not
            // because anything here compares case-insensitively or decodes IDN. They
            // are the variants an attacker reaches for, so they are pinned: swapping
            // this predicate for a raw string comparison must break the suite.
            (
                "https://node.example/a",
                "https://NODE.EXAMPLE/b",
                true,
                "same host in a different case: parse lowercases it",
            ),
            (
                "https://node.example/a",
                "https://node.example./b",
                false,
                "a trailing dot is a different host to url, so the redirect is refused",
            ),
            (
                "https://exämple.test/a",
                "https://xn--exmple-cua.test/b",
                true,
                "unicode host and its punycode spelling are one host after parse",
            ),
            (
                "https://node.example/a",
                "https://user:pw@node.example/b",
                true,
                "userinfo is not part of the origin: same host, still followed",
            ),
            (
                "https://node.example/a",
                "https://node.example@attacker.example/b",
                false,
                "the node's name smuggled into userinfo: the host is the attacker's",
            ),
            (
                "https://node.example/a",
                "https://attacker.example#node.example/b",
                false,
                "the node's name pushed into the fragment: the host is the attacker's",
            ),
        ];
        for (previous, next, expected, why) in cases {
            assert_eq!(
                may_follow(&url(previous), &url(next)),
                *expected,
                "{previous} -> {next} ({why})"
            );
        }
    }
}
