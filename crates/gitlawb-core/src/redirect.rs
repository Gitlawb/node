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
//! That same missing authority component is why the predicate also pins the
//! request-target: `@path` is signed as the client sent it and verified as the node
//! received it, so a same-origin hop that rewrites the path or the query (a
//! trailing-slash or query normalization) makes the signature cover a target the
//! node never saw and the read 401s. Only a hop that re-issues the identical target,
//! an http-to-https upgrade being the one that matters in practice, is followed.
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

/// Follow a redirect only when it stays on the origin that issued it AND re-issues
/// the identical request-target.
///
/// `Policy::none()` would have been the simpler answer, but one same-origin redirect
/// shape is legitimate here: a node fronted by a proxy that upgrades http to https,
/// or otherwise re-issues the same path and query, so the policy is scoped rather
/// than switched off.
///
/// Path and query must match exactly, and that is the request-target clause rather
/// than an origin one. `@path` is signed as the client sent it and verified as the
/// node received it, so a hop that rewrites either half leaves a signature covering
/// a target nobody asked for and the node answers 401. Refusing the hop turns a
/// confusing 401 into the 3xx that names what actually happened. One policy covers
/// signed and unsigned callers alike, for the same reason the predicate is shared:
/// two rules would drift.
///
/// The clause pins `@path`, and only `@path`. A gitlawb signature also covers
/// `@method` and `content-digest`, and both of those are still open on a followed
/// hop: on a 301, 302 or 303, reqwest 0.12.28 delegates to tower-http's
/// `FollowRedirect`, which rewrites a POST to a GET and empties the body
/// (tower-http-0.6.8 `src/follow_redirect/mod.rs:273-285`), while its
/// `drop_payload_headers` removes only `Content-Type`, `Content-Length`,
/// `Content-Encoding` and `Transfer-Encoding`. So `Signature`, `Signature-Input` and
/// `Content-Digest` ride along on a request that no longer has the method or the body
/// they were computed over. Only 307 and 308 preserve both. This predicate returning
/// true therefore makes a GET-shaped hop safe to replay against the node's verifier
/// and says nothing about a bodied one: a signed write must not rely on it alone.
///
/// `Url::query` is `None` for `/a` and `Some("")` for `/a?`, and those are two
/// different request-targets on the node side too, so the comparison is strict and
/// needs no special case.
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
    let same_target = next.path() == previous.path() && next.query() == previous.query();
    let downgraded = previous.scheme() == "https" && next.scheme() != "https";
    same_origin && same_target && !downgraded
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
                false,
                "same origin but the path changed: @path is signed as sent and verified as received",
            ),
            (
                "http://node.example/a",
                "https://node.example/a",
                true,
                "http to https on one host with an identical request-target: both ports are \
                 the scheme default, so the proxy upgrade is still followed",
            ),
            (
                "https://node.example/a",
                "https://node.example/a/",
                false,
                "trailing-slash normalization changes the request-target, so it is refused",
            ),
            (
                "https://node.example:8443/a",
                "https://node.example:8443/a",
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
            // Each of these pairs an IDENTICAL path on both sides, deliberately. The
            // request-target clause below would make every one of them false on the
            // path alone, and a row that is false for two reasons has stopped pinning
            // either. With the paths equal, the host or port comparison is the only
            // thing left that can decide them.
            (
                "https://node.example/a",
                "https://NODE.EXAMPLE/a",
                true,
                "same host in a different case: parse lowercases it",
            ),
            (
                "https://node.example/a",
                "https://node.example./a",
                false,
                "a trailing dot is a different host to url, so the redirect is refused",
            ),
            (
                "https://exämple.test/a",
                "https://xn--exmple-cua.test/a",
                true,
                "unicode host and its punycode spelling are one host after parse",
            ),
            (
                "https://node.example/a",
                "https://user:pw@node.example/a",
                true,
                "userinfo is not part of the origin: same host, still followed",
            ),
            (
                "https://node.example/a",
                "https://node.example@attacker.example/a",
                false,
                "the node's name smuggled into userinfo: the host is the attacker's",
            ),
            (
                "https://node.example/a",
                "https://attacker.example/a#node.example",
                false,
                "the node's name pushed into the fragment: the host is the attacker's",
            ),
            // The request-target clause, both directions. `@path` is the only thing a
            // gitlawb signature binds the request to, so a hop that rewrites it hands
            // the node a signature over a target it never received.
            (
                "https://node.example/a?x=1",
                "https://node.example/a?x=1",
                true,
                "identical request-target: the same-origin hop that is still followed",
            ),
            (
                "https://node.example/a?x=1",
                "https://node.example/a?x=2",
                false,
                "same path but a different query: the request-target covers the query too",
            ),
            (
                "https://node.example/a",
                "https://node.example/a?x=1",
                false,
                "a query added where there was none",
            ),
            (
                "http://node.example/a",
                "http://node.example/a?",
                false,
                "an empty query added where there was none: a missing query and an empty \
                 one are different request-targets",
            ),
            (
                "https://node.example/a?x=1",
                "https://node.example/a",
                false,
                "the query dropped where there was one: the comparison is symmetric, and \
                 nothing else in the matrix pins that direction",
            ),
            (
                "https://node.example/a#x",
                "https://node.example/a#y",
                true,
                "a fragment-only difference is still followed: a fragment never reaches \
                 the wire, so it is no part of the request-target the node verifies",
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
