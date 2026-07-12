//! INV-8 deny assertion. A denial must be an actual refusal (4xx) whose body
//! carries none of the data it is withholding, and must never be a 2xx (an
//! empty-200 rendered as success is the denial-as-success bug this guards).
//!
//! The check is split into a pure `check_denied` (unit-tested below with the
//! self-check scenarios) and an async `assert_denied` wrapper that reads a real
//! `reqwest::Response`.

/// Pure deny check. Returns `Err(reason)` when the response is not a clean
/// denial. `withheld` are exact tokens (OIDs, paths, private slugs) that must
/// not appear anywhere in the body; register short-OID prefixes and encoded
/// path forms as separate tokens at the call site (a raw substring scan cannot
/// normalize them).
pub fn check_denied(
    status: u16,
    body: &str,
    expected: u16,
    withheld: &[&str],
) -> Result<(), String> {
    // The harness only ever expects denials; a non-4xx expectation is a
    // programming error in the test, not a node behavior under test.
    if !(400..500).contains(&expected) {
        return Err(format!(
            "test bug: assert_denied expected status {expected} is not a 4xx"
        ));
    }
    // INV-8: a denial rendered as success is the headline bug. Catch it
    // explicitly so the failure message names it, rather than only failing the
    // status-equality check below.
    if (200..300).contains(&status) {
        return Err(format!(
            "denial rendered as success: got {status}, expected denial {expected}. \
             body={body:?}"
        ));
    }
    if status != expected {
        return Err(format!(
            "expected denial status {expected}, got {status}. body={body:?}"
        ));
    }
    for token in withheld {
        if !token.is_empty() && body.contains(token) {
            return Err(format!(
                "withheld token {token:?} leaked in denial body: {body:?}"
            ));
        }
    }
    Ok(())
}

/// Drive a real response through the deny check and panic on failure. Reads the
/// full body once.
pub async fn assert_denied(resp: reqwest::Response, expected: u16, withheld: &[&str]) {
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    if let Err(reason) = check_denied(status, &body, expected, withheld) {
        panic!("{reason}");
    }
}

#[cfg(test)]
mod tests {
    use super::check_denied;

    #[test]
    fn clean_403_with_no_leak_passes() {
        let r = check_denied(403, r#"{"error":"only the repo owner can do this"}"#, 403, &["a1b2c3"]);
        assert!(r.is_ok(), "{r:?}");
    }

    #[test]
    fn empty_200_is_flagged_as_denial_rendered_as_success() {
        let r = check_denied(200, "", 403, &[]);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("rendered as success"));
    }

    #[test]
    fn leaking_403_fails_and_names_the_token() {
        let withheld = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let body = format!("not found near object {withheld}");
        let r = check_denied(403, &body, 403, &[withheld]);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains(withheld));
    }

    #[test]
    fn wrong_status_fails() {
        // A 404 when the owner gate's 403 was expected must not pass: it means
        // an earlier layer denied, so the gate under test was never exercised.
        let r = check_denied(404, "not found", 403, &[]);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("expected denial status 403"));
    }
}
