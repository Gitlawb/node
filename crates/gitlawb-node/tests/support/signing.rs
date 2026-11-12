//! Real RFC-9421 request signing for the deny harness (U2). Wraps
//! `gitlawb_core::http_sig::sign_request` (the same entry point the
//! git-remote-gitlawb helper uses in production) so a test can present a valid
//! signature for any identity, reaching the authenticated-but-wrong-owner path
//! that an injected-DID shortcut cannot.

use gitlawb_core::http_sig::sign_request;
use gitlawb_core::identity::Keypair;

/// Build a reqwest request carrying a valid RFC-9421 signature for `keypair`.
///
/// `path` is both appended to `base_url` to form the request URL and signed as
/// the `@path` component, so the value the server reconstructs and the value
/// that was signed are guaranteed identical. `body` is signed via its
/// content-digest and sent as the request body.
pub fn signed_request(
    client: &reqwest::Client,
    method: reqwest::Method,
    base_url: &str,
    path: &str,
    body: Vec<u8>,
    keypair: &Keypair,
) -> reqwest::RequestBuilder {
    let sig = sign_request(keypair, method.as_str(), path, &body);
    let url = format!("{base_url}{path}");
    client
        .request(method, url)
        .header("content-digest", sig.content_digest)
        .header("signature-input", sig.signature_input)
        .header("signature", sig.signature)
        .body(body)
}
