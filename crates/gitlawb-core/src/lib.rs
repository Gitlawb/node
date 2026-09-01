pub mod cert;
pub mod cid;
pub mod did;
pub mod encrypt;
pub mod error;
pub mod http_sig;
pub mod identity;
// `url` is the one dependency here that drags a tail (idna, then the icu
// crates), and gitlawb-core is allowlisted to stay embeddable. Every client that
// needs this predicate already parses URLs, so they opt in and nothing else
// pays. `test` is in the cfg so `cargo test -p gitlawb-core` still compiles and
// runs the matrix below with no feature selected; without it the tests would
// silently not run, which is the failure this module exists to prevent.
#[cfg(any(feature = "redirect", test))]
pub mod redirect;
pub mod sanitize;
pub mod scan_token;
pub mod ucan;

/// Node URL the git transport falls back to when `GITLAWB_NODE` is unset.
///
/// `gl` defaults to the public node instead, so the two disagree on an install
/// that never sets the variable.
pub const DEFAULT_LOCAL_NODE: &str = "http://127.0.0.1:7545";

/// The node `git clone` and `git push` will contact, given the raw `GITLAWB_NODE`
/// value (`None` when the variable is absent).
///
/// `git-remote-gitlawb` calls this to pick its base URL and `gl doctor` calls it
/// to report that URL, so a diagnostic cannot describe a node the transport will
/// not use. A blank or whitespace-only value is not a configured node: treating
/// it as one gave the helper an empty base and every clone URL a missing scheme
/// and host.
pub fn resolve_transport_node(env_value: Option<&str>) -> String {
    match env_value.map(str::trim) {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => DEFAULT_LOCAL_NODE.to_string(),
    }
}

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod transport_node_tests {
    use super::*;

    #[test]
    fn absent_or_blank_resolves_to_the_local_default() {
        for raw in [None, Some(""), Some("   "), Some("\t\n")] {
            assert_eq!(resolve_transport_node(raw), DEFAULT_LOCAL_NODE, "{raw:?}");
        }
    }

    #[test]
    fn a_configured_value_wins_and_is_trimmed() {
        assert_eq!(
            resolve_transport_node(Some("https://n.example")),
            "https://n.example"
        );
        assert_eq!(
            resolve_transport_node(Some("  https://n.example  ")),
            "https://n.example"
        );
    }
}
