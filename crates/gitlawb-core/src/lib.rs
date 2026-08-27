pub mod cert;
pub mod cid;
pub mod did;
pub mod encrypt;
pub mod error;
pub mod http_sig;
pub mod identity;
pub mod identity_path;
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

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;
