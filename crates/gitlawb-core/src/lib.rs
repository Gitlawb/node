pub mod did;
pub mod cid;
pub mod identity;
pub mod http_sig;
pub mod ucan;
pub mod cert;
pub mod error;

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;
