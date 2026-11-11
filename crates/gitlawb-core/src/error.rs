use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid DID: {0}")]
    InvalidDid(String),

    #[error("invalid CID: {0}")]
    InvalidCid(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("signature verification failed")]
    SignatureInvalid,

    #[error("invalid HTTP signature: {0}")]
    HttpSignature(String),

    #[error("invalid UCAN: {0}")]
    Ucan(String),

    #[error("invalid ref certificate: {0}")]
    RefCert(String),

    #[error("key error: {0}")]
    Key(String),

    #[error("encoding error: {0}")]
    Encoding(String),

    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
}
