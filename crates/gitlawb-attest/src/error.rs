use thiserror::Error;

/// Errors from building or verifying an attestation.
#[derive(Debug, Error)]
pub enum Error {
    /// Discriminator failed validation (empty, whitespace, control char,
    /// disallowed grammar).
    #[error("attestation type: {0}")]
    Type(String),

    /// Attestation was signed against a different cert.
    #[error("cert hash mismatch")]
    CertHashMismatch,

    /// Ed25519 signature failed verification.
    #[error("signature: {0}")]
    Signature(String),

    /// DID could not be parsed.
    #[error("did: {0}")]
    Did(String),

    /// Payload structure check failed, or the cert body was not a JSON object.
    #[error("payload: {0}")]
    Payload(String),

    /// No verifier registered for the type and policy required one.
    #[error("no verifier registered for type '{0}'")]
    UnknownType(String),

    /// `RequireAll` policy did not find an entry for a required type, or the
    /// entry was not fully verified.
    #[error("required attestation type missing or unverified: '{0}'")]
    RequiredMissing(String),

    /// JSON failure.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    /// JCS encoding failure.
    #[error("jcs: {0}")]
    Jcs(String),
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, Error>;
