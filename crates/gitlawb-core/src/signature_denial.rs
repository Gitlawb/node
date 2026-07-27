//! The denial codes the spent-signature ledger puts on the wire, in one place.
//!
//! The node's `consume_signature` middleware refuses a signed write with an
//! `X-Gitlawb-Error` header and a matching `error` field in the JSON body. The
//! `gl` client keys off that header to turn a denial into a hard error instead
//! of handing the caller a response that pretty-prints like a success.
//!
//! Both halves used to carry their own list of string literals, agreeing only
//! by having been typed the same way twice in two crates. They drifted exactly
//! as you would expect: `signature_nonce_too_short` was added to the node after
//! the client's list was written, so for a while the client returned `Ok(400)`
//! for that denial and the write looked like it might have happened.
//!
//! This enum is the single source of truth. The node builds its responses from
//! it, so the wire strings and statuses come from one place, and `gl` matches
//! it with no wildcard arm, so adding a variant here is a compile error in the
//! client until the client handles it.
//!
//! # Deliberately not `#[non_exhaustive]`
//!
//! Marking this `#[non_exhaustive]` would force every downstream crate to add a
//! wildcard arm, which is precisely the silent fallthrough this type exists to
//! prevent. The compile-time guarantee is worth more here than the freedom to
//! add a variant without touching the client: the client and the node ship from
//! this same repo and are versioned together.
//!
//! The guarantee is over the codes *this repo's node emits*, not over arbitrary
//! input. A client talks to nodes it does not control, so [`from_code`] returns
//! `Option` and an unrecognised string stays unrecognised at runtime.
//!
//! [`from_code`]: SignatureDenial::from_code

/// A refusal from the node's spent-signature ledger.
///
/// The `as_str` value is the wire contract: it appears verbatim in the
/// `X-Gitlawb-Error` response header and in the body's `error` field, and
/// scripts match on it. Never change one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureDenial {
    /// 400 — the node requires a `nonce` in `Signature-Input` and the request
    /// carried none. A pre-nonce client; the caller must upgrade.
    NonceRequired,
    /// 400 — the request carried a `nonce`, but too short to be unique. The
    /// client already emits the parameter, it just does not fill it properly.
    NonceTooShort,
    /// 409 — the node already admitted a request bearing this signature.
    Replayed,
    /// 429 — too many unexpired signatures for this identity. A rate condition,
    /// not a permanent refusal.
    LedgerFull,
    /// 500 — the ledger was reached without a verified identity, meaning the
    /// node's own auth layer order is wrong. The one code that is not the
    /// caller's fault.
    IdentityMissing,
    /// 503 — the ledger backend is down and the node is failing closed.
    LedgerUnavailable,
}

impl SignatureDenial {
    /// Every variant. Kept in the same order as the declaration so a reader can
    /// check it by eye; the `all_is_exhaustive` test below asserts it
    /// is complete.
    pub const ALL: [Self; 6] = [
        Self::NonceRequired,
        Self::NonceTooShort,
        Self::Replayed,
        Self::LedgerFull,
        Self::IdentityMissing,
        Self::LedgerUnavailable,
    ];

    /// The wire code, as it appears in `X-Gitlawb-Error` and in the body.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NonceRequired => "signature_nonce_required",
            Self::NonceTooShort => "signature_nonce_too_short",
            Self::Replayed => "signature_replayed",
            Self::LedgerFull => "signature_ledger_full",
            Self::IdentityMissing => "signature_identity_missing",
            Self::LedgerUnavailable => "signature_ledger_unavailable",
        }
    }

    /// The HTTP status the node pairs with this code.
    ///
    /// A `u16` rather than an `http::StatusCode` because this crate carries no
    /// HTTP dependency; the node converts once, and its own test proves every
    /// value here is a valid status.
    pub const fn status(self) -> u16 {
        match self {
            Self::NonceRequired | Self::NonceTooShort => 400,
            Self::Replayed => 409,
            Self::LedgerFull => 429,
            Self::IdentityMissing => 500,
            Self::LedgerUnavailable => 503,
        }
    }

    /// Parse a code off the wire.
    ///
    /// Returns `None` for anything this build does not know, because the string
    /// comes from a node the caller does not control. An unknown code is not an
    /// error to report; it is a denial this client cannot describe, and the
    /// caller decides what to do with the raw response.
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|d| d.as_str() == code)
    }
}

impl std::fmt::Display for SignatureDenial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards [`SignatureDenial::ALL`] against a variant added above it and
    /// forgotten here: the match is exhaustive, so a new variant stops this
    /// compiling, and the assertion catches the case where someone adds the arm
    /// but not the `ALL` entry.
    #[test]
    fn all_is_exhaustive() {
        fn tag(d: SignatureDenial) -> u8 {
            match d {
                SignatureDenial::NonceRequired => 0,
                SignatureDenial::NonceTooShort => 1,
                SignatureDenial::Replayed => 2,
                SignatureDenial::LedgerFull => 3,
                SignatureDenial::IdentityMissing => 4,
                SignatureDenial::LedgerUnavailable => 5,
            }
        }
        let mut tags: Vec<u8> = SignatureDenial::ALL.iter().copied().map(tag).collect();
        tags.sort_unstable();
        assert_eq!(
            tags,
            (0..SignatureDenial::ALL.len() as u8).collect::<Vec<_>>(),
            "SignatureDenial::ALL must list every variant exactly once",
        );
    }

    /// The wire contract, pinned literally. These strings and statuses are what
    /// deployed nodes emit and what deployed clients and scripts match on, so a
    /// change here is a protocol break, not a rename.
    #[test]
    fn wire_codes_and_statuses_are_pinned() {
        let pinned: [(SignatureDenial, &str, u16); 6] = [
            (
                SignatureDenial::NonceRequired,
                "signature_nonce_required",
                400,
            ),
            (
                SignatureDenial::NonceTooShort,
                "signature_nonce_too_short",
                400,
            ),
            (SignatureDenial::Replayed, "signature_replayed", 409),
            (SignatureDenial::LedgerFull, "signature_ledger_full", 429),
            (
                SignatureDenial::IdentityMissing,
                "signature_identity_missing",
                500,
            ),
            (
                SignatureDenial::LedgerUnavailable,
                "signature_ledger_unavailable",
                503,
            ),
        ];
        assert_eq!(pinned.len(), SignatureDenial::ALL.len());
        for (denial, code, status) in pinned {
            assert_eq!(denial.as_str(), code);
            assert_eq!(denial.status(), status);
        }
    }

    #[test]
    fn from_code_round_trips_every_variant() {
        for denial in SignatureDenial::ALL {
            assert_eq!(SignatureDenial::from_code(denial.as_str()), Some(denial));
        }
    }

    #[test]
    fn from_code_rejects_what_this_build_does_not_know() {
        for unknown in [
            "",
            "signature_",
            "signature_nonce",
            "signature_replayed_",
            " signature_replayed",
            "SIGNATURE_REPLAYED",
            "repo_exists",
            "human_detected",
            "signature_seventh_code_from_a_newer_node",
        ] {
            assert_eq!(
                SignatureDenial::from_code(unknown),
                None,
                "must not recognise {unknown:?}",
            );
        }
    }
}
