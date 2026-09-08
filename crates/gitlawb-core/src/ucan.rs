//! UCAN (User Controlled Authorization Networks) — capability token types.
//!
//! UCANs let a DID delegate specific capabilities to another DID,
//! with optional expiry and revocation. gitlawb uses UCANs for:
//!   - Delegating push access to a branch to a CI agent
//!   - Granting a reviewer the ability to approve PRs
//!   - Bootstrap tokens issued at registration
//!
//! This module provides the data types and serialization.
//! Cryptographic verification is handled by `identity::verify`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::did::Did;
use crate::identity::Keypair;
use crate::{Error, Result};

/// A UCAN capability: what resource the token grants access to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capability {
    /// The resource URI. e.g. `"gitlawb://repos/gitlawb/gitlawb"`
    pub with: String,
    /// The action. e.g. `"git/push"`, `"pr/open"`, `"issue/create"`, `"network/join"`
    pub can: String,
    /// Optional constraints on the capability.
    #[serde(rename = "nb", skip_serializing_if = "Option::is_none")]
    pub constraints: Option<serde_json::Value>,
}

impl Capability {
    pub fn new(with: impl Into<String>, can: impl Into<String>) -> Self {
        Self {
            with: with.into(),
            can: can.into(),
            constraints: None,
        }
    }

    pub fn with_constraints(mut self, constraints: serde_json::Value) -> Self {
        self.constraints = Some(constraints);
        self
    }

    /// Returns `true` if `self` is a valid attenuation of `parent`.
    ///
    /// A delegated capability is only valid if it is at most as permissive as
    /// the parent capability backing it. `"*"` on the **parent**'s resource or
    /// action field and `repo/admin` in the parent's action position act as
    /// wildcards that cover any delegated value; wildcards on `self` carry no
    /// special meaning.
    ///
    /// Constraints (`nb`) participate, and conservatively:
    ///
    /// | parent | child | verdict |
    /// |---|---|---|
    /// | none | anything | attenuated — adding constraints narrows |
    /// | some | identical | attenuated |
    /// | some | different | refused — narrowing is unprovable without semantics |
    /// | some | none | refused — dropping constraints widens |
    ///
    /// The last row is the one that matters. Ignoring `nb` here let a holder of a
    /// constrained capability re-delegate the same resource and action with the
    /// constraints removed, and the chain still verified — so a consumer that
    /// refuses constrained capabilities at the leaf saw an unconstrained one and
    /// granted it. Since `nb` has no interpreted semantics yet, "different" cannot
    /// be shown to be narrower and is refused with it.
    pub fn is_attenuated_by(&self, parent: &Capability) -> bool {
        let resource_ok = parent.with == self.with || parent.with == "*";
        let action_ok =
            parent.can == self.can || parent.can == "*" || parent.can == caps::REPO_ADMIN;
        let constraints_ok = match (&parent.constraints, &self.constraints) {
            (None, _) => true,
            (Some(p), Some(c)) => p == c,
            (Some(_), None) => false,
        };
        resource_ok && action_ok && constraints_ok
    }
}

/// Well-known gitlawb capability strings.
pub mod caps {
    pub const GIT_PUSH: &str = "git/push";
    pub const GIT_FETCH: &str = "git/fetch";
    pub const PR_OPEN: &str = "pr/open";
    pub const PR_MERGE: &str = "pr/merge";
    pub const PR_REVIEW: &str = "pr/review";
    pub const ISSUE_CREATE: &str = "issue/create";
    pub const ISSUE_CLOSE: &str = "issue/close";
    pub const NETWORK_JOIN: &str = "network/join";
    pub const AGENT_DEPLOY: &str = "agent/deploy";
    pub const REPO_ADMIN: &str = "repo/admin";
}

/// Rules shared by every boundary that decides whether a UCAN can push.
///
/// Four places answer "can this token push to this repository?": `gl ucan
/// delegate` and the MCP `ucan_delegate` tool when a token is issued, `gl ucan
/// import` when one is stored, `git-remote-gitlawb` when it mints an invocation,
/// and the node when it authorizes the push. For three review rounds each of them
/// carried its own copy of the answer, and every round found a token that one
/// boundary accepted and the next refused: a constrained grant that imported and
/// then authorized nothing; a wildcard proof the helper narrowed and the node
/// rejected; a resource whose owner the leaf named but the chain root did not.
///
/// The rules live here, once, in the crate all four already depend on. A boundary
/// may add checks of its own — the node anchors the chain root to a repository
/// record it holds independently, import binds the audience to the local key —
/// but the definition of a *usable push capability* is not one of them.
pub mod push {
    use super::{caps, Capability, Ucan};

    /// The `did:key` representation rule: `did:key:z6Mk…` and bare `z6Mk…` are
    /// the same identity. Mirror rows store the bare form; canonical rows and
    /// every token store the full form.
    ///
    /// Collapses representation only within `did:key`. `did:web` and
    /// `did:gitlawb` share the base58 space, so a trailing-segment compare would
    /// treat `did:key:X` and `did:gitlawb:X` as equal; after stripping the prefix,
    /// a value that still contains `:` is a non-key DID and matches nothing bare.
    pub fn did_key_eq(a: &str, b: &str) -> bool {
        if a == b {
            return true;
        }
        fn key_id(d: &str) -> &str {
            d.strip_prefix("did:key:").unwrap_or(d)
        }
        let (ka, kb) = (key_id(a), key_id(b));
        !ka.contains(':') && !kb.contains(':') && ka == kb
    }

    /// The actions that authorize a push: `git/push` itself, the action wildcard,
    /// and `repo/admin`, which covers it.
    pub fn is_push_action(can: &str) -> bool {
        can == caps::GIT_PUSH || can == "*" || can == caps::REPO_ADMIN
    }

    /// `gitlawb://repos/<owner>/<repo>` → `(owner, repo)`, or `None` for any other
    /// shape. Exactly two non-empty segments: an owner DID never contains `/`, so
    /// a third segment, a trailing slash, or an empty half is malformed rather than
    /// something to interpret.
    pub fn parse_repo_resource(with: &str) -> Option<(&str, &str)> {
        let rest = with.strip_prefix("gitlawb://repos/")?;
        let (owner, repo) = rest.split_once('/')?;
        if owner.is_empty() || repo.is_empty() || repo.contains('/') {
            return None;
        }
        Some((owner, repo))
    }

    /// A push-class capability whose resource is the wildcard. Refused at
    /// issuance, at import, by the helper, and by the node: a delegation's scope is
    /// fixed when it is issued, and `*` cannot say which repositories it covered
    /// at that moment.
    pub fn is_push_wildcard(with: &str, can: &str) -> bool {
        with == "*" && is_push_action(can)
    }

    /// Proof chains deeper than this fail closed. Nothing this codebase mints is
    /// longer than owner → agent → node, and the bound is what keeps a hand-built
    /// token from recursing without limit in a helper that runs mid-push.
    pub const MAX_CHAIN_DEPTH: usize = 8;

    impl Capability {
        /// Push-class, unconstrained, and naming exactly this repository.
        ///
        /// Unconstrained because `nb` has no semantics yet: an owner who wrote
        /// constraints meant to restrict, and honouring the capability while
        /// ignoring them would grant more than was intended. The owner segment is
        /// compared with [`did_key_eq`], so a token issued against the full DID
        /// matches a mirror row keyed on the bare form.
        pub fn grants_push_to(&self, owner: &str, repo: &str) -> bool {
            self.constraints.is_none()
                && is_push_action(&self.can)
                && parse_repo_resource(&self.with)
                    .is_some_and(|(o, r)| did_key_eq(o, owner) && r == repo)
        }
    }

    impl Ucan {
        /// Whether this chain — the leaf **and every proof behind it** — carries a
        /// capability that [`Capability::grants_push_to`] this repository.
        ///
        /// Every link, not just the leaf. [`Capability::is_attenuated_by`] accepts
        /// a concrete child under a `*` parent, so a leaf that names the repository
        /// can sit on a proof that names every repository the root owns — including
        /// ones created after the delegation was issued. Checking the leaf alone
        /// let exactly that through.
        ///
        /// This establishes scope, not trust. It does not verify signatures,
        /// expiry, or audience; call [`Ucan::verify_chain`] first, and anchor the
        /// root it returns to something held independently of the token.
        ///
        /// Fails closed on anything it cannot vouch for: a proof that does not
        /// decode, more than one proof per link, or a chain deeper than
        /// [`MAX_CHAIN_DEPTH`].
        pub fn chain_grants_push_to(&self, owner: &str, repo: &str) -> bool {
            self.chain_grants_push_to_at(owner, repo, 0)
        }

        fn chain_grants_push_to_at(&self, owner: &str, repo: &str, depth: usize) -> bool {
            if depth >= MAX_CHAIN_DEPTH {
                return false;
            }
            if !self
                .payload
                .att
                .iter()
                .any(|c| c.grants_push_to(owner, repo))
            {
                return false;
            }
            // `verify_chain` refuses more than one proof per link for the same
            // reason: two proofs mean two roots, and nothing says which authorized
            // what.
            if self.payload.prf.len() > 1 {
                return false;
            }
            match self.payload.prf.first() {
                None => true,
                Some(token) => match Ucan::decode(token) {
                    Ok(proof) => proof.chain_grants_push_to_at(owner, repo, depth + 1),
                    Err(_) => false,
                },
            }
        }
    }
}

/// The UCAN payload (what gets signed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UcanPayload {
    /// UCAN version. Always "1.0.0".
    pub ucan: String,
    /// Issuer DID — who is granting this capability.
    pub iss: Did,
    /// Audience DID — who receives this capability.
    pub aud: Did,
    /// The capabilities being granted.
    pub att: Vec<Capability>,
    /// Expiry as Unix timestamp (seconds). None = no expiry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Not-before as Unix timestamp. None = valid immediately.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// Proof chain — UCANs that authorize the issuer to delegate.
    /// Empty for root capabilities (self-issued by a repo owner).
    #[serde(default)]
    pub prf: Vec<String>,
}

/// A signed UCAN token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ucan {
    pub payload: UcanPayload,
    /// base64url-encoded Ed25519 signature over the payload JSON.
    pub s: String,
}

impl Ucan {
    /// Issue a new UCAN token.
    pub fn issue(
        issuer: &Keypair,
        audience: Did,
        capabilities: Vec<Capability>,
        exp: Option<DateTime<Utc>>,
    ) -> Result<Self> {
        let payload = UcanPayload {
            ucan: "1.0.0".to_string(),
            iss: issuer.did(),
            aud: audience,
            att: capabilities,
            exp: exp.map(|e| e.timestamp()),
            nbf: None,
            prf: vec![],
        };

        let signing_bytes = serde_json::to_vec(&payload)?;
        let sig = issuer.sign_b64(&signing_bytes);

        Ok(Self { payload, s: sig })
    }

    /// Issue a bootstrap UCAN — grants `network/join` on the alpha network.
    pub fn bootstrap(issuer: &Keypair, audience: Did) -> Result<Self> {
        let exp = chrono::Utc::now() + chrono::Duration::days(30);
        Self::issue(
            issuer,
            audience,
            vec![Capability::new("gitlawb://alpha", caps::NETWORK_JOIN)],
            Some(exp),
        )
    }

    /// Check if this UCAN has expired.
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.payload.exp {
            Utc::now().timestamp() > exp
        } else {
            false
        }
    }

    /// Whether every link in this chain carries a finite `exp`.
    ///
    /// `exp` is optional in the format, and [`Self::is_expired`] reports `false`
    /// when it is absent — so a link without one never expires. With no revocation
    /// mechanism, a chain containing such a link is a permanent grant: a leaked
    /// token cannot be withdrawn, and the issuer's only remedy is to rotate the
    /// identity the resource is keyed on.
    ///
    /// Consumers that turn a UCAN into write authority should require this. It is
    /// deliberately not enforced inside [`Self::verify_chain`], because a
    /// non-expiring token is well-formed and may be perfectly appropriate for a
    /// read-only or advisory capability; whether an unbounded grant is acceptable
    /// is the consumer's policy, not the format's.
    pub fn chain_lifetime_is_bounded(&self) -> bool {
        if self.payload.exp.is_none() {
            return false;
        }
        self.payload
            .prf
            .iter()
            .all(|token| Self::decode(token).is_ok_and(|proof| proof.chain_lifetime_is_bounded()))
    }

    /// Check if this UCAN's not-before time is in the future (token not yet valid).
    pub fn is_before_valid(&self) -> bool {
        if let Some(nbf) = self.payload.nbf {
            Utc::now().timestamp() < nbf
        } else {
            false
        }
    }

    /// Verify this UCAN's audience matches `expected`.
    pub fn verify_audience(&self, expected: &Did) -> Result<()> {
        if &self.payload.aud != expected {
            return Err(Error::Ucan(format!(
                "audience mismatch: expected {expected}, got {}",
                self.payload.aud
            )));
        }
        Ok(())
    }

    /// Verify the signature on this UCAN.
    pub fn verify_signature(&self) -> Result<()> {
        use crate::identity::verify;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let vk = self.payload.iss.to_verifying_key()?;
        let signing_bytes = serde_json::to_vec(&self.payload)?;

        let sig_bytes_vec = URL_SAFE_NO_PAD
            .decode(&self.s)
            .map_err(|e| Error::Ucan(format!("invalid base64 signature: {e}")))?;

        let sig_bytes: [u8; 64] = sig_bytes_vec
            .try_into()
            .map_err(|_| Error::Ucan("signature must be 64 bytes".to_string()))?;

        verify(&vk, &signing_bytes, &sig_bytes)
            .map_err(|_| Error::Ucan("signature verification failed".to_string()))
    }

    /// Check if this UCAN grants a specific capability on a resource.
    ///
    /// Mirrors `Capability::is_attenuated_by`'s wildcard semantics: a stored
    /// capability of `with: "*"` or `can: "*"` / `"repo/admin"` covers any
    /// requested resource/action, since a valid delegation chain can produce
    /// exactly that capability (see `is_attenuated_by`).
    pub fn can(&self, resource: &str, action: &str) -> bool {
        self.payload.att.iter().any(|cap| {
            let resource_ok = cap.with == resource || cap.with == "*";
            let action_ok = cap.can == action || cap.can == "*" || cap.can == caps::REPO_ADMIN;
            resource_ok && action_ok
        })
    }

    /// Encode to a compact JSON string (the wire format).
    pub fn encode(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    /// Decode from a JSON string.
    pub fn decode(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| Error::Ucan(e.to_string()))
    }

    /// Issue a UCAN with proof chain — delegates from a parent UCAN.
    ///
    /// The issuer must be the audience of the parent UCAN (the entity
    /// that received the capability). The parent's encoded token is
    /// included in the `prf` field.
    pub fn delegate(
        issuer: &Keypair,
        audience: Did,
        capabilities: Vec<Capability>,
        exp: Option<DateTime<Utc>>,
        proof: &Ucan,
    ) -> Result<Self> {
        let proof_token = proof.encode()?;
        let payload = UcanPayload {
            ucan: "1.0.0".to_string(),
            iss: issuer.did(),
            aud: audience,
            att: capabilities,
            exp: exp.map(|e| e.timestamp()),
            nbf: None,
            prf: vec![proof_token],
        };

        let signing_bytes = serde_json::to_vec(&payload)?;
        let sig = issuer.sign_b64(&signing_bytes);

        Ok(Self { payload, s: sig })
    }

    /// Verify the full proof chain of this UCAN.
    ///
    /// For each proof in the `prf` field:
    /// 1. Decode and verify its signature
    /// 2. Ensure the proof's audience matches this UCAN's issuer
    ///    (the entity that received the capability must be the one delegating)
    /// 3. Check the proof is not expired
    /// 4. Recursively verify the proof's own chain
    ///
    /// A UCAN with no proofs is its own root, so it returns its own issuer.
    ///
    /// **This establishes internal consistency, not trust.** `did:key` is
    /// self-certifying, so anyone can mint a keypair and produce a chain that
    /// verifies. A caller making an authorization decision MUST compare the
    /// returned root against an identity it trusts for some reason outside this
    /// token — a repo owner, a configured value, a registry lookup. Discarding
    /// the return value is only correct when the caller is checking that a token
    /// is well-formed and deliberately does not care who issued it.
    pub fn verify_chain(&self) -> Result<Did> {
        // First verify our own signature
        self.verify_signature()?;

        if self.is_expired() {
            return Err(Error::Ucan("token is expired".to_string()));
        }

        if self.is_before_valid() {
            return Err(Error::Ucan("token is not yet valid".to_string()));
        }

        if self.payload.prf.len() > 1 {
            return Err(Error::Ucan(
                "multi-proof chains are not supported: more than one proof means \
                 more than one root, and which root authorized a given capability \
                 is ambiguous"
                    .to_string(),
            ));
        }

        let Some(proof_token) = self.payload.prf.first() else {
            // No proofs: this token is its own root.
            return Ok(self.payload.iss.clone());
        };

        let proof = Self::decode(proof_token)
            .map_err(|e| Error::Ucan(format!("failed to decode proof: {e}")))?;

        // The proof's audience must be this UCAN's issuer
        if proof.payload.aud != self.payload.iss {
            return Err(Error::Ucan(format!(
                "proof chain broken: proof audience {} does not match issuer {}",
                proof.payload.aud, self.payload.iss
            )));
        }

        // Every delegated capability must be covered by the proof (attenuation).
        for cap in &self.payload.att {
            let covered = proof.payload.att.iter().any(|p| cap.is_attenuated_by(p));
            if !covered {
                return Err(Error::Ucan(format!(
                    "capability attenuation violated: '{}' on '{}' not covered by proof",
                    cap.can, cap.with
                )));
            }
        }

        // Recurse; the root of the proof's chain is the root of ours.
        proof.verify_chain()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Keypair;

    #[test]
    fn issue_and_verify() {
        let issuer = Keypair::generate();
        let audience = Keypair::generate().did();

        let ucan = Ucan::issue(
            &issuer,
            audience.clone(),
            vec![Capability::new("gitlawb://repos/test/repo", caps::GIT_PUSH)],
            None,
        )
        .unwrap();

        ucan.verify_signature().unwrap();
        assert!(!ucan.is_expired());
        assert_eq!(ucan.payload.iss, issuer.did());
        assert_eq!(ucan.payload.aud, audience);
        assert!(ucan.can("gitlawb://repos/test/repo", caps::GIT_PUSH));
        assert!(!ucan.can("gitlawb://repos/test/repo", caps::PR_MERGE));
    }

    #[test]
    fn can_honors_resource_wildcard() {
        let issuer = Keypair::generate();
        let audience = Keypair::generate().did();

        let ucan = Ucan::issue(
            &issuer,
            audience,
            vec![Capability::new("*", caps::GIT_PUSH)],
            None,
        )
        .unwrap();

        assert!(ucan.can("gitlawb://repos/test/repo", caps::GIT_PUSH));
        assert!(ucan.can("gitlawb://repos/other/repo", caps::GIT_PUSH));
        assert!(!ucan.can("gitlawb://repos/test/repo", caps::PR_MERGE));
    }

    #[test]
    fn can_honors_repo_admin_action_wildcard() {
        let issuer = Keypair::generate();
        let audience = Keypair::generate().did();

        let ucan = Ucan::issue(
            &issuer,
            audience,
            vec![Capability::new(
                "gitlawb://repos/test/repo",
                caps::REPO_ADMIN,
            )],
            None,
        )
        .unwrap();

        assert!(ucan.can("gitlawb://repos/test/repo", caps::GIT_PUSH));
        assert!(ucan.can("gitlawb://repos/test/repo", caps::PR_MERGE));
        assert!(!ucan.can("gitlawb://repos/other/repo", caps::GIT_PUSH));
    }

    #[test]
    fn can_honors_action_wildcard() {
        let issuer = Keypair::generate();
        let audience = Keypair::generate().did();

        let ucan = Ucan::issue(
            &issuer,
            audience,
            vec![Capability::new("gitlawb://repos/test/repo", "*")],
            None,
        )
        .unwrap();

        assert!(ucan.can("gitlawb://repos/test/repo", caps::GIT_PUSH));
        assert!(ucan.can("gitlawb://repos/test/repo", caps::PR_MERGE));
        assert!(!ucan.can("gitlawb://repos/other/repo", caps::GIT_PUSH));
    }

    #[test]
    fn bootstrap_ucan() {
        let issuer = Keypair::generate();
        let audience = Keypair::generate().did();
        let ucan = Ucan::bootstrap(&issuer, audience).unwrap();
        ucan.verify_signature().unwrap();
        assert!(ucan.can("gitlawb://alpha", caps::NETWORK_JOIN));
    }

    #[test]
    fn encode_decode_roundtrip() {
        let issuer = Keypair::generate();
        let audience = Keypair::generate().did();
        let ucan = Ucan::bootstrap(&issuer, audience).unwrap();
        let encoded = ucan.encode().unwrap();
        let decoded = Ucan::decode(&encoded).unwrap();
        assert_eq!(ucan.payload.iss, decoded.payload.iss);
        assert_eq!(ucan.payload.aud, decoded.payload.aud);
        decoded.verify_signature().unwrap();
    }

    #[test]
    fn capability_with_constraints() {
        use serde_json::json;
        let cap = Capability::new("gitlawb://repos/org/repo", caps::GIT_PUSH)
            .with_constraints(json!({ "branch": "refs/heads/ci/*" }));

        let json = serde_json::to_string(&cap).unwrap();
        assert!(json.contains("ci/*"));
    }

    #[test]
    fn verify_chain_root_ucan() {
        let issuer = Keypair::generate();
        let audience = Keypair::generate().did();
        let ucan = Ucan::issue(
            &issuer,
            audience,
            vec![Capability::new("gitlawb://repos/test", caps::GIT_PUSH)],
            None,
        )
        .unwrap();
        // Root UCAN (no proofs) should verify fine
        ucan.verify_chain().unwrap();
    }

    #[test]
    fn verify_chain_valid_delegation() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let charlie = Keypair::generate();

        // Alice grants Bob push access
        let root = Ucan::issue(
            &alice,
            bob.did(),
            vec![Capability::new("gitlawb://repos/test", caps::GIT_PUSH)],
            None,
        )
        .unwrap();

        // Bob delegates to Charlie (with proof from Alice)
        let delegated = Ucan::delegate(
            &bob,
            charlie.did(),
            vec![Capability::new("gitlawb://repos/test", caps::GIT_PUSH)],
            None,
            &root,
        )
        .unwrap();

        // Chain should verify: Charlie's token → Bob's proof → Alice signed it
        delegated.verify_chain().unwrap();
        assert_eq!(delegated.payload.prf.len(), 1);
    }

    #[test]
    fn verify_chain_broken_audience_issuer() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let charlie = Keypair::generate();
        let eve = Keypair::generate();

        // Alice grants Bob access
        let root = Ucan::issue(
            &alice,
            bob.did(),
            vec![Capability::new("gitlawb://repos/test", caps::GIT_PUSH)],
            None,
        )
        .unwrap();

        // Eve (NOT Bob) tries to delegate using Alice's proof
        let bad = Ucan::delegate(
            &eve,
            charlie.did(),
            vec![Capability::new("gitlawb://repos/test", caps::GIT_PUSH)],
            None,
            &root,
        )
        .unwrap();

        // Should fail: proof audience (Bob) != UCAN issuer (Eve)
        let err = bad.verify_chain().unwrap_err();
        assert!(err.to_string().contains("proof chain broken"));
    }

    #[test]
    fn verify_chain_expired_proof() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let charlie = Keypair::generate();

        // Alice grants Bob access with expiry in the past
        let exp = chrono::Utc::now() - chrono::Duration::hours(1);
        let root = Ucan::issue(
            &alice,
            bob.did(),
            vec![Capability::new("gitlawb://repos/test", caps::GIT_PUSH)],
            Some(exp),
        )
        .unwrap();

        let delegated = Ucan::delegate(
            &bob,
            charlie.did(),
            vec![Capability::new("gitlawb://repos/test", caps::GIT_PUSH)],
            None,
            &root,
        )
        .unwrap();

        // Should fail: the proof is expired
        let err = delegated.verify_chain().unwrap_err();
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn is_before_valid_future_nbf() {
        let issuer = Keypair::generate();
        let audience = Keypair::generate().did();
        let nbf_future = chrono::Utc::now() + chrono::Duration::hours(1);

        let payload = UcanPayload {
            ucan: "1.0.0".to_string(),
            iss: issuer.did(),
            aud: audience,
            att: vec![],
            exp: None,
            nbf: Some(nbf_future.timestamp()),
            prf: vec![],
        };
        let signing_bytes = serde_json::to_vec(&payload).unwrap();
        let sig = issuer.sign_b64(&signing_bytes);
        let ucan = Ucan { payload, s: sig };

        assert!(ucan.is_before_valid());
        let err = ucan.verify_chain().unwrap_err();
        assert!(err.to_string().contains("not yet valid"));
    }

    #[test]
    fn is_before_valid_past_nbf() {
        let issuer = Keypair::generate();
        let audience = Keypair::generate().did();
        let nbf_past = chrono::Utc::now() - chrono::Duration::hours(1);

        let payload = UcanPayload {
            ucan: "1.0.0".to_string(),
            iss: issuer.did(),
            aud: audience,
            att: vec![Capability::new("gitlawb://repos/test", caps::GIT_PUSH)],
            exp: None,
            nbf: Some(nbf_past.timestamp()),
            prf: vec![],
        };
        let signing_bytes = serde_json::to_vec(&payload).unwrap();
        let sig = issuer.sign_b64(&signing_bytes);
        let ucan = Ucan { payload, s: sig };

        assert!(!ucan.is_before_valid());
        ucan.verify_chain().unwrap();
    }

    #[test]
    fn verify_audience_matches() {
        let issuer = Keypair::generate();
        let audience = Keypair::generate().did();
        let ucan = Ucan::issue(&issuer, audience.clone(), vec![], None).unwrap();
        ucan.verify_audience(&audience).unwrap();
    }

    #[test]
    fn verify_audience_mismatch() {
        let issuer = Keypair::generate();
        let audience = Keypair::generate().did();
        let wrong = Keypair::generate().did();
        let ucan = Ucan::issue(&issuer, audience, vec![], None).unwrap();
        let err = ucan.verify_audience(&wrong).unwrap_err();
        assert!(err.to_string().contains("audience mismatch"));
    }

    #[test]
    fn attenuation_valid_subset() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let charlie = Keypair::generate();

        // Alice grants Bob push on a specific repo
        let root = Ucan::issue(
            &alice,
            bob.did(),
            vec![Capability::new("gitlawb://repos/org/repo", caps::GIT_PUSH)],
            None,
        )
        .unwrap();

        // Bob delegates the same capability (exact subset) to Charlie
        let delegated = Ucan::delegate(
            &bob,
            charlie.did(),
            vec![Capability::new("gitlawb://repos/org/repo", caps::GIT_PUSH)],
            None,
            &root,
        )
        .unwrap();

        delegated.verify_chain().unwrap();
    }

    #[test]
    fn attenuation_exceeds_parent_is_rejected() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let charlie = Keypair::generate();

        // Alice grants Bob push on one repo only
        let root = Ucan::issue(
            &alice,
            bob.did(),
            vec![Capability::new("gitlawb://repos/org/repo", caps::GIT_PUSH)],
            None,
        )
        .unwrap();

        // Bob tries to delegate merge (not in the original grant) to Charlie
        let delegated = Ucan::delegate(
            &bob,
            charlie.did(),
            vec![Capability::new("gitlawb://repos/org/repo", caps::PR_MERGE)],
            None,
            &root,
        )
        .unwrap();

        let err = delegated.verify_chain().unwrap_err();
        assert!(err.to_string().contains("attenuation violated"));
    }

    #[test]
    fn attenuation_repo_admin_covers_all() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let charlie = Keypair::generate();

        // Alice grants Bob repo/admin (superpower)
        let root = Ucan::issue(
            &alice,
            bob.did(),
            vec![Capability::new(
                "gitlawb://repos/org/repo",
                caps::REPO_ADMIN,
            )],
            None,
        )
        .unwrap();

        // Bob delegates a more specific capability — covered by repo/admin
        let delegated = Ucan::delegate(
            &bob,
            charlie.did(),
            vec![Capability::new("gitlawb://repos/org/repo", caps::GIT_PUSH)],
            None,
            &root,
        )
        .unwrap();

        delegated.verify_chain().unwrap();
    }

    #[test]
    fn verify_chain_returns_the_root_issuer_of_a_delegated_chain() {
        // owner -> agent (delegation), agent -> node (invocation).
        // The root is the owner: that is the identity the whole chain rests on,
        // and the only one a caller can meaningfully anchor a trust decision to.
        let owner = Keypair::generate();
        let agent = Keypair::generate();
        let node = Keypair::generate();
        let caps_vec = vec![Capability::new("gitlawb://repos/zowner/r", caps::GIT_PUSH)];

        let delegation =
            Ucan::issue(&owner, agent.did(), caps_vec.clone(), None).expect("issue delegation");
        let invocation = Ucan::delegate(&agent, node.did(), caps_vec, None, &delegation)
            .expect("wrap invocation");

        assert_eq!(
            invocation.verify_chain().expect("chain must verify"),
            owner.did(),
            "the root issuer is the owner who started the chain, not the agent presenting it"
        );
    }

    /// A chain is only bounded if EVERY link is. An unbounded link anywhere makes
    /// the whole grant permanent, because `is_expired` reports false for it and
    /// there is no revocation path to withdraw it.
    #[test]
    fn chain_lifetime_is_bounded_requires_an_expiry_on_every_link() {
        let owner = Keypair::generate();
        let agent = Keypair::generate();
        let node = Keypair::generate();
        let cap = || vec![Capability::new("gitlawb://repos/zowner/r", caps::GIT_PUSH)];
        let hour = Utc::now() + chrono::Duration::hours(1);

        let bounded_root = Ucan::issue(&owner, agent.did(), cap(), Some(hour)).expect("issue");
        let unbounded_root = Ucan::issue(&owner, agent.did(), cap(), None).expect("issue");

        assert!(
            Ucan::delegate(&agent, node.did(), cap(), Some(hour), &bounded_root)
                .expect("wrap")
                .chain_lifetime_is_bounded(),
            "both links finite"
        );
        assert!(
            !Ucan::delegate(&agent, node.did(), cap(), None, &bounded_root)
                .expect("wrap")
                .chain_lifetime_is_bounded(),
            "the leaf has no expiry, so the grant never lapses"
        );
        assert!(
            !Ucan::delegate(&agent, node.did(), cap(), Some(hour), &unbounded_root)
                .expect("wrap")
                .chain_lifetime_is_bounded(),
            "a bounded leaf cannot rescue an unbounded proof: the holder can always \
             mint a fresh leaf from it"
        );
        assert!(
            !unbounded_root.chain_lifetime_is_bounded(),
            "a self-issued token with no expiry is itself unbounded"
        );
    }

    /// A three-link chain: owner -> lead -> agent, which is the real shape of an
    /// org delegating to a team lead who delegates to a CI identity.
    ///
    /// Every other chain here is depth two, where the immediate proof IS the root —
    /// so nothing distinguishes recursing to the true root from simply returning the
    /// proof's issuer. Both `assert_eq!` and `assert_ne!` below are load-bearing:
    /// without the second, returning the middle issuer would still satisfy a test
    /// that only checked "not the leaf".
    #[test]
    fn verify_chain_walks_past_the_immediate_proof_to_the_true_root() {
        let owner = Keypair::generate();
        let lead = Keypair::generate();
        let agent = Keypair::generate();
        let node = Keypair::generate();
        let cap = || vec![Capability::new("gitlawb://repos/zowner/r", caps::GIT_PUSH)];

        let root = Ucan::issue(&owner, lead.did(), cap(), None).expect("owner -> lead");
        let mid = Ucan::delegate(&lead, agent.did(), cap(), None, &root).expect("lead -> agent");
        let leaf = Ucan::delegate(&agent, node.did(), cap(), None, &mid).expect("agent -> node");

        let found = leaf.verify_chain().expect("a three-link chain must verify");
        assert_eq!(
            found,
            owner.did(),
            "the root is the owner who started the chain, two hops up"
        );
        assert_ne!(
            found,
            lead.did(),
            "returning the immediate proof's issuer is not walking to the root"
        );
    }

    #[test]
    fn verify_chain_returns_self_as_root_for_a_self_issued_token() {
        // A token with no proofs roots at its own issuer. This is what makes a
        // self-minted token useless: the caller compares this against the repo
        // owner and it will only ever match when the presenter IS the owner.
        let agent = Keypair::generate();
        let node = Keypair::generate();
        let ucan =
            Ucan::issue(&agent, node.did(), vec![Capability::new("*", "*")], None).expect("issue");

        assert_eq!(
            ucan.verify_chain().expect("a root token still verifies"),
            agent.did(),
            "a self-minted token roots at the minter, however permissive its capabilities"
        );
    }

    /// Stripping `nb` is a widening, and a widening must fail attenuation.
    ///
    /// Without this, a constrained delegation is trivially escalated: the holder
    /// re-delegates the same resource and action with the constraints removed,
    /// `verify_chain` accepts the chain because attenuation only compared `with`
    /// and `can`, and a consumer that refuses constrained capabilities at the leaf
    /// (as the node's push gate does) then sees an unconstrained one and grants it.
    /// Guarding only the leaf guards the wrong end of the chain.
    #[test]
    fn verify_chain_rejects_a_child_that_strips_the_parents_constraints() {
        let owner = Keypair::generate();
        let agent = Keypair::generate();
        let node = Keypair::generate();

        let constrained = Capability::new("gitlawb://repos/zowner/r", caps::GIT_PUSH)
            .with_constraints(serde_json::json!({ "refs": ["refs/heads/feat/*"] }));
        let delegation = Ucan::issue(&owner, agent.did(), vec![constrained], None)
            .expect("issue constrained delegation");

        // Same resource, same action, constraints dropped.
        let widened = Capability::new("gitlawb://repos/zowner/r", caps::GIT_PUSH);
        let forged =
            Ucan::delegate(&agent, node.did(), vec![widened], None, &delegation).expect("wrap");

        let err = forged
            .verify_chain()
            .expect_err("dropping the parent's constraints must fail attenuation");
        assert!(
            err.to_string().contains("attenuation"),
            "the failure must name attenuation, got: {err}"
        );
    }

    #[test]
    fn verify_chain_accepts_a_child_that_keeps_the_parents_constraints() {
        let owner = Keypair::generate();
        let agent = Keypair::generate();
        let node = Keypair::generate();

        let nb = serde_json::json!({ "refs": ["refs/heads/feat/*"] });
        let constrained = Capability::new("gitlawb://repos/zowner/r", caps::GIT_PUSH)
            .with_constraints(nb.clone());
        let delegation =
            Ucan::issue(&owner, agent.did(), vec![constrained.clone()], None).expect("issue");
        let invocation =
            Ucan::delegate(&agent, node.did(), vec![constrained], None, &delegation).expect("wrap");

        assert_eq!(
            invocation
                .verify_chain()
                .expect("an unchanged constraint must verify"),
            owner.did()
        );
    }

    #[test]
    fn an_unconstrained_parent_still_allows_a_child_to_add_constraints() {
        // Adding `nb` narrows, which is always a legal attenuation.
        let owner = Keypair::generate();
        let agent = Keypair::generate();
        let node = Keypair::generate();

        let open = Capability::new("gitlawb://repos/zowner/r", caps::GIT_PUSH);
        let delegation = Ucan::issue(&owner, agent.did(), vec![open], None).expect("issue");
        let narrowed = Capability::new("gitlawb://repos/zowner/r", caps::GIT_PUSH)
            .with_constraints(serde_json::json!({ "refs": ["refs/heads/main"] }));
        let invocation =
            Ucan::delegate(&agent, node.did(), vec![narrowed], None, &delegation).expect("wrap");

        assert_eq!(
            invocation.verify_chain().expect("narrowing must verify"),
            owner.did()
        );
    }

    #[test]
    fn verify_chain_rejects_a_multi_proof_chain() {
        // Two proofs mean two roots, and nothing says which root authorized a
        // given capability. Returning either one would be unsound, so refuse.
        let owner_a = Keypair::generate();
        let owner_b = Keypair::generate();
        let agent = Keypair::generate();
        let node = Keypair::generate();
        let caps_vec = vec![Capability::new("gitlawb://repos/zowner/r", caps::GIT_PUSH)];

        let proof_a = Ucan::issue(&owner_a, agent.did(), caps_vec.clone(), None).expect("issue a");
        let proof_b = Ucan::issue(&owner_b, agent.did(), caps_vec.clone(), None).expect("issue b");

        // `delegate` only ever writes one proof, so build the two-proof payload by hand.
        let payload = UcanPayload {
            ucan: "1.0.0".to_string(),
            iss: agent.did(),
            aud: node.did(),
            att: caps_vec,
            exp: None,
            nbf: None,
            prf: vec![
                proof_a.encode().expect("encode a"),
                proof_b.encode().expect("encode b"),
            ],
        };
        let signing_bytes = serde_json::to_vec(&payload).expect("serialize payload");
        let s = agent.sign_b64(&signing_bytes);
        let multi = Ucan { payload, s };

        let err = multi
            .verify_chain()
            .expect_err("a two-proof chain must be refused");
        assert!(
            err.to_string().contains("multi-proof"),
            "the error must name the reason, got: {err}"
        );
    }
}

#[cfg(test)]
mod push_scope_tests {
    use super::push::*;
    use super::{caps, Capability, Ucan};
    use crate::identity::Keypair;

    fn hour() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now() + chrono::Duration::hours(1)
    }

    #[test]
    fn did_key_eq_collapses_representation_only_within_did_key() {
        assert!(did_key_eq("did:key:z6MkAbc", "z6MkAbc"));
        assert!(did_key_eq("z6MkAbc", "did:key:z6MkAbc"));
        assert!(did_key_eq("did:key:z6MkAbc", "did:key:z6MkAbc"));
        assert!(!did_key_eq("did:key:z6MkAbc", "did:key:z6MkXyz"));
        // A bare id must never match across methods: `did:gitlawb` shares the
        // base58 space with `did:key`.
        assert!(!did_key_eq("did:gitlawb:z6MkAbc", "z6MkAbc"));
        assert!(!did_key_eq("did:key:z6MkAbc", "did:gitlawb:z6MkAbc"));
        assert!(!did_key_eq("did:web:example.com", "example.com"));
    }

    #[test]
    fn parse_repo_resource_requires_exactly_two_segments() {
        assert_eq!(
            parse_repo_resource("gitlawb://repos/did:key:z6Mk/r"),
            Some(("did:key:z6Mk", "r"))
        );
        for bad in [
            "*",
            "",
            "gitlawb://repos/",
            "gitlawb://repos/owner",
            "gitlawb://repos/owner/",
            "gitlawb://repos//r",
            "gitlawb://repos/owner/r/extra",
            "https://repos/owner/r",
        ] {
            assert_eq!(parse_repo_resource(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn is_push_wildcard_is_the_resource_wildcard_with_a_push_action() {
        for can in [caps::GIT_PUSH, "*", caps::REPO_ADMIN] {
            assert!(is_push_wildcard("*", can), "{can}");
        }
        assert!(!is_push_wildcard("*", caps::GIT_FETCH));
        assert!(!is_push_wildcard("*", caps::PR_OPEN));
        assert!(!is_push_wildcard("gitlawb://repos/o/r", caps::GIT_PUSH));
    }

    #[test]
    fn a_capability_grants_push_only_when_concrete_unconstrained_and_push_class() {
        let owner = "did:key:z6MkOwner";
        let ok = Capability::new("gitlawb://repos/did:key:z6MkOwner/r", caps::GIT_PUSH);
        assert!(ok.grants_push_to(owner, "r"));
        // Bare and full owner forms are the same identity.
        assert!(ok.grants_push_to("z6MkOwner", "r"));

        assert!(!Capability::new("*", caps::GIT_PUSH).grants_push_to(owner, "r"));
        assert!(
            !Capability::new("gitlawb://repos/did:key:z6MkOwner/r", caps::GIT_FETCH)
                .grants_push_to(owner, "r")
        );
        assert!(
            !Capability::new("gitlawb://repos/did:key:z6MkOwner/other", caps::GIT_PUSH)
                .grants_push_to(owner, "r")
        );
        assert!(
            !Capability::new("gitlawb://repos/did:key:z6MkOther/r", caps::GIT_PUSH)
                .grants_push_to(owner, "r")
        );
        assert!(
            !Capability::new("gitlawb://repos/did:key:z6MkOwner/r", caps::GIT_PUSH)
                .with_constraints(serde_json::json!({"max_bytes": 1}))
                .grants_push_to(owner, "r")
        );
        for can in ["*", caps::REPO_ADMIN] {
            assert!(
                Capability::new("gitlawb://repos/did:key:z6MkOwner/r", can)
                    .grants_push_to(owner, "r"),
                "{can} covers git/push"
            );
        }
    }

    /// The chain walk, at every depth: a wildcard anywhere denies; concrete
    /// everywhere grants. The grandparent case is the one a single-level check
    /// misses, because the immediate proof already names the repo.
    #[test]
    fn chain_grants_push_only_when_every_link_names_the_repo() {
        let owner = Keypair::generate();
        let a = Keypair::generate();
        let b = Keypair::generate();
        let node = Keypair::generate();
        let owner_s = owner.did().to_string();
        let res = format!("gitlawb://repos/{owner_s}/r");
        let concrete = || vec![Capability::new(&res, caps::GIT_PUSH)];
        let wild = || vec![Capability::new("*", caps::GIT_PUSH)];

        // Single self-issued link.
        assert!(Ucan::issue(&owner, a.did(), concrete(), Some(hour()))
            .unwrap()
            .chain_grants_push_to(&owner_s, "r"));
        assert!(!Ucan::issue(&owner, a.did(), wild(), Some(hour()))
            .unwrap()
            .chain_grants_push_to(&owner_s, "r"));

        // Two links: concrete leaf on a wildcard proof must deny.
        let wild_proof = Ucan::issue(&owner, a.did(), wild(), Some(hour())).unwrap();
        let leaf = Ucan::delegate(&a, node.did(), concrete(), Some(hour()), &wild_proof).unwrap();
        assert!(
            leaf.verify_chain().is_ok(),
            "attenuation accepts it — that is why we walk"
        );
        assert!(!leaf.chain_grants_push_to(&owner_s, "r"));

        // Three links: wildcard grandparent, concrete parent, concrete leaf.
        let gp = Ucan::issue(&owner, a.did(), wild(), Some(hour())).unwrap();
        let parent = Ucan::delegate(&a, b.did(), concrete(), Some(hour()), &gp).unwrap();
        let leaf = Ucan::delegate(&b, node.did(), concrete(), Some(hour()), &parent).unwrap();
        assert!(leaf.verify_chain().is_ok());
        assert!(
            !leaf.chain_grants_push_to(&owner_s, "r"),
            "a wildcard two links up must deny"
        );

        // Three links, all concrete.
        let gp = Ucan::issue(&owner, a.did(), concrete(), Some(hour())).unwrap();
        let parent = Ucan::delegate(&a, b.did(), concrete(), Some(hour()), &gp).unwrap();
        let leaf = Ucan::delegate(&b, node.did(), concrete(), Some(hour()), &parent).unwrap();
        assert!(leaf.chain_grants_push_to(&owner_s, "r"));
        // And the bare owner form is the same repo.
        assert!(leaf.chain_grants_push_to(owner_s.strip_prefix("did:key:").unwrap(), "r"));
        // But not another repo.
        assert!(!leaf.chain_grants_push_to(&owner_s, "other"));
    }

    /// Fail closed on anything the walk cannot vouch for.
    #[test]
    fn chain_walk_fails_closed_on_undecodable_or_multi_proofs_or_excess_depth() {
        let owner = Keypair::generate();
        let a = Keypair::generate();
        let owner_s = owner.did().to_string();
        let res = format!("gitlawb://repos/{owner_s}/r");
        let cap = || vec![Capability::new(&res, caps::GIT_PUSH)];

        let mut broken = Ucan::issue(&owner, a.did(), cap(), Some(hour())).unwrap();
        broken.payload.prf = vec!["not a ucan".into()];
        assert!(!broken.chain_grants_push_to(&owner_s, "r"));

        let good = Ucan::issue(&owner, a.did(), cap(), Some(hour())).unwrap();
        let mut two = Ucan::issue(&owner, a.did(), cap(), Some(hour())).unwrap();
        two.payload.prf = vec![good.encode().unwrap(), good.encode().unwrap()];
        assert!(!two.chain_grants_push_to(&owner_s, "r"));

        // Deeper than MAX_CHAIN_DEPTH, all concrete: refused on depth alone.
        let mut cur = Ucan::issue(&owner, a.did(), cap(), Some(hour())).unwrap();
        let mut signer = a;
        for _ in 0..MAX_CHAIN_DEPTH {
            let next = Keypair::generate();
            cur = Ucan::delegate(&signer, next.did(), cap(), Some(hour()), &cur).unwrap();
            signer = next;
        }
        assert!(
            !cur.chain_grants_push_to(&owner_s, "r"),
            "depth bound must fail closed"
        );
    }
}
