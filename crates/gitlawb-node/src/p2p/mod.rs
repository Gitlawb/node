//! libp2p networking layer — Kademlia DHT + Gossipsub.
//!
//! Provides:
//!   - Peer discovery via Kademlia DHT (DID → multiaddr mapping)
//!   - Real-time ref-update events via Gossipsub
//!
//! The node's PeerId comes from an Ed25519 keypair loaded from a persistent
//! key file, so the PeerId is stable across restarts.

use std::collections::{hash_map::DefaultHasher, HashMap};
use std::hash::{Hash, Hasher};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use futures::StreamExt;
use libp2p_core::{muxing::StreamMuxerBox, Multiaddr, PeerId, Transport};
use libp2p_gossipsub as gossipsub;
use libp2p_identify as identify;
use libp2p_identity as identity;
use libp2p_kad as kad;
use libp2p_swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};
use uuid::Uuid;
use zeroize::Zeroizing;

use gitlawb_core::identity::Keypair;

use crate::db::{Db, PeerWriteDenied, ReceivedRefUpdate};

/// Topic for ref-update notifications published after every push.
pub const REF_UPDATES_TOPIC: &str = "gitlawb/ref-updates/v1";

/// Pre-parse budget, keyed on the mesh peer that HANDED us the message: 2000
/// events per 60 seconds.
///
/// This one is not an authorization control and must not be sized like one.
/// `propagation_source` is free to mint and identifies a forwarder, not an
/// author, so it is weak in both directions: an attacker rotates it, and a
/// flood relayed through an honest neighbour debits that neighbour. All it buys
/// is a bound on raw CPU before anything is parsed or verified, so it is sized
/// to be well clear of any legitimate burst. Gossipsub re-shares mesh-wide, so
/// one edge carries the traffic of every author routed through it; 2000 per
/// minute is roughly 33 parse-plus-Ed25519-verify per second, a fraction of a
/// core, while still bounding what a single edge can cost.
const GOSSIP_SOURCE_MAX_EVENTS: usize = 2000;
/// Post-auth budget, keyed on the authenticated `node_did`: 500 events per 60
/// seconds.
///
/// This is the tight bound, and it is where the tightness belongs, because it
/// is charged ONLY when a signature has proven who is asking. An unsigned
/// event's `node_did` is a claim anyone on the mesh can make, so charging this
/// bucket on one would let an attacker deny a DID it names; unsigned traffic is
/// bounded on the forwarder instead, below. It bounds the two durable writes
/// per event, charged to the principal that authored them. `api::repos`
/// publishes one event per updated ref, so the number has to admit a whole
/// large push: 500 covers a tag-heavy push, an initial import, or a mirror
/// backfill of a few hundred refs arriving in one window.
const GOSSIP_AUTHOR_MAX_EVENTS: usize = 500;
/// Budget for UNSIGNED events, keyed on `propagation_source`: 1500 events per
/// 60 seconds.
///
/// An unsigned event's `node_did` is asserted, not proven, so it cannot be
/// charged to an author without handing an attacker a way to deny a chosen
/// victim. The forwarder is the only identity available, and this is the bound
/// that keeps an unsigned flood from buying an unlimited number of `peer_exists`
/// round trips and durable writes.
///
/// Sized deliberately, and NOT at the author cap. 500 is what ONE author's
/// large push needs: `a_sixty_one_ref_push_from_one_known_peer_is_accepted_whole`
/// exists because a 60-per-source bound broke a 61-ref push. A forwarder
/// aggregates many unsigned authors, so sizing a forwarder-keyed bucket AT the
/// per-author cap re-imposes exactly the mesh-edge denial the pre-parse brake's
/// doc comment above warns against. 1500 is three times the largest legitimate
/// single-author burst, which covers the aggregation this network can actually
/// produce (one global topic, and a peers table in the low hundreds), while
/// staying strictly below the 2000 pre-parse brake so it binds first.
///
/// It is defeated by `PeerId` rotation, like the pre-parse brake it sits under.
/// That is inherent to keying on a free identity and is why the unsigned path
/// is a rolling-upgrade allowance rather than a permanent one.
const GOSSIP_UNSIGNED_SOURCE_MAX_EVENTS: usize = 1500;
/// Two forwarder-keyed bounds now exist, and both must stay looser than the
/// per-author budget: sizing either at or below it puts the tight bound back on
/// the mesh edge, which is the shape being fixed here. The unsigned bound must
/// in turn stay under the pre-parse brake, or the brake it nests inside never
/// binds. Enforced at compile time rather than in a test, because it is a
/// relation between constants and a test can only catch it after someone runs
/// it.
const _: () = assert!(
    GOSSIP_SOURCE_MAX_EVENTS > GOSSIP_UNSIGNED_SOURCE_MAX_EVENTS
        && GOSSIP_UNSIGNED_SOURCE_MAX_EVENTS > GOSSIP_AUTHOR_MAX_EVENTS,
    "both forwarder-keyed bounds must stay looser than the per-author bound, \
     and the unsigned bound must stay under the pre-parse brake"
);
const GOSSIP_INGEST_WINDOW: Duration = Duration::from_secs(60);
/// Ceiling on tracked source peers, matching the bound the HTTP brakes use in
/// `main.rs`. Keeps a source-rotation flood from growing the limiter's own map.
const GOSSIP_INGEST_MAX_SOURCES: usize = 200_000;
/// Ceiling on tracked author DIDs. Reaching this map costs an attacker a
/// registered peer row per key, but registration is open through the announce
/// path, so the bound is not left to that.
const GOSSIP_INGEST_MAX_AUTHORS: usize = 200_000;
/// How often the swarm loop evicts expired keys from the ingest limiters.
///
/// Matches the 300s the HTTP-side sweeper in `main.rs` runs on, so both halves
/// of the node reclaim limiter keys on the same cadence rather than each having
/// its own tuning. Any interval comfortably above [`GOSSIP_INGEST_WINDOW`]
/// works: a key whose window has not elapsed is retained by `cleanup` anyway,
/// so sweeping more often would cost lock traffic and reclaim nothing extra.
const GOSSIP_INGEST_SWEEP_INTERVAL: Duration = Duration::from_secs(300);

/// How far into the past a signed ref-update's own `timestamp` may sit and
/// still be admitted: 10 minutes.
///
/// This is the outer bound on replay, and it is the bound that still holds when
/// the seen-set below degrades. Sized for the delivery this mesh actually
/// produces: gossipsub re-shares through several hops, a peer coming back from
/// a partition drains a backlog, and clocks drift, so a window measured in
/// seconds would refuse honest traffic. Ten minutes is short enough that a
/// captured signature stops being useful quickly and long enough that no
/// legitimate delivery path is near it.
const GOSSIP_REF_UPDATE_FRESHNESS_WINDOW: Duration = Duration::from_secs(600);
/// How far AHEAD of this node's clock a ref-update's `timestamp` may sit: 60
/// seconds.
///
/// Deliberately much tighter than the past window, and checked as its own
/// comparison rather than folded into a distance (see [`check_freshness`]). A
/// publisher whose clock is a minute fast is ordinary; one whose events are
/// stamped further ahead is either badly misconfigured or buying itself a
/// longer replay lifetime, and both deserve the same refusal.
const GOSSIP_REF_UPDATE_FUTURE_SKEW: Duration = Duration::from_secs(60);
/// How long the replay seen-set keeps an entry.
///
/// DERIVED from the two constants above rather than written out, because the
/// relation is what matters and a hand-written 660 drifts the moment either
/// input moves. It must be at least window plus skew: an event stamped at the
/// +60s future edge stays inside the freshness window until 660 seconds after
/// receipt, so evicting its entry at 600 would open a 60-second gap in which
/// that exact event replays clean past both layers.
const GOSSIP_SEEN_EVENTS_RETENTION: Duration = Duration::from_secs(
    GOSSIP_REF_UPDATE_FRESHNESS_WINDOW.as_secs() + GOSSIP_REF_UPDATE_FUTURE_SKEW.as_secs(),
);
/// Ceiling on entries in the replay seen-set.
///
/// Only events that were actually admitted and written are recorded, so the
/// record rate is bounded by the author brake: 500 per 60 seconds per
/// registered DID. Occupancy is that rate times retention plus one sweep
/// interval (an entry can outlive retention until the next tick reclaims it),
/// so roughly 8,000 entries per author running flat out.
///
/// Be exact about what does and does not bound the DID side of that: NOTHING
/// does. A DID count is not a cost to an attacker, because `upsert_peer`
/// accepts a `PeerWriteAuthority::Unproven` announce for an unseen did:key (see
/// the ingest path's own note on why authentication is not authorization), so
/// fresh DIDs are minted for free and each one arrives with its own author
/// budget. Any rationale of the form "it would take N registered DIDs" is
/// therefore not a bound at all.
///
/// The real cost is on the other side of the write. Every entry here
/// corresponds to an event that was individually signed, durably written, and
/// enqueued, so reaching this ceiling means 100,000 ref-update rows and 100,000
/// sync enqueues inside one retention horizon. That is the bound worth citing,
/// and it is loud in two places an operator already watches: the database, and
/// the `accepted` ingest counter. What this constant buys is that the seen-set
/// itself cannot be the thing that fails first. At roughly 100 bytes per entry
/// the ceiling is about 10 MB, comparable to the limiters' own 200k-key maps.
const GOSSIP_SEEN_EVENTS_MAX: usize = 100_000;
/// The retention horizon cannot be shortened below the span the freshness
/// window admits. Enforced at compile time for the same reason the limiter
/// ordering above is: it is a relation between constants, and a test can only
/// catch it after someone runs it.
const _: () = assert!(
    GOSSIP_SEEN_EVENTS_RETENTION.as_secs()
        >= GOSSIP_REF_UPDATE_FRESHNESS_WINDOW.as_secs() + GOSSIP_REF_UPDATE_FUTURE_SKEW.as_secs(),
    "the seen-set must retain an entry for at least as long as the freshness window will keep \
     admitting the event, or a future-dated event replays clean in the gap"
);

/// The gossip ingest budgets, built the same way for the swarm loop and for the
/// tests so a test can never assert against a budget production does not run.
///
/// They are deliberately separate limiters rather than one: they key on
/// different identities (a forwarder before parsing, a forwarder again for
/// unproven traffic, an author after authentication) and sit at different
/// points in the path. `unsigned` is its own limiter rather than a second
/// `check` against `source`, which would spend the same budget twice and bound
/// nothing tighter than `source` already does.
pub(crate) struct IngestLimiters {
    /// Keyed on `propagation_source`, checked before the parse.
    source: crate::rate_limit::RateLimiter,
    /// Keyed on `propagation_source`, checked in the unsigned branch before the
    /// `peer_exists` round trip, because an unsigned event names no principal
    /// that could be charged instead.
    unsigned: crate::rate_limit::RateLimiter,
    /// Keyed on the `node_did` a signature PROVED, checked before the writes.
    author: crate::rate_limit::RateLimiter,
}

impl IngestLimiters {
    pub(crate) fn new() -> Self {
        Self::with_window(GOSSIP_INGEST_WINDOW)
    }

    /// The single place the three limiters are built. `new` is the only
    /// production caller and passes the real window; the parameter exists so a
    /// test can exercise expiry without sleeping a minute, and it deliberately
    /// leaves the caps and key ceilings alone so a test still asserts against
    /// the budgets production runs.
    fn with_window(window: Duration) -> Self {
        Self {
            source: crate::rate_limit::RateLimiter::new_bounded(
                GOSSIP_SOURCE_MAX_EVENTS,
                window,
                GOSSIP_INGEST_MAX_SOURCES,
            ),
            unsigned: crate::rate_limit::RateLimiter::new_bounded(
                GOSSIP_UNSIGNED_SOURCE_MAX_EVENTS,
                window,
                GOSSIP_INGEST_MAX_SOURCES,
            ),
            author: crate::rate_limit::RateLimiter::new_bounded(
                GOSSIP_AUTHOR_MAX_EVENTS,
                window,
                GOSSIP_INGEST_MAX_AUTHORS,
            ),
        }
    }

    /// Every limiter in this struct, by DESTRUCTURING `Self` rather than by a
    /// hand-written list. A fourth limiter added later fails to compile here
    /// (both the pattern and the array length), which is what keeps [`cleanup`]
    /// from silently skipping it.
    ///
    /// This is the same completeness idea `sweep_rate_limiters` in `main.rs`
    /// documents for the `AppState` limiters, except that one is driven off a
    /// hand-written list and a missed field there costs only a review; here the
    /// compiler refuses.
    ///
    /// [`cleanup`]: IngestLimiters::cleanup
    fn each(&self) -> [&crate::rate_limit::RateLimiter; 3] {
        let Self {
            source,
            unsigned,
            author,
        } = self;
        [source, unsigned, author]
    }

    /// Evict expired entries from every ingest limiter.
    ///
    /// These limiters are locals of the swarm task, not fields of `AppState`,
    /// so the periodic `sweep_rate_limiters` in `main.rs` cannot reach them and
    /// the swarm loop has to sweep its own. Without this a key stays resident
    /// from the first event a peer forwards until the map hits its 200k ceiling
    /// and the inline capacity sweep fires, so a node that has merely SEEN a lot
    /// of forwarders over its uptime pays for all of them at once.
    async fn cleanup(&self) {
        for limiter in self.each() {
            limiter.cleanup().await;
        }
    }
}

#[cfg(test)]
impl IngestLimiters {
    /// Every limiter in this struct, paired with the cap and key ceiling it is
    /// documented to carry.
    ///
    /// Derived by DESTRUCTURING `Self` rather than listed by hand, so a fourth
    /// limiter added later fails to compile here instead of quietly escaping
    /// the wiring tests that assert each one is built as documented.
    fn all(&self) -> Vec<(&'static str, &crate::rate_limit::RateLimiter, usize, usize)> {
        let Self {
            source,
            unsigned,
            author,
        } = self;
        vec![
            (
                "source",
                source,
                GOSSIP_SOURCE_MAX_EVENTS,
                GOSSIP_INGEST_MAX_SOURCES,
            ),
            (
                "unsigned",
                unsigned,
                GOSSIP_UNSIGNED_SOURCE_MAX_EVENTS,
                GOSSIP_INGEST_MAX_SOURCES,
            ),
            (
                "author",
                author,
                GOSSIP_AUTHOR_MAX_EVENTS,
                GOSSIP_INGEST_MAX_AUTHORS,
            ),
        ]
    }
}

/// The event format version this build emits and understands.
///
/// 0 is the versionless form: the field set this struct shipped with, before
/// `v` existed. It is not a placeholder for "unset", it is a real version whose
/// wire encoding happens to omit the key.
pub(crate) const CURRENT_REF_UPDATE_VERSION: u32 = 0;

/// True for the version whose key is omitted from the wire form. Free function
/// because `skip_serializing_if` takes a path, not a closure.
fn is_zero(v: &u32) -> bool {
    *v == 0
}

/// A ref-update event published to Gossipsub when a push lands.
///
/// The signing bytes are this struct serialized with `sig` set to None (see
/// [`signing_bytes`]), so the FIELD SET IS A WIRE FORMAT, not a struct that can
/// be extended. Any field added here changes the signing bytes for every event
/// that carries it: a node that does not know the new field re-serializes
/// without it, computes different bytes, and rejects the event as a bad
/// signature. That failure names forgery while describing a version skew, which
/// is the worst direction for it to fail in.
///
/// So `v` carries the format version INSIDE the signed bytes, and a field
/// addition means bumping it and keeping a verification path for every version
/// still in the wild, not just editing this struct. A version alongside the
/// signature rather than under it would be attacker-mutable and prove nothing.
/// `ingest_ref_update` refuses anything above [`CURRENT_REF_UPDATE_VERSION`] in
/// its own words, so a newer publisher's events fail as an unsupported version
/// rather than as a signature mismatch; that guard is what makes the loud
/// failure real, and it cannot be retrofitted into receivers already deployed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RefUpdateEvent {
    /// Format version of the signed field set, 0 being the versionless form
    /// this struct shipped with.
    ///
    /// Declared FIRST so a later version's signing bytes lead with it, and
    /// skipped when zero so a v0 event's wire bytes and signing bytes stay
    /// byte-identical to what the pre-version build emits: no `"v"` key
    /// appears, `GOLDEN_SIGNING_BYTES` is unchanged, and every signature
    /// already in flight still verifies. `#[serde(default)]` is the other half:
    /// an event from a peer that predates the field parses as 0, and
    /// re-serializing reproduces its exact original bytes, which IS the v0
    /// verification path.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub v: u32,
    /// Twigpine DID of the node publishing the event
    pub node_did: String,
    /// DID of the agent who pushed
    pub pusher_did: String,
    /// Repository identifier (owner/name)
    pub repo: String,
    /// Full owner DID — added in #144 for display and storage; not yet
    /// wired into the feed gate matcher. Optional for backward compat with
    /// older peers that don't include it.
    #[serde(default)]
    pub owner_did: Option<String>,
    /// Git ref that changed (e.g., "refs/heads/main")
    pub ref_name: String,
    /// SHA before the push (all-zeros for new ref)
    pub old_sha: String,
    /// SHA after the push
    pub new_sha: String,
    /// RFC-3339 timestamp
    pub timestamp: String,
    /// Certificate ID (from the ref certificate, if issued)
    pub cert_id: Option<String>,
    /// IPFS CID of the latest commit object (set after pinning completes)
    pub cid: Option<String>,
    /// Ed25519 signature (base64url, no padding) by the key behind `node_did`,
    /// over the signing bytes defined by `signing_bytes` (this struct serialized
    /// with `sig` set to None). Optional for backward compat with older peers
    /// that don't include it; enforcement is the operator flag's job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

/// The bytes a `RefUpdateEvent` signature is computed over: the event
/// serialized with `sig` set to None.
///
/// This is the ONLY producer of signing input on either side. Emit and verify
/// both call it, so the two cannot drift. `skip_serializing_if` on `sig` keeps
/// the output byte-identical to the legacy wire form (no `"sig": null`), and
/// serde's derive serializes in declaration order, so both sides re-serializing
/// the same struct definition agree regardless of the order fields arrived in.
fn signing_bytes(event: &RefUpdateEvent) -> serde_json::Result<Vec<u8>> {
    let mut unsigned = event.clone();
    unsigned.sig = None;
    serde_json::to_vec(&unsigned)
}

/// Sign an event in place: sets `sig` to the base64url signature by `keypair`
/// over [`signing_bytes`].
fn sign_ref_update(keypair: &Keypair, event: &mut RefUpdateEvent) -> serde_json::Result<()> {
    let bytes = signing_bytes(event)?;
    event.sig = Some(keypair.sign_b64(&bytes));
    Ok(())
}

/// The bytes the node publishes for one outbound ref-update: the event signed
/// by the node keypair, then serialized.
///
/// The swarm loop and the round-trip test share this one function, so the bytes
/// a test verifies are the bytes the mesh actually receives.
fn signed_publish_bytes(keypair: &Keypair, event: &RefUpdateEvent) -> serde_json::Result<Vec<u8>> {
    let mut event = event.clone();
    sign_ref_update(keypair, &mut event)?;
    serde_json::to_vec(&event)
}

/// Exactly the pair the swarm loop hands `gossipsub.publish` for one outbound
/// ref-update: the topic, and the signed bytes.
///
/// Extracted from the publish arm so a test can hold what the loop publishes.
/// The arm itself sits inside a `select!` that no test drives, so before this
/// existed the only thing standing between a regression and the mesh was that
/// the arm happened to call `signed_publish_bytes`; an arm rewritten to
/// `serde_json::to_vec(&event)` would have published unsigned bytes with the
/// whole suite green. Now that regression has to be made HERE to stay silent.
///
/// Be exact about what this does and does not close. It closes
/// sign-before-publish and the topic the bytes go out on. It does NOT observe
/// the `select!` arm dispatching to it, and it does not observe `require_signed`
/// arriving from `main.rs`; both need a live swarm. Those remain uncovered
/// seams, named rather than implied away.
fn ref_update_publish_args(
    keypair: &Keypair,
    event: &RefUpdateEvent,
) -> serde_json::Result<(gossipsub::IdentTopic, Vec<u8>)> {
    let bytes = signed_publish_bytes(keypair, event)?;
    Ok((gossipsub::IdentTopic::new(REF_UPDATES_TOPIC), bytes))
}

/// Resolve the public key behind a claimed `node_did`, refusing anything that
/// is not a resolvable `did:key`.
///
/// The did-method and resolution refusals answer in the SAME words as the
/// peers-table gate in db/mod.rs, so the two surfaces that judge the same input
/// do not drift into separate vocabularies. The sentences are built from
/// `PeerWriteDenied` itself rather than retyped, so they cannot.
fn resolve_node_did(node_did: &str) -> Result<ed25519_dalek::VerifyingKey, String> {
    let unresolvable = |reason: String| {
        PeerWriteDenied::UnresolvableDid {
            did: node_did.to_string(),
            reason,
        }
        .to_string()
    };

    let did = node_did
        .parse::<gitlawb_core::did::Did>()
        .map_err(|e| unresolvable(e.to_string()))?;
    if !did.is_did_key() {
        return Err(PeerWriteDenied::UnsupportedDidMethod {
            did: node_did.to_string(),
        }
        .to_string());
    }
    did.to_verifying_key()
        .map_err(|e| unresolvable(e.to_string()))
}

/// Verify that `event.sig` is an Ed25519 signature over [`signing_bytes`] by
/// the key behind `event.node_did`.
///
/// The signature is bound to the claimed identity structurally: the key comes
/// from `node_did` and nowhere else, so a valid signature by some other key
/// never passes.
fn verify_ref_update(event: &RefUpdateEvent) -> Result<(), String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    let verifying_key = resolve_node_did(&event.node_did)?;

    let sig_b64 = event
        .sig
        .as_deref()
        .ok_or_else(|| "event carries no signature".to_string())?;

    let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| "signature is not valid base64url".to_string())?
        .try_into()
        .map_err(|_| "signature is not 64 bytes".to_string())?;

    let bytes = signing_bytes(event).map_err(|e| e.to_string())?;
    gitlawb_core::identity::verify(&verifying_key, &bytes, &sig_bytes)
        .map_err(|_| "signature does not verify against node_did".to_string())
}

#[cfg(test)]
thread_local! {
    /// Test-only override for [`ingest_now`].
    ///
    /// Thread-local rather than a global for the same reason `PEER_EXISTS_CALLS`
    /// is: `#[sqlx::test]` drives each test on its own current-thread runtime,
    /// so a pinned clock is naturally per-test and cannot be observed by a test
    /// running in parallel.
    static INGEST_NOW_OVERRIDE: std::cell::Cell<Option<DateTime<Utc>>> =
        const { std::cell::Cell::new(None) };
}

/// The one clock the guard layer reads.
///
/// Both the freshness comparison and the seen-set's recorded-at and expiry go
/// through this, so the two layers cannot disagree about what "now" is. A
/// seen-set expiring on a different clock than the window it is sized against
/// is exactly the gap [`GOSSIP_SEEN_EVENTS_RETENTION`] exists to close, and two
/// independent `Utc::now()` calls would reintroduce it as a race rather than a
/// constant. The test override also means expiry tests pin an instant instead
/// of sleeping out an eleven-minute horizon.
fn ingest_now() -> DateTime<Utc> {
    #[cfg(test)]
    if let Some(pinned) = INGEST_NOW_OVERRIDE.with(|c| c.get()) {
        return pinned;
    }
    Utc::now()
}

/// The seen-set key for one signed ref-update: the full SHA-256 of its
/// canonical [`signing_bytes`].
///
/// Three choices are load-bearing here.
///
/// SIGNING BYTES, not the raw `msg.data` the message arrived as. The signature
/// covers a re-serialization of the parsed struct, so one signature verifies
/// against a whole family of wire encodings (injecting `"v":0` into a v0
/// artifact is the demonstrated case: different bytes, different gossipsub
/// message id, same struct, same signature). Keyed on raw bytes, every member
/// of that family gets its own slot and the guard deduplicates nothing.
///
/// FULL SHA-256, not a truncation and not the `DefaultHasher` idiom this file
/// uses for node-identity seeding and `message_id_fn`. Those are keyed on
/// attacker-supplied bytes too, but a collision there costs a routing hiccup.
/// A collision here drops a DISTINCT legitimate event as a replay, which is
/// censorship: strictly worse than the replay the guard is refusing. Derived by
/// calling `gitlawb_core::cid::sha256_bytes` rather than by an open-coded sha2
/// sequence, so there is one digest implementation to audit.
///
/// Not the event's identity fields either. There is no `id` on
/// `RefUpdateEvent` and the row UUID is minted per ingest, so any id-derived
/// key is fresh on every replay by construction; and `(repo, ref_name,
/// new_sha)` would silently censor a legitimate revert republishing an earlier
/// sha for the same ref.
fn replay_key(event: &RefUpdateEvent) -> serde_json::Result<[u8; 32]> {
    Ok(gitlawb_core::cid::sha256_bytes(&signing_bytes(event)?))
}

/// One entry in the replay seen-set.
struct SeenEntry {
    /// When [`ReplayGuard::begin`] admitted this key, on the guard-layer clock
    /// ([`ingest_now`]) and never on a second independent one. Expiry is
    /// measured against the same clock the freshness window uses, so the two
    /// layers cannot disagree about how long an event stays interesting.
    recorded_at: DateTime<Utc>,
    /// Whether the ingest that reserved this key went on to succeed.
    ///
    /// Carries no decision: a pending entry answers `Replayed` exactly as a
    /// confirmed one does (KTD-8, and the concurrent-delivery case it names),
    /// and an unconfirmed reservation removes its entry on drop rather than
    /// leaving it behind in some other state. It is kept because it makes the
    /// set's state legible when a test or a debugger asks whether an entry
    /// survived a settled ingest or is merely in flight, which is the
    /// distinction the reserve-and-settle shape exists to draw.
    confirmed: bool,
}

/// What [`ReplayGuard::begin`] decided about one key.
#[derive(Debug)]
enum Begin<'a> {
    /// The key was not in the set. The caller holds the slot until it either
    /// confirms the reservation or drops it.
    Reserved(ReplayReservation<'a>),
    /// The key is already in the set, pending or confirmed. This is the replay.
    Replayed,
    /// The set is at capacity and an inline sweep of expired entries could not
    /// make room. The caller ADMITS the event anyway; see
    /// [`ReplayGuard::begin`] for why fail-open is the policy and what it
    /// costs.
    Saturated,
}

/// The bounded set of ref-update events this node has already admitted.
///
/// A `std::sync::Mutex` rather than the tokio mutex `RateLimiter` uses, because
/// the release path runs in `Drop`, which is synchronous and cannot await. The
/// critical sections are a hash lookup and an insert, so holding a blocking
/// lock across them costs nothing a runtime would notice.
///
/// IN-PROCESS, so a restart empties it, and that is a real exposure rather than
/// an implementation detail worth leaving unstated. A captured event still
/// inside its freshness window replays once more after each restart, because
/// the node that already refused it no longer remembers doing so; a
/// crash-looping node gives an attacker one replay per loop. Bound it honestly
/// in both directions. The exposure is one extra admission per restart per
/// event and not an unbounded one, since
/// [`GOSSIP_REF_UPDATE_FRESHNESS_WINDOW`] still refuses the event outright ten
/// minutes after its stamp no matter how many times the process has cycled, and
/// the author brake still applies to the writes. Persisting the set was
/// considered and is not worth it: it would put a durable write on the hot
/// ingest path to close a window that the freshness check already closes for
/// free, and a node restarting often enough for this to matter has a louder
/// problem.
/// Everything the guard's one mutex protects.
///
/// The map and the inline-sweep bookkeeping are behind the SAME lock rather
/// than in two, because [`ReplayGuard::begin`] reads both inside one critical
/// section and a second lock would only add a way for them to disagree.
struct SeenState {
    entries: HashMap<[u8; 32], SeenEntry>,
    /// When [`ReplayGuard::begin`] last ran its inline sweep, or `None` if it
    /// never has. Read on the guard-layer clock ([`ingest_now`]), like
    /// everything else here.
    last_inline_sweep: Option<DateTime<Utc>>,
    /// How many inline sweeps have run. The throttle's whole subject is a count
    /// that must NOT track the event count, and a test cannot see that from
    /// outcomes alone: a throttled guard and an unthrottled one return the same
    /// `Saturated` on every call.
    #[cfg(test)]
    inline_sweeps: usize,
}

pub(crate) struct ReplayGuard {
    seen: std::sync::Mutex<SeenState>,
    /// How long an entry stays authoritative. Production passes
    /// [`GOSSIP_SEEN_EVENTS_RETENTION`]; the parameter exists so an expiry test
    /// pins a clock instead of waiting out eleven minutes.
    retention: Duration,
    /// Hard ceiling on entries. Production passes
    /// [`GOSSIP_SEEN_EVENTS_MAX`]; the parameter exists so a saturation test
    /// fills two slots rather than a hundred thousand.
    capacity: usize,
}

impl ReplayGuard {
    pub(crate) fn new() -> Self {
        Self::with_limits(GOSSIP_SEEN_EVENTS_RETENTION, GOSSIP_SEEN_EVENTS_MAX)
    }

    /// The single place a guard is built, so a test can never assert against a
    /// shape production does not run. Both parameters are relations the
    /// constants above document; nothing else about the guard varies.
    fn with_limits(retention: Duration, capacity: usize) -> Self {
        Self {
            seen: std::sync::Mutex::new(SeenState {
                entries: HashMap::new(),
                last_inline_sweep: None,
                #[cfg(test)]
                inline_sweeps: 0,
            }),
            retention,
            capacity,
        }
    }

    /// A poisoned mutex is not a reason to stop deduplicating. Nothing behind
    /// this lock is an invariant a panicking holder could have half-broken: it
    /// is a map of opaque keys to timestamps, and the worst a poisoned state
    /// can hold is one stale entry. Refusing to serve it would turn a panic
    /// somewhere else in the process into a replay window here.
    fn lock_seen(&self) -> std::sync::MutexGuard<'_, SeenState> {
        self.seen.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn is_expired(&self, entry: &SeenEntry, now: DateTime<Utc>) -> bool {
        now.signed_duration_since(entry.recorded_at)
            > chrono::Duration::seconds(self.retention.as_secs() as i64)
    }

    /// Look up `key` and, if it is new, reserve it. ONE critical section.
    ///
    /// Check-then-insert with the lock released in between admits two
    /// concurrent deliveries of the same bytes: both look, both miss, both
    /// insert, both are admitted. The swarm loop is sequential today so that
    /// race is theoretical, but the guard must not depend on a caller property
    /// it cannot see, and the atomic shape costs nothing given the lock is
    /// already held.
    ///
    /// An entry past [`retention`] is treated as absent rather than as a
    /// replay. The periodic sweep runs every 300 seconds, so an entry can
    /// outlive its horizon by up to a tick, and answering `Replayed` on one
    /// would make the retention constant mean whatever the sweep cadence
    /// happened to be.
    ///
    /// At capacity the answer is `Saturated`, and the caller admits the event
    /// unrecorded. Fail-closed was considered and rejected: a saturated set
    /// that dropped all fresh gossip would convert a loud resource attack into
    /// quiet mesh-wide censorship of legitimate events, while fail-open leaves
    /// the freshness window as a hard 10-minute ceiling on any replay. Be exact
    /// about what that costs: while saturated, a single captured signature can
    /// again drain the victim author's budget, so
    /// `gitlawb_gossip_replay_guard_saturated_total` is an alert-worthy signal
    /// rather than a debug counter.
    ///
    /// The counter is incremented HERE rather than at the call site. There is
    /// exactly one caller today so either would work, but a signal owned by the
    /// data structure cannot be forgotten by a second caller added later, and
    /// this one is the only evidence the guard has degraded.
    ///
    /// [`retention`]: ReplayGuard::retention
    fn begin(&self, key: [u8; 32], now: DateTime<Utc>) -> Begin<'_> {
        let mut seen = self.lock_seen();

        let present = match seen.entries.get(&key) {
            Some(entry) if !self.is_expired(entry, now) => return Begin::Replayed,
            Some(_) => true,
            None => false,
        };

        // Only a NEW key can grow the map, so an expired entry being replaced
        // in place never has to clear the capacity bar.
        if !present && seen.entries.len() >= self.capacity {
            // THROTTLED, and the throttle is the difference between a guard and
            // an amplifier. Once the map is full of unexpired entries every
            // subsequent event lands here, and an unconditional sweep would pay
            // an O(capacity) retain under this mutex, on the swarm loop, once
            // per event, reclaiming nothing: the attacker driving the guard to
            // capacity would be buying CPU with it. At most one sweep per second
            // costs nothing in reclamation, because entries expire on an
            // eleven-minute horizon and the periodic 300-second tick sweeps on
            // its own cadence regardless. What the inline sweep is for is
            // reclaiming BETWEEN those ticks, and a second's granularity is far
            // finer than the horizon it is reclaiming against.
            let owed = seen
                .last_inline_sweep
                .is_none_or(|last| now.signed_duration_since(last) >= chrono::Duration::seconds(1));
            if owed {
                Self::sweep_inline_locked(&mut seen, now, self.retention);
            }
            if seen.entries.len() >= self.capacity {
                drop(seen);
                crate::metrics::record_gossip_replay_guard_saturated();
                return Begin::Saturated;
            }
        }

        seen.entries.insert(
            key,
            SeenEntry {
                recorded_at: now,
                confirmed: false,
            },
        );
        drop(seen);
        Begin::Reserved(ReplayReservation {
            guard: self,
            key,
            armed: true,
        })
    }

    /// Evict every entry past the retention horizon. Called from the swarm
    /// loop's existing sweep tick alongside `IngestLimiters::cleanup`, and
    /// inline by [`begin`] when the map is at capacity.
    ///
    /// [`begin`]: ReplayGuard::begin
    fn cleanup(&self, now: DateTime<Utc>) {
        let mut seen = self.lock_seen();
        Self::sweep_locked(&mut seen, now, self.retention);
    }

    /// Takes the already-held map rather than locking, so [`begin`] can sweep
    /// inside its own critical section without releasing and reacquiring.
    ///
    /// [`begin`]: ReplayGuard::begin
    /// The inline sweep [`begin`] runs when the map is full.
    ///
    /// [`begin`]: ReplayGuard::begin
    fn sweep_inline_locked(seen: &mut SeenState, now: DateTime<Utc>, retention: Duration) {
        Self::sweep_locked(seen, now, retention);
        seen.last_inline_sweep = Some(now);
        #[cfg(test)]
        {
            seen.inline_sweeps += 1;
        }
    }

    fn sweep_locked(seen: &mut SeenState, now: DateTime<Utc>, retention: Duration) {
        let horizon = chrono::Duration::seconds(retention.as_secs() as i64);
        seen.entries
            .retain(|_, entry| now.signed_duration_since(entry.recorded_at) <= horizon);
    }
}

/// Everything the swarm loop's sweep tick does, as a function a test can call.
///
/// Extracted rather than left inline because the seen-set's periodic sweep is
/// the only thing reclaiming slots between saturation events, and while it
/// lived entirely inside the `select!` arm, deleting the `replay_guard.cleanup`
/// line left the whole suite green. What is now covered by execution is that a
/// sweep reclaims expired entries from BOTH the limiters and the seen-set, and
/// on one shared instant.
///
/// UNCOVERED SEAM, stated rather than implied: nothing here proves the `select!`
/// arm still calls this, nor that `ingest_sweep` is built with
/// `GOSSIP_INGEST_SWEEP_INTERVAL` and actually fires. That dispatch needs a live
/// swarm, a real transport, and a 300-second interval to observe, which is not a
/// test this suite can hold. Deleting the call from the arm above still leaves
/// every test green. The reduction is real (the body is proven, only the wiring
/// is not) but it is a reduction and not a closure.
///
/// `now` is a parameter rather than a call to [`ingest_now`] for the same
/// reason it is on `check_freshness`: the seen-set is sized against the
/// guard-layer clock, so the sweep must measure on the instant its caller
/// already read rather than on a second independent one.
async fn run_ingest_sweep(
    limiters: &IngestLimiters,
    replay_guard: &ReplayGuard,
    now: DateTime<Utc>,
) {
    limiters.cleanup().await;
    replay_guard.cleanup(now);
}

#[cfg(test)]
impl ReplayGuard {
    /// Entry count, which is what makes the sweep observable. Every outcome the
    /// guard returns treats an expired entry as absent whether or not it was
    /// ever swept, so a test asserting on `begin` alone stays green with the
    /// sweep deleted.
    fn len_for_test(&self) -> usize {
        self.lock_seen().entries.len()
    }

    fn is_confirmed_for_test(&self, key: &[u8; 32]) -> bool {
        self.lock_seen()
            .entries
            .get(key)
            .is_some_and(|e| e.confirmed)
    }

    fn inline_sweeps_for_test(&self) -> usize {
        self.lock_seen().inline_sweeps
    }
}

/// A slot held in the seen-set for an ingest still in flight.
///
/// The seen-set records on `Accepted` ONLY, and this is what makes that true
/// without giving up atomic checking. Recording at check time would mean an
/// event whose write failed transiently is remembered as seen, so the
/// publisher's re-publish is dropped as a replay and the row is permanently
/// lost with nothing left to repair it. Reserving instead means the entry
/// exists for the duration of the ingest (so a concurrent delivery of the same
/// bytes still answers `Replayed`) but only a CONFIRMED entry outlives it.
pub(crate) struct ReplayReservation<'a> {
    guard: &'a ReplayGuard,
    key: [u8; 32],
    /// Whether `Drop` still owes a release.
    ///
    /// This flag is why `confirm` is not the obvious `fn confirm(self)` that
    /// moves the key out: a type with a `Drop` impl cannot have its fields
    /// moved out (E0509). `confirm` disarms instead, and `Drop` releases only
    /// while armed.
    armed: bool,
}

impl ReplayReservation<'_> {
    /// Settle the reservation as kept: the event was admitted and its writes
    /// landed, so the entry outlives this ingest and a later copy of the same
    /// bytes is a replay.
    fn confirm(mut self) {
        {
            let mut seen = self.guard.lock_seen();
            if let Some(entry) = seen.entries.get_mut(&self.key) {
                entry.confirmed = true;
            }
        }
        // Disarm inside an explicit scope above rather than relying on drop
        // order between this frame's lock guard and `self`: `Drop` for the
        // reservation takes the same lock, and a release that ran while the
        // guard above was still alive would deadlock the swarm loop.
        self.armed = false;
    }
}

impl Drop for ReplayReservation<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.guard.lock_seen().entries.remove(&self.key);
    }
}

impl std::fmt::Debug for ReplayReservation<'_> {
    /// Hand-written because `ReplayGuard` holds a mutex and deriving would
    /// print through it. The key is the digest of attacker-supplied bytes, so
    /// only its armed state is worth a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayReservation")
            .field("armed", &self.armed)
            .finish_non_exhaustive()
    }
}

/// Why a ref-update's own timestamp put it outside the freshness window.
///
/// Three cases carried explicitly rather than one boolean, because the ingest
/// path puts the direction in the log line: a mesh full of `TooOld` is a
/// healing partition or a replay, a mesh full of `TooFarFuture` is one peer
/// with a broken clock, and `Unparseable` is a publisher emitting something
/// that is not RFC-3339 at all. An operator reading a spike has to tell them
/// apart.
#[derive(Debug, PartialEq, Eq)]
enum FreshnessViolation {
    /// Older than [`GOSSIP_REF_UPDATE_FRESHNESS_WINDOW`]. Carries the PARSED
    /// instant, not the wire string, and that choice is load-bearing: the
    /// refusal detail is rendered from this value, so what reaches the log is a
    /// bounded canonical re-encoding rather than whatever bytes the sender put
    /// on the wire (see [`freshness_refusal_detail`]).
    TooOld(DateTime<Utc>),
    /// Ahead of this node's clock by more than
    /// [`GOSSIP_REF_UPDATE_FUTURE_SKEW`]. Carries the parsed instant for the
    /// same reason as `TooOld`.
    TooFarFuture(DateTime<Utc>),
    /// Not parseable as RFC-3339, so it cannot be freshness-checked at all.
    /// Nothing to carry: there is no parsed value, and the wire string is the
    /// one thing the detail must NOT interpolate raw.
    Unparseable,
}

/// Decide whether a ref-update's `timestamp` is fresh enough to admit, against
/// a caller-supplied `now`.
///
/// Pure, and `now` is a parameter rather than a call to [`ingest_now`], so the
/// unit tests pin an instant without touching the thread-local override at all.
///
/// The two directions are TWO COMPARISONS and there is no `abs()` here on
/// purpose. A distance check admits an event stamped up to a full window into
/// the future, and a future-dated event is the worse of the two: it pins its
/// slot in the seen-set while sitting outside the past-window check's reach
/// until this node's clock catches up, so it outlives the bound the window is
/// supposed to place on it. The 60-second skew allowance covers honest drift
/// and nothing more.
///
/// An unparseable timestamp is a violation, not an admission. Every producer
/// emits RFC-3339 (the sole production publish site writes
/// `chrono::Utc::now().to_rfc3339()`), so nothing legitimate lands here, and
/// admitting the unparseable case would let a self-signing attacker opt out of
/// the window entirely by stamping garbage.
fn check_freshness(timestamp: &str, now: DateTime<Utc>) -> Result<(), FreshnessViolation> {
    let stamped = DateTime::parse_from_rfc3339(timestamp)
        .map_err(|_| FreshnessViolation::Unparseable)?
        .with_timezone(&Utc);

    let window = chrono::Duration::seconds(GOSSIP_REF_UPDATE_FRESHNESS_WINDOW.as_secs() as i64);
    let skew = chrono::Duration::seconds(GOSSIP_REF_UPDATE_FUTURE_SKEW.as_secs() as i64);

    if now - stamped > window {
        return Err(FreshnessViolation::TooOld(stamped));
    }
    if stamped - now > skew {
        return Err(FreshnessViolation::TooFarFuture(stamped));
    }
    Ok(())
}

/// Render the refusal detail for one freshness violation, safe to log.
///
/// Every arm bounds what it interpolates, and the split between the two
/// strategies is the point of this function existing. The tempting shortcut —
/// echo `wire_timestamp` raw in the parsed arms because the parser accepted it
/// — rests on a false invariant: `DateTime::parse_from_rfc3339` accepts
/// arbitrarily many fractional-second digits, so an event stamped with an old
/// instant followed by megabytes of trailing digits parses successfully,
/// lands in `TooOld`, and would copy the sender's entire wire string into a
/// `warn!`. Successful parsing proves the string names an instant; it proves
/// nothing about the length of the bytes that named it.
///
/// So the parsed arms render `to_rfc3339()` of the PARSED instant instead: a
/// canonical re-encoding whose length is fixed by this build's formatter, not
/// by the sender, and which cannot contain a control character by
/// construction. Nothing diagnostic is lost — the instant is the only fact the
/// operator acts on, and the overlong fraction the canonical form drops is
/// precisely the part that carried no information.
///
/// The unparseable arm has no parsed value to render, so there the wire string
/// itself goes through [`sanitize_for_log`], which bounds it and strips
/// control characters.
fn freshness_refusal_detail(violation: &FreshnessViolation, wire_timestamp: &str) -> String {
    match violation {
        FreshnessViolation::TooOld(stamped) => format!(
            "ref-update timestamp {} is more than {}s old",
            stamped.to_rfc3339(),
            GOSSIP_REF_UPDATE_FRESHNESS_WINDOW.as_secs()
        ),
        FreshnessViolation::TooFarFuture(stamped) => format!(
            "ref-update timestamp {} is more than {}s ahead of this node's clock",
            stamped.to_rfc3339(),
            GOSSIP_REF_UPDATE_FUTURE_SKEW.as_secs()
        ),
        FreshnessViolation::Unparseable => format!(
            "ref-update timestamp {} is not a valid RFC-3339 instant",
            sanitize_for_log(wire_timestamp)
        ),
    }
}

/// Render an attacker-controlled string safe to put in a log line.
///
/// Control characters are dropped rather than escaped, because the only caller
/// is diagnosing a timestamp: a legal instant contains none of them, so their
/// presence is itself the finding and their exact bytes add nothing an operator
/// can act on. Dropping them is what stops a `\n` from forging a second log
/// line and a `\x1b[` sequence from driving the operator's terminal.
///
/// The 64-character cap is measured in CHARS, not bytes, so the truncation
/// cannot split a UTF-8 sequence. It is comfortably longer than any legal
/// RFC-3339 instant (the longest form this parser accepts runs to the mid-30s
/// with sub-second digits and a numeric offset), so nothing diagnostic is lost:
/// what it removes is the unbounded case, where one refused event writes
/// however much log the sender chose to send.
fn sanitize_for_log(raw: &str) -> String {
    raw.chars().filter(|c| !c.is_control()).take(64).collect()
}

/// What the ingest path decided about one inbound gossip message.
#[derive(Debug)]
pub(crate) enum IngestOutcome {
    /// The event was authenticated AND every write it implies landed.
    Accepted,
    /// The event was admitted WITHOUT authentication, through the rolling-upgrade
    /// window, and every write it implies landed.
    ///
    /// Deliberately a distinct outcome from `Accepted`: a valid signature proves
    /// who the sender is, an unsigned event proves nothing, and counting the two
    /// under one label would make the fleet's authenticated-admission rate
    /// indistinguishable from its reliance on the legacy compatibility path.
    UnsignedAdmitted,
    /// The event passed every guard, but a durable write failed. The decision
    /// was still "admit it", so this is not a refusal; it exists because
    /// returning an admission outcome (`Accepted` or `UnsignedAdmitted`) for an
    /// event whose row never landed would make the outcome an observability
    /// lie.
    WriteFailed(String),
    /// The event was dropped. Nothing is stored, so the reason exists only to
    /// be logged and counted.
    Rejected(String),
    /// The forwarding peer is over the pre-parse ingest budget. Dropped without
    /// being parsed or verified, which is the whole point of that brake.
    SourceRateLimited,
    /// The authenticated author is over its own write budget. Carries the DID
    /// so the drop names a principal and not just a mesh edge.
    AuthorRateLimited(String),
    /// A forwarder is over the budget for UNSIGNED events relayed down its
    /// edge. Carries the `propagation_source`.
    ///
    /// Deliberately not folded into `AuthorRateLimited`: that variant asserts a
    /// proven principal, and an unsigned event's `node_did` is a claim. Naming
    /// a forwarder as an author would be the same class of observability lie
    /// that `WriteFailed` exists to avoid.
    UnsignedSourceRateLimited(String),
    /// The exact event was already admitted inside the seen-set's retention
    /// horizon. Carries nothing: a replay names no principal that can be
    /// trusted, only the forwarder that handed it over, and the swarm loop
    /// already has that.
    Replayed,
    /// The event's own `timestamp` put it outside the freshness window. Carries
    /// the direction (`TooOld`, `TooFarFuture`, or unparseable) as a sentence
    /// for the log line.
    ///
    /// Deliberately not folded into `Replayed`, for the reason
    /// `UnsignedSourceRateLimited` is not folded into `AuthorRateLimited`:
    /// they diagnose different conditions. A spike of `Replayed` is a mesh
    /// replay or an attacker. A spike of `StaleTimestamp` is a peer with a
    /// broken clock, a partition healing and delivering a backlog, or a replay
    /// of something older than the set retains. An operator has to tell those
    /// apart, and one label for both would be an observability lie.
    StaleTimestamp(String),
}

impl IngestOutcome {
    /// The `outcome` label this decision is counted under in
    /// `gitlawb_gossip_ingest_events_total`.
    ///
    /// A method with an exhaustive match rather than a label written at each
    /// call site: a seventh variant added later fails to compile here instead of
    /// landing in production as an outcome no dashboard can see. `/metrics` is
    /// the only externally observable surface this daemon has, so an uncounted
    /// outcome is an invisible one.
    ///
    /// Returns `&'static str` on purpose. The reason strings `Rejected` and
    /// `WriteFailed` carry are shaped by the sender and would make the label set
    /// unbounded in a process-wide registry, so they stay in the log line and
    /// only the variant reaches the counter.
    fn metric_label(&self) -> &'static str {
        match self {
            IngestOutcome::Accepted => "accepted",
            IngestOutcome::UnsignedAdmitted => "unsigned_admitted",
            IngestOutcome::WriteFailed(_) => "write_failed",
            IngestOutcome::Rejected(_) => "rejected",
            IngestOutcome::SourceRateLimited => "source_rate_limited",
            IngestOutcome::AuthorRateLimited(_) => "author_rate_limited",
            IngestOutcome::UnsignedSourceRateLimited(_) => "unsigned_source_rate_limited",
            IngestOutcome::Replayed => "replayed",
            IngestOutcome::StaleTimestamp(_) => "stale_timestamp",
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Test-only tally of the `peer_exists` round trips this path makes.
    ///
    /// It exists so a test can prove a guard runs BEFORE the database is
    /// touched rather than merely before a debit. Asserting an outcome cannot
    /// tell those two placements apart, and the difference is the whole point
    /// of hoisting the slug check: a malformed event has to cost nothing, not
    /// merely be charged to nobody.
    ///
    /// Thread-local rather than a global counter because `#[sqlx::test]` drives
    /// each test on its own current-thread runtime, so the count is naturally
    /// per-test and cannot be polluted by a test running in parallel.
    static PEER_EXISTS_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Handle one inbound gossip ref-update: authenticate it, then write it.
///
/// The swarm loop and the tests share this one path, so a guard cannot hold in
/// one and not the other. The guards are the same trio the HTTP twin
/// (`api::peers::notify_sync`) applies, carried by a payload signature because
/// gossip has no HTTP signature to key off: the sender proves the `node_did` it
/// claims, that DID is a known peer, and the repo slug is well formed. Every
/// refusal drops the event; nothing is stored (KTD-4), so an unauthenticated
/// sender cannot grow a table.
pub(crate) async fn ingest_ref_update(
    db: &Db,
    limiters: &IngestLimiters,
    replay_guard: &ReplayGuard,
    require_signed: bool,
    auto_sync: bool,
    data: &[u8],
    propagation_source: &PeerId,
) -> IngestOutcome {
    // FIRST, ahead of the parse and ahead of signature verification. Verifying
    // a signature is the expensive step on this path, so a brake placed after it
    // would let an unauthenticated flood buy exactly the CPU the brake exists to
    // protect. Same ordering rationale as the HTTP sync-trigger brake in
    // server.rs, which is layered outermost so it runs before auth.
    //
    // It is kept generous on purpose. The key is a forwarder, so a tight bound
    // here denies an honest neighbour on someone else's flood. The tighter
    // bounds live below: unsigned traffic on a second forwarder-keyed bucket,
    // and verified traffic on the author the signature proved.
    if !limiters.source.check(&propagation_source.to_string()).await {
        return IngestOutcome::SourceRateLimited;
    }

    let event = match serde_json::from_slice::<RefUpdateEvent>(data) {
        Ok(event) => event,
        Err(e) => return IngestOutcome::Rejected(format!("malformed ref-update event: {e}")),
    };

    // Version gate, immediately after the parse and ahead of every gate that
    // reads a field, the signature match included.
    //
    // A version this build does not know means the meaning of every field below
    // is unknown, so no gate down there is entitled to judge the event, and
    // admitting it would write rows whose semantics this node cannot state.
    //
    // The reason it must run ahead of the SIGNATURE specifically is
    // observability, and it is the whole point of carrying a version at all.
    // The signing bytes cover the version, so a newer publisher's correctly
    // signed event reaches a v0 receiver as bytes that receiver cannot
    // reproduce: without this gate it lands as "signature does not verify
    // against node_did", which is an accusation of forgery levelled at an
    // honest peer, and it reads that way in the logs and counters an operator
    // would use to notice a mesh partition forming. Same class of lie
    // `UnsignedSourceRateLimited` was split out to avoid.
    //
    // It goes in now, with the version, because it cannot be added later: the
    // receivers that need it are the ones already deployed by the time a v1
    // publisher exists.
    if event.v > CURRENT_REF_UPDATE_VERSION {
        return IngestOutcome::Rejected(format!(
            "unsupported ref-update event version {}; this build understands version {}",
            event.v, CURRENT_REF_UPDATE_VERSION
        ));
    }

    // did-method gate first, and in BOTH enforcement modes: a non-did:key peer
    // is unauthenticatable by design, and running this before the flag branch
    // is what keeps the answer independent of flag state.
    if let Err(reason) = resolve_node_did(&event.node_did) {
        return IngestOutcome::Rejected(reason);
    }

    // #272: the slug reaches a `PathBuf::join` in the sync worker, so it is
    // rejected here, before the ref-update row and the queue row.
    //
    // It sits this high on purpose, above the signature verify and above the
    // `peer_exists` round trip, not merely above the budgets. It depends on
    // nothing but the parsed struct, so hoisting it costs nothing and removes
    // the work entirely: a structurally invalid event now buys no Ed25519
    // verify and no database query. Placing it below either of those would buy
    // the fairness property (a malformed event charges nobody) while leaving
    // the cost in place, charged only to the pre-parse brake that `PeerId`
    // rotation defeats.
    if let Err(e) = crate::git::repo_store::validate_repo_slug(&event.repo) {
        return IngestOutcome::Rejected(format!("invalid repo field: {e}"));
    }

    // Whether `node_did` was PROVEN by a signature on this event, as opposed to
    // merely asserted. Only a proven author may be charged the author budget
    // below, and there is exactly one debit site reading this, so the two arms
    // cannot drift apart.
    let mut verified = false;
    // Whether this event arrived with no signature at all and was let through
    // by the rolling-upgrade window. Carried down the same way `verified` is,
    // and for the same reason: the warning it drives belongs below the gates
    // that can still drop the event, not in the arm that merely reached them.
    //
    // Deliberately a second flag rather than `!verified`. Those two coincide
    // only because the present-but-invalid case returns early above, which is a
    // property of the arms as they stand today, not something this variable's
    // meaning should depend on.
    let mut unsigned = false;
    match event.sig {
        // A signature that is present must verify. A present-but-invalid one is
        // forgery, never a peer that has not upgraded yet, so the flag does not
        // enter into it.
        Some(_) => {
            if let Err(reason) = verify_ref_update(&event) {
                return IngestOutcome::Rejected(reason);
            }
            verified = true;
        }
        None if require_signed => {
            return IngestOutcome::Rejected("unsigned ref-update event".to_string());
        }
        // Rolling-upgrade window, same posture and same pointer at the flag as
        // the HTTP twin's unsigned-notify warning.
        None => {
            unsigned = true;
            // Unsigned traffic is bounded here, on the forwarder, because it is
            // the only identity this event establishes. Charged BEFORE
            // `peer_exists`, which is a Postgres round trip per event: a brake
            // sitting below it would not bound what an unsigned flood costs the
            // node, leaving that cost to the deliberately loose pre-parse brake
            // alone.
            //
            // No new key-farming axis: `propagation_source` is already a key in
            // the pre-parse map, under the same ceiling.
            //
            // Only this arm. Charging it on the verified arm too would let a
            // spent unsigned edge shed a peer's genuine signed pushes, which is
            // the mesh-edge denial the source brake's doc comment above exists
            // to avoid.
            let source_key = propagation_source.to_string();
            if !limiters.unsigned.check(&source_key).await {
                return IngestOutcome::UnsignedSourceRateLimited(source_key);
            }
        }
    }

    // The freshness window and the replay seen-set, on the VERIFIED path only
    // and immediately below the signature that makes it verified.
    //
    // Be precise about what the window buys, because it is narrower than
    // "events are recent". `timestamp` is covered by the signature, but it is
    // self-asserted by `node_did`, and DIDs self-register through the open
    // announce path, so a signer can re-mint fresh events with any timestamp it
    // likes and this gate never sees it. What the window bounds is a THIRD
    // PARTY replaying someone else's captured message: that attacker cannot
    // move the timestamp without invalidating the signature, so a captured
    // event is replayable for at most the window. The seen-set below then
    // bounds it further, to once.
    //
    // Unsigned events skip both, and that is the point rather than an omission.
    // Unsigned bytes carry no signature and are therefore predictable, so a
    // node that deduplicated them would let an attacker pre-send a victim's
    // expected event and have the genuine one dropped as a replay. Dedup on
    // unauthenticated traffic is a censorship primitive, and it buys nothing
    // in exchange: an attacker who can forge one unsigned event can forge a
    // thousand distinct ones. The forwarder brake in the `None` arm above is
    // what bounds that path.
    //
    // Both gates sit ABOVE the `peer_exists` round trip and above the author
    // debit, not merely above the writes. Below the debit they would still stop
    // the duplicate row and the duplicate sync, while leaving every replay free
    // to drain the victim author's budget until their own next push came back
    // `AuthorRateLimited`, which is the harm this guard exists to remove.
    let mut reservation = None;
    if verified {
        // ONE reading, shared by the freshness comparison and the seen-set
        // below. `ingest_now`'s whole reason to exist is that the two layers
        // measure against the same instant: the retention horizon is derived
        // from the freshness window, so a seen-set recording on a second,
        // independently sampled `now` would put the two layers a scheduling
        // delay apart on exactly the relation that derivation rests on. Two
        // calls here left that invariant asserted in a doc comment and unheld
        // in production.
        let now = ingest_now();
        if let Err(violation) = check_freshness(&event.timestamp, now) {
            // Every arm of the detail is rendered bounded, not just the
            // unparseable one. This detail reaches a `warn!` in the swarm
            // loop, and `event.timestamp` is attacker-chosen on all three
            // paths: a parseable stamp can still carry megabytes of
            // fractional-second digits, so "the parser accepted it" is not
            // "safe to echo". `freshness_refusal_detail` holds that invariant
            // and its rationale.
            return IngestOutcome::StaleTimestamp(freshness_refusal_detail(
                &violation,
                &event.timestamp,
            ));
        }

        // Keyed on the canonical signing bytes, which is what makes the two
        // wire encodings of one signature collapse to one key. A serde failure
        // here is the same class of event as a parse failure at the top: bytes
        // this build cannot render canonically, so it cannot judge them.
        let key = match replay_key(&event) {
            Ok(key) => key,
            Err(e) => {
                return IngestOutcome::Rejected(format!(
                    "cannot derive replay key for ref-update event: {e}"
                ));
            }
        };
        match replay_guard.begin(key, now) {
            Begin::Replayed => return IngestOutcome::Replayed,
            // Fail open. A saturated set that refused fresh gossip would turn a
            // loud resource attack into quiet mesh-wide censorship; the counter
            // `begin` already incremented is what makes the degraded state
            // visible, since the event below is counted `accepted` exactly like
            // a healthy one.
            Begin::Saturated => {}
            Begin::Reserved(held) => reservation = Some(held),
        }
    }

    // Authentication is not authorization: a freshly minted did:key signs its
    // own events perfectly well, so the signature alone says nothing about who
    // this peer is to us. Be precise about what this check buys, because it is
    // NOT a closed membership boundary: `upsert_peer` accepts an
    // `PeerWriteAuthority::Unproven` announce for an unseen did:key, so an
    // attacker can self-register a fresh DID through the announce path and then
    // pass this gate. What it does buy is that an unregistered DID cannot write
    // at all, and that combined with the signature check above, an existing
    // peer cannot be impersonated: claiming a registered DID now requires the
    // key behind it.
    //
    // Shed an author that is ALREADY over budget before paying for the lookup.
    // The brake belongs in front of the work it bounds: an over-budget author is
    // going to be refused whatever the peer table says, so the round trip is work
    // done for a request that was never going to be admitted, and a signed author
    // can drive it at the pre-parse source rate.
    //
    // Deliberately a READ, not the charge. `check` inserts a window for a key it
    // has never seen, so probing with it here would let a flood of self-minted
    // signed DIDs occupy the bounded author map before `peer_exists` had a chance
    // to refuse them, turning a brake into a memory-fill surface. `is_throttled`
    // allocates nothing and an unseen DID reads as within budget, so the only
    // behaviour that changes is WHEN an already-over-budget author is refused.
    // The charge itself stays below the lookup, unmoved.
    if verified && limiters.author.is_throttled(&event.node_did).await {
        return IngestOutcome::AuthorRateLimited(event.node_did.clone());
    }

    // Keyed lookup, not `list_peers`: this runs on every event that survives
    // the parse, and scanning the whole table per event makes ingest cost grow
    // with the peer count.
    #[cfg(test)]
    PEER_EXISTS_CALLS.with(|calls| calls.set(calls.get() + 1));
    match db.peer_exists(&event.node_did).await {
        Ok(true) => {}
        Ok(false) => {
            return IngestOutcome::Rejected(format!("unknown peer DID: {}", event.node_did));
        }
        Err(e) => return IngestOutcome::Rejected(format!("peer lookup failed: {e}")),
    }

    // The tight budget, and the only one keyed on an identity the sender had to
    // prove. It is charged ONLY when the signature verified, which is what
    // `verified` carries down from the match above.
    //
    // Charging it on an unsigned event would make it a victim-selection
    // mechanism rather than a fairness control. `peer_exists` proves the DID is
    // registered; it does not prove this sender holds it, and in the
    // rolling-upgrade window anyone on the open mesh can name a registered DID.
    // An attacker would then spend a chosen victim's budget from an unrelated
    // `PeerId` and the victim's own signed pushes would come back
    // `AuthorRateLimited`. A rate-limit key derived from an unproven claim is
    // worse than no key at all, because the denial it produces is targetable.
    // Unsigned traffic is bounded on the forwarder instead, in the `None` arm
    // above.
    //
    // What this does NOT buy: an aggregate write bound. A verified signature
    // proves key possession, not a scarce principal, and the announce path
    // registers fresh did:keys, so an attacker who rotates keys still gets a
    // fresh budget each time. The aggregate per-edge bound remains the
    // pre-parse source brake. What it buys is that a NAMED victim's budget is
    // no longer spendable by anyone else.
    if verified && !limiters.author.check(&event.node_did).await {
        return IngestOutcome::AuthorRateLimited(event.node_did.clone());
    }

    // Below every gate that can still drop the event, so "accepted" is a report
    // of an outcome rather than a prediction of one.
    //
    // It used to sit up in the `None` arm, which put it above the unsigned
    // forwarder budget and above `peer_exists`. An event shed by either of
    // those left a log that said the node accepted it and a database that had
    // never heard of it, which is the same class of lie as an accusation of
    // forgery for a version skew: it misdirects whoever is reading the logs to
    // find out why gossip is not landing. Single site on purpose. A warning
    // emitted in the arm AND again down here would double-count in anything
    // grepping for it.
    if unsigned {
        warn!(
            did = %event.node_did,
            "accepted unsigned gossip ref-update; set GITLAWB_REQUIRE_SIGNED_PEER_WRITES=true after all peers upgrade"
        );
    }

    info!(
        from = %propagation_source,
        repo = %event.repo,
        ref_name = %event.ref_name,
        new_sha = %event.new_sha,
        "ref-update received via gossipsub"
    );

    let update = ReceivedRefUpdate {
        id: Uuid::new_v4().to_string(),
        node_did: event.node_did.clone(),
        pusher_did: event.pusher_did.clone(),
        repo: event.repo.clone(),
        owner_did: event.owner_did.clone(),
        ref_name: event.ref_name.clone(),
        old_sha: event.old_sha.clone(),
        new_sha: event.new_sha.clone(),
        timestamp: event.timestamp.clone(),
        cert_id: event.cert_id.clone(),
        received_at: Utc::now().to_rfc3339(),
        // The peer that FORWARDED this message through the mesh, not the
        // author. The authenticated author is `node_did` beside it.
        from_peer: propagation_source.to_string(),
    };
    // Both writes are still attempted independently: a failed row must not cost
    // the queue entry, and a failed queue entry must not undo the row. Only the
    // OUTCOME changes, so `Accepted` keeps meaning "authenticated AND stored".
    let mut write_error: Option<String> = None;
    if let Err(e) = db.insert_ref_update(&update).await {
        warn!(err = %e, "failed to store received ref-update");
        write_error = Some(format!("failed to store received ref-update: {e}"));
    }
    if auto_sync {
        if let Err(e) = db
            .enqueue_sync(
                &event.repo,
                &event.node_did,
                &event.ref_name,
                &event.new_sha,
                event.cid.as_deref(),
            )
            .await
        {
            warn!(err = %e, "failed to enqueue sync for received ref-update");
            write_error.get_or_insert(format!("failed to enqueue sync: {e}"));
        }
    }
    match write_error {
        Some(reason) => IngestOutcome::WriteFailed(reason),
        None if unsigned => {
            // No reservation to settle: the replay block above is gated on
            // `verified`, so an unsigned admission never holds one. Kept as its
            // own arm because the outcome differs, not because the guard does.
            IngestOutcome::UnsignedAdmitted
        }
        None => {
            // The ONE place a reservation is kept. Every other exit from this
            // function, the early returns above and the `WriteFailed` arm
            // beside this one, drops it and releases the slot, so a transient
            // failure never permanently burns an event's key and the publisher
            // can re-publish. That release is the drop guard's job rather than
            // a call on each path, because a path added later would otherwise
            // silently inherit the wrong behaviour.
            if let Some(held) = reservation.take() {
                held.confirm();
            }
            IngestOutcome::Accepted
        }
    }
}

/// A DID record stored in the Kademlia DHT — maps a Twigpine DID to a node.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DidRecord {
    pub did: String,
    pub http_url: String,
    pub peer_id: String,
    pub p2p_port: u16,
    pub timestamp: String,
}

/// Snapshot of the libp2p swarm state for observability.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SwarmStatus {
    pub connected_peers: usize,
    pub gossipsub_mesh_peers: usize,
    pub gossipsub_all_peers: usize,
    pub listen_addrs: Vec<String>,
}

/// Commands sent to the swarm task from the rest of the node.
#[derive(Debug)]
pub enum P2pCommand {
    /// Publish a ref-update event to Gossipsub
    PublishRefUpdate(RefUpdateEvent),
    /// Add a known peer address to the Kademlia routing table
    #[allow(dead_code)]
    AddKnownPeer { peer_id: PeerId, addr: Multiaddr },
    /// Dial a specific multiaddr
    #[allow(dead_code)]
    Dial(Multiaddr),
    /// Store a DID record in the Kademlia DHT (fire-and-forget)
    PutDid(DidRecord),
    /// Look up a DID in the Kademlia DHT; reply on the oneshot sender
    GetDid {
        did: String,
        reply: oneshot::Sender<Option<DidRecord>>,
    },
    /// Get a snapshot of the swarm status
    GetStatus { reply: oneshot::Sender<SwarmStatus> },
}

/// Handle returned to the rest of the node for sending commands to the swarm.
#[derive(Clone)]
pub struct P2pHandle {
    tx: mpsc::Sender<P2pCommand>,
    pub local_peer_id: PeerId,
}

impl P2pHandle {
    pub async fn publish_ref_update(&self, event: RefUpdateEvent) {
        let _ = self.tx.send(P2pCommand::PublishRefUpdate(event)).await;
    }

    #[allow(dead_code)]
    pub async fn add_peer(&self, peer_id: PeerId, addr: Multiaddr) {
        let _ = self
            .tx
            .send(P2pCommand::AddKnownPeer { peer_id, addr })
            .await;
    }

    #[allow(dead_code)]
    pub async fn dial(&self, addr: Multiaddr) {
        let _ = self.tx.send(P2pCommand::Dial(addr)).await;
    }

    /// Store a DID record in the DHT (fire-and-forget).
    pub async fn put_did(&self, record: DidRecord) {
        let _ = self.tx.send(P2pCommand::PutDid(record)).await;
    }

    pub async fn status(&self) -> Option<SwarmStatus> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(P2pCommand::GetStatus { reply: tx }).await;
        tokio::time::timeout(std::time::Duration::from_secs(2), rx)
            .await
            .ok()
            .and_then(|r| r.ok())
    }

    /// Look up a DID in the DHT. Returns None if not found or timeout (10s).
    pub async fn get_did(&self, did: String) -> Option<DidRecord> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(P2pCommand::GetDid { did, reply: tx }).await;
        tokio::time::timeout(std::time::Duration::from_secs(10), rx)
            .await
            .ok()
            .and_then(|r| r.ok())
            .flatten()
    }
}

/// Derive a stable Kademlia record key from a DID string.
fn did_to_kad_key(did: &str) -> kad::RecordKey {
    kad::RecordKey::new(&format!("/gitlawb/did/{did}").as_bytes())
}

/// Combined libp2p behaviour.
#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p_swarm::derive_prelude")]
struct GitlawbBehaviour {
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
}

/// The directory holding `key_path`, and the single answer to that question for
/// every site in this module plus `Config::validate`.
///
/// `Path::parent` is not enough on its own. A bare filename yields `Some("")`
/// and `./p2p.key` yields `Some(".")`, both naming the process working
/// directory while looking different; an empty path yields `None`. Collapsing
/// all of those to `.` keeps the callers from each inventing their own answer,
/// which is what they used to do: one filtered the empty case out and skipped
/// the directory guard entirely, one already normalized correctly, and one
/// opened `""` and silently did nothing.
///
/// The `.` return is the "names no directory" signal, not a usable directory.
/// `Config::validate` rejects a p2p key path that lands here, so a validated
/// config never reaches it; `load_or_create_p2p_keypair` refuses it as well, as
/// a backstop rather than the gate.
pub(crate) fn key_parent(key_path: &Path) -> &Path {
    match key_path.parent() {
        Some(parent) if parent.components().any(|c| c != Component::CurDir) => parent,
        _ => Path::new("."),
    }
}

/// Whether the identity key's lexical parent is a directory the operator has
/// already nominated by shape alone: the working directory (`identity.pem`,
/// `./identity.pem`) or the filesystem root (`/identity.pem`). Those are
/// published into as-is and never created, pinned, or chmodded; any other
/// parent is a named component this process may create.
///
/// Lexical on purpose so the contract is testable without touching the
/// filesystem: a probe against `/` cannot be isolated and, run as root, leaves
/// a real key at `/identity.pem`.
pub(crate) fn identity_parent_is_already_nominated(key_path: &Path) -> bool {
    key_parent(key_path).file_name().is_none()
}

/// Whether `key_path` fails to name a directory the node is willing to manage.
///
/// This is the gate `Config::validate` applies, kept next to `key_parent`
/// because the two answer the same question and drifting apart is how the
/// original defect happened.
///
/// An absolute path always names its directory unambiguously, so it passes.
/// A relative path is judged lexically against two ways of failing to name one:
///
///   * no directory at all, so the parent is empty or nothing but `.`
///     (`p2p.key`, `./p2p.key`, `p2p.key/`, `""`), and
///   * a parent that walks back out through `..` (`a/../p2p.key`,
///     `./keys/../p2p.key`, `../p2p.key`).
///
/// The second case is the one that is easy to miss and was missed once: those
/// paths look like they name a directory, and they do not. `a/..` and
/// `./keys/..` resolve to the working directory itself, and `..` resolves above
/// it, so accepting them would put the key exactly where this check exists to
/// keep it out of, and would have the node chmod that directory to 0700 on the
/// way. Any `..` in a relative parent makes the target depend on where the
/// process was started, which is the property being refused, so the whole class
/// is rejected rather than resolved.
///
/// Lexical on purpose: no `canonicalize` (the parent legitimately does not exist
/// yet on a first start) and no `current_dir` comparison (it would reject
/// `/data/p2p.key` under a `/data` WORKDIR, an absolute directory the operator
/// named).
pub(crate) fn names_no_usable_directory(key_path: &Path) -> bool {
    let Some(parent) = key_path.parent() else {
        return true;
    };

    let mut named_a_directory = false;
    for component in parent.components() {
        match component {
            // Rejected wherever it appears, absolute paths included. An earlier
            // version exempted absolute paths on the reasoning that they cannot
            // depend on the working directory, which is true and beside the
            // point: `key_parent` hands `ensure_key_dir` the LEXICAL parent, so
            // `/data/keys/../p2p.key` chmods `/data` rather than the `keys`
            // directory the path appears to name, and `/data/../p2p.key` run as
            // root would try to tighten `/` to 0700. The hazard is chmodding a
            // resolved ancestor nobody nominated, and that does not care whether
            // the path was absolute.
            Component::ParentDir => return true,
            // `/` is a directory the operator named, so an absolute path's root
            // counts the same way a normal component does.
            Component::Normal(_) | Component::RootDir | Component::Prefix(_) => {
                named_a_directory = true
            }
            Component::CurDir => {}
        }
    }
    !named_a_directory
}

/// Whether the key file's parent directory is the filesystem root.
///
/// A key at `/p2p.key` would have `ensure_key_dir` tighten `/` to `0700` on a
/// root-run node, which breaks every other service on the host.
#[cfg(unix)]
fn key_parent_is_filesystem_root(key_path: &Path) -> bool {
    key_parent(key_path) == Path::new("/")
}

#[cfg(not(unix))]
fn key_parent_is_filesystem_root(_key_path: &Path) -> bool {
    false
}

/// Maximum protobuf-encoded libp2p key size accepted on read.
const MAX_P2P_KEY_BYTES: usize = 4096;

/// Whether the remainder of a `~/...` value would escape home when joined.
///
/// This is rule 2 of the key-storage contract (see
/// [`load_or_create_p2p_keypair`]): a `~/`-prefixed path must stay beneath the
/// resolved home directory. `PathBuf::join` does not guarantee that on its
/// own — an absolute right-hand operand *replaces* the left-hand side, so
/// `home.join("/etc/p2p.key")` (from `GITLAWB_P2P_KEY=~//etc/p2p.key`, whose
/// doubled separator leaves a rooted suffix after the `~/` is stripped) is
/// `/etc/p2p.key`. On Windows a drive or UNC prefix replaces the base the same
/// way even without a root, and `..` walks back out of home lexically. So the
/// suffix is accepted only when every component is an ordinary name (or a
/// no-op `.`), which is exactly the class of suffixes for which
/// `home.join(suffix)` provably keeps `home` as a prefix. Everything else is
/// rejected before the join, instead of joined and repaired after.
pub(crate) fn tilde_suffix_escapes_home(suffix: &str) -> bool {
    Path::new(suffix).components().any(|c| {
        matches!(
            c,
            Component::RootDir | Component::Prefix(_) | Component::ParentDir
        )
    })
}

/// Mode bits alone do not make something node-owned. A `0700` directory or a
/// `0600` file belonging to a different user passes every permission check here
/// while that user keeps the ability to replace what is inside it, which means
/// they choose the node's libp2p identity. That is the capability the persisted
/// key exists to take away, so it is refused rather than warned about.
#[cfg(unix)]
fn foreign_ownership_error(what: &str, path: &Path, owner_uid: u32, euid: u32) -> Option<String> {
    if owner_uid == euid {
        return None;
    }
    Some(format!(
        "p2p {what} {} is owned by uid {} but this node runs as uid {}; that user can \
         replace it and so decides the node's libp2p identity, which is what the persisted \
         key exists to prevent. Point {} at a location this user owns, or have the owner \
         hand it over; the node will not adopt it.",
        path.display(),
        owner_uid,
        euid,
        if what == "key directory" {
            "GITLAWB_P2P_KEY's directory"
        } else {
            "GITLAWB_P2P_KEY"
        }
    ))
}

/// Pinned-creation primitives: the only way to obtain a `Pinned<T>`.
///
/// POSIX applies the process umask to every requested creation mode, so the
/// mode argument to `mkdirat`, `openat(O_CREAT)`, `mkdir` or `create_dir_all`
/// is a REQUEST and not a result. Under a mask that removes owner bits a
/// requested 0700 directory lands 0000 and cannot be reopened at all, and a
/// requested 0600 key is published unreadable, so the boot that created it
/// succeeds on its already-open descriptor and the next boot loses p2p.
///
/// Every object this process creates therefore goes through one rule: create,
/// pin the mode on the object we just made, reopen or keep the descriptor, and
/// verify the ACHIEVED mode by `fstat` before anything relies on it. A race
/// winner is never pinned; it is verified as-is, which is the rule the ancestor
/// walk already applied and this module preserves.
///
/// `Pinned<T>`'s field is private to this module and no constructor is
/// exported, so a descriptor that did not go through one of these helpers
/// cannot be handed to key-directory construction or to publication. That is
/// what makes the rule compile-enforced rather than reviewed.
#[cfg(unix)]
pub(crate) mod pin {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::path::Path;

    /// A file or directory whose achieved mode has been verified on this
    /// descriptor. Constructible only by the helpers below.
    #[derive(Debug)]
    pub(crate) struct Pinned<T>(T);

    impl<T> Pinned<T> {
        pub(crate) fn get(&self) -> &T {
            &self.0
        }
        pub(crate) fn get_mut(&mut self) -> &mut T {
            &mut self.0
        }
        pub(crate) fn into_inner(self) -> T {
            self.0
        }
    }

    // Test-only injection points, thread-local so an armed test cannot
    // disturb the ones running beside it.
    //   SKIP_MODE_PIN     makes the pin a no-op, so the exact-mode verification
    //                     is observed refusing rather than silently masked by a
    //                     pin that was doing the work (INV-21(i)).
    //   RACE_CREATE_MODE  creates the component by path between the ENOENT and
    //                     the mkdirat, so the race-lost arm is deterministic.
    #[cfg(test)]
    thread_local! {
        pub(crate) static SKIP_MODE_PIN: std::cell::Cell<bool> =
            const { std::cell::Cell::new(false) };
        pub(crate) static RACE_CREATE_MODE: std::cell::Cell<Option<u32>> =
            const { std::cell::Cell::new(None) };
    }

    fn io_err(kind: std::io::ErrorKind, msg: String) -> std::io::Error {
        std::io::Error::new(kind, msg)
    }

    /// `fstat` the descriptor and require the exact mode, the expected object
    /// type, and ownership by this uid. The error names the ACHIEVED mode
    /// against the REQUESTED one, which is what lets a failure be attributed to
    /// the mode rather than read as a generic open failure.
    pub(crate) fn verify_exact_mode(
        fd: std::os::fd::RawFd,
        want: libc::mode_t,
        want_dir: bool,
        display: &Path,
        euid: u32,
    ) -> std::io::Result<()> {
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fstat writes the struct on success; the return value is
        // checked before the struct is read.
        if unsafe { libc::fstat(fd, st.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fstat returned 0, so the struct is initialised.
        let st = unsafe { st.assume_init() };

        let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        if is_dir != want_dir {
            return Err(io_err(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "{} is not {}",
                    display.display(),
                    if want_dir {
                        "a directory"
                    } else {
                        "a regular file"
                    }
                ),
            ));
        }
        if st.st_uid != euid {
            return Err(io_err(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "{} is owned by uid {} rather than this node (uid {})",
                    display.display(),
                    st.st_uid,
                    euid
                ),
            ));
        }
        let achieved = st.st_mode & 0o7777;
        if achieved != want {
            return Err(io_err(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "{} achieved mode {:04o}, requested {:04o}; the process umask masks every \
                     requested creation mode, so the mode must be pinned on the descriptor and \
                     verified rather than assumed",
                    display.display(),
                    achieved,
                    want
                ),
            ));
        }
        Ok(())
    }

    /// Create `name` below `parent_fd` at exactly 0700, or adopt the winner of
    /// a creation race.
    ///
    /// Returns the descriptor and whether this process created it. The pin is
    /// issued BEFORE the reopen, by name off the verified parent, because a
    /// directory that landed 0000 cannot be opened for reading at all, so a pin
    /// that waits for the reopen is unreachable in exactly the case it exists
    /// for. That by-name step is safe because `parent_fd` is verified here
    /// against the same predicate the ancestor walk applies (real directory,
    /// owned by this uid or root, no write beyond the owner unless sticky), and
    /// sticky forbids a non-owner from renaming our entry. The verdict is still
    /// the `fstat` on the reopened descriptor, not the chmod.
    pub(crate) fn create_dir_pinned_at(
        parent_fd: std::os::fd::RawFd,
        name: &std::ffi::OsStr,
        display: &Path,
        euid: u32,
        open_flags: libc::c_int,
    ) -> std::io::Result<(Pinned<OwnedFd>, bool)> {
        use std::os::unix::ffi::OsStrExt;

        // The helper carries its own precondition rather than inheriting it
        // from one call site: the by-name chmod below is only safe over a
        // parent that cannot be repointed by another user.
        verify_trusted_parent(parent_fd, display, euid)?;

        let cname = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
            io_err(
                std::io::ErrorKind::InvalidInput,
                "path component contains an interior NUL byte".to_string(),
            )
        })?;

        // Fast path: it already exists. Adopt and verify as-is (never pin).
        // SAFETY: openat resolves `name` relative to the verified parent.
        let existing = unsafe { libc::openat(parent_fd, cname.as_ptr(), open_flags) };
        if existing >= 0 {
            // SAFETY: a descriptor we just received and own exactly once.
            return Ok((Pinned(unsafe { OwnedFd::from_raw_fd(existing) }), false));
        }
        let open_err = std::io::Error::last_os_error();
        if open_err.raw_os_error() != Some(libc::ENOENT) {
            return Err(open_err);
        }

        #[cfg(test)]
        if let Some(mode) = RACE_CREATE_MODE.with(|c| c.take()) {
            // SAFETY: mkdirat creates `name` relative to the verified parent.
            unsafe { libc::mkdirat(parent_fd, cname.as_ptr(), mode as libc::mode_t) };
        }

        let mut created = true;
        // SAFETY: mkdirat creates `name` relative to the verified parent
        // descriptor. 0700 is the requested mode; the umask masks it, which the
        // pin below repairs.
        if unsafe { libc::mkdirat(parent_fd, cname.as_ptr(), 0o700) } != 0 {
            let mk_err = std::io::Error::last_os_error();
            if mk_err.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(mk_err);
            }
            // Lost the race. The winner is verified, never pinned.
            created = false;
        }

        if created {
            let skip = {
                #[cfg(test)]
                {
                    SKIP_MODE_PIN.with(|c| c.get())
                }
                #[cfg(not(test))]
                {
                    false
                }
            };
            if !skip {
                // SAFETY: fchmodat with flags 0 on a name below the verified
                // parent; the object was created by this process a moment ago
                // and the parent cannot be repointed by another user.
                if unsafe { libc::fchmodat(parent_fd, cname.as_ptr(), 0o700, 0) } != 0 {
                    return Err(rollback_created_dir(
                        parent_fd,
                        &cname,
                        std::io::Error::last_os_error(),
                    ));
                }
            }
        }

        // SAFETY: openat as above, re-resolving the object that actually landed.
        let fd = unsafe { libc::openat(parent_fd, cname.as_ptr(), open_flags) };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(if created {
                rollback_created_dir(parent_fd, &cname, err)
            } else {
                err
            });
        }
        // SAFETY: a descriptor we just received and own exactly once.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };

        if created {
            if let Err(err) = verify_exact_mode(owned.as_raw_fd(), 0o700, true, display, euid) {
                drop(owned);
                return Err(rollback_created_dir(parent_fd, &cname, err));
            }
        }
        Ok((Pinned(owned), created))
    }

    /// Remove a directory `mkdirat` created in this invocation. Never called
    /// for an `AlreadyExists` race winner.
    fn rollback_created_dir(
        parent_fd: std::os::fd::RawFd,
        cname: &std::ffi::CString,
        primary: std::io::Error,
    ) -> std::io::Error {
        // SAFETY: `name` was created by this invocation under `parent_fd`.
        let rc = unsafe { libc::unlinkat(parent_fd, cname.as_ptr(), libc::AT_REMOVEDIR) };
        if rc == 0 {
            return primary;
        }
        let clean = std::io::Error::last_os_error();
        std::io::Error::new(
            primary.kind(),
            format!("{primary}; also failed to remove the directory this process created: {clean}"),
        )
    }

    /// Pin a file this process just created to `want` on its held descriptor
    /// and verify the achieved mode.
    pub(crate) fn pin_created_file(
        file: std::fs::File,
        want: libc::mode_t,
        display: &Path,
        euid: u32,
    ) -> std::io::Result<Pinned<std::fs::File>> {
        let skip = {
            #[cfg(test)]
            {
                SKIP_MODE_PIN.with(|c| c.get())
            }
            #[cfg(not(test))]
            {
                false
            }
        };
        if !skip {
            // SAFETY: fchmod on a descriptor this process owns.
            if unsafe { libc::fchmod(file.as_raw_fd(), want) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        verify_exact_mode(file.as_raw_fd(), want, false, display, euid)?;
        Ok(Pinned(file))
    }

    /// The ancestor predicate, applied to the parent this helper is about to
    /// chmod a child of.
    pub(crate) fn verify_trusted_parent(
        fd: std::os::fd::RawFd,
        display: &Path,
        euid: u32,
    ) -> std::io::Result<()> {
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fstat writes the struct on success; checked before read.
        if unsafe { libc::fstat(fd, st.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fstat returned 0.
        let st = unsafe { st.assume_init() };
        if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
            return Err(io_err(
                std::io::ErrorKind::InvalidInput,
                format!("{}'s parent is not a directory", display.display()),
            ));
        }
        if st.st_uid != euid && st.st_uid != 0 {
            return Err(io_err(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "{}'s parent is owned by uid {} rather than this node (uid {}) or root",
                    display.display(),
                    st.st_uid,
                    euid
                ),
            ));
        }
        let perms = st.st_mode & 0o777;
        let sticky = st.st_mode & 0o1000 != 0;
        if perms & 0o022 != 0 && !sticky {
            return Err(io_err(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "{}'s parent has mode {:04o} and is writable beyond its owner",
                    display.display(),
                    perms
                ),
            ));
        }
        Ok(())
    }
}

/// Non-unix publication has no mode pin, so `Pinned` is only a wrapper that
/// lets the shared scratch-then-link writer type-check. The unix module above
/// stays helper-only: this constructor is not compiled there.
#[cfg(not(unix))]
pub(crate) mod pin {
    #[derive(Debug)]
    pub(crate) struct Pinned<T>(T);

    impl<T> Pinned<T> {
        pub(crate) fn wrap(inner: T) -> Self {
            Self(inner)
        }

        pub(crate) fn get_mut(&mut self) -> &mut T {
            &mut self.0
        }
    }
}

/// Descriptor-anchored ancestor walk from a trusted anchor to the key
/// directory's parent.
///
/// This replaces the old `foreign_ancestor_error` walk (path-following
/// `metadata`, missing components skipped, group-write never checked, and the
/// separately-created `create_dir_all` output never re-verified) with one walk
/// that verifies and creates the chain together:
///
///   1. Resolve the trusted anchor: the filesystem root for an absolute path,
///      or the process cwd (opened as `.`, no-follow) for a relative one. The
///      cwd's own ancestors are out of scope: the process cwd is an inode that
///      external users cannot repoint, which is what makes a relative anchor
///      safe.
///   2. Walk every component strictly above the key directory, opening each one
///      relative to the previously verified descriptor without following
///      symlinks, and judge it by fstat on the opened descriptor: real
///      directory, owner is the effective uid or root, no write bits beyond the
///      owner unless sticky (the 1777 `/tmp` shape is accepted; 0770/0775 and
///      non-sticky 0777 are refused).
///   3. Create a missing component at 0700 relative to the verified parent,
///      then reopen it no-follow and verify the object that actually landed.
///      `AlreadyExists` on create is a race: the winner gets the same full
///      verification, never automatic acceptance or refusal.
///
/// The key directory itself (the leaf) is deliberately not part of this walk:
/// `ensure_key_dir` opens it no-follow, checks its ownership, and tightens it
/// to 0700 afterwards.
#[cfg(unix)]
fn walk_dir_open_flags() -> libc::c_int {
    // Traversal needs search/execute, not directory-list. `O_RDONLY` on a
    // directory additionally requires read permission, so a safe 0111 ancestor
    // would fail before the ownership/write-authority predicate ran.
    let common = libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        libc::O_PATH | common
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
    ))]
    {
        libc::O_SEARCH | common
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
    )))]
    {
        libc::O_RDONLY | common
    }
}

#[cfg(unix)]
fn leaf_dir_open_flags() -> libc::c_int {
    // The key directory handle must support fsync and fchmod. Those fail on
    // an `O_PATH` descriptor, and a 0700 leaf is owner-readable.
    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC
}

/// Open `path` as a directory without following a symlink in the final
/// position. `flags` is either the walk set (`O_PATH` on Linux) or the leaf
/// set (`O_RDONLY`).
#[cfg(unix)]
fn open_dir_with_flags(path: &Path, flags: libc::c_int) -> std::io::Result<std::fs::File> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;

    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} contains an interior NUL byte", path.display()),
        )
    })?;
    // SAFETY: `open` returns a new descriptor we own on success.
    let fd = unsafe { libc::open(cpath.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// Map a failed no-follow component open onto the refusal vocabulary the key
/// storage tests assert on. `ENOTDIR` is what `O_NOFOLLOW | O_DIRECTORY`
/// returns for a symlink in that position, dangling or not; `ELOOP` is the
/// same refusal from a flag set without `O_DIRECTORY`. Anything else, notably
/// `ENOENT`, is passed through unchanged so callers keep their missing-component
/// handling.
#[cfg(unix)]
fn nofollow_component_error(e: std::io::Error, component: &Path) -> std::io::Error {
    match e.raw_os_error() {
        Some(code) if code == libc::ELOOP || code == libc::ENOTDIR => std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{} is a symlink or another object type rather than a real directory",
                component.display()
            ),
        ),
        _ => e,
    }
}

/// Resolve `path` to a directory descriptor one component at a time, opening
/// each component relative to the previously opened one so `O_NOFOLLOW` binds
/// at EVERY position rather than only the last.
///
/// A path-based `open(2)` applies `O_NOFOLLOW` to the final component alone,
/// which is all the kernel offers for a multi-component pathname, so every
/// interior symlink is followed during resolution. That is enough to substitute
/// the whole identity rather than merely misplace it: the load and the create
/// path resolve the configured pathname identically, so repointing one interior
/// link redirects both and the node boots as whichever key sits behind the new
/// target while its own key stays untouched on disk.
///
/// Resolution only. No component is created here, and an existing one is
/// adopted with NO ownership or mode judgment: `GITLAWB_KEY` is a file path
/// rather than a dedicated-directory setting, so its ancestors are allowed to
/// be a shared volume or owned by another uid, and the p2p `verify_component`
/// predicate deliberately does not apply. The single refusal this adds is a
/// symlink on the key path.
///
/// The anchor is the filesystem root for an absolute path and the process cwd
/// (opened as `.`) for a relative one. A symlinked cwd is not a hole: `chdir`
/// resolves to an inode, so `open(".")` is the real directory and its ancestors
/// are out of reach of anyone who can repoint a name.
///
/// `leaf_flags` applies to the final component, which is the one the caller
/// actually uses (`leaf_dir_open_flags` when it will fsync or fchmod through
/// the handle, the walk set otherwise). Interior components are opened with the
/// walk set, which needs search rather than directory-list permission.
#[cfg(unix)]
fn resolve_dir_nofollow(path: &Path, leaf_flags: libc::c_int) -> std::io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    let mut names: Vec<std::ffi::OsString> = Vec::new();
    for component in path.components() {
        match component {
            // The anchor covers both, and a `.` inside the path is a no-op.
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::Normal(n) => names.push(n.to_os_string()),
            // `..` is not a symlink, so stepping through it relative to the
            // descriptor we hold is the same object the kernel would reach.
            std::path::Component::ParentDir => names.push(std::ffi::OsString::from("..")),
            std::path::Component::Prefix(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("{} carries an unsupported path prefix", path.display()),
                ));
            }
        }
    }

    let absolute = path.is_absolute();
    let (anchor, mut acc) = if absolute {
        (Path::new("/"), PathBuf::from("/"))
    } else {
        (Path::new("."), PathBuf::from("."))
    };
    // With no components of its own the anchor IS the requested directory, so
    // it takes the caller's flags.
    let anchor_flags = if names.is_empty() {
        leaf_flags
    } else {
        walk_dir_open_flags()
    };
    let mut cur =
        open_dir_with_flags(anchor, anchor_flags).map_err(|e| nofollow_component_error(e, &acc))?;

    let last = names.len().saturating_sub(1);
    for (idx, name) in names.iter().enumerate() {
        acc.push(name);
        let flags = if idx == last {
            leaf_flags
        } else {
            walk_dir_open_flags()
        };
        let cname = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} contains an interior NUL byte", path.display()),
            )
        })?;
        // SAFETY: openat relative to a directory descriptor this process owns;
        // O_NOFOLLOW refuses a symlink in this position instead of resolving
        // through it, and the returned descriptor is owned exactly once.
        let fd = unsafe { libc::openat(cur.as_raw_fd(), cname.as_ptr(), flags) };
        if fd < 0 {
            return Err(nofollow_component_error(
                std::io::Error::last_os_error(),
                &acc,
            ));
        }
        // SAFETY: a descriptor we just received from openat and own exactly once.
        cur = unsafe { std::fs::File::from_raw_fd(fd) };
    }
    Ok(cur)
}

#[cfg(unix)]
fn verify_and_create_ancestor_chain(dir: &Path, euid: u32) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd};

    /// Refuse an opened component unless it is a real directory owned by
    /// `euid` or root with no write bits beyond the owner unless sticky.
    fn verify_component(fd: i32, key_dir: &Path, component: &Path, euid: u32) -> Result<()> {
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fstat writes the stat struct on success; the return value is
        // checked before the struct is read.
        if unsafe { libc::fstat(fd, st.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to stat {}", component.display()));
        }
        let st = unsafe { st.assume_init() };

        if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
            anyhow::bail!(
                "p2p key directory {} sits under {}, which is not a real directory; the node \
                 refuses symlinks and other object types on the key storage path",
                key_dir.display(),
                component.display()
            );
        }

        let owner = st.st_uid;
        if owner != euid && owner != 0 {
            anyhow::bail!(
                "p2p key directory {} sits under {}, which is owned by uid {} rather than this \
                 node (uid {}) or root; that user can rename or replace the directory holding \
                 the key and so control which identity the node presents. Put the key somewhere \
                 this user or root owns the whole path.",
                key_dir.display(),
                component.display(),
                owner,
                euid
            );
        }

        let write_bits = st.st_mode & 0o777;
        let sticky = st.st_mode & 0o1000 != 0;
        if write_bits & 0o022 != 0 && !sticky {
            anyhow::bail!(
                "p2p key directory {} sits under {}, which has mode {:04o} and is writable \
                 beyond its owner; anyone with that write access can rename or replace the \
                 directory holding the key and so control which identity the node presents.",
                key_dir.display(),
                component.display(),
                write_bits
            );
        }
        Ok(())
    }

    // The components strictly above the key directory, below the anchor.
    let Some(parent) = dir.parent() else {
        // `dir` is the filesystem root, so there is no parent descriptor to
        // hand back. `key_parent_is_filesystem_root` already refuses this
        // configuration lexically; this arm is the backstop and bails rather
        // than opening `/` for a path the validator rejects.
        anyhow::bail!(
            "p2p key directory {} is the filesystem root; the key needs a dedicated directory",
            dir.display()
        );
    };
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let absolute = parent.is_absolute();
    let components: Vec<std::ffi::OsString> = parent
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(n) => Some(n.to_os_string()),
            _ => None,
        })
        .collect();

    // Open and verify the anchor. The descriptor stays owned for the whole walk
    // and is closed on every exit path.
    let (anchor, anchor_display) = if absolute {
        // SAFETY: open(2) on "/" returns a new descriptor we own on success;
        // the root is not a symlink, so O_NOFOLLOW is moot there.
        let root = std::ffi::CString::new("/").unwrap();
        let fd = unsafe { libc::open(root.as_ptr(), walk_dir_open_flags()) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!("failed to open the filesystem root for {}", dir.display())
            });
        }
        // SAFETY: a descriptor we just received and own exactly once.
        (
            unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) },
            PathBuf::from("/"),
        )
    } else {
        // SAFETY: open(2) on "." returns a descriptor for the process cwd
        // itself; O_NOFOLLOW and O_DIRECTORY pin the object type. The display
        // path is only for error messages (no pathname is re-resolved for IO).
        let dot = std::ffi::CString::new(".").unwrap();
        let fd = unsafe { libc::open(dot.as_ptr(), walk_dir_open_flags()) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!("failed to open the working directory for {}", dir.display())
            });
        }
        let display = std::env::current_dir()
            .map(|d| {
                if d.as_os_str().is_empty() {
                    PathBuf::from(".")
                } else {
                    d
                }
            })
            .unwrap_or_else(|_| PathBuf::from("."));
        // SAFETY: a descriptor we just received and own exactly once.
        (unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) }, display)
    };

    verify_component(anchor.as_raw_fd(), dir, &anchor_display, euid)?;

    let mut acc = anchor_display;
    let mut cur = anchor;
    for name in &components {
        acc.push(name);

        // One call covers both cases: an existing component is opened
        // no-follow and adopted as-is, a missing one is created at 0700, pinned
        // on the object this process just made, reopened, and verified at its
        // ACHIEVED mode. Before this, the create arm pinned only AFTER the
        // reopen, so under a mask that strips owner bits the reopen failed
        // EACCES and the pin was unreachable in exactly the case it existed
        // for.
        let (next, _created) =
            pin::create_dir_pinned_at(cur.as_raw_fd(), name, &acc, euid, walk_dir_open_flags())
                .map_err(|e| walk_component_error(e, dir, &acc))?;

        // The R3 predicate still judges every component, created or adopted.
        verify_component(next.get().as_raw_fd(), dir, &acc, euid)?;
        cur = next.into_inner();
    }
    Ok(cur)
}

/// Map an io error from the pinned-creation helper onto the walk's own
/// vocabulary, preserving the symlink and wrong-object-type messages the
/// storage-contract tests assert on.
#[cfg(unix)]
fn walk_component_error(e: std::io::Error, key_dir: &Path, component: &Path) -> anyhow::Error {
    match e.raw_os_error() {
        Some(code) if code == libc::ELOOP || code == libc::ENOTDIR => anyhow::anyhow!(
            "p2p key directory {} sits under {}, which is a symlink or another object type; \
             the node refuses anything but a real directory on the key storage path",
            key_dir.display(),
            component.display()
        ),
        _ => anyhow::Error::new(e).context(format!(
            "failed to open or create key directory component {}",
            component.display()
        )),
    }
}

/// Whether a configured spelling names a directory rather than a key file.
///
/// Inspects the stored string, not `Path::file_name`. Rust's `Path` drops a
/// final `.` component, so `/data/keys/.` would otherwise be stored as the
/// file `keys` under `/data`.
fn spelling_denotes_a_directory(spelling: &str) -> bool {
    if spelling == "~/" || spelling.ends_with('/') || spelling.ends_with('\\') {
        return true;
    }
    let last = spelling.rsplit(['/', '\\']).next().unwrap_or(spelling);
    last == "." || last == ".."
}

/// Whether the configured path names a directory rather than a key file.
///
/// Checked lexically (`~/`, a trailing `/`, a final `.` or `..` component)
/// before any directory is created or chmodded. The Path is consulted only
/// as a backstop for callers that pass no raw spelling: the OsStr still
/// carries the operator's `.` even after `components()` has dropped it.
pub(crate) fn path_denotes_a_directory(key_path: &Path, configured_raw: Option<&str>) -> bool {
    if let Some(raw) = configured_raw {
        if spelling_denotes_a_directory(raw) {
            return true;
        }
    }
    if let Some(stored) = key_path.to_str() {
        if spelling_denotes_a_directory(stored) {
            return true;
        }
    }

    match key_path.file_name() {
        None => return true,
        Some(name) if name.is_empty() => return true,
        _ => {}
    }

    // Deliberately lexical only. Asking the filesystem whether the path is
    // currently a directory turns a configuration question into a live storage
    // observation, and the load path already refuses a directory at the key
    // position by fstat on the descriptor it opened.
    false
}

/// Validate the resolved key path before creating or chmodding anything.
///
/// `configured_raw` is the operator's `GITLAWB_P2P_KEY` string when available.
/// A key path that cannot name a securable key file, whatever is on disk.
///
/// A distinct type rather than a `String` so the two failure domains cannot be
/// confused at a call site: this one is boot-fatal, and everything the load
/// path discovers about live filesystem objects is not.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(crate) struct P2pKeyConfigError(String);

/// Directory plus leaf name of a validated p2p key path. Later storage must
/// consume this pair rather than asking `Path` again, because `Path` drops a
/// final `.` and would retarget `/data/keys/.` as the file `keys` under `/data`.
#[derive(Debug, Clone)]
pub(crate) struct P2pKeyTarget {
    pub dir: PathBuf,
    pub leaf: std::ffi::OsString,
}

pub(crate) fn validate_p2p_key_config(
    key_path: &Path,
    configured_raw: Option<&str>,
) -> Result<P2pKeyTarget, P2pKeyConfigError> {
    let display = configured_raw.unwrap_or_else(|| key_path.to_str().unwrap_or("<invalid utf-8>"));

    if names_no_usable_directory(key_path) {
        return Err(P2pKeyConfigError(format!(
            "GITLAWB_P2P_KEY ({display}) must include a directory that does not walk back through \
             `..`, such as ./keys/p2p.key or /data/keys/p2p.key: the node will not store its p2p \
             identity key in the working directory, where the directory holding it cannot be secured."
        )));
    }

    if key_parent_is_filesystem_root(key_path) {
        return Err(P2pKeyConfigError(format!(
            "GITLAWB_P2P_KEY ({display}) must not place the key in the filesystem root; use a \
             dedicated directory such as /data/keys/p2p.key"
        )));
    }

    if path_denotes_a_directory(key_path, configured_raw) {
        return Err(P2pKeyConfigError(format!(
            "GITLAWB_P2P_KEY ({display}) must name a key file, not a directory"
        )));
    }

    // Nothing below this point may look at the filesystem. A symlink at the key
    // path, a directory in its place, a symlinked or non-directory parent, and
    // an unreadable parent are all live storage facts, and the load path
    // re-establishes every one of them on a descriptor it actually opens:
    // `open_key_for_read` adds O_NOFOLLOW, `read_p2p_keypair_from` refuses a
    // non-regular file, and the leaf openat gives ELOOP or ENOTDIR through
    // `describe_unusable_key_dir`. Deciding them here made the same fault
    // fatal or degradable depending only on which layer noticed it first.
    let leaf = key_path
        .file_name()
        .filter(|n| !n.is_empty())
        .ok_or_else(|| {
            P2pKeyConfigError(format!(
                "GITLAWB_P2P_KEY ({display}) must name a key file, not a directory"
            ))
        })?;
    Ok(P2pKeyTarget {
        dir: key_parent(key_path).to_path_buf(),
        leaf: leaf.to_os_string(),
    })
}

/// Load the node's persistent libp2p identity from `key_path`, generating and
/// storing a fresh Ed25519 keypair the first time.
///
/// This is the enforcement point for the key-storage contract. Rules 1 and 2
/// live in configuration, rules 3–5 here:
///
///   1. Disabled p2p (`GITLAWB_P2P_PORT=0`) never resolves, inspects, or
///      mutates key storage at all (`Config::validate` gates on the port).
///   2. A `~/`-relative path is parsed exactly once, and the suffix is proven
///      relative before it is joined, so expansion cannot land outside home
///      ([`tilde_suffix_escapes_home`]).
///   3. Every mutation of the key directory goes through a [`KeyDirHandle`]:
///      a descriptor opened without following symlinks and `fstat`-verified to
///      be a real directory this uid owns. chmod, scratch creation,
///      publication, cleanup, and the durability sync all address that
///      descriptor, so replacing the pathname after validation redirects
///      nothing. Paths that cannot reach that state are rejected before any
///      chmod or key IO.
///   4. An existing key is opened through the same handle without following
///      symlinks and without blocking, and the *opened* object must be a
///      regular file within [`MAX_P2P_KEY_BYTES`] before any byte of it is
///      trusted ([`read_p2p_keypair_from`]).
///   5. Losing a creation race — at the key directory or at the key file — is
///      a normal concurrent-first-start outcome: the loser verifies what the
///      winner made and adopts it, so simultaneous boots converge on one
///      PeerId.
pub fn load_or_create_p2p_keypair(key_path: &Path) -> Result<identity::Keypair> {
    // Rule 3's rejection half: refuse paths that cannot name a securable key
    // file before anything on disk is created, opened, or chmodded. Purely
    // inspective — the checks below re-establish everything it observed on the
    // actual opened objects, so this exists for early, precise errors rather
    // than for safety.
    let target = validate_p2p_key_config(key_path, None).map_err(|e| anyhow::anyhow!(e))?;

    let dir = ensure_key_dir(&target.dir)?;

    if let Some(file) = open_existing_key(&dir, &target.leaf, key_path)? {
        return read_p2p_keypair_from(file, key_path);
    }

    let kp = identity::Keypair::generate_ed25519();
    // The serialized form carries the private key, so scrub it on drop rather
    // than leaving it in a heap buffer for the rest of the process. Same
    // convention `gitlawb-core` applies to its own key material.
    let bytes = Zeroizing::new(
        kp.to_protobuf_encoding()
            .map_err(|e| anyhow::anyhow!("failed to serialize p2p key: {e}"))?,
    );

    match write_key_atomically(&dir, &target.leaf, &bytes) {
        Ok(()) => {
            info!(
                path = %key_path.display(),
                peer_id = %PeerId::from(kp.public()),
                "generated new p2p identity"
            );
            Ok(kp)
        }
        // Rule 5 at the key-file layer: another node process won the race
        // between the open above and the atomic publish. Adopt its key,
        // through the same handle, so both processes converge on one PeerId.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let file = open_existing_key(&dir, &target.leaf, key_path)?.ok_or_else(|| {
                anyhow::anyhow!(
                    "p2p key at {} vanished after another process published it; \
                     refusing to guess which identity this node should have",
                    key_path.display()
                )
            })?;
            read_p2p_keypair_from(file, key_path)
        }
        Err(e) => Err(anyhow::Error::new(e)
            .context(format!("failed to write p2p key to {}", key_path.display()))),
    }
}

/// An open, verified handle on the key directory: the anchor that closes the
/// gap between checking the directory and mutating it.
///
/// A `symlink_metadata` check followed by path-addressed chmod/open/link calls
/// is a check-then-use sequence: whatever the check proved about the pathname
/// can be invalidated by renaming a symlink or another object into place
/// before the next call resolves the same path again. This handle is the fix.
/// On unix it is opened with `O_NOFOLLOW` (a symlink in the final position
/// fails instead of being followed) and `O_DIRECTORY` (any other object type
/// fails), and every judgment after that — owner, mode, the chmod itself —
/// comes from `fstat`/`fchmod` on the descriptor, while scratch creation
/// (`openat`), publication (`linkat`), cleanup (`unlinkat`), and the
/// durability sync (`fsync`) address children *relative to* the descriptor.
/// After the open there is no second pathname resolution left to redirect.
///
/// Child names are single components this module generates itself (the key's
/// `file_name` and the scratch names), never operator input containing
/// separators.
///
/// On non-unix targets the same sequence falls back to path-addressed calls
/// with a no-follow pre-check; the pre-flight validation still runs, and unix
/// is where the node deploys.
#[derive(Debug)]
struct KeyDirHandle {
    #[cfg(unix)]
    dir: std::fs::File,
    /// On unix: for error messages only, never resolved again for IO.
    path: std::path::PathBuf,
}

#[cfg(unix)]
impl KeyDirHandle {
    /// Build a handle from a descriptor that has already been pinned and
    /// verified by [`pin::create_dir_pinned_at`].
    ///
    /// Taking a `Pinned` rather than a bare descriptor is what makes the mode
    /// rule compile-enforced for nominated key directories: a directory that
    /// never went through the pin helper cannot reach that constructor.
    fn from_pinned_fd(pinned: pin::Pinned<std::os::fd::OwnedFd>, dir_path: &Path) -> KeyDirHandle {
        KeyDirHandle {
            dir: std::fs::File::from(pinned.into_inner()),
            path: dir_path.to_path_buf(),
        }
    }

    /// Publish into an already-existing directory without creating or chmodding
    /// it. Identity-key paths use this for cwd, `/`, and any nominated parent
    /// that already exists, so the p2p key's dedicated-directory contract (pin
    /// to 0700) is not imported onto `GITLAWB_KEY`. Write-authority is still
    /// checked: a 0600 key is unprotected if this directory is group/world
    /// writable, so [`pin::verify_trusted_parent`] runs on the held descriptor
    /// before the handle is returned.
    fn from_existing_dir(
        dir: std::fs::File,
        dir_path: &Path,
        held_for: &Path,
    ) -> std::io::Result<KeyDirHandle> {
        use std::os::fd::AsRawFd;

        let md = dir.metadata()?;
        if !md.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} is not a directory", dir_path.display()),
            ));
        }
        pin::verify_trusted_parent(dir.as_raw_fd(), held_for, effective_uid())?;
        Ok(KeyDirHandle {
            dir,
            path: dir_path.to_path_buf(),
        })
    }

    /// Open `dir_path` refusing symlinks and non-directories at the open
    /// itself, so rejection happens before any chmod or key IO rather than
    /// after a separate stat that something else could invalidate.
    ///
    /// Test-only on unix: the production path builds its handle from the
    /// pinned descriptor the walk hands back, never by re-resolving a pathname.
    #[cfg(test)]
    fn open(dir_path: &Path) -> std::io::Result<KeyDirHandle> {
        use std::os::unix::fs::OpenOptionsExt;

        let dir = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(dir_path)?;
        Ok(KeyDirHandle {
            dir,
            path: dir_path.to_path_buf(),
        })
    }

    /// `fstat` on the held descriptor: the object this metadata describes is
    /// the object every other method mutates, with no path in between.
    fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        self.dir.metadata()
    }

    /// `fchmod` on the held descriptor, for the same reason.
    fn tighten_to_0700(&self) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        self.dir
            .set_permissions(std::fs::Permissions::from_mode(0o700))
    }

    /// `openat` relative to the held descriptor. `O_NOFOLLOW` and `O_CLOEXEC`
    /// are always added: no child of the key directory is ever a symlink this
    /// module is willing to follow.
    fn open_child(
        &self,
        name: &std::ffi::OsStr,
        flags: libc::c_int,
        mode: libc::mode_t,
    ) -> std::io::Result<std::fs::File> {
        use std::os::fd::{AsRawFd, FromRawFd};

        let name = Self::child_name(name)?;
        // SAFETY: `openat` resolves `name` relative to our owned, verified
        // directory descriptor and returns a new descriptor on success;
        // `from_raw_fd` assumes ownership of it exactly once.
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                libc::c_uint::from(mode),
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` is a valid descriptor we just received and own.
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    /// Open an existing key for reading. `O_NONBLOCK` so that a FIFO left at
    /// the key path cannot park startup in `open(2)` waiting for a writer;
    /// whether the opened object is actually a regular file is judged by
    /// `fstat` on the result, in [`read_p2p_keypair_from`].
    fn open_key_for_read(&self, name: &std::ffi::OsStr) -> std::io::Result<std::fs::File> {
        self.open_child(name, libc::O_RDONLY | libc::O_NONBLOCK, 0)
    }

    /// Create a scratch file with 0600 applied at creation. `O_EXCL` keeps a
    /// collision an error rather than an adoption.
    fn create_scratch(
        &self,
        name: &std::ffi::OsStr,
    ) -> std::io::Result<pin::Pinned<std::fs::File>> {
        let file = self.open_child(
            name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600 as libc::mode_t,
        )?;
        // 0600 was the REQUESTED mode and the umask has already edited it, so
        // pin it on the descriptor we hold and verify what actually landed.
        // Without this the key is published at whatever the mask allowed, the
        // creating boot still succeeds on this open descriptor, and the NEXT
        // boot cannot read its own key. `O_EXCL` guarantees this process
        // created the inode, so there is no race winner to leave alone.
        pin::pin_created_file(file, 0o600, &self.path.join(name), effective_uid()).map_err(|e| {
            match self.remove_child(name) {
                Ok(()) => e,
                Err(clean) => std::io::Error::new(
                    e.kind(),
                    format!("{e}; also failed to remove the scratch this process created: {clean}"),
                ),
            }
        })
    }

    /// Atomically publish `from` at `to` via `linkat` on the held descriptor.
    /// Fails with `AlreadyExists` if anything already occupies `to`, which is
    /// the signal the concurrency protocol in the caller relies on.
    fn publish(&self, from: &std::ffi::OsStr, to: &std::ffi::OsStr) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;

        let from = Self::child_name(from)?;
        let to = Self::child_name(to)?;
        // SAFETY: both names resolve relative to our owned directory
        // descriptor; `linkat` with no flags follows no symlinks.
        let rc = unsafe {
            libc::linkat(
                self.dir.as_raw_fd(),
                from.as_ptr(),
                self.dir.as_raw_fd(),
                to.as_ptr(),
                0,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// `unlinkat` relative to the held descriptor.
    fn remove_child(&self, name: &std::ffi::OsStr) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;

        #[cfg(test)]
        if FAIL_SCRATCH_UNLINK.with(|f| f.get()) {
            return Err(std::io::Error::other("injected scratch unlink failure"));
        }

        let name = Self::child_name(name)?;
        // SAFETY: resolves relative to our owned directory descriptor;
        // `unlinkat` without AT_REMOVEDIR removes only non-directories.
        let rc = unsafe { libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// `fsync` the directory itself so a just-published entry survives a crash.
    fn sync(&self) -> std::io::Result<()> {
        #[cfg(test)]
        SYNC_COUNT.with(|c| c.set(c.get() + 1));
        self.dir.sync_all()
    }

    fn child_name(name: &std::ffi::OsStr) -> std::io::Result<std::ffi::CString> {
        use std::os::unix::ffi::OsStrExt;
        std::ffi::CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "key file name contains an interior NUL byte",
            )
        })
    }
}

#[cfg(not(unix))]
impl KeyDirHandle {
    fn open(dir_path: &Path) -> std::io::Result<KeyDirHandle> {
        let md = std::fs::symlink_metadata(dir_path)?;
        if md.is_symlink() || !md.is_dir() {
            // The closest std kind to ELOOP/ENOTDIR that maps onto the same
            // caller-side diagnosis as the unix open flags.
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a real directory",
            ));
        }
        Ok(KeyDirHandle {
            path: dir_path.to_path_buf(),
        })
    }

    fn open_key_for_read(&self, name: &std::ffi::OsStr) -> std::io::Result<std::fs::File> {
        let path = self.path.join(name);
        if std::fs::symlink_metadata(&path)?.is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "p2p key is a symlink",
            ));
        }
        std::fs::OpenOptions::new().read(true).open(path)
    }

    fn create_scratch(
        &self,
        name: &std::ffi::OsStr,
    ) -> std::io::Result<pin::Pinned<std::fs::File>> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.path.join(name))?;
        Ok(pin::Pinned::wrap(file))
    }

    fn publish(&self, from: &std::ffi::OsStr, to: &std::ffi::OsStr) -> std::io::Result<()> {
        std::fs::hard_link(self.path.join(from), self.path.join(to))
    }

    fn remove_child(&self, name: &std::ffi::OsStr) -> std::io::Result<()> {
        std::fs::remove_file(self.path.join(name))
    }

    fn sync(&self) -> std::io::Result<()> {
        // Directory fsync is not expressible through std here; publication
        // durability degrades to best-effort on non-unix targets.
        Ok(())
    }
}

/// Map a failed [`KeyDirHandle::open`] to the operator-facing explanation.
///
/// `ELOOP` is the flag-refused symlink and `ENOTDIR` the wrong object type;
/// both messages match the ones `parent_directory_is_safe_to_mutate` produces
/// at validation time, because they are the same finding made at the moment
/// that actually matters — the open that everything after is anchored to.
fn describe_unusable_key_dir(dir: &Path, e: std::io::Error) -> anyhow::Error {
    #[cfg(unix)]
    {
        match e.raw_os_error() {
            Some(code) if code == libc::ELOOP => {
                return anyhow::anyhow!(
                    "GITLAWB_P2P_KEY's directory {} must be a real directory, not a symlink",
                    dir.display()
                );
            }
            Some(code) if code == libc::ENOTDIR => {
                // Linux returns ENOTDIR, not ELOOP, when O_NOFOLLOW is
                // combined with O_DIRECTORY on a symlink, so the errno alone
                // cannot separate a symlink from a regular file. The refusal
                // already happened; this lstat only picks the wording, and
                // naming the symlink is what tells an operator what to look
                // for.
                if std::fs::symlink_metadata(dir).is_ok_and(|md| md.is_symlink()) {
                    return anyhow::anyhow!(
                        "GITLAWB_P2P_KEY's directory {} must be a real directory, not a symlink",
                        dir.display()
                    );
                }
                return anyhow::anyhow!(
                    "GITLAWB_P2P_KEY's directory {} must be a directory, not another file type",
                    dir.display()
                );
            }
            Some(code) if code == libc::EACCES => {
                return anyhow::anyhow!(
                    "GITLAWB_P2P_KEY's directory {} cannot be opened by this node; run \
                     `chmod 700 {}` if it should own it. Check the directory's current mode \
                     first: two node processes starting at once can produce this transiently, \
                     in which case the directory is already 0700 and the next start succeeds.",
                    dir.display(),
                    dir.display()
                );
            }
            _ => {}
        }
    }
    #[cfg(not(unix))]
    if e.kind() == std::io::ErrorKind::InvalidInput {
        return anyhow::anyhow!(
            "GITLAWB_P2P_KEY's directory {} must be a real directory, not a symlink \
             or another file type",
            dir.display()
        );
    }
    anyhow::Error::new(e).context(format!("failed to open key directory {}", dir.display()))
}

/// Group or world write on a directory is replacement authority over the next
/// entry. Execute or list without write is not.
fn dir_mode_allows_untrusted_replace(mode: u32) -> bool {
    mode & 0o022 != 0
}

/// Create the directory holding the key with owner-only permissions, tighten
/// it if it already exists with a looser mode, and hand back the verified
/// handle every subsequent operation is anchored to. Write permission on this
/// directory is enough to unlink or replace the 0600 key inside it, so the
/// directory guards the key as much as the key's own mode does.
///
/// `create_dir_all` takes 0777 masked by the umask, which lands 0755 under a
/// normal umask and 0777 under a permissive one. `DirBuilder`'s mode fixes that
/// for directories it creates, but an existing directory keeps whatever mode it
/// was made with, so the load path has to check too.
///
/// A loose existing directory is repaired rather than rejected. Rejecting it
/// would refuse to boot on every node whose directory already landed 0755,
/// which is the common case, and through `main.rs`'s non-fatal handling that
/// would read as a silent p2p outage rather than a clear failure. Tightening
/// applies exactly the remedy the alternative would have asked the operator to
/// run by hand. Failure to tighten is fatal, since at that point the key cannot
/// be protected.
///
/// `~/.gitlawb/identity.pem` lives in this directory too, so this covers both
/// keys. Issue #231 owns the sibling gap in `main.rs`'s own creation path for
/// that file; nothing here touches it.
#[cfg(unix)]
fn ensure_key_dir(dir: &Path) -> Result<KeyDirHandle> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let euid = effective_uid();

    // The walk hands back the key directory's PARENT descriptor, so the leaf is
    // created and judged relative to a verified parent rather than by resolving
    // its pathname a second time.
    let parent_fd = verify_and_create_ancestor_chain(dir, euid)?;
    let leaf_name = dir.file_name().ok_or_else(|| {
        anyhow::anyhow!(
            "p2p key directory {} names no final component",
            dir.display()
        )
    })?;

    let (pinned, created) = pin::create_dir_pinned_at(
        parent_fd.as_raw_fd(),
        leaf_name,
        dir,
        euid,
        leaf_dir_open_flags(),
    )
    .map_err(|e| describe_unusable_key_dir(dir, e))?;
    let handle = KeyDirHandle::from_pinned_fd(pinned, dir);

    // A directory this process just created is already verified at exactly 0700
    // by the helper. Only an adopted one (pre-existing, or the winner of a
    // creation race) is judged here, and it is never widened beyond 0700.
    if !created {
        let md = handle
            .metadata()
            .with_context(|| format!("failed to stat key directory {}", dir.display()))?;

        if let Some(err) = foreign_ownership_error("key directory", dir, md.uid(), euid) {
            anyhow::bail!(err);
        }

        // Owner rwx is required to use the directory. Group/world bits and
        // special bits (setgid 2700, sticky 1700) are repairable and are
        // normalized to 0700. Missing owner bits are over-closed: refuse,
        // do not widen.
        let mode = md.permissions().mode() & 0o7777;
        if mode & 0o700 != 0o700 {
            anyhow::bail!(
                "p2p key directory {} has mode {:04o}, which this node cannot use; it is not \
                 widened automatically because a directory closed on purpose is an operator \
                 decision. Run `chmod 700 {}` if the node should own it.",
                dir.display(),
                mode,
                dir.display()
            );
        }
        if mode != 0o700 {
            let writable = dir_mode_allows_untrusted_replace(mode);
            let extra_access = mode & 0o077 != 0;
            warn!(
                dir = %dir.display(),
                mode = format!("{mode:04o}"),
                writable,
                "{}",
                if writable {
                    "key directory is writable beyond its owner; tightening it to 0700. Treat a key that was sitting there as possibly exposed"
                } else if extra_access {
                    "key directory grants access beyond its owner; tightening it to 0700"
                } else {
                    "key directory carries special mode bits; normalizing it to 0700"
                }
            );
            // `fchmod` through the handle: the directory whose mode changes is
            // the object that was just verified, not whatever the pathname
            // resolves to by now.
            handle.tighten_to_0700().with_context(|| {
                if writable {
                    format!(
                        "key directory {} has mode {:04o}, which lets other users replace \
                         the keys it holds, and it could not be tightened; run `chmod 700 {}`",
                        dir.display(),
                        mode,
                        dir.display()
                    )
                } else {
                    format!(
                        "key directory {} has mode {:04o} and could not be tightened; run `chmod 700 {}`",
                        dir.display(),
                        mode,
                        dir.display()
                    )
                }
            })?;
            let after = handle
                .metadata()
                .with_context(|| format!("failed to re-stat key directory {}", dir.display()))?
                .permissions()
                .mode()
                & 0o7777;
            if after != 0o700 {
                anyhow::bail!(
                    "key directory {} achieved mode {:04o}, requested 0700, after tightening",
                    dir.display(),
                    after
                );
            }
        }
    }

    Ok(handle)
}

/// Non-unix builds have no descriptor-anchored walk and no mode enforcement,
/// so they keep the platform-neutral create-then-open flow unchanged.
#[cfg(not(unix))]
fn ensure_key_dir(dir: &Path) -> Result<KeyDirHandle> {
    if let Some(parent) = dir.parent() {
        if !parent.as_os_str().is_empty() && parent != dir {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create parent directories for key directory {}",
                    dir.display()
                )
            })?;
        }
    }

    let handle = match KeyDirHandle::open(dir) {
        Ok(handle) => handle,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::DirBuilder::new().create(dir) {
                Ok(()) => {}
                // Losing a creation race is a successful outcome of the same
                // state transition; the re-open below judges whatever occupies
                // the path now.
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!("failed to create key directory {}", dir.display())
                    });
                }
            }
            KeyDirHandle::open(dir).map_err(|e| describe_unusable_key_dir(dir, e))?
        }
        Err(e) => return Err(describe_unusable_key_dir(dir, e)),
    };

    Ok(handle)
}

/// Load an existing identity PEM without following a symlink at the key path
/// or anywhere above it: the parent is resolved component by component by
/// [`resolve_dir_nofollow`], and the key itself is opened `openat` no-follow
/// against that descriptor. Missing parent or missing file is `Ok(None)`
/// so the caller can create. A symlink, or any other non-regular object, is
/// an error. Write-authority on the parent is not judged here: an existing
/// key must still load after upgrade even if its directory is one we would
/// refuse to create into.
#[cfg(unix)]
pub(crate) fn load_identity_pem_if_present(key_path: &Path) -> Result<Option<String>> {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    let file_name = key_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{} names no key file", key_path.display()))?;
    let parent = key_parent(key_path);
    let dir = match resolve_dir_nofollow(parent, leaf_dir_open_flags()) {
        Ok(dir) => dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e).with_context(|| {
                format!(
                    "failed to open {} to read the identity key (a symlink here is refused rather than followed)",
                    parent.display()
                )
            });
        }
    };
    let cname = std::ffi::CString::new(file_name.as_bytes())
        .map_err(|_| anyhow::anyhow!("{} contains an interior NUL byte", key_path.display()))?;
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    // SAFETY: openat relative to the directory descriptor we hold; O_NOFOLLOW
    // refuses a symlink in the final position instead of reading through it.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), cname.as_ptr(), flags) };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(err).with_context(|| {
            format!(
                "failed to open identity key at {} (a symlink here is refused rather than followed)",
                key_path.display()
            )
        });
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let md = file
        .metadata()
        .with_context(|| format!("failed to stat identity key at {}", key_path.display()))?;
    if !md.is_file() {
        anyhow::bail!(
            "identity key at {} must be a regular file; directories, FIFOs, and special files are refused",
            key_path.display()
        );
    }
    let mut pem = String::new();
    file.read_to_string(&mut pem)
        .with_context(|| format!("failed to read key from {}", key_path.display()))?;
    Ok(Some(pem))
}

/// The directories one identity boot created, held open so a failed boot can
/// remove exactly them and nothing else.
#[cfg(unix)]
#[derive(Default)]
struct CreatedDirs {
    /// Every directory opened on the walk, anchor first, then each created or
    /// adopted intermediate, held so each removal is addressed relative to the
    /// descriptor it was created in. The leaf is not here; its descriptor goes
    /// to the caller.
    chain: Vec<std::os::fd::OwnedFd>,
    /// (index into `chain` of the parent, entry name, display path), in
    /// creation order. Only entries `create_dir_pinned_at` reported `created`.
    created: Vec<(usize, std::ffi::CString, PathBuf)>,
}

#[cfg(unix)]
impl CreatedDirs {
    /// Remove, deepest first, only what this invocation created, and fold a
    /// removal failure into the primary error.
    ///
    /// A race winner is never in `created`, so an adopted directory is never
    /// removed. `AT_REMOVEDIR` refuses a non-empty directory, so a leaf another
    /// boot has published into survives this loser's rollback. The first
    /// failure stops the walk: a directory that cannot be removed keeps every
    /// ancestor above it non-empty, so continuing would only report the same
    /// leftover again, and what is left behind is 0700 owner-only.
    fn roll_back(self, primary: anyhow::Error) -> anyhow::Error {
        use std::os::fd::AsRawFd;

        for (parent_idx, name, display) in self.created.iter().rev() {
            let parent_fd = self.chain[*parent_idx].as_raw_fd();
            // SAFETY: `name` was created by this invocation under a descriptor
            // this struct still owns, so no pathname is re-resolved and no
            // other user can repoint it; `AT_REMOVEDIR` removes only an empty
            // directory, never a file and never a populated one.
            let rc = unsafe { libc::unlinkat(parent_fd, name.as_ptr(), libc::AT_REMOVEDIR) };
            if rc != 0 {
                let clean = std::io::Error::last_os_error();
                return anyhow::anyhow!(
                    "{primary:#}; also failed to remove {} which this process created: {clean}",
                    display.display()
                );
            }
        }
        primary
    }
}

/// The lexical parent of `p` for the walk up, with the two spellings of "the
/// working directory" collapsed onto `.` the way [`key_parent`] collapses them.
///
/// Applied on EVERY step, not only the first: `Path::new("one").parent()` is
/// `Some("")`, `open("")` is `NotFound`, and `Path::new("").parent()` is
/// `None`, so an unnormalized loop would read the empty parent as one more
/// missing component and walk off the top of a relative key path.
#[cfg(unix)]
fn identity_parent_step(p: &Path) -> &Path {
    match p.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Create every missing component from the deepest existing ancestor down to
/// `dir`, and hand back the leaf's descriptor.
///
/// Pass 1 walks up by name from `dir`'s parent, opening each candidate until
/// one opens; that descriptor is the anchor and the discovery open IS the use,
/// so the anchor pathname is not resolved a second time. Termination is by
/// shape: a candidate with no file name (`""`, `.`, `/`, `..`) is never stepped
/// past, so the helper carries its own precondition rather than inheriting the
/// `..` refusal from `load_or_create_keypair_at` in another file.
///
/// Each candidate is resolved by [`resolve_dir_nofollow`], one component at a
/// time from the filesystem root or the cwd, so `O_NOFOLLOW` binds at every
/// position rather than only the last one a path-based open would cover. A
/// symlink anywhere on the key path is refused instead of followed, which is
/// what stops an attacker who can repoint a single interior component from
/// redirecting the walk into a tree of their choosing. Ancestors above the
/// anchor are still neither judged nor mutated: the resolver applies no
/// ownership or mode predicate, because `GITLAWB_KEY` names a file rather than
/// a dedicated directory and its ancestors are allowed to be a shared volume or
/// owned by another uid. That is the difference from
/// [`verify_and_create_ancestor_chain`], which walks the same way but applies
/// the full `GITLAWB_P2P_KEY` ancestor policy and creates what is missing.
///
/// Pass 2 walks back down calling [`pin::create_dir_pinned_at`] per component
/// against the descriptor of the one before it, so from the anchor down no
/// pathname is resolved again. The only judgment an existing directory
/// receives is `verify_trusted_parent` on the descriptor a child is actually
/// created in.
///
/// `created_dirs` is an out-parameter so a failure on any component leaves the
/// caller holding exactly what was made so far.
#[cfg(unix)]
fn create_missing_identity_parents(
    dir: &Path,
    dir_name: &std::ffi::OsStr,
    euid: u32,
    created_dirs: &mut CreatedDirs,
) -> Result<(pin::Pinned<std::os::fd::OwnedFd>, bool)> {
    use std::os::fd::AsRawFd;

    // The caller has already observed `dir` as NotFound, so it is the first
    // missing component. Deepest first; pass 2 iterates in reverse.
    let mut missing: Vec<(std::ffi::OsString, PathBuf)> =
        vec![(dir_name.to_os_string(), dir.to_path_buf())];
    let mut cur = identity_parent_step(dir);
    let anchor = loop {
        match resolve_dir_nofollow(cur, walk_dir_open_flags()) {
            Ok(fd) => break fd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && cur.file_name().is_some() => {
                let name = cur
                    .file_name()
                    .expect("the arm guard just observed a file name")
                    .to_os_string();
                missing.push((name, cur.to_path_buf()));
                cur = identity_parent_step(cur);
            }
            Err(e) => {
                return Err(anyhow::Error::new(e).context(format!(
                    "failed to open {} (a symlink here is refused rather than followed)",
                    cur.display()
                )));
            }
        }
    };
    created_dirs.chain.push(std::os::fd::OwnedFd::from(anchor));

    let mut leaf = None;
    for (idx, (name, display)) in missing.iter().enumerate().rev() {
        let is_leaf = idx == 0;
        let flags = if is_leaf {
            leaf_dir_open_flags()
        } else {
            walk_dir_open_flags()
        };
        let cname = KeyDirHandle::child_name(name).map_err(|e| {
            anyhow::Error::new(e).context(format!("failed to name {}", display.display()))
        })?;
        let parent_idx = created_dirs.chain.len() - 1;
        let parent_fd = created_dirs.chain[parent_idx].as_raw_fd();
        let (pinned, created) = pin::create_dir_pinned_at(parent_fd, name, display, euid, flags)
            .map_err(|e| {
                anyhow::Error::new(e).context(format!(
                    "failed to create key directory {}",
                    display.display()
                ))
            })?;
        if created {
            created_dirs
                .created
                .push((parent_idx, cname, display.clone()));
        }
        if is_leaf {
            leaf = Some((pinned, created));
        } else {
            created_dirs.chain.push(pinned.into_inner());
        }
    }
    Ok(leaf.expect("the leaf is the first entry of a list that always holds it"))
}

/// Publish `bytes` as a 0600 key at `key_path` through the same scratch-then-link
/// path the p2p key uses.
///
/// Every component below the deepest existing ancestor is created pinned to
/// 0700 on one descriptor chain, so a two-deep missing prefix lands at the
/// mode this process chose rather than at the ambient umask. A pre-existing
/// ancestor is adopted as-is and never chmodded: `GITLAWB_KEY` is a file path,
/// not a dedicated-directory setting. Write-authority is still required on the
/// directory each component is created in. Anything this invocation created is
/// removed again if the boot fails past it, except a directory that has since
/// been published into, which `AT_REMOVEDIR` refuses. Deliberately NOT the full
/// `ensure_key_dir` ancestor walk: components above the deepest existing
/// ancestor are neither judged nor mutated, only resolved without following a
/// symlink at any position.
#[cfg(unix)]
pub(crate) fn create_pinned_dir_and_publish(key_path: &Path, bytes: &[u8]) -> Result<()> {
    let file_name = key_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{} names no key file", key_path.display()))?;

    // A bare filename (`identity.pem` / `./identity.pem`) or a root-adjacent
    // path (`/identity.pem`) publishes into an already-nominated directory.
    // That form is legal for GITLAWB_KEY and illegal for GITLAWB_P2P_KEY; this
    // helper must not chmod cwd or `/` as if they were a nominated key
    // directory.
    let parent = key_parent(key_path);
    if identity_parent_is_already_nominated(key_path) {
        let cwd = open_dir_with_flags(parent, leaf_dir_open_flags())
            .with_context(|| format!("failed to open {} for the identity key", parent.display()))?;
        let handle = KeyDirHandle::from_existing_dir(cwd, parent, key_path)?;
        write_key_atomically(&handle, file_name, bytes)
            .with_context(|| format!("failed to write identity key to {}", key_path.display()))?;
        return Ok(());
    }

    let dir = parent;
    let dir_name = dir
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{} names no final directory component", dir.display()))?;

    // An existing nominated parent is used as-is. GITLAWB_KEY is a file path,
    // not a dedicated-directory setting, so this must not chmod `/etc` or a
    // shared 0755 volume. Write-authority still refuses a group/world-writable
    // parent. A missing parent is created at 0700 below.
    match resolve_dir_nofollow(dir, leaf_dir_open_flags()) {
        Ok(existing) => {
            let handle = KeyDirHandle::from_existing_dir(existing, dir, key_path)?;
            write_key_atomically(&handle, file_name, bytes).with_context(|| {
                format!("failed to write identity key to {}", key_path.display())
            })?;
            return Ok(());
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(anyhow::Error::new(e).context(format!(
                "failed to open {} for the identity key (a symlink here is refused rather than followed)",
                dir.display()
            )));
        }
    }

    // Every missing component below the deepest existing ancestor is created on
    // one descriptor chain. The accumulator is an out-parameter so a failure
    // mid-walk and a failure after it reach the same rollback arm.
    let euid = effective_uid();
    let mut created_dirs = CreatedDirs::default();
    let result = create_missing_identity_parents(dir, dir_name, euid, &mut created_dirs).and_then(
        |(pinned, created)| publish_into_leaf(pinned, created, dir, key_path, file_name, bytes),
    );
    match result {
        Ok(()) => Ok(()),
        Err(e) => Err(created_dirs.roll_back(e)),
    }
}

/// Publish the key into the leaf the walk handed back.
///
/// `created` is the walk's verdict on the leaf: a directory this invocation
/// made arrives pinned and verified, and a race winner is adopted without
/// chmod, exactly as the single-level path did before the walk existed.
#[cfg(unix)]
fn publish_into_leaf(
    pinned: pin::Pinned<std::os::fd::OwnedFd>,
    created: bool,
    dir: &Path,
    key_path: &Path,
    file_name: &std::ffi::OsStr,
    bytes: &[u8],
) -> Result<()> {
    let handle = if created {
        KeyDirHandle::from_pinned_fd(pinned, dir)
    } else {
        // Lost the mkdir race: use the winner without chmodding it.
        KeyDirHandle::from_existing_dir(std::fs::File::from(pinned.into_inner()), dir, key_path)?
    };

    write_key_atomically(&handle, file_name, bytes)
        .with_context(|| format!("failed to write identity key to {}", key_path.display()))?;
    Ok(())
}

/// Write the key to a scratch file in the same directory, then publish it to
/// `key_path` in one atomic step, so no reader ever sees a partial key and a
/// crash mid-write cannot leave a truncated file at the final path.
///
/// The publish is `link(2)`, not `rename(2)`. Rename would replace an existing
/// key silently, throwing away the `O_EXCL` protection the previous code got
/// from `create_new`; guarding it with an existence check first only narrows
/// the window rather than closing it, since a concurrent start can land its own
/// key between the check and the rename. `hard_link` is atomic and fails with
/// `AlreadyExists` if anything already occupies the path (a real file, or a
/// symlink, which it does not follow), so the two properties hold together
/// without a check-then-act gap. On success the scratch name is unlinked and
/// the directory is fsynced again so the leftover name is not the durable
/// state. On failure the scratch is removed too, and a cleanup error is
/// reported alongside the write error.
fn write_key_atomically(
    dir: &KeyDirHandle,
    key_name: &std::ffi::OsStr,
    bytes: &[u8],
) -> std::io::Result<()> {
    let (scratch_name, mut file) = create_scratch_key_file(dir)?;
    let result = fill_and_publish(&mut file, bytes, dir, &scratch_name, key_name);
    drop(file);
    match result {
        Ok(()) => {
            dir.remove_child(&scratch_name).map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!(
                        "published the key but failed to remove the scratch name {}: {e}",
                        Path::new(&scratch_name).display()
                    ),
                )
            })?;
            dir.sync().map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!(
                        "failed to sync key directory {} after removing the scratch name; the \
                         identity may not survive a crash until the next successful start: {e}",
                        dir.path.display()
                    ),
                )
            })?;
            Ok(())
        }
        Err(e) => {
            if let Err(clean) = dir.remove_child(&scratch_name) {
                return Err(std::io::Error::new(
                    e.kind(),
                    format!("{e}; also failed to remove the scratch this process created: {clean}"),
                ));
            }
            Err(e)
        }
    }
}

/// Open a uniquely named scratch file in `dir` with owner-only permissions
/// applied at creation time. The name carries the pid so concurrent node starts
/// do not pick the same one, and `O_EXCL` plus the retry makes a collision
/// with a leftover or a sibling thread impossible rather than merely unlikely.
fn create_scratch_key_file(
    dir: &KeyDirHandle,
) -> std::io::Result<(std::ffi::OsString, pin::Pinned<std::fs::File>)> {
    let pid = std::process::id();
    for attempt in 0..64u32 {
        let scratch_name = std::ffi::OsString::from(format!(".p2p.key.{pid}.{attempt}.tmp"));
        match dir.create_scratch(&scratch_name) {
            Ok(file) => return Ok((scratch_name, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!("no free scratch key file name in {}", dir.path.display()),
    ))
}

fn fill_and_publish(
    file: &mut pin::Pinned<std::fs::File>,
    bytes: &[u8],
    dir: &KeyDirHandle,
    scratch_name: &std::ffi::OsStr,
    key_name: &std::ffi::OsStr,
) -> std::io::Result<()> {
    use std::io::Write;

    #[cfg(test)]
    if FAIL_KEY_WRITE.with(|f| f.get()) {
        file.get_mut().write_all(&bytes[..bytes.len() / 2])?;
        return Err(std::io::Error::other("injected key-write failure"));
    }

    file.get_mut().write_all(bytes)?;
    // The bytes must be durable before the name that points at them appears,
    // otherwise a crash can leave the entry pointing at an empty file.
    file.get_mut().sync_all()?;
    dir.publish(scratch_name, key_name)?;

    // The new directory entry must reach disk too, and the sync goes to the
    // same descriptor the entry was created through — not to a fresh
    // path-resolved open of the directory, which could by now be something
    // else entirely.
    dir.sync().map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "failed to sync key directory {} after publishing the key; the identity may not \
                 survive a crash until the next successful start: {e}",
                dir.path.display()
            ),
        )
    })?;
    Ok(())
}

#[cfg(test)]
thread_local! {
    /// Test-only fault injection for the key write. Thread-local so an armed
    /// test cannot disturb the others running beside it.
    pub(crate) static FAIL_KEY_WRITE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };

    /// Test-only fault injection for scratch unlink after publish.
    pub(crate) static FAIL_SCRATCH_UNLINK: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };

    /// How many times this test thread fsync'd a key directory.
    static SYNC_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };

    /// Test-only override for the process effective uid.
    static EUID_OVERRIDE: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

/// The effective uid the ownership checks compare against.
#[cfg(unix)]
fn effective_uid() -> u32 {
    #[cfg(test)]
    if let Some(uid) = EUID_OVERRIDE.with(|c| c.get()) {
        return uid;
    }
    // SAFETY: `geteuid` only reads the calling process's effective uid.
    unsafe { libc::geteuid() }
}

fn read_bounded_key_bytes<R: std::io::Read>(
    reader: &mut R,
    key_path: &Path,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(Vec::new());
    let mut chunk = [0u8; 256];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() + n > MAX_P2P_KEY_BYTES {
                    anyhow::bail!(
                        "p2p key at {} exceeds the maximum accepted size of {} bytes",
                        key_path.display(),
                        MAX_P2P_KEY_BYTES
                    );
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                anyhow::bail!(
                    "p2p key at {} is not a readable regular file (open would block)",
                    key_path.display()
                );
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("failed to read p2p key from {}", key_path.display())
                });
            }
        }
    }
    Ok(buf)
}

/// Open the key through the verified directory handle, mapping "no key yet"
/// to `None` and everything else to an error the operator can act on.
///
/// The open itself refuses symlinks (`O_NOFOLLOW`) and cannot block on a FIFO
/// (`O_NONBLOCK`); what kind of object was actually opened is judged by
/// [`read_p2p_keypair_from`] on the descriptor it returns.
fn open_existing_key(
    dir: &KeyDirHandle,
    key_name: &std::ffi::OsStr,
    key_path: &Path,
) -> Result<Option<std::fs::File>> {
    match dir.open_key_for_read(key_name) {
        Ok(file) => Ok(Some(file)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        // An unreadable key is its own diagnosis and must not be reported as a
        // refused symlink: a key published under a mask that stripped the owner
        // bits lands here, and naming the wrong cause sends the operator after
        // a link that does not exist. The key is NOT chmodded back; a key file
        // closed on purpose is an operator decision.
        Err(e) if e.raw_os_error() == Some(libc::EACCES) => {
            Err(anyhow::Error::new(e).context(format!(
                "failed to open p2p key at {}: this node cannot read it. Run `chmod 600 {}` if \
                 the key should be readable, or delete it to generate a fresh identity.",
                key_path.display(),
                key_path.display()
            )))
        }
        Err(e) => Err(anyhow::Error::new(e).context(format!(
            "failed to open p2p key at {} (a symlink here is refused rather than followed)",
            key_path.display()
        ))),
    }
}

/// Read an existing, already-opened key file, refusing one whose type,
/// permissions, size, or contents make it untrustworthy. Never regenerates: a
/// node that silently replaces an unreadable key file would change its PeerId
/// without the operator knowing.
///
/// Every judgment is made by `fstat` on `file` itself — the object that will
/// be read — not on the pathname it was opened by. Regular-file status is an
/// explicit invariant, not an inference from "not a directory, not a symlink":
/// a FIFO or device node that survived the open (thanks to `O_NONBLOCK`) is
/// refused here before a byte of it is consumed, and the read that follows is
/// capped at [`MAX_P2P_KEY_BYTES`] so nothing that lies about being finite can
/// feed the process an unbounded stream.
fn read_p2p_keypair_from(mut file: std::fs::File, key_path: &Path) -> Result<identity::Keypair> {
    let md = file
        .metadata()
        .with_context(|| format!("failed to stat p2p key at {}", key_path.display()))?;

    if !md.is_file() {
        anyhow::bail!(
            "p2p key at {} must be a regular file; directories, FIFOs, and special files are refused",
            key_path.display()
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;

        let euid = effective_uid();
        if let Some(err) = foreign_ownership_error("key", key_path, md.uid(), euid) {
            anyhow::bail!(err);
        }

        let mode = md.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "p2p key at {} has mode {:04o}, which grants access beyond its owner; \
                 run `chmod 600 {}` or delete the file to regenerate the identity",
                key_path.display(),
                mode,
                key_path.display()
            );
        }
    }

    let bytes = read_bounded_key_bytes(&mut file, key_path)?;

    // An empty file decodes as a valid protobuf with a key type of RSA, so
    // without this the operator gets a misleading complaint about a missing
    // `rsa` cargo feature instead of being told the file is empty.
    if bytes.is_empty() {
        anyhow::bail!(
            "p2p key file {} is empty; restore it from backup, \
             or delete it to regenerate the identity",
            key_path.display()
        );
    }

    let kp = identity::Keypair::from_protobuf_encoding(&bytes)
        .with_context(|| format!("invalid p2p key in {}", key_path.display()))?;
    info!(path = %key_path.display(), "loaded existing p2p identity");
    Ok(kp)
}

/// Test-only convenience over the anchored read path: production callers hold
/// the [`KeyDirHandle`] from [`ensure_key_dir`] and go through
/// [`open_existing_key`] directly, so nothing outside the tests re-resolves
/// the pathname here.
#[cfg(test)]
fn read_p2p_keypair(key_path: &Path) -> Result<identity::Keypair> {
    let dir = KeyDirHandle::open(key_parent(key_path))
        .map_err(|e| describe_unusable_key_dir(key_parent(key_path), e))?;
    let key_name = key_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("p2p key path {} names no file", key_path.display()))?;
    let file = open_existing_key(&dir, key_name, key_path)?
        .ok_or_else(|| anyhow::anyhow!("p2p key at {} does not exist", key_path.display()))?;
    read_p2p_keypair_from(file, key_path)
}

/// Start the libp2p swarm. Returns a handle for sending commands and the
/// listening multiaddrs. Runs the event loop as a background tokio task
/// that exits cleanly when `shutdown_rx` flips to `true`.
/// `local_key` is the node's libp2p identity, loaded from the persistent key
/// file by [`load_or_create_p2p_keypair`].
// Wide, but each argument is a distinct piece of node configuration and there
// is exactly one call site; bundling them would buy nothing.
#[allow(clippy::too_many_arguments)]
pub async fn start(
    local_key: identity::Keypair,
    listen_port: u16,
    bootstrap_addrs: Vec<Multiaddr>,
    db: Arc<Db>,
    auto_sync: bool,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    keypair: Arc<Keypair>,
    require_signed: bool,
) -> Result<P2pHandle> {
    let local_peer_id = PeerId::from(local_key.public());

    info!(peer_id = %local_peer_id, "libp2p identity");

    // Per-source ingest brake, held across the whole swarm loop so budgets
    // accumulate per forwarding peer.
    let ingest_limiters = IngestLimiters::new();

    // The replay seen-set, held for the same reason and for the same lifetime:
    // a guard rebuilt per message remembers nothing and deduplicates nothing.
    let replay_guard = ReplayGuard::new();

    let (cmd_tx, mut cmd_rx) = mpsc::channel::<P2pCommand>(64);

    let handle = P2pHandle {
        tx: cmd_tx,
        local_peer_id,
    };

    let kad_store = kad::store::MemoryStore::new(local_peer_id);
    let mut kademlia = kad::Behaviour::new(local_peer_id, kad_store);
    kademlia.set_mode(Some(kad::Mode::Server));

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(10))
        .validation_mode(gossipsub::ValidationMode::Permissive)
        .message_id_fn(|msg: &gossipsub::Message| {
            let mut h = DefaultHasher::new();
            msg.data.hash(&mut h);
            gossipsub::MessageId::from(h.finish().to_string())
        })
        .build()
        .expect("gossipsub config");
    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_key.clone()),
        gossipsub_config,
    )
    .expect("gossipsub behaviour");

    let identify = identify::Behaviour::new(identify::Config::new(
        "/gitlawb/1.0.0".to_string(),
        local_key.public(),
    ));

    let behaviour = GitlawbBehaviour {
        kademlia,
        gossipsub,
        identify,
    };
    // DNS wraps QUIC so multiaddrs like /dns6/<app>.internal/udp/…/quic-v1
    // resolve at dial time. On Fly, peer nodes must dial each other over the
    // private 6PN network via <app>.internal hostnames — dialing through the
    // public anycast edge breaks the handshake (the proxy closes the
    // connection mid-stream).
    let quic = libp2p_quic::tokio::Transport::new(libp2p_quic::Config::new(&local_key))
        .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)));
    let transport = libp2p_dns::tokio::Transport::system(quic)?.boxed();
    let mut swarm = Swarm::new(
        transport,
        behaviour,
        local_peer_id,
        libp2p_swarm::Config::with_tokio_executor(),
    );

    // Subscribe to the ref-updates topic
    let topic = gossipsub::IdentTopic::new(REF_UPDATES_TOPIC);
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

    // Listen on both IPv4 (local/mDNS + any IPv4 dials) and IPv6 (required
    // for Fly's 6PN inter-app network — <app>.internal DNS only returns AAAA
    // records, so peers dial us via IPv6 and need a matching IPv6 socket).
    let v4: Multiaddr = format!("/ip4/0.0.0.0/udp/{listen_port}/quic-v1").parse()?;
    if let Err(e) = swarm.listen_on(v4) {
        warn!(err = %e, "failed to listen on IPv4");
    }
    let v6: Multiaddr = format!("/ip6/::/udp/{listen_port}/quic-v1").parse()?;
    if let Err(e) = swarm.listen_on(v6) {
        warn!(err = %e, "failed to listen on IPv6");
    }

    // Bootstrap Kademlia with known peers
    for addr in bootstrap_addrs {
        // Dial the address; Kademlia will learn the PeerId via Identify
        if let Err(e) = swarm.dial(addr.clone()) {
            warn!(addr = %addr, err = %e, "failed to dial bootstrap peer");
        }
    }

    // Track in-flight GetRecord queries → reply channels
    let mut pending_get_did: HashMap<kad::QueryId, oneshot::Sender<Option<DidRecord>>> =
        HashMap::new();

    // Start the event loop as a background task
    tokio::spawn(async move {
        let mut shutdown_rx = shutdown_rx;
        // The ingest limiters are owned by this task, so this loop is the only
        // thing that can sweep them. Delay on a missed tick because a sweep the
        // loop was too busy to run has no value in being run twice back to back.
        let mut ingest_sweep = tokio::time::interval(GOSSIP_INGEST_SWEEP_INTERVAL);
        ingest_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                // Reclaim ingest-limiter keys whose window has elapsed. Kept in
                // the select! rather than a second task so the limiters stay
                // task-local and need no Arc or lock shared with the rest of the
                // node. `tokio::time::interval` fires its first tick
                // immediately, which sweeps an empty map and is a no-op.
                _ = ingest_sweep.tick() => {
                    run_ingest_sweep(&ingest_limiters, &replay_guard, ingest_now()).await;
                }
                // Graceful shutdown: exit the swarm loop when the
                // process-wide signal flips. This drops the Swarm
                // which closes all libp2p connections cleanly.
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("p2p swarm: shutdown signal received, exiting event loop");
                        break;
                    }
                }
                // Handle swarm events
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            info!(addr = %address, "p2p listening");
                        }
                        SwarmEvent::Behaviour(GitlawbBehaviourEvent::Gossipsub(
                            gossipsub::Event::Message { propagation_source, message, .. }
                        )) => {
                            let outcome = ingest_ref_update(
                                &db,
                                &ingest_limiters,
                                &replay_guard,
                                require_signed,
                                auto_sync,
                                &message.data,
                                &propagation_source,
                            ).await;
                            // Counted before the log match, once, for every
                            // variant including `Accepted`. The logs describe an
                            // individual drop; the counter is what an alert can
                            // read, and without an accepted count the shed
                            // reasons have no denominator to be a rate of.
                            crate::metrics::record_gossip_ingest(outcome.metric_label());
                            match outcome {
                                IngestOutcome::Accepted => {}
                                IngestOutcome::UnsignedAdmitted => {}
                                IngestOutcome::WriteFailed(reason) => warn!(
                                    from = %propagation_source,
                                    reason = %reason,
                                    "admitted gossip ref-update but a write failed"
                                ),
                                IngestOutcome::Rejected(reason) => warn!(
                                    from = %propagation_source,
                                    reason = %reason,
                                    "dropped gossip ref-update"
                                ),
                                // Both arms are warn, not debug: a dropped
                                // ref-update is a ref this node will not
                                // federate and the publisher gets no
                                // back-pressure signal, so the budget and the
                                // window are named here to make a silent
                                // federation miss a diagnosable one.
                                IngestOutcome::SourceRateLimited => warn!(
                                    from = %propagation_source,
                                    limit = GOSSIP_SOURCE_MAX_EVENTS,
                                    window_secs = GOSSIP_INGEST_WINDOW.as_secs(),
                                    "dropped gossip ref-update: forwarding peer over the pre-parse ingest budget"
                                ),
                                IngestOutcome::AuthorRateLimited(did) => warn!(
                                    from = %propagation_source,
                                    did = %did,
                                    limit = GOSSIP_AUTHOR_MAX_EVENTS,
                                    window_secs = GOSSIP_INGEST_WINDOW.as_secs(),
                                    "dropped gossip ref-update: authenticated peer over its write budget"
                                ),
                                IngestOutcome::UnsignedSourceRateLimited(source) => warn!(
                                    from = %source,
                                    limit = GOSSIP_UNSIGNED_SOURCE_MAX_EVENTS,
                                    window_secs = GOSSIP_INGEST_WINDOW.as_secs(),
                                    "dropped gossip ref-update: forwarding peer over its unsigned-event budget"
                                ),
                                // Both name the forwarder and nothing else. A
                                // replayed event carries a signature that
                                // proves who AUTHORED it, which is exactly the
                                // party being impersonated, so logging that DID
                                // as the source of the problem would point an
                                // operator at the victim. The forwarder is the
                                // only identity that says anything about where
                                // the copy came from.
                                IngestOutcome::Replayed => warn!(
                                    from = %propagation_source,
                                    window_secs = GOSSIP_REF_UPDATE_FRESHNESS_WINDOW.as_secs(),
                                    "dropped gossip ref-update: already admitted this exact signed event"
                                ),
                                IngestOutcome::StaleTimestamp(reason) => warn!(
                                    from = %propagation_source,
                                    reason = %reason,
                                    window_secs = GOSSIP_REF_UPDATE_FRESHNESS_WINDOW.as_secs(),
                                    skew_secs = GOSSIP_REF_UPDATE_FUTURE_SKEW.as_secs(),
                                    "dropped gossip ref-update: timestamp outside the freshness window"
                                ),
                            }
                        }
                        // ── Kademlia results ──────────────────────────
                        SwarmEvent::Behaviour(GitlawbBehaviourEvent::Kademlia(
                            kad::Event::OutboundQueryProgressed { id, result, .. }
                        )) => {
                            match result {
                                kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(pr))) => {
                                    if let Some(reply) = pending_get_did.remove(&id) {
                                        let record = serde_json::from_slice::<DidRecord>(
                                            &pr.record.value
                                        ).ok();
                                        let _ = reply.send(record);
                                    }
                                }
                                kad::QueryResult::GetRecord(Err(e)) => {
                                    debug!(err = ?e, "kademlia get_record failed");
                                    if let Some(reply) = pending_get_did.remove(&id) {
                                        let _ = reply.send(None);
                                    }
                                }
                                kad::QueryResult::PutRecord(Ok(ok)) => {
                                    debug!(key = ?ok.key, "kademlia put_record ok");
                                }
                                kad::QueryResult::PutRecord(Err(e)) => {
                                    warn!(err = ?e, "kademlia put_record failed");
                                }
                                _ => {}
                            }
                        }

                        SwarmEvent::Behaviour(GitlawbBehaviourEvent::Identify(
                            identify::Event::Received { peer_id, info, .. }
                        )) => {
                            debug!(peer = %peer_id, "identify received");
                            for addr in info.listen_addrs {
                                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                            }
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            debug!(peer = %peer_id, "connection established");
                        }
                        SwarmEvent::ConnectionClosed { peer_id, .. } => {
                            debug!(peer = %peer_id, "connection closed");
                        }
                        _ => {}
                    }
                }
                // Handle commands from the rest of the node
                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        P2pCommand::PublishRefUpdate(event) => {
                            match ref_update_publish_args(&keypair, &event) {
                                Ok((topic, bytes)) => {
                                    match swarm.behaviour_mut().gossipsub.publish(topic, bytes) {
                                        Ok(id) => info!(msg_id = %id, repo = %event.repo, "published ref-update"),
                                        Err(e) => warn!(err = %e, "failed to publish ref-update"),
                                    }
                                }
                                // Skip the publish rather than emit something a
                                // verifying peer would drop anyway.
                                Err(e) => warn!(err = %e, "failed to sign ref-update; not publishing"),
                            }
                        }
                        P2pCommand::AddKnownPeer { peer_id, addr } => {
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                        }
                        P2pCommand::Dial(addr) => {
                            let _ = swarm.dial(addr);
                        }

                        P2pCommand::PutDid(record) => {
                            if let Ok(bytes) = serde_json::to_vec(&record) {
                                let kad_record = kad::Record {
                                    key: did_to_kad_key(&record.did),
                                    value: bytes,
                                    publisher: None,
                                    expires: None,
                                };
                                match swarm.behaviour_mut().kademlia
                                    .put_record(kad_record, kad::Quorum::One)
                                {
                                    Ok(qid) => debug!(query = ?qid, did = %record.did, "DID record put queued"),
                                    Err(e) => warn!(err = ?e, "kademlia put_record error"),
                                }
                            }
                        }

                        P2pCommand::GetDid { did, reply } => {
                            let key = did_to_kad_key(&did);
                            let query_id = swarm.behaviour_mut().kademlia.get_record(key);
                            pending_get_did.insert(query_id, reply);
                        }
                        P2pCommand::GetStatus { reply } => {
                            let topic_hash = gossipsub::IdentTopic::new(REF_UPDATES_TOPIC).hash();
                            let status = SwarmStatus {
                                connected_peers: swarm.connected_peers().count(),
                                gossipsub_mesh_peers: swarm.behaviour().gossipsub.mesh_peers(&topic_hash).count(),
                                gossipsub_all_peers: swarm.behaviour().gossipsub.all_peers().count(),
                                listen_addrs: swarm.listeners().map(|a| a.to_string()).collect(),
                            };
                            let _ = reply.send(status);
                        }
                    }
                }
            }
        }
    });

    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_mode_replace_authority_is_the_write_bits() {
        assert!(!dir_mode_allows_untrusted_replace(0o755));
        assert!(!dir_mode_allows_untrusted_replace(0o711));
        assert!(!dir_mode_allows_untrusted_replace(0o111));
        assert!(dir_mode_allows_untrusted_replace(0o775));
        assert!(dir_mode_allows_untrusted_replace(0o777));
        assert!(dir_mode_allows_untrusted_replace(0o722));
    }

    #[test]
    fn p2p_identity_not_derivable_from_did_alone() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();

        let kp_a = load_or_create_p2p_keypair(&dir_a.path().join("p2p.key")).unwrap();
        let kp_b = load_or_create_p2p_keypair(&dir_b.path().join("p2p.key")).unwrap();

        assert_ne!(
            PeerId::from(kp_a.public()),
            PeerId::from(kp_b.public()),
            "two independent key files must yield different PeerIds"
        );
    }

    #[test]
    fn p2p_identity_stable_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p2p.key");

        let first = load_or_create_p2p_keypair(&path).unwrap();
        let second = load_or_create_p2p_keypair(&path).unwrap();

        assert_eq!(
            PeerId::from(first.public()),
            PeerId::from(second.public()),
            "the same key file must yield the same PeerId"
        );
    }

    /// A tempdir base whose mode is 0700, for tests that place the key
    /// DIRECTORY beneath it.
    ///
    /// `tempfile::tempdir()` creates the base at `0777 & !umask` (0775 under
    /// the suite's umask 0002), and the descriptor-anchored ancestor walk
    /// refuses any group-writable ancestor, so a key tree built under a plain
    /// tempdir base would be refused for the base's mode rather than for
    /// whatever the test is actually exercising. Chmodding the base to 0700
    /// keeps the ancestor contract intact while giving the test a safe parent.
    #[cfg(unix)]
    fn key_base_0700() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    /// Non-unix builds have no ancestor walk, so the plain tempdir is a safe
    /// base already.
    #[cfg(not(unix))]
    fn key_base_0700() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    // ---- Permission probe, run in a child process -------------------------
    //
    // The probe has to create the key under a zeroed umask, otherwise a
    // restrictive ambient umask masks the bits down to 0600 by itself and the
    // assertion passes whether or not the code pins the mode. That zeroing is
    // the problem: `umask` is process-global and cargo runs these tests on
    // threads, so any test creating a file in that window inherits 000. Measured
    // before this change, an unrelated concurrent test's file was created 0666.
    //
    // So the probe runs in a dedicated child process, where the zeroed umask
    // cannot reach a sibling and dies with the child. The parent test below is
    // an ordinary `#[test]` that runs concurrently with everything else.
    //
    // Two halves, and the split is worth naming: the child's assertions are the
    // committed deterministic guard, and the concurrency leak itself was proven
    // out of band by a throwaway probe rather than by a committed test. A race
    // on process-global state has no reliable committed red-green.

    /// Printed by the permission fixture only after its assertions have run,
    /// and required by the parent. See the parent test for why "1 passed" is
    /// not sufficient on its own.
    #[cfg(unix)]
    const FIXTURE_SENTINEL: &str = "p2p-key-perms: asserted";

    /// Re-invoke this test binary to run one `#[ignore]`d fixture test.
    fn fixture_command(fixture_test: &str) -> std::process::Command {
        let mut cmd = std::process::Command::new(std::env::current_exe().expect("current_exe"));
        cmd.args([fixture_test, "--exact", "--ignored", "--nocapture"]);
        cmd
    }

    #[cfg(unix)]
    fn fixture_command_with_env(fixture_test: &str, fixture_name: &str) -> std::process::Command {
        let mut cmd = fixture_command(fixture_test);
        cmd.env("GITLAWB_TEST_FIXTURE", fixture_name);
        cmd
    }

    /// Fixture: refuse key paths that name no directory inside an isolated cwd.
    #[test]
    #[ignore = "self-exec fixture: only runs under GITLAWB_TEST_FIXTURE=p2p-key-backstop"]
    fn fixture_p2p_key_backstop_refuses_no_directory() {
        if std::env::var("GITLAWB_TEST_FIXTURE").ok().as_deref() != Some("p2p-key-backstop") {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        std::env::set_current_dir(dir.path()).expect("chdir into isolated tempdir");

        for path in [
            "p2p.key",
            "./p2p.key",
            "a/../p2p.key",
            "./keys/../p2p.key",
            "../p2p.key",
        ] {
            let result = load_or_create_p2p_keypair(Path::new(path));
            let leaked = Path::new(path).exists();
            let err = result.expect_err(&format!("{path:?} must be refused by the backstop"));
            let msg = format!("{err:#}");
            assert!(
                msg.contains("must include a directory")
                    || msg.contains("names no directory")
                    || msg.contains("must name a key file"),
                "{path:?} must be refused before touching the filesystem, got: {msg}"
            );
            assert!(!leaked, "{path:?} must not have been created");
        }

        // Beyond the probed names themselves: rejection must have caused no
        // filesystem mutation at all, scratch files and directories included.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        assert!(
            leftovers.is_empty(),
            "rejected paths must leave the working directory untouched, found: {leftovers:?}"
        );

        println!("p2p-key-backstop: asserted");
    }

    /// The backstop inside `load_or_create_p2p_keypair`, exercised in a child
    /// process so cwd is not mutated for sibling tests.
    #[cfg(unix)]
    #[test]
    fn p2p_key_path_naming_no_directory_is_refused_without_the_config_gate() {
        let dir = tempfile::tempdir().unwrap();
        let sentinel = dir.path().join("sentinel");
        std::fs::write(&sentinel, b"keep").unwrap();

        let output = fixture_command_with_env(
            "p2p::tests::fixture_p2p_key_backstop_refuses_no_directory",
            "p2p-key-backstop",
        )
        .output()
        .expect("spawn the backstop fixture");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "the backstop fixture must pass in its child process\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
        );
        assert!(
            stdout.contains("1 passed"),
            "the fixture filter must select exactly one test\n--- stdout ---\n{stdout}"
        );
        assert!(
            stdout.contains("p2p-key-backstop: asserted"),
            "the fixture must print its sentinel after asserting\n--- stdout ---\n{stdout}"
        );

        assert_eq!(
            std::fs::read(&sentinel).unwrap(),
            b"keep",
            "the parent process cwd must stay untouched"
        );
    }

    /// Fixture: create the key under a zeroed umask and assert the modes the
    /// code is supposed to pin. Double-gated so it is inert unless the parent
    /// invoked it: `#[ignore]` keeps it out of a normal run, and the env check
    /// keeps it inert even under a bare `--ignored` sweep, which would otherwise
    /// zero the umask inside the shared test process.
    #[cfg(unix)]
    #[test]
    #[ignore = "self-exec fixture: only runs under GITLAWB_TEST_FIXTURE=p2p-key-perms"]
    fn fixture_p2p_key_perms_under_zero_umask() {
        use std::os::unix::fs::PermissionsExt;

        if std::env::var("GITLAWB_TEST_FIXTURE").ok().as_deref() != Some("p2p-key-perms") {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys").join("p2p.key");

        // The tempdir base is itself an ancestor of the key directory under
        // umask 0000, and the ancestor walk refuses any group/world-writable
        // component; pin it to 0700 so the fixture measures the CREATED
        // directory/key modes rather than the tempdir's own mode.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        // SAFETY: `umask` only reads and replaces the process-wide value, and
        // this process exists solely for this probe. No restore: the value dies
        // with the child.
        unsafe { libc::umask(0o000) };
        load_or_create_p2p_keypair(&path).expect("key creation under a permissive umask");

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "key file must be owner-read/write only"
        );

        // The directory was created inside the same permissive-umask window, so
        // this proves the directory mode is pinned by the code and not by the
        // ambient umask. Write permission on the directory alone is enough to
        // unlink or replace the 0600 key inside it.
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700, "key directory must be owner-only");

        // Proof-of-work sentinel, printed only after both assertions have run.
        // "1 passed" alone does not prove this fixture asserted anything: the
        // early return above is itself a passing test, so an env-var mismatch
        // (a renamed variable, a changed value) would report 1 passed while
        // checking nothing. The parent requires this line.
        println!("{FIXTURE_SENTINEL}");
    }

    /// Fixture: create a MULTI-LEVEL missing ancestor chain under a zeroed
    /// umask and assert every created ancestor lands 0700, not 0777.
    ///
    /// This is the r4-F2 shape: `create_dir_all` creates missing intermediates
    /// at `0777 & !umask`, so under umask 0000 the intermediate directories
    /// would land world-writable. Only the nominated key directory is pinned
    /// today. The fix must make the ancestor walk create every missing
    /// component at 0700 and verify it.
    #[cfg(unix)]
    #[test]
    #[ignore = "self-exec fixture: only runs under GITLAWB_TEST_FIXTURE=p2p-key-multilevel"]
    fn fixture_p2p_key_multilevel_ancestors_under_zero_umask() {
        use std::os::unix::fs::PermissionsExt;

        if std::env::var("GITLAWB_TEST_FIXTURE").ok().as_deref() != Some("p2p-key-multilevel") {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a").join("b").join("keys").join("p2p.key");

        // Pin the tempdir base to 0700 (it is the anchor's child and would
        // otherwise land 0775 under umask 0000, which the ancestor walk
        // correctly refuses); the fixture measures the CREATED `a`/`b`
        // ancestors, not the tempdir's own mode.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        // SAFETY: `umask` only reads and replaces the process-wide value, and
        // this process exists solely for this probe. No restore: the value dies
        // with the child.
        unsafe { libc::umask(0o000) };
        load_or_create_p2p_keypair(&path).expect("key creation under a permissive umask");

        for ancestor in [dir.path().join("a"), dir.path().join("a").join("b")] {
            let mode = std::fs::metadata(&ancestor).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o700,
                "created ancestor {} must be owner-only, not world-writable under umask 0000",
                ancestor.display()
            );
        }

        let keys_mode = std::fs::metadata(dir.path().join("a").join("b").join("keys"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(keys_mode & 0o777, 0o700, "key directory must be owner-only");

        let key_mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            key_mode & 0o777,
            0o600,
            "key file must be owner-read/write only"
        );

        println!("p2p-key-multilevel: asserted");
    }

    #[cfg(unix)]
    #[test]
    fn p2p_multilevel_missing_ancestors_are_created_0700_under_zero_umask() {
        let output = fixture_command_with_env(
            "p2p::tests::fixture_p2p_key_multilevel_ancestors_under_zero_umask",
            "p2p-key-multilevel",
        )
        .output()
        .expect("spawn the multilevel fixture");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            output.status.success(),
            "the multilevel fixture must pass in its child process\n\
             --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
        );
        assert!(
            stdout.contains("1 passed"),
            "the fixture filter must select exactly one test that passed\n--- stdout ---\n{stdout}"
        );
        assert!(
            stdout.contains("p2p-key-multilevel: asserted"),
            "the fixture must print its sentinel after asserting\n--- stdout ---\n{stdout}"
        );
    }

    // ---- U1: umask x layout x phase lifecycle matrix ----------------------
    //
    // The committed umask fixtures above both use `umask(0o000)`, the
    // PERMISSIVE direction, which proves only that an ambient mask cannot
    // WIDEN a requested mode. Neither can go red on the round-5 defect, which
    // needs a mask that REMOVES owner access: under `umask 0777` a requested
    // 0700 lands 0000, the no-follow reopen fails EACCES before the repairing
    // fchmod is reached, and a requested 0600 key is published unreadable, so
    // the boot that created it succeeds on its already-open descriptor and the
    // NEXT boot silently loses p2p.
    //
    // `umask` is process-global, so the matrix cannot live in the shared test
    // process; every row is a child, double-gated like the fixtures above.

    /// Requested modes, named once so the failure text can print achieved
    /// against requested rather than a bare boolean.
    #[cfg(unix)]
    const WANT_DIR_MODE: u32 = 0o700;
    #[cfg(unix)]
    const WANT_KEY_MODE: u32 = 0o600;
    /// Mode the fixture builds PRE-EXISTING ancestors at. Not group-writable,
    /// so the ancestor predicate accepts it, and R6 says it must survive.
    #[cfg(unix)]
    const PREEXISTING_ANCESTOR_MODE: u32 = 0o755;

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::symlink_metadata(path)
            .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
            .permissions()
            .mode()
            & 0o7777
    }

    /// Every object on the key path with its achieved mode against what the
    /// contract requested. This is what makes a RED attributable to the mode
    /// rather than to "something failed" (INV-21(g)); red-check matches on it.
    #[cfg(unix)]
    fn describe_key_tree(base: &Path, key: &Path) -> String {
        let mut out = String::new();
        let mut cur = key.parent();
        let mut dirs = Vec::new();
        while let Some(d) = cur {
            dirs.push(d.to_path_buf());
            if d == base {
                break;
            }
            cur = d.parent();
        }
        dirs.reverse();
        for d in dirs {
            match std::fs::symlink_metadata(&d) {
                Ok(_) => out.push_str(&format!(
                    "  dir  {} achieved mode {:04o}, requested {:04o}\n",
                    d.display(),
                    mode_of(&d),
                    WANT_DIR_MODE
                )),
                Err(e) => out.push_str(&format!("  dir  {} absent ({e})\n", d.display())),
            }
        }
        match std::fs::symlink_metadata(key) {
            Ok(_) => out.push_str(&format!(
                "  key  {} achieved mode {:04o}, requested {:04o}\n",
                key.display(),
                mode_of(key),
                WANT_KEY_MODE
            )),
            Err(e) => out.push_str(&format!("  key  {} absent ({e})\n", key.display())),
        }
        out
    }

    /// Fail with the achieved-vs-requested tree rather than the bare error, so
    /// the reason a row went red is in the output.
    #[cfg(unix)]
    fn expect_boot(base: &Path, key: &Path, phase: &str) -> identity::Keypair {
        match load_or_create_p2p_keypair(key) {
            Ok(kp) => kp,
            // `{e:#}`, not `{e}`: the mode refusal is raised deep in the pin
            // helper and every layer above it adds context, so the default
            // format shows only "failed to write p2p key" and hides the
            // achieved-versus-requested text that says WHY. A failure whose
            // reason is not in the output cannot be attributed to the mode.
            Err(e) => panic!(
                "{phase} must boot, got: {e:#}\nkey storage at failure:\n{}",
                describe_key_tree(base, key)
            ),
        }
    }

    #[cfg(unix)]
    fn assert_contract_modes(base: &Path, key: &Path, layout: &str) {
        let keys_dir = key.parent().unwrap();
        let created_dirs: Vec<std::path::PathBuf> = match layout {
            // `a` and `b` were created by the node, `keys` too.
            "all-missing" => vec![
                base.join("a"),
                base.join("a").join("b"),
                keys_dir.to_path_buf(),
            ],
            // `a` and `b` pre-existed; only `keys` was created.
            "ancestors-present" => vec![keys_dir.to_path_buf()],
            // nothing was created.
            "leaf-present" => vec![],
            other => panic!("unknown layout {other}"),
        };
        for d in created_dirs {
            assert_eq!(
                mode_of(&d),
                WANT_DIR_MODE,
                "created directory {} achieved mode {:04o}, requested {:04o}\n{}",
                d.display(),
                mode_of(&d),
                WANT_DIR_MODE,
                describe_key_tree(base, key)
            );
        }
        if layout != "all-missing" {
            for d in [base.join("a"), base.join("a").join("b")] {
                assert_eq!(
                    mode_of(&d),
                    PREEXISTING_ANCESTOR_MODE,
                    "pre-existing ancestor {} must keep its mode (R6): achieved {:04o}, \
                     expected {:04o}",
                    d.display(),
                    mode_of(&d),
                    PREEXISTING_ANCESTOR_MODE
                );
            }
        }
        assert_eq!(
            mode_of(key),
            WANT_KEY_MODE,
            "key {} achieved mode {:04o}, requested {:04o}\n{}",
            key.display(),
            mode_of(key),
            WANT_KEY_MODE,
            describe_key_tree(base, key)
        );
        let entries: Vec<String> = std::fs::read_dir(keys_dir)
            .expect("read key directory")
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            entries,
            vec![key.file_name().unwrap().to_string_lossy().into_owned()],
            "the key directory must hold only the published key, no scratch residue: {entries:?}"
        );
    }

    /// Build the pre-existing part of the layout. Runs AFTER the umask is set,
    /// with explicit chmods, so a pre-existing directory has the mode the row
    /// names regardless of the mask.
    #[cfg(unix)]
    fn build_layout(base: &Path, layout: &str) {
        use std::os::unix::fs::PermissionsExt;
        let ab = base.join("a").join("b");
        match layout {
            "all-missing" => {}
            "ancestors-present" | "leaf-present" => {
                // One level at a time, chmodding each before descending.
                // `create_dir_all` would build every level under the row's
                // umask first, so under 0777 the outermost lands 0000 and the
                // next `mkdir` inside it fails: the fixture that proves umask
                // independence has to be umask-independent itself.
                for d in [base.join("a"), ab.clone()] {
                    std::fs::create_dir(&d).expect("create pre-existing ancestor");
                    std::fs::set_permissions(
                        &d,
                        std::fs::Permissions::from_mode(PREEXISTING_ANCESTOR_MODE),
                    )
                    .expect("chmod pre-existing ancestor");
                }
                if layout == "leaf-present" {
                    let keys = ab.join("keys");
                    std::fs::create_dir(&keys).expect("create pre-existing leaf");
                    std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700))
                        .expect("chmod pre-existing leaf");
                }
            }
            other => panic!("unknown layout {other}"),
        }
    }

    /// Fixture: one (umask, layout, phase) row of the lifecycle matrix.
    ///
    /// Double-gated exactly like the fixtures above: `#[ignore]` keeps it out
    /// of a normal run and the env check keeps it inert under a bare
    /// `--ignored` sweep, which would otherwise set a process-global umask
    /// inside the shared test process.
    #[cfg(unix)]
    #[test]
    #[ignore = "self-exec fixture: only runs under GITLAWB_TEST_FIXTURE=p2p-key-umask"]
    fn fixture_p2p_key_umask_lifecycle() {
        if std::env::var("GITLAWB_TEST_FIXTURE").ok().as_deref() != Some("p2p-key-umask") {
            return;
        }

        let base = std::path::PathBuf::from(
            std::env::var("GITLAWB_TEST_BASE").expect("GITLAWB_TEST_BASE"),
        );
        let umask_str = std::env::var("GITLAWB_TEST_UMASK").expect("GITLAWB_TEST_UMASK");
        let umask_val = u32::from_str_radix(&umask_str, 8).expect("octal umask");
        let layout = std::env::var("GITLAWB_TEST_LAYOUT").expect("GITLAWB_TEST_LAYOUT");
        let phase = std::env::var("GITLAWB_TEST_PHASE").expect("GITLAWB_TEST_PHASE");

        // The EACCES rows are meaningless as root, which bypasses mode checks.
        // Fail loudly rather than skipping: a silent skip here would make the
        // whole matrix vacuous in a root container.
        // SAFETY: `geteuid` only reads the calling process's effective uid.
        assert_ne!(
            unsafe { libc::geteuid() },
            0,
            "the lifecycle matrix must not run as root: mode refusals do not apply to uid 0"
        );

        // SAFETY: `umask` only reads and replaces the process-wide value, and
        // this process exists solely for this row. No restore: the value dies
        // with the child.
        unsafe { libc::umask(umask_val as libc::mode_t) };

        let key = base.join("a").join("b").join("keys").join("p2p.key");

        let peer_id = match phase.as_str() {
            "create" => {
                build_layout(&base, &layout);
                let kp = expect_boot(&base, &key, "first boot");
                assert_contract_modes(&base, &key, &layout);
                PeerId::from(kp.public())
            }
            "reload" => {
                // The tree was left by a previous `create` child under this
                // same base; this process only reads it.
                assert!(
                    key.exists(),
                    "reload row requires the create row to have published a key at {}",
                    key.display()
                );
                let kp = expect_boot(&base, &key, "reload in a fresh process");
                assert_contract_modes(&base, &key, &layout);
                PeerId::from(kp.public())
            }
            "create-concurrent" => {
                build_layout(&base, &layout);
                let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
                let mut handles = Vec::new();
                for _ in 0..2 {
                    let b = std::sync::Arc::clone(&barrier);
                    let k = key.clone();
                    handles.push(std::thread::spawn(move || {
                        b.wait();
                        load_or_create_p2p_keypair(&k).map(|kp| PeerId::from(kp.public()))
                    }));
                }
                let results: Vec<Result<PeerId>> =
                    handles.into_iter().map(|h| h.join().unwrap()).collect();
                let winners: Vec<PeerId> = results
                    .iter()
                    .filter_map(|r| r.as_ref().ok())
                    .copied()
                    .collect();
                // Requiring at least one success is what keeps this row able to
                // go RED. "every Ok agrees" alone passes when zero creators
                // succeed, which is exactly the regression a widened
                // create-to-pin window would produce.
                assert!(
                    !winners.is_empty(),
                    "at least one concurrent creator must succeed; all failed:\n{:?}\n{}",
                    results
                        .iter()
                        .map(|r| r.as_ref().err().map(|e| e.to_string()))
                        .collect::<Vec<_>>(),
                    describe_key_tree(&base, &key)
                );
                assert!(
                    winners.iter().all(|p| *p == winners[0]),
                    "concurrent creators disagreed on the PeerId: {winners:?}"
                );
                assert_contract_modes(&base, &key, &layout);
                // A fresh reload after both finish must agree with the winners.
                let reloaded = PeerId::from(expect_boot(&base, &key, "post-race reload").public());
                assert_eq!(
                    reloaded, winners[0],
                    "the published key must reload to the winning PeerId"
                );
                reloaded
            }
            "create-interrupted" => {
                build_layout(&base, &layout);
                FAIL_KEY_WRITE.with(|f| f.set(true));
                let interrupted = load_or_create_p2p_keypair(&key);
                FAIL_KEY_WRITE.with(|f| f.set(false));
                assert!(
                    interrupted.is_err(),
                    "an injected write failure must not report success"
                );
                assert!(
                    !key.exists(),
                    "an interrupted publish must leave nothing at the final key path"
                );
                let keys_dir = key.parent().unwrap();
                if keys_dir.exists() {
                    let residue: Vec<String> = std::fs::read_dir(keys_dir)
                        .expect("read key directory")
                        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                        .collect();
                    assert!(
                        residue.is_empty(),
                        "an interrupted publish must leave no scratch residue: {residue:?}"
                    );
                }
                let kp = expect_boot(&base, &key, "boot after an interrupted publish");
                assert_contract_modes(&base, &key, &layout);
                PeerId::from(kp.public())
            }
            other => panic!("unknown phase {other}"),
        };

        // Printed only after every assertion for this row, and carrying the
        // PeerId so the parent can compare create against reload. "1 passed"
        // does not prove the row asserted anything: the env gate above returns
        // early, and an early return is itself a passing test.
        println!("p2p-key-umask: asserted peer_id={peer_id}");
    }

    // ---- U2: the pin and the exact-mode verify are load-bearing -----------

    /// Fixture: disable the pin and confirm the exact-mode VERIFY is what
    /// refuses, naming the achieved mode.
    ///
    /// Without this the verify could be inert: with the pin doing the work, a
    /// weakened or deleted verify would never be observed. Deleting the added
    /// term alone and watching it go red is the INV-21(i) precondition.
    #[cfg(unix)]
    #[test]
    #[ignore = "self-exec fixture: only runs under GITLAWB_TEST_FIXTURE=p2p-key-skip-pin"]
    fn fixture_p2p_key_skip_pin_is_caught_by_the_verify() {
        if std::env::var("GITLAWB_TEST_FIXTURE").ok().as_deref() != Some("p2p-key-skip-pin") {
            return;
        }
        let base = std::path::PathBuf::from(
            std::env::var("GITLAWB_TEST_BASE").expect("GITLAWB_TEST_BASE"),
        );
        let target = std::env::var("GITLAWB_TEST_TARGET").expect("GITLAWB_TEST_TARGET");
        let umask_val =
            u32::from_str_radix(&std::env::var("GITLAWB_TEST_UMASK").unwrap(), 8).unwrap();

        // SAFETY: `umask` only reads and replaces the process-wide value, and
        // this process exists solely for this probe.
        unsafe { libc::umask(umask_val as libc::mode_t) };
        pin::SKIP_MODE_PIN.with(|c| c.set(true));

        let key = base.join("keys").join("p2p.key");
        let err = load_or_create_p2p_keypair(&key)
            .expect_err("with the pin disabled the exact-mode verify must refuse");
        let text = format!("{err:#}");

        // The refusal must name the ACHIEVED mode. A generic failure would let
        // an unrelated RED (an EACCES on the reopen, say) pass for this one.
        let (want_achieved, want_requested) = match target.as_str() {
            "dir" => ("achieved mode 0500", "requested 0700"),
            "key" => ("achieved mode 0200", "requested 0600"),
            other => panic!("unknown target {other}"),
        };
        assert!(
            text.contains(want_achieved) && text.contains(want_requested),
            "the refusal must name the achieved mode against the requested one, got: {text}"
        );
        println!("p2p-key-skip-pin: asserted target={target}");
    }

    #[cfg(unix)]
    #[test]
    fn p2p_key_mode_pin_is_load_bearing() {
        use std::os::unix::fs::PermissionsExt;

        // dir: umask 0277 leaves a created directory at 0500, which is still
        // openable, so the reopen succeeds and only the verify can catch it.
        // key: umask 0477 leaves a created file at 0200.
        for (target, umask) in [("dir", "0277"), ("key", "0477")] {
            let base = tempfile::tempdir().unwrap();
            std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            if target == "key" {
                // Pre-create the key directory so the run reaches the key.
                let keys = base.path().join("keys");
                std::fs::create_dir(&keys).unwrap();
                std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            let output = fixture_command_with_env(
                "p2p::tests::fixture_p2p_key_skip_pin_is_caught_by_the_verify",
                "p2p-key-skip-pin",
            )
            .env("GITLAWB_TEST_BASE", base.path())
            .env("GITLAWB_TEST_TARGET", target)
            .env("GITLAWB_TEST_UMASK", umask)
            .output()
            .expect("spawn the skip-pin fixture");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                output.status.success(),
                "target={target}: the skip-pin fixture must pass\n\
                 --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
            );
            assert!(
                stdout.contains("1 passed"),
                "target={target}: filter must select one passing test\n{stdout}"
            );
            assert!(
                stdout.contains(&format!("p2p-key-skip-pin: asserted target={target}")),
                "target={target}: fixture must print its sentinel\n{stdout}"
            );
            // A pin/verify failure on an object this process just created must
            // not leave that object behind. The dir target mkdirat's `keys`;
            // the key target O_EXCL-creates a scratch file inside a pre-existing
            // `keys`. Either leftover turns a transient pin fault into the next
            // boot's adopted-existing path.
            if target == "dir" {
                assert!(
                    !base.path().join("keys").exists(),
                    "target=dir: a failed pin must remove the directory this process created"
                );
            } else {
                let leftovers: Vec<_> = std::fs::read_dir(base.path().join("keys"))
                    .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.file_name()).collect())
                    .unwrap_or_default();
                assert!(
                    leftovers.is_empty(),
                    "target=key: a failed pin must remove the scratch this process created, found: {leftovers:?}"
                );
            }
        }
    }

    /// A directory this process did NOT create is verified as-is and never
    /// chmodded, which is what keeps a concurrent first boot from rewriting the
    /// winner's directory.
    #[cfg(unix)]
    #[test]
    fn ancestor_race_winner_keeps_its_mode() {
        use std::os::unix::fs::PermissionsExt;

        let base = key_base_0700();
        let key = base.path().join("a").join("keys").join("p2p.key");

        // Arm the race: `a` is created by "another process" at 0750 in the
        // window between the ENOENT and our mkdirat.
        pin::RACE_CREATE_MODE.with(|c| c.set(Some(0o750)));
        load_or_create_p2p_keypair(&key).expect("a race-won ancestor at 0750 is acceptable");

        let mode = std::fs::metadata(base.path().join("a"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(
            mode, 0o750,
            "race winner must keep its mode: achieved {mode:04o}, expected 0750"
        );
    }

    /// The leaf rule in both directions: a directory that is too OPEN is
    /// tightened, one that is too CLOSED is refused rather than widened.
    #[cfg(unix)]
    #[test]
    fn key_directory_is_tightened_when_loose_and_refused_when_over_closed() {
        use std::os::unix::fs::PermissionsExt;

        // Too open: tightened to exactly 0700.
        for loose in [0o750u32, 0o755, 0o770] {
            let base = key_base_0700();
            let keys = base.path().join("keys");
            std::fs::create_dir(&keys).unwrap();
            std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(loose)).unwrap();
            load_or_create_p2p_keypair(&keys.join("p2p.key")).unwrap_or_else(|e| {
                panic!("a loose key directory ({loose:04o}) is tightened: {e}")
            });
            let after = std::fs::metadata(&keys).unwrap().permissions().mode() & 0o7777;
            assert_eq!(after, 0o700, "loose {loose:04o} must be tightened to 0700");
        }

        // Repairable: owner rwx is present, and group/world or special bits are
        // stripped to 0700. 2700 (setgid only) is the control-flow hole the
        // 0o077 predicate misses; 2750 still has to keep working.
        for repairable in [0o700u32, 0o2700, 0o1700, 0o2750] {
            let base = key_base_0700();
            let keys = base.path().join("keys");
            std::fs::create_dir(&keys).unwrap();
            std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(repairable)).unwrap();
            load_or_create_p2p_keypair(&keys.join("p2p.key")).unwrap_or_else(|e| {
                panic!("mode {repairable:04o} must boot and land at 0700, got: {e:#}")
            });
            let after = std::fs::metadata(&keys).unwrap().permissions().mode() & 0o7777;
            assert_eq!(
                after, 0o700,
                "{repairable:04o} must be left/normalized to 0700, found {after:04o}"
            );
        }

        // Too closed: refused, named, and left exactly as the operator set it.
        for closed in [0o500u32, 0o100, 0o600, 0o000] {
            let base = key_base_0700();
            let keys = base.path().join("keys");
            std::fs::create_dir(&keys).unwrap();
            std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(closed)).unwrap();
            let err = load_or_create_p2p_keypair(&keys.join("p2p.key"))
                .expect_err("an over-closed key directory must be refused, not widened");
            let text = format!("{err:#}");
            assert!(
                text.contains("chmod 700"),
                "the refusal must name the remedy, got: {text}"
            );
            let after = std::fs::metadata(&keys).unwrap().permissions().mode() & 0o7777;
            assert_eq!(
                after, closed,
                "an over-closed directory ({closed:04o}) must be left untouched, found {after:04o}"
            );
            assert!(
                !keys.join("p2p.key").exists(),
                "a refusal must not create a key"
            );
        }
    }

    /// An unreadable existing key names its own cause and its own remedy, and
    /// is never chmodded back.
    #[cfg(unix)]
    #[test]
    fn unreadable_existing_key_is_refused_with_the_chmod_600_remedy() {
        use std::os::unix::fs::PermissionsExt;

        let base = key_base_0700();
        let keys = base.path().join("keys");
        std::fs::create_dir(&keys).unwrap();
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = keys.join("p2p.key");

        let created = load_or_create_p2p_keypair(&key).expect("first boot");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o000)).unwrap();

        let err = load_or_create_p2p_keypair(&key).expect_err("an unreadable key must be refused");
        let text = format!("{err:#}");
        assert!(
            text.contains("chmod 600"),
            "the refusal must name the remedy, got: {text}"
        );
        // The old message blamed a symlink for every open failure, which sent
        // the operator after a link that does not exist.
        assert!(
            !text.contains("symlink here is refused"),
            "an unreadable key must not be reported as a refused symlink, got: {text}"
        );
        assert_eq!(
            std::fs::metadata(&key).unwrap().permissions().mode() & 0o7777,
            0o000,
            "a refusal must not chmod the key back"
        );

        // 0400 is readable and owner-only, so it still loads.
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o400)).unwrap();
        let reloaded = load_or_create_p2p_keypair(&key).expect("a 0400 key still loads");
        assert_eq!(
            PeerId::from(created.public()),
            PeerId::from(reloaded.public()),
            "the reloaded key must be the same identity"
        );
    }

    /// Parent for the lifecycle matrix: drives every row as a child process,
    /// inspects the resulting tree itself, and requires create and reload to
    /// agree on the PeerId.
    #[cfg(unix)]
    #[test]
    fn p2p_key_lifecycle_matrix_is_umask_independent() {
        use std::os::unix::fs::PermissionsExt;

        const SENTINEL: &str = "p2p-key-umask: asserted peer_id=";

        // Run one row and return the PeerId it printed.
        fn run_row(base: &Path, umask: &str, layout: &str, phase: &str) -> String {
            let output = fixture_command_with_env(
                "p2p::tests::fixture_p2p_key_umask_lifecycle",
                "p2p-key-umask",
            )
            .env("GITLAWB_TEST_BASE", base)
            .env("GITLAWB_TEST_UMASK", umask)
            .env("GITLAWB_TEST_LAYOUT", layout)
            .env("GITLAWB_TEST_PHASE", phase)
            .output()
            .expect("spawn the lifecycle fixture");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let row = format!("umask={umask} layout={layout} phase={phase}");

            assert!(
                output.status.success(),
                "row {row} must pass in its child process\n\
                 --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
            );
            // A filter matching nothing runs zero tests and exits 0.
            assert!(
                stdout.contains("1 passed"),
                "row {row}: the fixture filter must select exactly one test that passed\
                 \n--- stdout ---\n{stdout}"
            );
            // And "1 passed" does not prove it asserted: the env gate's early
            // return is itself a passing test.
            let line = stdout
                .lines()
                .find(|l| l.starts_with(SENTINEL))
                .unwrap_or_else(|| {
                    panic!(
                        "row {row}: the fixture must print its sentinel after asserting\
                     \n--- stdout ---\n{stdout}"
                    )
                });
            line[SENTINEL.len()..].trim().to_string()
        }

        // A base the PARENT owns, at 0700 so the ancestor predicate accepts it,
        // and created here (not in the child) so it survives across the create
        // and reload processes of the same row.
        fn fresh_base() -> tempfile::TempDir {
            let d = tempfile::tempdir().unwrap();
            std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            d
        }

        let umasks = ["0000", "0022", "0777"];
        let layouts = ["all-missing", "ancestors-present", "leaf-present"];

        // 9 create/reload pairs: every umask against every layout.
        for umask in umasks {
            for layout in layouts {
                let base = fresh_base();
                let created = run_row(base.path(), umask, layout, "create");
                let reloaded = run_row(base.path(), umask, layout, "reload");
                assert_eq!(
                    created, reloaded,
                    "umask={umask} layout={layout}: a fresh process must reload the same PeerId"
                );
            }
        }

        // 12 concurrent/interrupted rows on the two layouts where creation
        // actually happens.
        for umask in umasks {
            for layout in ["all-missing", "leaf-present"] {
                for phase in ["create-concurrent", "create-interrupted"] {
                    let base = fresh_base();
                    let created = run_row(base.path(), umask, layout, phase);
                    let reloaded = run_row(base.path(), umask, layout, "reload");
                    assert_eq!(
                        created, reloaded,
                        "umask={umask} layout={layout} phase={phase}: reload must agree"
                    );
                }
            }
        }

        // A tree created under an ordinary mask must reload under a hostile
        // one: reload creates nothing, so the mask must not matter there.
        let base = fresh_base();
        let created = run_row(base.path(), "0022", "all-missing", "create");
        let reloaded = run_row(base.path(), "0777", "all-missing", "reload");
        assert_eq!(
            created, reloaded,
            "a key created under umask 0022 must reload unchanged under umask 0777"
        );
    }

    /// Fixture: a relative key path under a WORLD-WRITABLE non-sticky cwd must
    /// be refused before anything is created.
    #[cfg(unix)]
    #[test]
    #[ignore = "self-exec fixture: only runs under GITLAWB_TEST_FIXTURE=p2p-key-cwd-writable"]
    fn fixture_p2p_key_relative_under_writable_cwd_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        if std::env::var("GITLAWB_TEST_FIXTURE").ok().as_deref() != Some("p2p-key-cwd-writable") {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        std::env::set_current_dir(dir.path()).expect("chdir into isolated tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();

        let err = load_or_create_p2p_keypair(Path::new("keys/p2p.key"))
            .expect_err("a relative key path under a writable cwd must be refused");
        let cwd = std::env::current_dir().expect("cwd still readable");
        assert!(
            format!("{err:#}").contains(&cwd.display().to_string()),
            "the refusal must name the working directory, got: {err:#}"
        );

        // Nothing may be created in the cwd.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        assert!(
            leftovers.is_empty(),
            "a refused cwd must not have `keys` created, found: {leftovers:?}"
        );

        println!("p2p-key-cwd-writable: asserted");
    }

    /// Fixture: a relative key path under a safe 0700 cwd boots and reloads to
    /// the same PeerId.
    #[cfg(unix)]
    #[test]
    #[ignore = "self-exec fixture: only runs under GITLAWB_TEST_FIXTURE=p2p-key-cwd-safe"]
    fn fixture_p2p_key_relative_under_safe_cwd_boots() {
        use std::os::unix::fs::PermissionsExt;

        if std::env::var("GITLAWB_TEST_FIXTURE").ok().as_deref() != Some("p2p-key-cwd-safe") {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        std::env::set_current_dir(dir.path()).expect("chdir into isolated tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        let kp = load_or_create_p2p_keypair(Path::new("keys/p2p.key"))
            .expect("a relative key path under a safe cwd must boot");
        let reloaded = load_or_create_p2p_keypair(Path::new("keys/p2p.key"))
            .expect("the same relative key path must reload");
        assert_eq!(
            PeerId::from(kp.public()),
            PeerId::from(reloaded.public()),
            "the relative-path identity must be stable across reloads"
        );

        println!("p2p-key-cwd-safe: asserted");
    }

    #[cfg(unix)]
    #[test]
    fn p2p_relative_key_path_verifies_the_cwd() {
        for (fixture, env, label) in [
            (
                "p2p::tests::fixture_p2p_key_relative_under_writable_cwd_is_refused",
                "p2p-key-cwd-writable",
                "writable-cwd refusal",
            ),
            (
                "p2p::tests::fixture_p2p_key_relative_under_safe_cwd_boots",
                "p2p-key-cwd-safe",
                "safe-cwd boot",
            ),
        ] {
            let output = fixture_command_with_env(fixture, env)
                .output()
                .expect("spawn the cwd fixture");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                output.status.success(),
                "the {label} fixture must pass in its child process\n\
                 --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
            );
            assert!(
                stdout.contains("1 passed"),
                "the {label} fixture filter must select exactly one test\n--- stdout ---\n{stdout}"
            );
            assert!(
                stdout.contains(if env == "p2p-key-cwd-writable" {
                    "p2p-key-cwd-writable: asserted"
                } else {
                    "p2p-key-cwd-safe: asserted"
                }),
                "the {label} fixture must print its sentinel\n--- stdout ---\n{stdout}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn p2p_key_file_is_0600_on_unix() {
        let output = fixture_command_with_env(
            "p2p::tests::fixture_p2p_key_perms_under_zero_umask",
            "p2p-key-perms",
        )
        .output()
        .expect("spawn the permission fixture");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            output.status.success(),
            "the permission fixture must pass in its child process\n\
             --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
        );

        // Two separate vacuity holes, and each assertion closes one the other
        // does not.
        //
        // A filter matching no test runs zero tests and still exits 0, so a
        // renamed or mistyped fixture name would look like a green permission
        // check. "1 passed" closes that.
        assert!(
            stdout.contains("1 passed"),
            "the fixture filter must select exactly one test that passed; a filter matching \
             nothing exits 0 and would make this check vacuous\n--- stdout ---\n{stdout}"
        );

        // But "1 passed" does not prove the fixture ASSERTED anything: its
        // env-var gate returns early, and an early return is itself a passing
        // test. A renamed variable or a changed value would report 1 passed
        // having checked nothing. The sentinel is printed only after both mode
        // assertions, so requiring it closes that second hole.
        assert!(
            stdout.contains(FIXTURE_SENTINEL),
            "the fixture must print {FIXTURE_SENTINEL:?} after its assertions; without it the \
             child may have returned early at its env gate and still reported 1 passed\
             \n--- stdout ---\n{stdout}"
        );
    }

    /// The predicate itself, over the whole input space in both directions.
    ///
    /// Deliberately does not call `load_or_create_p2p_keypair` on the accepted
    /// paths: that would create directories and write a real key relative to
    /// whatever directory the test process happens to run in. The rejected
    /// direction is covered above, where nothing is created by construction,
    /// and the gate and the backstop call this same function so they cannot
    /// disagree.
    #[test]
    fn names_no_usable_directory_covers_both_directions() {
        for path in [
            // No directory component.
            "p2p.key",
            "./p2p.key",
            "././p2p.key",
            "p2p.key/",
            "",
            // Resolves back to the working directory or above it.
            "a/../p2p.key",
            "./keys/../p2p.key",
            "../p2p.key",
            "keys/../../p2p.key",
            // Absolute paths are rejected on `..` too. The lexical parent is
            // what gets chmodded, so these tighten `/data` and `/` rather than
            // the directory the path appears to name.
            "/data/keys/../p2p.key",
            "/data/../p2p.key",
        ] {
            assert!(
                names_no_usable_directory(Path::new(path)),
                "{path:?} must be rejected"
            );
        }

        for path in [
            "keys/p2p.key",
            "./keys/p2p.key",
            "keys/nested/p2p.key",
            "/data/keys/p2p.key",
            "/data/p2p.key",
        ] {
            assert!(
                !names_no_usable_directory(Path::new(path)),
                "{path:?} must be accepted"
            );
        }

        {
            let path = "/p2p.key";
            assert!(
                names_no_usable_directory(Path::new(path))
                    || key_parent_is_filesystem_root(Path::new(path)),
                "{path:?} must be rejected"
            );
        }
    }

    /// The config validator is LEXICAL only, in both directions.
    ///
    /// It used to also stat the key path and its parent, which meant a
    /// symlinked or unreadable parent exited the node as invalid configuration
    /// while the very same class of fault found one layer later only logged a
    /// warning. The live cases now belong to the storage matrix; what stays
    /// here is what can be decided from the configured string alone.
    #[test]
    fn validate_p2p_key_config_decides_only_lexical_properties() {
        // Refused: properties of the value itself.
        for (raw, needle) in [
            ("/p2p.key", "filesystem root"),
            ("keys/", "must include a directory"),
            ("p2p.key", "must include a directory"),
            ("a/../p2p.key", "must include a directory"),
            ("/data/keys/.", "must name a key file"),
            ("/data/keys/./.", "must name a key file"),
            ("~/.gitlawb/.", "must name a key file"),
        ] {
            let err = validate_p2p_key_config(Path::new(raw), Some(raw))
                .expect_err("a lexically invalid key path must be refused");
            assert!(
                err.to_string().contains(needle),
                "{raw} must be refused for {needle}, got: {err}"
            );
        }

        // Accepted, and it must stay accepted no matter what is on disk: an
        // existing directory at the key position, a symlinked parent and an
        // unreadable parent are storage facts the load path judges on a
        // descriptor. Deciding them here is what made the fatal/degraded split
        // depend on which layer looked first.
        let dir = tempfile::tempdir().unwrap();
        let key_dir = dir.path().join("keys");
        std::fs::create_dir(&key_dir).unwrap();
        validate_p2p_key_config(&key_dir, Some(key_dir.to_str().unwrap()))
            .expect("an existing directory on disk is not a configuration error");

        #[cfg(unix)]
        {
            let target = dir.path().join("real");
            std::fs::create_dir(&target).unwrap();
            let link = dir.path().join("linked");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let via_link = link.join("p2p.key");
            validate_p2p_key_config(&via_link, Some(via_link.to_str().unwrap()))
                .expect("a symlinked parent is not a configuration error");
        }
    }

    #[cfg(unix)]
    #[test]
    fn p2p_key_path_in_filesystem_root_does_not_chmod_root() {
        use std::os::unix::fs::PermissionsExt;

        let before = std::fs::metadata("/").unwrap().permissions().mode() & 0o777;
        let err = load_or_create_p2p_keypair(Path::new("/p2p.key"))
            .expect_err("/p2p.key must be refused before touching /");
        let after = std::fs::metadata("/").unwrap().permissions().mode() & 0o777;
        assert_eq!(before, after, "refusing /p2p.key must not chmod /");
        assert!(
            format!("{err:#}").contains("filesystem root"),
            "error must name the root-parent hazard, got: {err:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn p2p_nested_key_path_leaves_ancestor_modes_unchanged() {
        use std::os::unix::fs::PermissionsExt;

        let base = key_base_0700();
        let ancestor_a = base.path().join("a");
        let ancestor_b = ancestor_a.join("b");
        std::fs::create_dir_all(&ancestor_b).unwrap();
        std::fs::set_permissions(&ancestor_a, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&ancestor_b, std::fs::Permissions::from_mode(0o755)).unwrap();

        let key_path = ancestor_b.join("keys").join("p2p.key");
        let a_mode_before = std::fs::metadata(&ancestor_a).unwrap().permissions().mode() & 0o777;
        let b_mode_before = std::fs::metadata(&ancestor_b).unwrap().permissions().mode() & 0o777;

        load_or_create_p2p_keypair(&key_path).expect("nested first boot");

        let a_mode = std::fs::metadata(&ancestor_a).unwrap().permissions().mode() & 0o777;
        let b_mode = std::fs::metadata(&ancestor_b).unwrap().permissions().mode() & 0o777;
        let keys_mode = std::fs::metadata(ancestor_b.join("keys"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(a_mode_before, a_mode, "ancestor a mode must stay unchanged");
        assert_eq!(b_mode_before, b_mode, "ancestor b mode must stay unchanged");
        assert_eq!(keys_mode, 0o700, "only the nominated key directory is 0700");
    }

    #[cfg(unix)]
    #[test]
    fn p2p_existing_symlink_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.key");
        let link = dir.path().join("p2p.key");

        load_or_create_p2p_keypair(&target).expect("create the real key");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err =
            load_or_create_p2p_keypair(&link).expect_err("a symlink key path must be refused");
        assert!(
            format!("{err:#}").contains("symlink"),
            "error must name the symlink refusal, got: {err:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn p2p_existing_key_dir_with_loose_permissions_is_tightened() {
        use std::os::unix::fs::PermissionsExt;

        let dir = key_base_0700();
        let key_dir = dir.path().join("keys");
        std::fs::create_dir(&key_dir).unwrap();
        std::fs::set_permissions(&key_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = key_dir.join("p2p.key");

        // Creation path: a pre-existing loose directory is detected and repaired.
        let created = load_or_create_p2p_keypair(&path).expect("boot must not fail on a loose dir");
        assert_eq!(
            std::fs::metadata(&key_dir).unwrap().permissions().mode() & 0o777,
            0o700,
            "an existing loose key directory must be tightened"
        );

        // Load path: same check, on a directory loosened after the key exists.
        std::fs::set_permissions(&key_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let loaded = load_or_create_p2p_keypair(&path).expect("reload must not fail");
        assert_eq!(
            std::fs::metadata(&key_dir).unwrap().permissions().mode() & 0o777,
            0o700,
            "the load path must tighten the key directory too"
        );
        assert_eq!(
            PeerId::from(created.public()),
            PeerId::from(loaded.public()),
            "tightening must not change the identity"
        );
    }

    #[test]
    fn p2p_failed_key_write_leaves_no_file_at_the_final_path() {
        let dir = key_base_0700();
        let key_dir = dir.path().join("keys");
        let path = key_dir.join("p2p.key");

        FAIL_KEY_WRITE.with(|f| f.set(true));
        let result = load_or_create_p2p_keypair(&path);
        FAIL_KEY_WRITE.with(|f| f.set(false));

        result.expect_err("an interrupted key write must not report success");
        assert!(
            !path.exists(),
            "a partially written key must never be observable at {}",
            path.display()
        );

        // Nor may a half-written scratch file be left behind for an operator to
        // trip over on the next boot.
        let leftovers: Vec<_> = std::fs::read_dir(&key_dir)
            .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path()).collect())
            .unwrap_or_default();
        assert!(
            leftovers.is_empty(),
            "a failed write must clean up after itself, found: {leftovers:?}"
        );

        // The next boot must be able to create the identity normally.
        let kp = load_or_create_p2p_keypair(&path).expect("a retry after a failed write must work");
        let reloaded = load_or_create_p2p_keypair(&path).unwrap();
        assert_eq!(PeerId::from(kp.public()), PeerId::from(reloaded.public()));
    }

    #[cfg(unix)]
    #[test]
    fn successful_publish_fsyncs_after_scratch_unlink() {
        SYNC_COUNT.with(|c| c.set(0));
        let dir = key_base_0700();
        let path = dir.path().join("keys").join("p2p.key");
        load_or_create_p2p_keypair(&path).expect("first boot");
        let syncs = SYNC_COUNT.with(|c| c.get());
        assert!(
            syncs >= 2,
            "publish must fsync after linking and again after unlinking the scratch, got {syncs}"
        );
        let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .collect();
        assert_eq!(
            leftovers,
            vec![std::ffi::OsString::from("p2p.key")],
            "success must leave only the nominated key, found: {leftovers:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn scratch_unlink_failure_is_not_reported_as_success() {
        let dir = key_base_0700();
        let key_dir = dir.path().join("keys");
        let path = key_dir.join("p2p.key");

        FAIL_SCRATCH_UNLINK.with(|f| f.set(true));
        let result = load_or_create_p2p_keypair(&path);
        FAIL_SCRATCH_UNLINK.with(|f| f.set(false));

        result.expect_err("an unlink failure after publish must not report success");
        assert!(
            path.exists(),
            "the nominated key is already linked; unlink failure must not delete it"
        );
        let leftovers: Vec<_> = std::fs::read_dir(&key_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            leftovers.iter().any(|n| n.starts_with(".p2p.key.") && n.ends_with(".tmp")),
            "the scratch name must still be present so the failure is visible, found: {leftovers:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn p2p_key_file_with_loose_permissions_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p2p.key");

        let kp = identity::Keypair::generate_ed25519();
        std::fs::write(&path, kp.to_protobuf_encoding().unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let err = load_or_create_p2p_keypair(&path)
            .expect_err("a group/world-readable key file must be an error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&path.display().to_string()) && msg.contains("0644"),
            "error must name the key path and the observed mode, got: {msg}"
        );
        // The rejection must not have regenerated the identity behind the
        // operator's back.
        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(on_disk, kp.to_protobuf_encoding().unwrap());
    }

    #[test]
    fn p2p_empty_key_file_reports_the_file_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p2p.key");
        std::fs::write(&path, b"").unwrap();
        // Keep the permission guard out of the way so this exercises the
        // empty-file path and not the mode check.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let err =
            load_or_create_p2p_keypair(&path).expect_err("an empty key file must be an error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&path.display().to_string()) && msg.contains("empty"),
            "error must name the key path and say the file is empty, got: {msg}"
        );
        assert!(
            !msg.contains("rsa"),
            "an empty file must not be reported as an RSA decoding problem, got: {msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn p2p_dangling_symlink_does_not_write_through_to_the_target() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("p2p.key");
        let target = dir.path().join("elsewhere.key");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        load_or_create_p2p_keypair(&link).expect_err("a dangling symlink must not be followed");
        assert!(
            !target.exists(),
            "no key may be written through the symlink to {}",
            target.display()
        );
    }

    #[test]
    fn p2p_corrupt_key_file_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p2p.key");
        std::fs::write(&path, [0xFFu8; 7]).unwrap();
        // Keep the permission guard out of the way so this exercises decoding.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let err =
            load_or_create_p2p_keypair(&path).expect_err("a corrupt key file must be an error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&path.display().to_string()),
            "error must name the key path, got: {msg}"
        );
        assert!(
            msg.contains("invalid p2p key"),
            "a corrupt key must be reported as a decoding failure, got: {msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn p2p_symlinked_key_parent_is_refused_before_chmod() {
        use std::os::unix::fs::PermissionsExt;

        // A 0700 base: a plain tempdir is 0775 under the suite's umask, and
        // the pinned-creation helper verifies its own parent, so an unsafe
        // base is refused before the symlink under test is ever reached.
        let dir = key_base_0700();
        let real_parent = dir.path().join("real");
        std::fs::create_dir(&real_parent).unwrap();
        std::fs::set_permissions(&real_parent, std::fs::Permissions::from_mode(0o755)).unwrap();

        let safe = dir.path().join("safe");
        std::fs::create_dir(&safe).unwrap();
        std::fs::set_permissions(&safe, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = safe.join("keys");
        std::os::unix::fs::symlink(&real_parent, &link).unwrap();

        let key_path = link.join("p2p.key");
        let mode_before = std::fs::metadata(&real_parent)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;

        let err = load_or_create_p2p_keypair(&key_path)
            .expect_err("a symlinked key directory must be refused before chmod");
        let after = std::fs::metadata(&real_parent)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode_before, after,
            "refusing a symlink parent must not chmod its target"
        );
        assert!(
            format!("{err:#}").contains("symlink"),
            "error must name the symlink refusal, got: {err:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn p2p_key_parent_that_is_a_file_is_refused_before_chmod() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let parent_file = dir.path().join("notadir");
        std::fs::write(&parent_file, b"x").unwrap();
        std::fs::set_permissions(&parent_file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let key_path = parent_file.join("p2p.key");
        let mode_before = std::fs::metadata(&parent_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;

        let err = load_or_create_p2p_keypair(&key_path)
            .expect_err("a file parent must be refused before chmod");
        let mode_after = std::fs::metadata(&parent_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode_before, mode_after,
            "refusing a file parent must not chmod it"
        );
        assert!(
            format!("{err:#}").contains("directory"),
            "error must name the non-directory parent, got: {err:#}"
        );
    }

    #[test]
    fn p2p_concurrent_first_boot_dir_creation_converges() {
        let dir = key_base_0700();
        let key_path = dir.path().join("keys").join("p2p.key");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let key_path2 = key_path.clone();
        let b1 = barrier.clone();
        let b2 = barrier.clone();

        let t1 = std::thread::spawn(move || {
            b1.wait();
            load_or_create_p2p_keypair(&key_path)
        });
        let t2 = std::thread::spawn(move || {
            b2.wait();
            load_or_create_p2p_keypair(&key_path2)
        });

        let kp1 = t1.join().expect("thread 1").expect("first concurrent boot");
        let kp2 = t2
            .join()
            .expect("thread 2")
            .expect("second concurrent boot");
        assert_eq!(
            PeerId::from(kp1.public()),
            PeerId::from(kp2.public()),
            "concurrent first boots must converge on one persisted identity"
        );
    }

    #[cfg(unix)]
    #[test]
    fn p2p_fifo_key_path_is_refused_without_blocking() {
        use std::ffi::CString;

        let dir = key_base_0700();
        let key_dir = dir.path().join("keys");
        std::fs::create_dir(&key_dir).unwrap();
        let path = key_dir.join("p2p.key");
        let c_path = CString::new(path.to_str().expect("utf-8 path")).unwrap();
        // SAFETY: `mkfifo` creates a FIFO at `c_path` with mode 0600.
        let ret = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(ret, 0, "mkfifo failed: {}", std::io::Error::last_os_error());

        let err = load_or_create_p2p_keypair(&path).expect_err("a FIFO key path must be refused");
        assert!(
            format!("{err:#}").contains("regular file"),
            "FIFO refusal must name the file-type requirement, got: {err:#}"
        );
    }

    #[test]
    fn p2p_oversized_key_file_is_refused() {
        let dir = key_base_0700();
        let key_dir = dir.path().join("keys");
        std::fs::create_dir(&key_dir).unwrap();
        let path = key_dir.join("p2p.key");
        std::fs::write(&path, vec![0u8; MAX_P2P_KEY_BYTES + 1]).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let err = load_or_create_p2p_keypair(&path).expect_err("oversized key must be refused");
        assert!(
            format!("{err:#}").contains("maximum accepted size"),
            "oversized refusal must name the size cap, got: {err:#}"
        );
    }

    /// Rule 2's parse-time half, in both directions, plus the invariant the
    /// acceptance rule is designed around: any accepted suffix joins to a path
    /// that still has home as a prefix. `PathBuf::join` replaces its base for
    /// rooted (and, on Windows, prefixed) right-hand operands, and `..` walks
    /// back out lexically, so those are exactly the rejected classes.
    #[test]
    fn tilde_suffix_escapes_home_matches_the_join_invariant() {
        let accepted = [".gitlawb/p2p.key", "keys/p2p.key", "./keys/p2p.key"];
        for suffix in accepted {
            assert!(
                !tilde_suffix_escapes_home(suffix),
                "{suffix:?} stays beneath home and must be accepted"
            );
        }

        for suffix in [
            // `~//etc/p2p.key`: the doubled separator leaves a rooted suffix,
            // and a rooted right-hand operand REPLACES home in `join`.
            "/etc/p2p.key",
            "//etc/p2p.key",
            // Walks back out of home lexically.
            "../etc/p2p.key",
            "keys/../../p2p.key",
        ] {
            assert!(
                tilde_suffix_escapes_home(suffix),
                "{suffix:?} escapes home and must be rejected"
            );
        }

        // Platform-prefixed forms replace the base in `join` even without a
        // root, so they are escapes on the platform that parses them.
        #[cfg(windows)]
        for suffix in ["C:/p2p.key", r"C:p2p.key", r"\\srv\share\p2p.key"] {
            assert!(
                tilde_suffix_escapes_home(suffix),
                "{suffix:?} carries a prefix and must be rejected"
            );
        }

        // The invariant itself, on the accepted set.
        let home = Path::new("/homes/gitlawb");
        for suffix in accepted {
            assert!(
                home.join(suffix).starts_with(home),
                "accepted suffix {suffix:?} must keep home as a prefix"
            );
        }
    }

    /// The key-storage contract, kept together in one table: which filesystem
    /// objects at and around the key path boot, and which are refused — and
    /// that every refusal leaves the filesystem exactly as it found it.
    ///
    /// Each row gets its own temp base (no cwd, no umask, no shared state).
    /// Refused rows are compared against a full recursive snapshot (path,
    /// type, mode, size) taken after setup, so an unintended chmod, a scratch
    /// file, a followed symlink, or a created directory all fail the row.
    /// The deep single-behavior tests around this one stay authoritative for
    /// their details (identity stability, race convergence, tightening); this
    /// table is the contract's index. The enabled/disabled and path-spelling
    /// half of the matrix lives with `Config::validate`'s tests, which gate
    /// on `p2p_port` before any of this code runs.
    #[cfg(unix)]
    #[test]
    fn p2p_key_storage_contract_matrix() {
        use std::os::unix::fs::PermissionsExt;

        enum Expect {
            /// Must boot; the key must sit 0600 inside a 0700 directory and
            /// reload to the same PeerId.
            Boots,
            /// Must fail with the needle in the message, mutating nothing.
            Refused(&'static str),
            /// Must fail promptly, mutating nothing; the message is
            /// platform-dependent (e.g. what `open(2)` says about a socket).
            RefusedAny,
        }

        struct Row {
            name: &'static str,
            setup: fn(&Path) -> std::path::PathBuf,
            expect: Expect,
        }

        fn valid_key_at(path: &Path) {
            let kp = identity::Keypair::generate_ed25519();
            std::fs::write(path, kp.to_protobuf_encoding().unwrap()).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        /// Rows probing refusal of the key object itself pre-create the key
        /// directory already at 0700: `ensure_key_dir` legitimately tightens
        /// a looser directory on the way in (its own tests cover that), and
        /// pre-tightening keeps this table's no-mutation assertion about the
        /// refusal itself rather than about that documented repair.
        fn key_dir_0700(base: &Path) -> std::path::PathBuf {
            let dir = base.join("keys");
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            dir
        }

        /// (path, is_dir, is_symlink, mode, len) for every entry under `base`,
        /// via `symlink_metadata` so links are recorded, not followed.
        fn snapshot(base: &Path) -> Vec<(std::path::PathBuf, bool, bool, u32, u64)> {
            let mut out = Vec::new();
            let mut stack = vec![base.to_path_buf()];
            while let Some(dir) = stack.pop() {
                for entry in std::fs::read_dir(&dir).unwrap() {
                    let path = entry.unwrap().path();
                    let md = std::fs::symlink_metadata(&path).unwrap();
                    out.push((
                        path.clone(),
                        md.is_dir(),
                        md.is_symlink(),
                        md.permissions().mode(),
                        md.len(),
                    ));
                    if md.is_dir() && !md.is_symlink() {
                        stack.push(path);
                    }
                }
            }
            out.sort();
            out
        }

        let rows = [
            Row {
                name: "fresh path under a real parent boots",
                setup: |base| base.join("keys").join("p2p.key"),
                expect: Expect::Boots,
            },
            Row {
                name: "existing 0600 regular key boots",
                setup: |base| {
                    let dir = key_dir_0700(base);
                    let path = dir.join("p2p.key");
                    valid_key_at(&path);
                    path
                },
                expect: Expect::Boots,
            },
            Row {
                name: "group-writable ancestor is refused",
                setup: |base| {
                    let g = base.join("g");
                    std::fs::create_dir(&g).unwrap();
                    std::fs::set_permissions(&g, std::fs::Permissions::from_mode(0o775)).unwrap();
                    g.join("keys").join("p2p.key")
                },
                expect: Expect::Refused("writable beyond its owner"),
            },
            Row {
                name: "world-writable non-sticky ancestor is refused",
                setup: |base| {
                    let w = base.join("w");
                    std::fs::create_dir(&w).unwrap();
                    std::fs::set_permissions(&w, std::fs::Permissions::from_mode(0o777)).unwrap();
                    w.join("keys").join("p2p.key")
                },
                expect: Expect::Refused("writable beyond its owner"),
            },
            Row {
                name: "intermediate symlink component is refused, target untouched",
                setup: |base| {
                    let real = base.join("real");
                    std::fs::create_dir(&real).unwrap();
                    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755))
                        .unwrap();
                    let link = base.join("link");
                    std::os::unix::fs::symlink(&real, &link).unwrap();
                    link.join("keys").join("p2p.key")
                },
                expect: Expect::Refused("symlink"),
            },
            Row {
                name: "symlinked parent is refused, target untouched",
                setup: |base| {
                    let target = base.join("real");
                    std::fs::create_dir(&target).unwrap();
                    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
                        .unwrap();
                    let link = base.join("keys");
                    std::os::unix::fs::symlink(&target, &link).unwrap();
                    link.join("p2p.key")
                },
                expect: Expect::Refused("symlink"),
            },
            Row {
                name: "regular-file parent is refused, mode and content kept",
                setup: |base| {
                    let file = base.join("keys");
                    std::fs::write(&file, b"payload").unwrap();
                    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644))
                        .unwrap();
                    file.join("p2p.key")
                },
                expect: Expect::Refused("directory"),
            },
            Row {
                name: "symlink at the key position is refused",
                setup: |base| {
                    let dir = key_dir_0700(base);
                    let real = dir.join("real.key");
                    valid_key_at(&real);
                    let link = dir.join("p2p.key");
                    std::os::unix::fs::symlink(&real, &link).unwrap();
                    link
                },
                expect: Expect::Refused("symlink"),
            },
            Row {
                name: "dangling symlink at the key position is refused",
                setup: |base| {
                    let dir = key_dir_0700(base);
                    let link = dir.join("p2p.key");
                    std::os::unix::fs::symlink(dir.join("absent"), &link).unwrap();
                    link
                },
                expect: Expect::Refused("symlink"),
            },
            Row {
                name: "directory at the key position is refused",
                setup: |base| {
                    let dir = key_dir_0700(base);
                    let path = dir.join("p2p.key");
                    std::fs::create_dir(&path).unwrap();
                    path
                },
                // The refusal moved from the config validator to the load
                // path, which judges the object it actually opened rather than
                // a pathname it stat'd, so it names the object type instead of
                // the setting. Same verdict, better diagnosis.
                expect: Expect::Refused("must be a regular file"),
            },
            Row {
                name: "FIFO at the key position is refused without blocking",
                setup: |base| {
                    let dir = key_dir_0700(base);
                    let path = dir.join("p2p.key");
                    let c_path =
                        std::ffi::CString::new(path.to_str().expect("utf-8 path")).unwrap();
                    // SAFETY: creates a FIFO at `c_path` with mode 0600.
                    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
                    assert_eq!(rc, 0, "mkfifo: {}", std::io::Error::last_os_error());
                    path
                },
                // No writer ever appears, so completing at all proves the
                // non-blocking open; the message proves the explicit
                // regular-file invariant on the opened object.
                expect: Expect::Refused("regular file"),
            },
            Row {
                name: "unix socket at the key position is refused",
                setup: |base| {
                    let dir = key_dir_0700(base);
                    let path = dir.join("p2p.key");
                    // The bound socket's fs entry outlives the listener.
                    std::os::unix::net::UnixListener::bind(&path)
                        .expect("bind a unix socket at the key path");
                    path
                },
                expect: Expect::RefusedAny,
            },
            Row {
                name: "oversized key is refused unread",
                setup: |base| {
                    let dir = key_dir_0700(base);
                    let path = dir.join("p2p.key");
                    std::fs::write(&path, vec![0u8; MAX_P2P_KEY_BYTES + 1]).unwrap();
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                    path
                },
                expect: Expect::Refused("maximum accepted size"),
            },
            Row {
                name: "loose 0644 key is refused, not regenerated",
                setup: |base| {
                    let dir = key_dir_0700(base);
                    let path = dir.join("p2p.key");
                    valid_key_at(&path);
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
                        .unwrap();
                    path
                },
                expect: Expect::Refused("0644"),
            },
        ];

        for row in rows {
            let base = key_base_0700();
            let key_path = (row.setup)(base.path());

            match row.expect {
                Expect::Boots => {
                    let kp = load_or_create_p2p_keypair(&key_path)
                        .unwrap_or_else(|e| panic!("[{}] must boot, got: {e:#}", row.name));
                    let key_mode =
                        std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
                    assert_eq!(key_mode, 0o600, "[{}] key must be 0600", row.name);
                    let dir_mode = std::fs::metadata(key_path.parent().unwrap())
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777;
                    assert_eq!(dir_mode, 0o700, "[{}] key directory must be 0700", row.name);
                    let reloaded = load_or_create_p2p_keypair(&key_path)
                        .unwrap_or_else(|e| panic!("[{}] must reload, got: {e:#}", row.name));
                    assert_eq!(
                        PeerId::from(kp.public()),
                        PeerId::from(reloaded.public()),
                        "[{}] identity must be stable",
                        row.name
                    );
                }
                ref refusal => {
                    let before = snapshot(base.path());
                    let err = load_or_create_p2p_keypair(&key_path)
                        .expect_err(&format!("[{}] must be refused", row.name));
                    if let Expect::Refused(needle) = refusal {
                        assert!(
                            format!("{err:#}").contains(needle),
                            "[{}] refusal must mention {needle:?}, got: {err:#}",
                            row.name
                        );
                    }
                    assert_eq!(
                        before,
                        snapshot(base.path()),
                        "[{}] refusal must not mutate the filesystem",
                        row.name
                    );
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn ancestor_walk_refuses_group_writable_ancestors() {
        use std::os::unix::fs::PermissionsExt;

        for mode in [0o770u32, 0o775] {
            let base = key_base_0700();
            let ancestor = base.path().join("g");
            std::fs::create_dir(&ancestor).unwrap();
            std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(mode)).unwrap();

            let path = ancestor.join("keys").join("p2p.key");
            let err = load_or_create_p2p_keypair(&path)
                .expect_err("a group-writable ancestor must be refused");
            let msg = format!("{err:#}");
            assert!(
                msg.contains("writable beyond its owner"),
                "mode {mode:04o} must be refused for group write, got: {msg}"
            );
            // Refusal must not create the key directory or the key.
            assert!(
                !ancestor.join("keys").exists(),
                "key dir must not be created"
            );
            assert!(!path.exists(), "key must not be created");
        }
    }

    #[cfg(unix)]
    #[test]
    fn ancestor_walk_accepts_safe_and_sticky_ancestors() {
        use std::os::unix::fs::PermissionsExt;

        // A 0755 ancestor (no group/world write) is accepted and the key boots.
        let base = key_base_0700();
        let safe = base.path().join("safe");
        std::fs::create_dir(&safe).unwrap();
        std::fs::set_permissions(&safe, std::fs::Permissions::from_mode(0o755)).unwrap();

        let kp = load_or_create_p2p_keypair(&safe.join("keys").join("p2p.key"))
            .expect("a 0755 ancestor must boot");
        assert_eq!(
            PeerId::from(
                load_or_create_p2p_keypair(&safe.join("keys").join("p2p.key"))
                    .unwrap()
                    .public()
            ),
            PeerId::from(kp.public()),
            "the identity must reload stably"
        );

        // A 1777 sticky ancestor (the /tmp shape) is accepted: sticky blocks
        // rename/delete of others' entries even though the directory is
        // world-writable.
        let sticky = base.path().join("sticky");
        std::fs::create_dir(&sticky).unwrap();
        std::fs::set_permissions(&sticky, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let _ = load_or_create_p2p_keypair(&sticky.join("keys").join("p2p.key"))
            .expect("a 1777 sticky ancestor must boot");
    }

    /// Owner-execute-only (0111) is enough to traverse. Requiring directory
    /// list permission would refuse a path the ownership/write-authority
    /// predicate already accepts. The next component must already exist:
    /// 0111 has no owner-write, so the walk cannot mkdirat through it.
    #[cfg(all(
        unix,
        any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "netbsd",
        )
    ))]
    #[test]
    fn ancestor_walk_accepts_search_only_ancestor() {
        use std::os::unix::fs::PermissionsExt;

        let base = key_base_0700();
        let anc = base.path().join("searchonly");
        let keys = anc.join("keys");
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&anc, std::fs::Permissions::from_mode(0o111)).unwrap();

        let path = keys.join("p2p.key");
        let loaded = load_or_create_p2p_keypair(&path);
        let kp = match loaded {
            Ok(kp) => kp,
            Err(e) => {
                std::fs::set_permissions(&anc, std::fs::Permissions::from_mode(0o700)).unwrap();
                panic!("a search-only ancestor must not require directory-list permission: {e:#}");
            }
        };
        let reloaded = load_or_create_p2p_keypair(&path);
        std::fs::set_permissions(&anc, std::fs::Permissions::from_mode(0o700)).unwrap();
        let reloaded = reloaded.expect("reload");
        assert_eq!(
            PeerId::from(kp.public()),
            PeerId::from(reloaded.public()),
            "the identity must reload stably through a search-only ancestor"
        );
    }

    #[cfg(unix)]
    #[test]
    fn ancestor_walk_refuses_intermediate_symlink() {
        let base = key_base_0700();
        let real = base.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let path = link.join("keys").join("p2p.key");
        let err = load_or_create_p2p_keypair(&path)
            .expect_err("an intermediate symlink component must be refused");
        assert!(
            format!("{err:#}").contains("symlink"),
            "intermediate symlink refusal must name the symlink, got: {err:#}"
        );
        // The symlink target must be untouched: no keys dir, no key inside.
        assert!(
            !real.join("keys").exists(),
            "symlink target must be untouched"
        );
    }

    #[cfg(unix)]
    #[test]
    fn read_p2p_keypair_refuses_a_key_owned_by_another_user() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p2p.key");
        let kp = identity::Keypair::generate_ed25519();
        std::fs::write(&path, kp.to_protobuf_encoding().unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let real_uid = std::fs::metadata(&path).unwrap().uid();
        let other = real_uid.wrapping_add(1);

        EUID_OVERRIDE.with(|c| c.set(Some(other)));
        let result = read_p2p_keypair(&path);
        EUID_OVERRIDE.with(|c| c.set(None));

        let err = format!(
            "{:#}",
            result.expect_err("a foreign-owned key must be refused")
        );
        assert!(
            err.contains(&format!(
                "owned by uid {real_uid} but this node runs as uid {other}"
            )),
            "the refusal must name the file's owner and the running uid"
        );
        assert!(
            read_p2p_keypair(&path).is_ok(),
            "the same key must load when the owner matches"
        );
    }

    #[cfg(unix)]
    #[test]
    fn ensure_key_dir_refuses_a_directory_owned_by_another_user() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        for mode in [0o700, 0o777] {
            let dir = tempfile::tempdir().unwrap();
            let keys = dir.path().to_path_buf();
            std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(mode)).unwrap();

            let real_uid = std::fs::metadata(&keys).unwrap().uid();
            EUID_OVERRIDE.with(|c| c.set(Some(real_uid.wrapping_add(1))));
            let result = ensure_key_dir(&keys);
            EUID_OVERRIDE.with(|c| c.set(None));

            let err = format!(
                "{:#}",
                result.expect_err("a foreign-owned key directory must be refused")
            );
            assert!(
                err.contains("owned by uid"),
                "mode {mode:04o} must be refused"
            );
            assert!(
                !err.contains("could not be tightened"),
                "ownership must be reported before chmod"
            );
            assert_eq!(
                std::fs::metadata(&keys).unwrap().permissions().mode() & 0o777,
                mode,
                "a refused directory must not have been chmodded first"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn ensure_key_dir_refuses_a_foreign_owned_ancestor() {
        use std::os::unix::fs::MetadataExt;

        let base = tempfile::tempdir().unwrap();
        let nested = base.path().join("keys");

        let real_uid = std::fs::metadata(base.path()).unwrap().uid();
        EUID_OVERRIDE.with(|c| c.set(Some(real_uid.wrapping_add(1))));
        let result = ensure_key_dir(&nested);
        EUID_OVERRIDE.with(|c| c.set(None));
        let err = format!(
            "{:#}",
            result.expect_err("a directory under a foreign-owned ancestor must be refused")
        );
        assert!(
            err.contains("sits under") && err.contains("control which identity"),
            "must be refused for the ancestor"
        );
        assert!(
            !nested.exists(),
            "the key directory must not have been created"
        );
    }

    /// The cwd anchor's ownership is verified the same way as any other
    /// component: with an overridden euid the real cwd is foreign and a
    /// relative key path must be refused before anything is created.
    #[cfg(unix)]
    #[test]
    fn ensure_key_dir_refuses_a_foreign_owned_cwd_anchor() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let base = tempfile::tempdir().unwrap();
        std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let real_uid = std::fs::metadata(base.path()).unwrap().uid();

        // Drive the walk on a relative key directory; the anchor is the cwd,
        // which is `base` only if the test process chdir'd there. Instead of
        // touching the process-global cwd, point the walk at a path whose
        // anchor walk sees the cwd: with the euid override armed, the cwd is
        // foreign and must be refused.
        EUID_OVERRIDE.with(|c| c.set(Some(real_uid.wrapping_add(1))));
        let result = ensure_key_dir(Path::new("keys"));
        EUID_OVERRIDE.with(|c| c.set(None));

        let err = format!(
            "{:#}",
            result.expect_err("a foreign-owned cwd anchor must be refused")
        );
        assert!(
            err.contains("owned by uid") || err.contains("control which identity"),
            "the cwd-anchor refusal must name the ownership hazard"
        );
        assert!(
            !Path::new("keys").exists(),
            "the key directory must not have been created under a foreign cwd"
        );
    }

    #[cfg(unix)]
    #[test]
    fn foreign_ownership_is_refused_and_matching_ownership_is_not() {
        let path = Path::new("/data/keys/p2p.key");

        for uid in [0u32, 1000, 65534] {
            assert!(
                foreign_ownership_error("key", path, uid, uid).is_none(),
                "a uid owning its own key must not be refused"
            );
        }

        let err = foreign_ownership_error("key", path, 1000, 1001)
            .expect("a key owned by another uid must be refused");
        assert!(
            err.contains("1000") && err.contains("1001"),
            "the refusal must name both uids"
        );
    }

    #[test]
    fn ref_update_event_round_trip_with_owner_did() {
        let event = RefUpdateEvent {
            v: 0,
            node_did: "did:key:zNode".into(),
            pusher_did: "did:key:zPusher".into(),
            repo: "zOwner/myrepo".into(),
            owner_did: Some("did:key:zOwner".into()),
            ref_name: "refs/heads/main".into(),
            old_sha: "0000000000000000000000000000000000000000".into(),
            new_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            timestamp: "2026-07-02T12:00:00Z".into(),
            cert_id: None,
            cid: None,
            sig: None,
        };
        let json = serde_json::to_value(&event).unwrap();
        // owner_did must be present in the serialized output
        assert_eq!(json["owner_did"], "did:key:zOwner");
        assert_eq!(json["repo"], "zOwner/myrepo");

        let deserialized: RefUpdateEvent = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized.owner_did, Some("did:key:zOwner".into()));
    }

    #[test]
    fn ref_update_event_backward_compat_no_owner_did() {
        let old_json = serde_json::json!({
            "node_did": "did:key:zNode",
            "pusher_did": "did:key:zPusher",
            "repo": "zOwner/myrepo",
            "ref_name": "refs/heads/main",
            "old_sha": "0000000000000000000000000000000000000000",
            "new_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "timestamp": "2026-07-02T12:00:00Z",
            "cert_id": null,
            "cid": null
        });
        let deserialized: RefUpdateEvent = serde_json::from_value(old_json).unwrap();
        assert_eq!(deserialized.owner_did, None);
        assert_eq!(deserialized.repo, "zOwner/myrepo");
    }

    #[test]
    fn ref_update_event_backward_compat_null_owner_did() {
        let with_null = serde_json::json!({
            "node_did": "did:key:zNode",
            "pusher_did": "did:key:zPusher",
            "repo": "zOwner/myrepo",
            "owner_did": null,
            "ref_name": "refs/heads/main",
            "old_sha": "0000000000000000000000000000000000000000",
            "new_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "timestamp": "2026-07-02T12:00:00Z",
            "cert_id": null,
            "cid": null
        });
        let deserialized: RefUpdateEvent = serde_json::from_value(with_null).unwrap();
        assert_eq!(deserialized.owner_did, None);
    }

    /// A fully populated event used by the wire-format tests. Every optional
    /// field is Some so the serialized form exercises the widest field set.
    fn populated_event() -> RefUpdateEvent {
        RefUpdateEvent {
            v: 0,
            node_did: "did:key:zNode".into(),
            pusher_did: "did:key:zPusher".into(),
            repo: "zOwner/myrepo".into(),
            owner_did: Some("did:key:zOwner".into()),
            ref_name: "refs/heads/main".into(),
            old_sha: "0000000000000000000000000000000000000000".into(),
            new_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            timestamp: "2026-07-02T12:00:00Z".into(),
            cert_id: Some("cert-1".into()),
            cid: Some("bafycid".into()),
            sig: None,
        }
    }

    /// The load-bearing backward-compatibility test (R12). An un-upgraded peer
    /// runs `from_slice::<RefUpdateEvent>` against the PRE-CHANGE field set, so
    /// this replicates that struct verbatim and proves bytes produced by the
    /// new code still parse into it. If this fails, upgraded nodes' events are
    /// silently dropped by every node that has not upgraded yet.
    #[test]
    fn signed_event_still_parses_under_the_pre_change_field_set() {
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct LegacyRefUpdateEvent {
            node_did: String,
            pusher_did: String,
            repo: String,
            #[serde(default)]
            owner_did: Option<String>,
            ref_name: String,
            old_sha: String,
            new_sha: String,
            timestamp: String,
            cert_id: Option<String>,
            cid: Option<String>,
        }

        /// The same field set with unknown keys REFUSED. The permissive struct
        /// above is serde's default, which drops keys it does not know, so it
        /// is structurally blind to an ADDED field and would stay green against
        /// the `"sig": null` regression `unsigned_event_serializes_with_no_sig_key`
        /// warns about. This one sees the addition, which is what lets the two
        /// assertions below state the intent: `sig` is a deliberate new key, so
        /// an unsigned event is byte-compatible with the old wire form and a
        /// signed one is not.
        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)]
        #[serde(deny_unknown_fields)]
        struct StrictLegacyRefUpdateEvent {
            node_did: String,
            pusher_did: String,
            repo: String,
            #[serde(default)]
            owner_did: Option<String>,
            ref_name: String,
            old_sha: String,
            new_sha: String,
            timestamp: String,
            cert_id: Option<String>,
            cid: Option<String>,
        }

        let mut event = populated_event();
        event.sig = Some("c2lnbmF0dXJl".into());
        let bytes = serde_json::to_vec(&event).unwrap();

        let legacy: LegacyRefUpdateEvent = serde_json::from_slice(&bytes)
            .expect("new-code bytes must deserialize under the old field set");
        assert_eq!(legacy.repo, "zOwner/myrepo");
        assert_eq!(legacy.owner_did, Some("did:key:zOwner".into()));

        // An UNSIGNED event carries no `sig` key at all, so it is byte-identical
        // in shape to the pre-change wire form and parses even under the strict
        // reader. This is what `skip_serializing_if` buys; drop it and a
        // `"sig": null` key appears here and this goes red.
        let unsigned_bytes = serde_json::to_vec(&populated_event()).unwrap();
        let strict: StrictLegacyRefUpdateEvent = serde_json::from_slice(&unsigned_bytes)
            .expect("an unsigned event must carry no field the pre-change reader did not know");
        assert_eq!(strict.repo, "zOwner/myrepo");

        // A SIGNED event does carry the new key, and that is intentional, not a
        // compatibility bug: the permissive reader above is what makes it
        // harmless. Pinning the refusal here documents `sig` as the one added
        // field, so a SECOND addition cannot slip in unnoticed.
        serde_json::from_slice::<StrictLegacyRefUpdateEvent>(&bytes)
            .expect_err("a signed event must be visibly carrying the added `sig` key");
    }

    #[test]
    fn legacy_json_without_sig_parses_with_sig_none() {
        let old_json = serde_json::json!({
            "node_did": "did:key:zNode",
            "pusher_did": "did:key:zPusher",
            "repo": "zOwner/myrepo",
            "ref_name": "refs/heads/main",
            "old_sha": "0000000000000000000000000000000000000000",
            "new_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "timestamp": "2026-07-02T12:00:00Z",
            "cert_id": null,
            "cid": null
        });
        let deserialized: RefUpdateEvent = serde_json::from_value(old_json).unwrap();
        assert_eq!(deserialized.sig, None);

        let with_null = serde_json::json!({
            "node_did": "did:key:zNode",
            "pusher_did": "did:key:zPusher",
            "repo": "zOwner/myrepo",
            "ref_name": "refs/heads/main",
            "old_sha": "0000000000000000000000000000000000000000",
            "new_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "timestamp": "2026-07-02T12:00:00Z",
            "cert_id": null,
            "cid": null,
            "sig": null
        });
        let deserialized: RefUpdateEvent = serde_json::from_value(with_null).unwrap();
        assert_eq!(deserialized.sig, None);
    }

    /// `skip_serializing_if` is not cosmetic: the signing bytes are the event
    /// with `sig` set to None, so a `"sig": null` key would change them and
    /// break byte-identity with the legacy wire form.
    #[test]
    fn unsigned_event_serializes_with_no_sig_key() {
        let json = serde_json::to_string(&populated_event()).unwrap();
        assert!(
            !json.contains("\"sig\""),
            "an unsigned event must carry no sig key at all, got: {json}"
        );
    }

    /// Golden signing input, pinned byte for byte.
    ///
    /// If this fails, the wire signing input changed. That is not a constant to
    /// re-pin: every already-signed event in flight, and every signature made by
    /// a previously deployed build, becomes unverifiable against the new build,
    /// so the change needs a rollout plan (ship the reader everywhere before
    /// anything emits the new form). A field REORDER or rename produces exactly
    /// this failure, and the emit-to-ingest round trip is structurally blind to
    /// it because both sides re-serialize the same new declaration order.
    const GOLDEN_SIGNING_BYTES: &str = concat!(
        r#"{"node_did":"did:key:zNode","pusher_did":"did:key:zPusher","#,
        r#""repo":"zOwner/myrepo","owner_did":"did:key:zOwner","#,
        r#""ref_name":"refs/heads/main","#,
        r#""old_sha":"0000000000000000000000000000000000000000","#,
        r#""new_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","#,
        r#""timestamp":"2026-07-02T12:00:00Z","cert_id":"cert-1","cid":"bafycid"}"#,
    );

    #[test]
    fn signing_bytes_match_the_golden_constant() {
        let bytes = signing_bytes(&populated_event()).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            GOLDEN_SIGNING_BYTES,
            "the wire signing input changed; see the comment on GOLDEN_SIGNING_BYTES"
        );
    }

    /// The same golden discipline, applied to the optional shape production
    /// actually emits.
    ///
    /// `GOLDEN_SIGNING_BYTES` above pins an event with `owner_did`, `cert_id`,
    /// and `cid` all populated, and no real publish looks like that. The sole
    /// production publish site, `api::repos::post_receive_replication_tail`,
    /// always passes `cert_id: None`, and `cid` is None on every push whose
    /// pinning has not finished. So the encoding of a null-valued optional, the
    /// one carried by essentially every live event, was pinned nowhere.
    ///
    /// What this catches that the all-`Some` constant structurally cannot:
    /// adding `skip_serializing_if = "Option::is_none"` to any of those three
    /// fields omits the key rather than writing `null`, which changes the
    /// signing input for every event in flight while leaving the all-`Some`
    /// golden byte-identical. That is not hypothetical; injecting exactly that
    /// attribute on `cert_id` left the whole suite green, both goldens passing,
    /// with the production signing input silently changed.
    ///
    /// Frozen for the same reason as the constant above: a failure here is a
    /// wire-format change that needs a rollout plan, not a constant to re-pin.
    const GOLDEN_SIGNING_BYTES_ALL_NONE: &str = concat!(
        r#"{"node_did":"did:key:zNode","pusher_did":"did:key:zPusher","#,
        r#""repo":"zOwner/myrepo","owner_did":null,"#,
        r#""ref_name":"refs/heads/main","#,
        r#""old_sha":"0000000000000000000000000000000000000000","#,
        r#""new_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","#,
        r#""timestamp":"2026-07-02T12:00:00Z","cert_id":null,"cid":null}"#,
    );

    /// The all-`None` optional shape: what the production publish site emits.
    fn all_none_optionals_event() -> RefUpdateEvent {
        RefUpdateEvent {
            owner_did: None,
            cert_id: None,
            cid: None,
            ..populated_event()
        }
    }

    #[test]
    fn signing_bytes_of_the_all_none_shape_match_the_golden_constant() {
        let bytes = signing_bytes(&all_none_optionals_event()).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            GOLDEN_SIGNING_BYTES_ALL_NONE,
            "the wire signing input for null-valued optionals changed; see the comment on GOLDEN_SIGNING_BYTES_ALL_NONE"
        );
    }

    /// The signature must be excluded from its own input, so a signed event and
    /// its unsigned original produce identical signing bytes.
    #[test]
    fn signing_bytes_ignore_the_sig_field() {
        let mut signed = populated_event();
        signed.sig = Some("c2lnbmF0dXJl".into());
        assert_eq!(
            signing_bytes(&signed).unwrap(),
            signing_bytes(&populated_event()).unwrap()
        );
    }

    /// A complete wire artifact signed by a build that had no version field.
    ///
    /// Captured at commit e3dc6f07, from a tree where `RefUpdateEvent` carried
    /// no `v` field at all, and confirmed to pass `verify_ref_update` there.
    /// The capture ORDER is the whole value. A v0 event re-serializes with no
    /// `"v"` key under `skip_serializing_if`, so an artifact captured after the
    /// field was added is byte-identical to this one, and nothing in a test run
    /// would distinguish the two. The only thing that makes this artifact
    /// evidence rather than decoration is that the code under test did not
    /// exist when it was produced.
    ///
    /// Never regenerate it. A signature the test just produced is
    /// self-consistent by construction: it proves the current encoder agrees
    /// with the current verifier, which stays true of an encoding that has
    /// silently stopped accepting every event already in flight. That is the
    /// only failure this constant can see, and regenerating it is precisely
    /// how you blind it. Same discipline as `GOLDEN_SIGNING_BYTES`, for the
    /// same reason: freeze it forever. `LEGACY_SIGNED_EVENT_V0_SHA256` below is
    /// what makes "never regenerate it" a check rather than a request.
    ///
    /// Non-degenerate on purpose: `owner_did`, `cert_id`, and `cid` are all
    /// populated, so the interaction between the optional fields' encoding and
    /// the version field's is pinned rather than left unexercised by an
    /// artifact that happened to carry none of them.
    const LEGACY_SIGNED_EVENT_V0: &str = r#"{"node_did":"did:key:z6MkiAJwX3dtfEY6KGeDDgxXB6ZZWCAxTSHDtJEyUVynqYtq","pusher_did":"did:key:zPusher","repo":"zOwner/myrepo","owner_did":"did:key:zOwner","ref_name":"refs/heads/main","old_sha":"0000000000000000000000000000000000000000","new_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","timestamp":"2026-07-02T12:00:00Z","cert_id":"cert-1","cid":"bafycid","sig":"-lH5aObROlqoTFjnjSXjbDgCVscLfVaKb1Y1gJL1tVsiBZlZnLKi55QgSo0ALTNtI_DyKo0ColzJMxL7w7ZODQ"}"#;

    /// SHA-256 of `LEGACY_SIGNED_EVENT_V0`, hex, lowercase. This is what makes
    /// the capture claim above checkable instead of merely attested.
    ///
    /// The obvious guard does not work, which is why this one exists. Asserting
    /// the artifact carries no `"v"` key proves nothing about its provenance: a
    /// v0 event re-serializes with no version key under `skip_serializing_if`,
    /// so an artifact regenerated from CURRENT code carries no `"v"` key either
    /// and that assertion passes against precisely the regeneration it was meant
    /// to refuse. A digest has no such blind spot. Any edit to those bytes,
    /// regeneration included, moves it.
    ///
    /// Frozen alongside the artifact. If it fails, the constant was edited:
    /// restore the original from commit e3dc6f07 rather than re-pinning the
    /// digest, since re-pinning is exactly the act of blinding the test that the
    /// "never regenerate it" paragraph above warns against.
    const LEGACY_SIGNED_EVENT_V0_SHA256: &str =
        "2482e053c8ab1841d784f523f1ef5e3d0bd5f9d563565af8fca8dd34a1e264fc";

    /// `LEGACY_SIGNED_EVENT_V0` with `"v":0,` injected as the leading key: the
    /// exact malleability the review demonstrated, frozen beside the artifact
    /// it was derived from.
    ///
    /// 460 bytes to the original's 454, a different gossipsub `message_id`, and
    /// the SAME signature, because `v` is `skip_serializing_if = "is_zero"` and
    /// therefore vanishes again when the parsed struct is re-serialized into
    /// signing bytes. One captured signature, two wire encodings, and nothing
    /// keyed on `msg.data` can see that they are the same event. It is kept as
    /// a literal rather than built by injecting into the constant at runtime
    /// for the reason the original is frozen: a fixture that regenerates itself
    /// from current code cannot witness a change to current code.
    const LEGACY_SIGNED_EVENT_V0_TWIN: &str = r#"{"v":0,"node_did":"did:key:z6MkiAJwX3dtfEY6KGeDDgxXB6ZZWCAxTSHDtJEyUVynqYtq","pusher_did":"did:key:zPusher","repo":"zOwner/myrepo","owner_did":"did:key:zOwner","ref_name":"refs/heads/main","old_sha":"0000000000000000000000000000000000000000","new_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","timestamp":"2026-07-02T12:00:00Z","cert_id":"cert-1","cid":"bafycid","sig":"-lH5aObROlqoTFjnjSXjbDgCVscLfVaKb1Y1gJL1tVsiBZlZnLKi55QgSo0ALTNtI_DyKo0ColzJMxL7w7ZODQ"}"#;

    /// SHA-256 of `LEGACY_SIGNED_EVENT_V0_TWIN`, hex, lowercase, and pinned for
    /// the same reason its sibling is: these bytes are evidence, and evidence
    /// that can be edited without anything going red is not evidence.
    const LEGACY_SIGNED_EVENT_V0_TWIN_SHA256: &str =
        "324c9cfa24bbd06681a0a2176fb6977d54257d632589fff11cd0ebbf5734b42c";

    /// The compatibility test the rest of this module cannot substitute for:
    /// the only one here that verifies an artifact it did not itself sign.
    ///
    /// Every other signature test in this file signs and verifies in one
    /// breath, which is self-consistent under any field set. Change the signed
    /// field set on both sides and they all stay green forever while every
    /// event a deployed peer already emitted becomes unverifiable. Driving a
    /// pre-change artifact through the post-change verifier is the one
    /// observation that can tell those two worlds apart.
    #[test]
    fn an_event_signed_before_the_version_field_existed_still_verifies() {
        // What this checks, exactly: that the constant still holds the bytes
        // captured at e3dc6f07, byte for byte. It does not, and cannot, observe
        // that those bytes predate the version field; that is established by the
        // capture commit and by review, not by anything a test run can see. What
        // the digest does buy is that a later edit which regenerates the artifact
        // from current code fails HERE, loudly, instead of quietly decaying this
        // test into the fresh-artifact round trip it exists to not be.
        use sha2::{Digest, Sha256};
        let digest = hex::encode(Sha256::digest(LEGACY_SIGNED_EVENT_V0.as_bytes()));
        assert_eq!(
            digest, LEGACY_SIGNED_EVENT_V0_SHA256,
            "the frozen legacy artifact was edited; restore it from commit e3dc6f07 rather than \
             re-pinning this digest"
        );

        // Exactly the bytes a peer would receive, straight off the wire.
        let event: RefUpdateEvent = serde_json::from_slice(LEGACY_SIGNED_EVENT_V0.as_bytes())
            .expect("an event from before the version field must still parse");
        verify_ref_update(&event).expect(
            "an event signed before the version field existed must still verify; the signed \
             field set is a wire format and this build has changed it",
        );
    }

    /// Build a populated event whose `node_did` is the given keypair's DID and
    /// whose `timestamp` is fresh on the guard-layer clock.
    ///
    /// The timestamp is overwritten HERE rather than in `populated_event`, and
    /// the split is load-bearing in both directions. `populated_event` has to
    /// stay frozen at `2026-07-02T12:00:00Z` because `GOLDEN_SIGNING_BYTES`
    /// pins its exact encoding, and a fixture that moves with the clock cannot
    /// pin bytes. But that same frozen instant is weeks outside the freshness
    /// window, so every ingest test built on it would answer `StaleTimestamp`
    /// and stop testing the guard it was written for. `event_for` feeds only
    /// the ingest and verify tests and no byte-pinning golden, so it is the one
    /// place the two requirements can be separated.
    ///
    /// Read through [`ingest_now`], not `Utc::now`, so a test that pins the
    /// clock gets a fixture stamped on the same instant its assertions are
    /// written against.
    fn event_for(keypair: &Keypair) -> RefUpdateEvent {
        let mut event = populated_event();
        event.node_did = keypair.did().to_string();
        event.timestamp = ingest_now().to_rfc3339();
        event
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let keypair = Keypair::generate();
        let mut event = event_for(&keypair);
        sign_ref_update(&keypair, &mut event).unwrap();
        assert!(event.sig.is_some(), "signing must populate sig");

        // Through the wire, since that is how a peer receives it.
        let bytes = serde_json::to_vec(&event).unwrap();
        let received: RefUpdateEvent = serde_json::from_slice(&bytes).unwrap();
        verify_ref_update(&received).expect("a correctly signed event must verify");
        assert_eq!(received.repo, "zOwner/myrepo");
        assert_eq!(received.node_did, keypair.did().to_string());
    }

    /// A cryptographically valid signature that does not bind the claimed
    /// identity. This is the RUSTSEC-2022-0009 shape: libp2p-core accepted a
    /// valid signature without checking it derived the claimed peer id, so the
    /// signature proved someone signed, not that the claimed party did. Here
    /// keypair A signs an event claiming keypair B's DID; the bytes carry a
    /// real signature, and verification must still refuse it because it does
    /// not verify against the key behind `node_did`.
    #[test]
    fn a_signature_that_does_not_bind_the_claimed_did_is_rejected() {
        let signer = Keypair::generate();
        let claimed = Keypair::generate();
        let mut event = event_for(&claimed);
        // Signed by `signer` over bytes that name `claimed` as node_did.
        sign_ref_update(&signer, &mut event).unwrap();
        assert!(event.sig.is_some());

        verify_ref_update(&event)
            .expect_err("a signature by a key other than node_did's must be refused");
    }

    #[test]
    fn tampering_with_a_signed_field_fails_verification() {
        let keypair = Keypair::generate();
        let mut event = event_for(&keypair);
        sign_ref_update(&keypair, &mut event).unwrap();
        verify_ref_update(&event).expect("baseline must verify before tampering");

        for tamper in [
            |e: &mut RefUpdateEvent| e.repo = "attacker/evil".into(),
            |e: &mut RefUpdateEvent| e.ref_name = "refs/heads/attacker".into(),
            |e: &mut RefUpdateEvent| e.new_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            |e: &mut RefUpdateEvent| e.old_sha = "cccccccccccccccccccccccccccccccccccccccc".into(),
            |e: &mut RefUpdateEvent| e.pusher_did = "did:key:zAttacker".into(),
            |e: &mut RefUpdateEvent| e.owner_did = Some("did:key:zAttacker".into()),
            |e: &mut RefUpdateEvent| e.timestamp = "2030-01-01T00:00:00Z".into(),
            |e: &mut RefUpdateEvent| e.cert_id = Some("cert-2".into()),
            |e: &mut RefUpdateEvent| e.cid = Some("bafyother".into()),
        ] {
            let mut tampered = event.clone();
            tamper(&mut tampered);
            verify_ref_update(&tampered)
                .expect_err("mutating any signed field must fail verification");
        }
    }

    /// The version is inside the signed region, in both directions, and the
    /// second direction is the one skip-when-zero creates.
    ///
    /// A version key beside the signature rather than under it is
    /// attacker-mutable and proves nothing, so downgrading a v1 event to v0
    /// has to be as detectable as upgrading a v0 event to v1. The two
    /// directions are not symmetric here: flipping 0 to 1 ADDS a key to the
    /// signing bytes, while flipping 1 to 0 REMOVES one, and only the second
    /// exercises the `skip_serializing_if` arm. Testing one direction would
    /// leave an encoding that emits the key unconditionally, or one that never
    /// emits it, indistinguishable from the correct one.
    #[test]
    fn the_version_is_covered_by_the_signature_in_both_directions() {
        let keypair = Keypair::generate();

        // Signed at v0, where the key is absent from the signing bytes.
        // Raising it on the received copy makes the key appear.
        let mut at_zero = event_for(&keypair);
        sign_ref_update(&keypair, &mut at_zero).unwrap();
        verify_ref_update(&at_zero).expect("baseline must verify before tampering");
        let mut raised = at_zero.clone();
        raised.v = 1;
        verify_ref_update(&raised)
            .expect_err("raising the version on a signed event must fail verification");

        // Signed at v1, where the key IS in the signing bytes. Lowering it to
        // zero on the received copy makes the key vanish, which is the arm a
        // one-directional test never reaches.
        let mut at_one = event_for(&keypair);
        at_one.v = 1;
        sign_ref_update(&keypair, &mut at_one).unwrap();
        verify_ref_update(&at_one).expect("a v1 event must verify against its own signature");
        let mut lowered = at_one.clone();
        lowered.v = 0;
        verify_ref_update(&lowered)
            .expect_err("lowering the version on a signed event must fail verification");
    }

    /// An event from a peer that predates the field parses as v0, and
    /// re-serializing it reproduces the versionless bytes. That round trip IS
    /// the v0 verification path: there is no separate legacy code path to keep
    /// working, only the property that the default and the skip agree.
    #[test]
    fn json_without_a_version_key_parses_as_v0_and_signs_without_one() {
        let old_json = serde_json::json!({
            "node_did": "did:key:zNode",
            "pusher_did": "did:key:zPusher",
            "repo": "zOwner/myrepo",
            "ref_name": "refs/heads/main",
            "old_sha": "0000000000000000000000000000000000000000",
            "new_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "timestamp": "2026-07-02T12:00:00Z",
            "cert_id": null,
            "cid": null
        });
        let deserialized: RefUpdateEvent = serde_json::from_value(old_json).unwrap();
        assert_eq!(
            deserialized.v, 0,
            "an event with no version key is the versionless form, which is v0"
        );

        let bytes = String::from_utf8(signing_bytes(&deserialized).unwrap()).unwrap();
        assert!(
            !bytes.contains("\"v\""),
            "a v0 event's signing bytes must carry no version key, or every peer \
             running the pre-version build computes different bytes; got: {bytes}"
        );
    }

    #[test]
    fn an_event_with_no_signature_is_rejected() {
        let keypair = Keypair::generate();
        let event = event_for(&keypair);
        assert_eq!(event.sig, None);
        verify_ref_update(&event).expect_err("an unsigned event must not verify");
    }

    /// Two surfaces judging the same input answer with the same sentence. The
    /// literals here are copied from `PeerWriteDenied` in db/mod.rs on purpose:
    /// if that wording changes, this goes red rather than letting the gossip
    /// surface drift into its own vocabulary for the same refusal.
    #[test]
    fn a_non_did_key_node_did_is_rejected_with_the_shared_sentence() {
        let keypair = Keypair::generate();
        let mut event = populated_event();
        event.node_did = "did:web:example.com".into();
        sign_ref_update(&keypair, &mut event).unwrap();

        let err = verify_ref_update(&event).expect_err("did:web must never authenticate");
        assert_eq!(
            err,
            "methodNotSupported: only did:key peers can be registered without a proof of control: did:web:example.com"
        );
    }

    // ── Ingest-path tests ─────────────────────────────────────────────────
    //
    // Every rejection case asserts BOTH sinks are empty: `received_ref_updates`
    // and `sync_queue`. They are two separate writes, so a guard that stops one
    // and not the other is exactly the bug this path is being fixed for, and a
    // row-count-only assertion would pass against that half-fix.

    use sqlx::PgPool;

    async fn ingest_db(pool: &PgPool) -> Db {
        let db = Db::for_testing(pool.clone());
        db.run_migrations()
            .await
            .expect("test schema migrations should apply");
        db
    }

    async fn seed_peer(pool: &PgPool, did: &str) {
        sqlx::query(
            "INSERT INTO peers (did, http_url, last_seen, last_ping_ok, announced_at)
             VALUES ($1, $2, $3, FALSE, $3)",
        )
        .bind(did)
        .bind("https://peer.example.com")
        .bind(Utc::now().to_rfc3339())
        .execute(pool)
        .await
        .expect("seed peer");
    }

    async fn count(pool: &PgPool, table: &str) -> i64 {
        sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(pool)
            .await
            .expect("count rows")
    }

    /// Both sinks, asserted separately. `context` names the case so a failure
    /// says which mode and which guard let the write through.
    async fn assert_nothing_written(pool: &PgPool, context: &str) {
        assert_eq!(
            count(pool, "received_ref_updates").await,
            0,
            "{context}: a rejected event must write no received_ref_updates row"
        );
        assert_eq!(
            count(pool, "sync_queue").await,
            0,
            "{context}: a rejected event must enqueue no sync_queue row"
        );
    }

    fn bytes_of(event: &RefUpdateEvent) -> Vec<u8> {
        serde_json::to_vec(event).expect("serialize event")
    }

    /// Zero the `peer_exists` tally, then read it back. The pair exists so a
    /// test can assert the DATABASE WAS NEVER TOUCHED, which no outcome value
    /// can express: a guard that runs above the debit and a guard that runs
    /// above the round trip return the identical `Rejected`.
    fn reset_peer_exists_calls() {
        PEER_EXISTS_CALLS.with(|calls| calls.set(0));
    }

    fn peer_exists_calls() -> usize {
        PEER_EXISTS_CALLS.with(|calls| calls.get())
    }

    /// Ingest one event against a limiter with no history, for the cases that
    /// are about a guard other than the rate brake. The rate-limit tests below
    /// hold one limiter across calls instead, since that is the state they
    /// assert on.
    async fn ingest_with_fresh_limiter(
        db: &Db,
        require_signed: bool,
        auto_sync: bool,
        data: &[u8],
        propagation_source: &PeerId,
    ) -> IngestOutcome {
        ingest_ref_update(
            db,
            &IngestLimiters::new(),
            &ReplayGuard::new(),
            require_signed,
            auto_sync,
            data,
            propagation_source,
        )
        .await
    }

    fn rejection_reason(outcome: IngestOutcome, context: &str) -> String {
        match outcome {
            IngestOutcome::Rejected(reason) => reason,
            IngestOutcome::Accepted => panic!("{context}: the event must be rejected"),
            IngestOutcome::UnsignedAdmitted => {
                panic!("{context}: the event must be rejected, not admitted unsigned")
            }
            IngestOutcome::WriteFailed(reason) => {
                panic!("{context}: the event must be rejected by a guard, not admitted and then failed to write: {reason}")
            }
            IngestOutcome::SourceRateLimited
            | IngestOutcome::AuthorRateLimited(_)
            | IngestOutcome::UnsignedSourceRateLimited(_) => {
                panic!("{context}: the event must be rejected by a guard, not by a rate brake")
            }
            IngestOutcome::Replayed => {
                panic!(
                    "{context}: the event must be rejected by a guard, not by the replay seen-set"
                )
            }
            IngestOutcome::StaleTimestamp(reason) => {
                panic!("{context}: the event must be rejected by a guard, not by the freshness window: {reason}")
            }
        }
    }

    /// Drive one prepared event through ingest in BOTH flag modes and assert it
    /// is refused by a guard, with no row and no queue entry either way.
    ///
    /// Six tests wrote this loop out by hand. Sharing it is not only less
    /// repetition: it means "in both modes" has ONE definition, so a case that
    /// only ever exercised `require_signed=true` cannot creep in unnoticed under
    /// a name that promises both.
    ///
    /// `label` names the witness ("tampered event"), and the mode is appended,
    /// so a failure still says which of the two directions broke.
    ///
    /// `expected_reason` is `Some((reason, why))` for the cases where the
    /// SENTENCE is the thing under test, carrying its own explanation of why
    /// that wording is load-bearing, since a shared assertion message could not
    /// say anything specific enough to be useful. `None` where the test only
    /// claims a guard refused it, and the particular guard is pinned by the
    /// witness rather than by the string.
    async fn assert_rejected_in_both_modes(
        db: &Db,
        pool: &PgPool,
        data: &[u8],
        label: &str,
        expected_reason: Option<(&str, &str)>,
    ) {
        for require_signed in [true, false] {
            let context = format!("{label}, require_signed={require_signed}");
            let outcome =
                ingest_with_fresh_limiter(db, require_signed, true, data, &PeerId::random()).await;
            assert_nothing_written(pool, &context).await;
            let reason = rejection_reason(outcome, &context);
            if let Some((expected, why)) = expected_reason {
                assert_eq!(reason, expected, "{context}: {why}");
            }
        }
    }

    /// R1, the core must-not: enforcement on, an unsigned event that merely
    /// CLAIMS a known peer's DID writes nothing. Anyone on the open mesh can
    /// send these, so this is the whole point of the unit.
    #[sqlx::test]
    async fn flag_on_unsigned_event_claiming_a_known_peer_writes_nothing(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let keypair = Keypair::generate();
        let event = event_for(&keypair);
        seed_peer(&pool, &event.node_did).await;

        let outcome =
            ingest_with_fresh_limiter(&db, true, true, &bytes_of(&event), &PeerId::random()).await;

        assert_nothing_written(&pool, "unsigned event with enforcement on").await;
        rejection_reason(outcome, "unsigned event with enforcement on");
    }

    /// An event from a build newer than this one is refused AS a version
    /// problem, in its own words.
    ///
    /// The witness is valid in every other respect on purpose: correctly
    /// signed by a key that resolves from its own `node_did`, seeded as a known
    /// peer, well-formed slug. So the version is the only rule that can reject
    /// it, and without the guard it is not rejected at all, it is ACCEPTED, and
    /// this node writes rows whose field semantics it does not know.
    ///
    /// The assertion is on the SENTENCE, not merely on the refusal, and that is
    /// the point of the test rather than a detail of it. An honest v1
    /// publisher's events would otherwise land as a signature mismatch,
    /// indistinguishable in logs and counters from forgery, and an operator
    /// watching a partition form would be reading an accusation instead of a
    /// version skew. Asserting only that the event was rejected cannot tell the
    /// two apart.
    #[sqlx::test]
    async fn an_unknown_version_is_refused_as_an_unknown_version(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let keypair = Keypair::generate();
        let mut event = event_for(&keypair);
        event.v = CURRENT_REF_UPDATE_VERSION + 1;
        sign_ref_update(&keypair, &mut event).unwrap();
        seed_peer(&pool, &event.node_did).await;
        // The witness must be rejectable only by the version rule, so confirm
        // the signature path would have admitted it.
        verify_ref_update(&event).expect("the witness must be correctly signed");

        assert_rejected_in_both_modes(
            &db,
            &pool,
            &bytes_of(&event),
            "v1 event",
            Some((
                "unsupported ref-update event version 1; this build understands version 0",
                "an unknown version must be named as one, never reported as a signature failure",
            )),
        )
        .await;
    }

    /// R2: a cryptographically valid signature that does not bind the claimed
    /// identity (the RUSTSEC-2022-0009 shape). Rejected in BOTH modes, because
    /// a present-but-wrong signature is forgery, never a legacy peer.
    #[sqlx::test]
    async fn a_signature_by_another_key_is_rejected_in_both_modes(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let signer = Keypair::generate();
        let claimed = Keypair::generate();
        let mut event = event_for(&claimed);
        sign_ref_update(&signer, &mut event).unwrap();
        seed_peer(&pool, &event.node_did).await;

        assert_rejected_in_both_modes(&db, &pool, &bytes_of(&event), "foreign-key signature", None)
            .await;
    }

    /// R2: a signed event whose payload was edited after signing.
    #[sqlx::test]
    async fn a_tampered_signed_event_is_rejected_in_both_modes(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let keypair = Keypair::generate();
        let mut event = event_for(&keypair);
        sign_ref_update(&keypair, &mut event).unwrap();
        seed_peer(&pool, &event.node_did).await;
        event.new_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into();

        assert_rejected_in_both_modes(&db, &pool, &bytes_of(&event), "tampered event", None).await;
    }

    /// R11: a non-did:key `node_did` cannot be authenticated by design, and the
    /// refusal answers in the SAME sentence as the peers-table gate.
    ///
    /// What this test guards is the REFUSAL WORDING, not the did-method
    /// gate itself. The event here is signed, so with that gate deleted
    /// `verify_ref_update` resolves `node_did` itself and returns the identical
    /// sentence; the assertion below cannot tell the two apart. The test that
    /// isolates the gate is
    /// `an_unsigned_non_did_key_event_from_a_known_peer_is_rejected_by_the_did_method_gate`.
    #[sqlx::test]
    async fn a_non_did_key_node_did_is_rejected_in_both_modes(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let keypair = Keypair::generate();
        let mut event = populated_event();
        event.node_did = "did:web:example.com".into();
        sign_ref_update(&keypair, &mut event).unwrap();
        seed_peer(&pool, &event.node_did).await;

        assert_rejected_in_both_modes(
            &db,
            &pool,
            &bytes_of(&event),
            "did:web node_did",
            Some((
                "methodNotSupported: only did:key peers can be registered without a proof of control: did:web:example.com",
                "the gossip surface must reuse the peers-table refusal sentence",
            )),
        )
        .await;
    }

    /// The load-bearing test for the did-method gate, and the ONLY
    /// combination that isolates it.
    ///
    /// Three inputs, each chosen to take one of the other guards out of the
    /// picture. The event is UNSIGNED, so `verify_ref_update` is never called
    /// and cannot resolve `node_did` on the gate's behalf. `require_signed` is
    /// FALSE, so the unsigned branch admits it rather than refusing it for a
    /// missing signature. The did:web DID is seeded into `peers`, so the
    /// known-peer gate admits it too. Everything downstream (the repo slug) is
    /// valid. With the gate present this is refused with the shared sentence;
    /// delete the gate and this exact event is accepted and written.
    #[sqlx::test]
    async fn an_unsigned_non_did_key_event_from_a_known_peer_is_rejected_by_the_did_method_gate(
        pool: PgPool,
    ) {
        let db = ingest_db(&pool).await;
        let mut event = populated_event();
        event.node_did = "did:web:example.com".into();
        assert_eq!(
            event.sig, None,
            "the gate must be what decides, not the sig"
        );
        seed_peer(&pool, &event.node_did).await;

        let context = "unsigned did:web event from a seeded peer, require_signed=false";
        let outcome =
            ingest_with_fresh_limiter(&db, false, true, &bytes_of(&event), &PeerId::random()).await;

        assert_nothing_written(&pool, context).await;
        assert_eq!(
            rejection_reason(outcome, context),
            "methodNotSupported: only did:key peers can be registered without a proof of control: did:web:example.com",
            "{context}: only the did-method gate can refuse this, so this is what goes red if it is removed"
        );
    }

    /// R3: authentication is not authorization. A correctly signed event from a
    /// DID nobody registered is still refused, mirroring the HTTP twin's
    /// unconditional known-peer gate.
    #[sqlx::test]
    async fn a_signed_event_from_an_unknown_peer_is_rejected_in_both_modes(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let keypair = Keypair::generate();
        let mut event = event_for(&keypair);
        sign_ref_update(&keypair, &mut event).unwrap();
        // Deliberately NOT seeded into the peers table.

        assert_rejected_in_both_modes(&db, &pool, &bytes_of(&event), "unknown peer DID", None)
            .await;
    }

    /// R4: the #272 slug guard, on this transport too. The slug reaches a
    /// `PathBuf::join` in the sync worker, so it is rejected before the row and
    /// before the queue entry.
    #[sqlx::test]
    async fn a_traversal_slug_is_rejected_before_any_write(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let keypair = Keypair::generate();
        let mut event = event_for(&keypair);
        event.repo = "../../x".into();
        sign_ref_update(&keypair, &mut event).unwrap();
        seed_peer(&pool, &event.node_did).await;

        assert_rejected_in_both_modes(&db, &pool, &bytes_of(&event), "traversal slug", None).await;
    }

    /// R6: the acceptance path, which is what keeps federation alive. A guard
    /// that rejects everything would pass every test above and fail here.
    #[sqlx::test]
    async fn flag_on_signed_known_peer_event_is_accepted_end_to_end(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let keypair = Keypair::generate();
        let mut event = event_for(&keypair);
        sign_ref_update(&keypair, &mut event).unwrap();
        seed_peer(&pool, &event.node_did).await;
        let source = PeerId::random();

        let outcome = ingest_with_fresh_limiter(&db, true, true, &bytes_of(&event), &source).await;
        assert!(
            matches!(outcome, IngestOutcome::Accepted),
            "a correctly signed event from a known peer must be accepted, got {outcome:?}"
        );

        let row: (String, String, String, String, String) = sqlx::query_as(
            "SELECT node_did, pusher_did, repo, ref_name, from_peer FROM received_ref_updates",
        )
        .fetch_one(&pool)
        .await
        .expect("exactly one ref-update row");
        assert_eq!(row.0, event.node_did);
        assert_eq!(row.1, "did:key:zPusher");
        assert_eq!(row.2, "zOwner/myrepo");
        assert_eq!(row.3, "refs/heads/main");
        // R9: from_peer records the FORWARDER, not the author.
        assert_eq!(row.4, source.to_string());

        assert_eq!(
            count(&pool, "sync_queue").await,
            1,
            "auto_sync on must enqueue the accepted event"
        );
    }

    /// The auto_sync=false half: the row lands, the queue stays empty. Without
    /// it, an ingest that enqueued unconditionally would go unnoticed.
    #[sqlx::test]
    async fn accepted_event_does_not_enqueue_when_auto_sync_is_off(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let keypair = Keypair::generate();
        let mut event = event_for(&keypair);
        sign_ref_update(&keypair, &mut event).unwrap();
        seed_peer(&pool, &event.node_did).await;

        let outcome =
            ingest_with_fresh_limiter(&db, true, false, &bytes_of(&event), &PeerId::random()).await;
        assert!(matches!(outcome, IngestOutcome::Accepted));

        assert_eq!(count(&pool, "received_ref_updates").await, 1);
        assert_eq!(
            count(&pool, "sync_queue").await,
            0,
            "auto_sync off must not enqueue"
        );
    }

    /// R7, the rolling-upgrade window: with enforcement off, an unsigned event
    /// from a KNOWN peer is still admitted. Turning the flag on is the
    /// operator's step, not a code change, so this path has to keep working
    /// until they take it.
    ///
    /// It is `UnsignedAdmitted`, not `Accepted`: the event wrote rows without
    /// authenticating its sender, and the two must not be observably the same.
    ///
    /// The ingest path also emits a `warn!` pointing at the flag on this
    /// branch. Nothing here asserts that, so the log line is uncovered:
    /// deleting it leaves this test green. Say so rather than implying the
    /// wording is pinned.
    #[sqlx::test]
    async fn flag_off_unsigned_known_peer_event_is_accepted(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let keypair = Keypair::generate();
        let event = event_for(&keypair);
        assert_eq!(event.sig, None);
        seed_peer(&pool, &event.node_did).await;

        let outcome =
            ingest_with_fresh_limiter(&db, false, true, &bytes_of(&event), &PeerId::random()).await;
        assert!(
            matches!(outcome, IngestOutcome::UnsignedAdmitted),
            "an unsigned known-peer event must be admitted (distinct from Accepted) through the rolling-upgrade window, got {outcome:?}"
        );
        assert_eq!(count(&pool, "received_ref_updates").await, 1);
        assert_eq!(count(&pool, "sync_queue").await, 1);
    }

    // ── Emit side ─────────────────────────────────────────────────────────

    /// The round trip that matters: bytes built by the emit path are fed to the
    /// real ingest with enforcement ON, and must be accepted.
    ///
    /// Nothing else proves emit and verify agree on the signing input by
    /// execution. The golden test pins the input's shape, and the helper tests
    /// sign and verify through `sign_ref_update` directly, but only this one
    /// exercises what the node actually puts on the wire. If it fails once the
    /// fleet turns enforcement on, every node drops every other node's events.
    #[sqlx::test]
    async fn emitted_bytes_verify_through_ingest_with_enforcement_on(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let keypair = Keypair::generate();
        // Straight off the publish path: the caller hands over an unsigned
        // event, exactly as `publish_ref_update` does.
        let event = event_for(&keypair);
        assert_eq!(event.sig, None, "the emit path is what adds the signature");
        seed_peer(&pool, &event.node_did).await;

        let bytes = signed_publish_bytes(&keypair, &event).expect("emit path must produce bytes");

        let published: RefUpdateEvent =
            serde_json::from_slice(&bytes).expect("published bytes must parse");
        assert!(
            published.sig.is_some(),
            "an emitted event must carry a signature"
        );

        let outcome = ingest_with_fresh_limiter(&db, true, true, &bytes, &PeerId::random()).await;
        assert!(
            matches!(outcome, IngestOutcome::Accepted),
            "bytes from the emit path must survive ingest with enforcement on, got {outcome:?}"
        );
        assert_eq!(count(&pool, "received_ref_updates").await, 1);
    }

    /// The publish arm's own output, driven end to end: whatever
    /// `ref_update_publish_args` hands gossipsub must be signed, must go out on
    /// the wire topic peers subscribe to, and must survive ingest with
    /// enforcement ON.
    ///
    /// This is deliberately not a second copy of the round trip above. That test
    /// calls `signed_publish_bytes`, one layer below the loop; this one calls
    /// the function the `select!` arm calls, so an arm that stopped signing
    /// would have to be rewritten rather than merely reordered to keep the suite
    /// green. The topic is asserted against the literal string, not against
    /// `REF_UPDATES_TOPIC`, because comparing the constant to itself proves
    /// nothing: the topic name is a wire format shared with every deployed peer,
    /// and renaming it silently partitions the mesh into two meshes that each
    /// look healthy.
    ///
    /// What is still NOT observed, and is not implied to be: the `select!` arm
    /// dispatching a `P2pCommand::PublishRefUpdate` into this function, and
    /// `require_signed` reaching `ingest_ref_update` from `main.rs` the right
    /// way round. Both live inside `p2p::start`, which needs a live swarm to
    /// drive, so an inverted flag threaded from the config would still leave
    /// this green. Uncovered seam, named.
    #[sqlx::test]
    async fn the_publish_arms_output_is_signed_and_survives_enforced_ingest(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let keypair = Keypair::generate();
        // Unsigned on the way in, exactly as `publish_ref_update` hands it over.
        let event = event_for(&keypair);
        assert_eq!(
            event.sig, None,
            "the publish path is what adds the signature"
        );
        seed_peer(&pool, &event.node_did).await;

        let (topic, bytes) =
            ref_update_publish_args(&keypair, &event).expect("the publish arm must produce args");

        assert_eq!(
            topic.to_string(),
            "gitlawb/ref-updates/v1",
            "the publish topic is a wire format; renaming it partitions the mesh"
        );

        let published: RefUpdateEvent =
            serde_json::from_slice(&bytes).expect("published bytes must parse");
        assert!(
            published.sig.is_some(),
            "the bytes the loop hands gossipsub must carry a signature"
        );

        let outcome = ingest_with_fresh_limiter(&db, true, true, &bytes, &PeerId::random()).await;
        assert!(
            matches!(outcome, IngestOutcome::Accepted),
            "the publish arm's bytes must survive ingest with enforcement on, got {outcome:?}"
        );
        assert_eq!(count(&pool, "received_ref_updates").await, 1);
    }

    // ── Durable-write failure ─────────────────────────────────────────────
    //
    // `WriteFailed` is unreachable from every other test here: a rejection stops
    // above both writes, and an acceptance has both succeed. So the variant that
    // exists to stop `Accepted` from meaning "authenticated but never stored"
    // was never once observed, and `rejection_reason` panics rather than
    // distinguishes if it turns up.
    //
    // The failure is made REAL by dropping the target table on the live test
    // database, so the error comes back from Postgres on the actual write rather
    // than from a stub standing in for one. Both directions are driven, because
    // the property is that the two writes are attempted INDEPENDENTLY: a test
    // that only broke the first could not tell that from "the first failure
    // aborts the rest", and each case therefore asserts what landed in the sink
    // that was left intact.

    /// The ref-update row fails, the queue entry still lands.
    #[sqlx::test]
    async fn a_failed_ref_update_insert_reports_write_failed_and_still_enqueues(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let keypair = Keypair::generate();
        let mut event = event_for(&keypair);
        sign_ref_update(&keypair, &mut event).unwrap();
        seed_peer(&pool, &event.node_did).await;

        sqlx::query("DROP TABLE received_ref_updates")
            .execute(&pool)
            .await
            .expect("drop the ref-update sink so its write genuinely fails");

        let outcome =
            ingest_with_fresh_limiter(&db, true, true, &bytes_of(&event), &PeerId::random()).await;

        match outcome {
            IngestOutcome::WriteFailed(reason) => assert!(
                reason.contains("failed to store received ref-update"),
                "the outcome must name the write that failed, got: {reason}"
            ),
            other => panic!(
                "an event whose durable write failed must not be reported as accepted, got {other:?}"
            ),
        }

        assert_eq!(
            count(&pool, "sync_queue").await,
            1,
            "the queue entry is a separate write and must not be lost to the row's failure"
        );
    }

    /// The mirror: the queue entry fails, the ref-update row still lands.
    #[sqlx::test]
    async fn a_failed_enqueue_reports_write_failed_and_still_stores_the_row(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let keypair = Keypair::generate();
        let mut event = event_for(&keypair);
        sign_ref_update(&keypair, &mut event).unwrap();
        seed_peer(&pool, &event.node_did).await;

        sqlx::query("DROP TABLE sync_queue")
            .execute(&pool)
            .await
            .expect("drop the queue sink so its write genuinely fails");

        let outcome =
            ingest_with_fresh_limiter(&db, true, true, &bytes_of(&event), &PeerId::random()).await;

        match outcome {
            IngestOutcome::WriteFailed(reason) => assert!(
                reason.contains("failed to enqueue sync"),
                "the outcome must name the write that failed, got: {reason}"
            ),
            other => panic!(
                "an event whose enqueue failed must not be reported as accepted, got {other:?}"
            ),
        }

        assert_eq!(
            count(&pool, "received_ref_updates").await,
            1,
            "the ref-update row is a separate write and must not be lost to the enqueue failure"
        );
    }

    // ── Ingest rate limits ────────────────────────────────────────────────

    /// The documented numbers, and then the check that matters: each cap
    /// actually reaches the limiter production builds. Asserting the constants
    /// alone leaves `IngestLimiters::new` free to pass the wrong one, and the
    /// three caps are close enough in shape that a copy-paste swap reads fine.
    #[test]
    fn the_ingest_budgets_are_wired_as_documented() {
        assert_eq!(GOSSIP_SOURCE_MAX_EVENTS, 2000);
        assert_eq!(GOSSIP_UNSIGNED_SOURCE_MAX_EVENTS, 1500);
        assert_eq!(GOSSIP_AUTHOR_MAX_EVENTS, 500);
        assert_eq!(GOSSIP_INGEST_WINDOW, Duration::from_secs(60));
        assert_eq!(GOSSIP_INGEST_MAX_SOURCES, 200_000);
        assert_eq!(GOSSIP_INGEST_MAX_AUTHORS, 200_000);

        let limiters = IngestLimiters::new();
        for (name, limiter, cap, _) in limiters.all() {
            assert_eq!(
                limiter.max_requests(),
                cap,
                "the {name} limiter must be built with the cap it is documented to carry"
            );
        }
    }

    /// The key ceilings have to reach the limiters production builds, not just
    /// exist as constants. Asserting the constants alone leaves
    /// `IngestLimiters::new` free to call the unbounded-ish `new`, which
    /// silently swaps in `DEFAULT_MAX_KEYS` and passes every other test here.
    ///
    /// Driving 200_000 distinct keys to observe the cap by behavior would cost
    /// more than it proves, so this reads the wired values through the
    /// test-only accessor instead. What it does NOT cover is the eviction
    /// behavior at the cap; that is `rate_limit`'s own test's job.
    #[test]
    fn every_ingest_limiter_carries_its_key_ceiling() {
        let limiters = IngestLimiters::new();
        for (name, limiter, _, ceiling) in limiters.all() {
            assert_eq!(
                limiter.max_keys(),
                ceiling,
                "the {name} limiter must be built bounded by its documented key ceiling"
            );
        }
    }

    /// The ingest limiters live as locals of the swarm task, so the periodic
    /// `sweep_rate_limiters` in `main.rs` cannot see them and its completeness
    /// test cannot cover them. This is that pair's counterpart: it proves the
    /// swarm loop's own sweep actually reclaims a key from EVERY ingest limiter,
    /// not just the first one someone remembered.
    ///
    /// Both loops walk `all()`, which destructures `Self`, and `cleanup` walks
    /// `each()`, which does the same. So a fourth limiter added later cannot
    /// slip past this the way `/ipfs` slipped past the `AppState` sweeper: it
    /// fails to compile in three places before it can fail silently in one.
    ///
    /// The short window comes from `with_window` rather than a limiter built by
    /// hand, so the thing under test is the real struct with its real caps.
    #[tokio::test]
    async fn the_swarm_sweep_evicts_expired_keys_from_every_ingest_limiter() {
        let window = Duration::from_millis(30);
        let limiters = IngestLimiters::with_window(window);

        for (name, limiter, _, _) in limiters.all() {
            assert!(
                limiter.check("forwarding-peer").await,
                "the {name} limiter must admit the first event, or this test proves nothing"
            );
            assert_eq!(limiter.tracked_keys().await, 1);
        }

        tokio::time::sleep(window * 3).await;
        limiters.cleanup().await;

        for (name, limiter, _, _) in limiters.all() {
            assert_eq!(
                limiter.tracked_keys().await,
                0,
                "the {name} ingest limiter was not swept"
            );
        }
    }

    /// Every outcome the ingest path can return has to reach the counter under
    /// its own label, because `/metrics` is the only externally observable
    /// surface this daemon exposes and an unlabelled outcome is an invisible
    /// one. The exhaustive match in `metric_label` is what makes the next
    /// variant a compile error; this pins the labels themselves, since a
    /// copy-paste that gave two variants the same string would still compile and
    /// would silently merge a shed reason into another on the dashboard.
    #[test]
    fn every_ingest_outcome_carries_a_distinct_metric_label() {
        let labels = [
            IngestOutcome::Accepted.metric_label(),
            IngestOutcome::UnsignedAdmitted.metric_label(),
            IngestOutcome::WriteFailed("db down".into()).metric_label(),
            IngestOutcome::Rejected("malformed".into()).metric_label(),
            IngestOutcome::SourceRateLimited.metric_label(),
            IngestOutcome::AuthorRateLimited("did:key:a".into()).metric_label(),
            IngestOutcome::UnsignedSourceRateLimited("peer".into()).metric_label(),
            IngestOutcome::Replayed.metric_label(),
            IngestOutcome::StaleTimestamp("too old".into()).metric_label(),
        ];
        assert_eq!(
            labels,
            [
                "accepted",
                "unsigned_admitted",
                "write_failed",
                "rejected",
                "source_rate_limited",
                "author_rate_limited",
                "unsigned_source_rate_limited",
                "replayed",
                "stale_timestamp",
            ]
        );

        let unique: std::collections::HashSet<&str> = labels.iter().copied().collect();
        assert_eq!(
            unique.len(),
            labels.len(),
            "two outcomes share a label, which would merge them in the counter"
        );
    }

    /// The ordering test, and the reason the pre-parse brake exists at all.
    /// Signature verification is the expensive step, so a limiter sitting after
    /// it lets an unauthenticated flood buy exactly the CPU the brake was meant
    /// to protect.
    ///
    /// This discriminates the ordering by execution rather than by inspection.
    /// The flood is garbage that neither parses nor verifies. With the check
    /// first, those messages spend the source's budget and the next event, a
    /// perfectly valid signed known-peer one, comes back `SourceRateLimited`.
    /// Move the check below the parse or below verification and the garbage
    /// never reaches the limiter, the budget is untouched, and that last event
    /// is accepted: this assertion is what goes red.
    #[sqlx::test]
    async fn rate_limit_runs_before_parse_and_signature_verification(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        let source = PeerId::random();
        let keypair = Keypair::generate();
        let mut event = event_for(&keypair);
        sign_ref_update(&keypair, &mut event).unwrap();
        seed_peer(&pool, &event.node_did).await;

        for i in 0..GOSSIP_SOURCE_MAX_EVENTS {
            let outcome = ingest_ref_update(
                &db,
                &limiters,
                &ReplayGuard::new(),
                true,
                true,
                b"not json at all",
                &source,
            )
            .await;
            assert!(
                matches!(outcome, IngestOutcome::Rejected(_)),
                "flood message {i} is inside the budget, so it is admitted and then dropped as malformed, got {outcome:?}"
            );
        }

        let outcome = ingest_ref_update(
            &db,
            &limiters,
            &ReplayGuard::new(),
            true,
            true,
            &bytes_of(&event),
            &source,
        )
        .await;
        assert!(
            matches!(outcome, IngestOutcome::SourceRateLimited),
            "the event past the budget from one source inside the window must be rate limited; \
             an unverifiable flood has to spend the budget, which only happens if the \
             check precedes the parse and the signature work. Got {outcome:?}"
        );
        assert_nothing_written(&pool, "source over its ingest budget").await;
    }

    /// The pre-parse budget is per source peer, not one global bucket. Without
    /// this, one noisy or hostile mesh source would silence the whole fleet.
    #[sqlx::test]
    async fn rate_limit_is_per_source_not_global(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        let throttled = PeerId::random();
        let other = PeerId::random();
        let keypair = Keypair::generate();
        let mut event = event_for(&keypair);
        sign_ref_update(&keypair, &mut event).unwrap();
        seed_peer(&pool, &event.node_did).await;

        for _ in 0..GOSSIP_SOURCE_MAX_EVENTS {
            ingest_ref_update(
                &db,
                &limiters,
                &ReplayGuard::new(),
                true,
                true,
                b"not json at all",
                &throttled,
            )
            .await;
        }
        let outcome = ingest_ref_update(
            &db,
            &limiters,
            &ReplayGuard::new(),
            true,
            true,
            &bytes_of(&event),
            &throttled,
        )
        .await;
        assert!(
            matches!(outcome, IngestOutcome::SourceRateLimited),
            "the first source must be over budget, got {outcome:?}"
        );

        let outcome = ingest_ref_update(
            &db,
            &limiters,
            &ReplayGuard::new(),
            true,
            true,
            &bytes_of(&event),
            &other,
        )
        .await;
        assert!(
            matches!(outcome, IngestOutcome::Accepted),
            "a second peer keeps its own budget while the first is throttled, got {outcome:?}"
        );
        assert_eq!(
            count(&pool, "received_ref_updates").await,
            1,
            "the second peer's event is the only one that should have been written"
        );
    }

    /// FINDING 2, the victim-denial case, and the reason the tight bound moved
    /// off `propagation_source`. Junk relayed through an honest neighbour is
    /// charged to that neighbour's key, because it is the only identity
    /// available before parsing. What must NOT follow is that the neighbour
    /// stops being a usable path for real traffic: a correctly signed event
    /// from a known author arriving down the same edge is still accepted.
    ///
    /// The flood here runs to one below the source ceiling, which is far past
    /// the old 60-per-source bound, so under that bound this event is the one
    /// that came back rate limited.
    ///
    /// What this canNOT express: the junk never reaches the author limiter at
    /// all (it does not parse), and whether the neighbour's own budget is spent
    /// on OTHER receivers is a property of the live mesh, which needs the swarm
    /// loop and is out of scope here.
    #[sqlx::test]
    async fn a_junk_flood_down_one_edge_does_not_deny_a_valid_author_on_that_edge(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        let neighbour = PeerId::random();
        let keypair = Keypair::generate();
        let mut event = event_for(&keypair);
        sign_ref_update(&keypair, &mut event).unwrap();
        seed_peer(&pool, &event.node_did).await;

        for _ in 0..GOSSIP_SOURCE_MAX_EVENTS - 1 {
            ingest_ref_update(
                &db,
                &limiters,
                &ReplayGuard::new(),
                true,
                true,
                b"not json at all",
                &neighbour,
            )
            .await;
        }

        let outcome = ingest_ref_update(
            &db,
            &limiters,
            &ReplayGuard::new(),
            true,
            true,
            &bytes_of(&event),
            &neighbour,
        )
        .await;
        assert!(
            matches!(outcome, IngestOutcome::Accepted),
            "an honest author must still get through an edge that carried a junk flood, got {outcome:?}"
        );
        assert_eq!(count(&pool, "received_ref_updates").await, 1);
        assert_eq!(count(&pool, "sync_queue").await, 1);
    }

    /// The per-author budget, end to end: a full budget of signed events from
    /// one known author is accepted, the next one is refused and writes NOTHING
    /// to either sink, and a DIFFERENT known author on the SAME mesh edge is
    /// unaffected.
    ///
    /// The last assertion is the other half of FINDING 2. With the tight bound
    /// keyed on `propagation_source`, one author exhausting the budget took the
    /// edge down for every author sharing it; keyed on the authenticated DID,
    /// the cost lands on the principal that incurred it.
    #[sqlx::test]
    async fn the_author_budget_bounds_one_author_without_touching_another(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        let replay_guard = ReplayGuard::new();
        let source = PeerId::random();
        let noisy = Keypair::generate();
        let quiet = Keypair::generate();
        seed_peer(&pool, &noisy.did().to_string()).await;
        seed_peer(&pool, &quiet.did().to_string()).await;

        // ONE guard across the whole burst, and a DISTINCT event per iteration.
        //
        // Both halves are deliberate. The obvious repair when the seen-set
        // landed was a fresh guard per call, which keeps this test green while
        // gutting the property it exists to prove: under a shared guard the
        // same bytes answer `Replayed` from iteration two onward, so the author
        // budget would never be exercised past a single event and the
        // rate-limit assertion below would be vacuous. Varying `ref_name` and
        // re-signing gives 500 events that are all genuinely new to the
        // seen-set and all charged to the same proven author, which is the
        // state this test is about. Same idiom as the 61-ref push test.
        //
        // One timestamp, stamped here and reused by all 500 iterations, so the
        // loop must finish inside the 600-second freshness window or the tail
        // of the burst starts answering `StaleTimestamp` instead of exercising
        // the budget. Measured at roughly 5 seconds in a debug build, so the
        // margin is about two orders of magnitude, but the dependency is
        // invisible from the loop body and worth naming.
        let mut event = event_for(&noisy);
        for i in 0..GOSSIP_AUTHOR_MAX_EVENTS {
            event.ref_name = format!("refs/heads/burst{i}");
            sign_ref_update(&noisy, &mut event).unwrap();
            let outcome = ingest_ref_update(
                &db,
                &limiters,
                &replay_guard,
                true,
                true,
                &bytes_of(&event),
                &source,
            )
            .await;
            assert!(
                matches!(outcome, IngestOutcome::Accepted),
                "event {i} is inside the author budget and must be accepted, got {outcome:?}"
            );
        }
        let accepted = GOSSIP_AUTHOR_MAX_EVENTS as i64;
        assert_eq!(count(&pool, "received_ref_updates").await, accepted);
        assert_eq!(count(&pool, "sync_queue").await, accepted);

        // Distinct again, for the same reason the burst above is: the budget is
        // what must refuse this event, so it has to be new to the seen-set or
        // the assertion would pass on a `Replayed` that says nothing about the
        // author budget at all.
        event.ref_name = "refs/heads/over-budget".into();
        sign_ref_update(&noisy, &mut event).unwrap();
        let outcome = ingest_ref_update(
            &db,
            &limiters,
            &replay_guard,
            true,
            true,
            &bytes_of(&event),
            &source,
        )
        .await;
        match &outcome {
            IngestOutcome::AuthorRateLimited(did) => assert_eq!(
                did, &event.node_did,
                "the refusal must name the author it was charged to"
            ),
            other => panic!("the over-budget author must be refused, got {other:?}"),
        }
        // Both sinks, separately: an over-budget refusal is a refusal, so
        // neither the row nor the queue entry may move.
        assert_eq!(
            count(&pool, "received_ref_updates").await,
            accepted,
            "an over-budget refusal must write no received_ref_updates row"
        );
        assert_eq!(
            count(&pool, "sync_queue").await,
            accepted,
            "an over-budget refusal must enqueue no sync_queue row"
        );

        let mut other_event = event_for(&quiet);
        other_event.repo = "zOwner/otherrepo".into();
        sign_ref_update(&quiet, &mut other_event).unwrap();
        let outcome = ingest_ref_update(
            &db,
            &limiters,
            &replay_guard,
            true,
            true,
            &bytes_of(&other_event),
            &source,
        )
        .await;
        assert!(
            matches!(outcome, IngestOutcome::Accepted),
            "a second author sharing the mesh edge keeps its own budget, got {outcome:?}"
        );
        assert_eq!(count(&pool, "received_ref_updates").await, accepted + 1);
    }

    /// The victim must-not, and the whole reason the author budget is charged
    /// only to a proven author. With enforcement off, an unsigned event's
    /// `node_did` is asserted, not proven: anyone on the open mesh can name a
    /// registered DID. If that claim debits the author bucket, an attacker
    /// spends a NAMED victim's budget from an unrelated `PeerId` and the
    /// victim's own genuine signed pushes come back `AuthorRateLimited`. The
    /// attacker picks the target, which is what makes this a P1 rather than a
    /// fairness wart.
    ///
    /// The flood runs to exactly the author cap, so under the pre-fix shape the
    /// signed event below is the first one past it.
    #[sqlx::test]
    async fn an_unsigned_flood_naming_a_victim_does_not_spend_the_victim_budget(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        let attacker_edge = PeerId::random();
        let victim = Keypair::generate();
        seed_peer(&pool, &victim.did().to_string()).await;

        // Unsigned, claiming the victim's DID, relayed from an edge the victim
        // has nothing to do with.
        let claim = bytes_of(&event_for(&victim));
        for i in 0..GOSSIP_AUTHOR_MAX_EVENTS {
            let outcome = ingest_ref_update(
                &db,
                &limiters,
                &ReplayGuard::new(),
                false,
                true,
                &claim,
                &attacker_edge,
            )
            .await;
            assert!(
                matches!(outcome, IngestOutcome::UnsignedAdmitted),
                "unsigned event {i} is inside every budget and is admitted in the rolling-upgrade window, got {outcome:?}"
            );
        }

        let mut genuine = event_for(&victim);
        genuine.ref_name = "refs/heads/genuine".into();
        sign_ref_update(&victim, &mut genuine).unwrap();
        let outcome = ingest_ref_update(
            &db,
            &limiters,
            &ReplayGuard::new(),
            false,
            true,
            &bytes_of(&genuine),
            &PeerId::random(),
        )
        .await;
        assert!(
            matches!(outcome, IngestOutcome::Accepted),
            "the victim's own signed push must survive an unsigned flood that merely claimed its DID, got {outcome:?}"
        );
        // The sink moved, not just the outcome class: `Accepted` alone would
        // still hold if the writes had been skipped.
        assert_eq!(
            count(&pool, "received_ref_updates").await,
            GOSSIP_AUTHOR_MAX_EVENTS as i64 + 1,
            "the victim's signed event must land its own row"
        );
        assert_eq!(
            count(&pool, "sync_queue").await,
            GOSSIP_AUTHOR_MAX_EVENTS as i64 + 1,
            "the victim's signed event must land its own queue entry"
        );
    }

    /// The brake must sit in front of the work it bounds, not behind it.
    ///
    /// An author already over its budget is going to be shed no matter what the
    /// peer lookup says, so paying a Postgres round trip first is work done for a
    /// request that was never going to be admitted. A signed author can drive that
    /// at the pre-parse source rate, and with peer-id rotation past it.
    ///
    /// The counter is what makes this a real assertion rather than a restatement
    /// of the code: it observes the lookup NOT happening, which reading the
    /// ordering cannot do.
    #[sqlx::test]
    async fn an_over_budget_author_is_shed_without_a_peer_lookup(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        let author = Keypair::generate();
        seed_peer(&pool, &author.did().to_string()).await;

        // A distinct signed event per iteration: identical bytes are a replay and
        // would be dropped by that guard instead of reaching the budget.
        let signed_nth = |n: usize| {
            let mut e = event_for(&author);
            e.ref_name = format!("refs/heads/b{n}");
            sign_ref_update(&author, &mut e).unwrap();
            e
        };
        for i in 0..GOSSIP_AUTHOR_MAX_EVENTS {
            let outcome = ingest_ref_update(
                &db,
                &limiters,
                &ReplayGuard::new(),
                true,
                true,
                &bytes_of(&signed_nth(i)),
                &PeerId::random(),
            )
            .await;
            assert!(
                matches!(outcome, IngestOutcome::Accepted),
                "event {i} is inside the budget, got {outcome:?}"
            );
        }

        reset_peer_exists_calls();
        let outcome = ingest_ref_update(
            &db,
            &limiters,
            &ReplayGuard::new(),
            true,
            true,
            &bytes_of(&signed_nth(GOSSIP_AUTHOR_MAX_EVENTS)),
            &PeerId::random(),
        )
        .await;
        assert!(
            matches!(outcome, IngestOutcome::AuthorRateLimited(_)),
            "the over-budget author must be shed, got {outcome:?}"
        );
        assert_eq!(
            peer_exists_calls(),
            0,
            "an over-budget author must be shed BEFORE the peer lookup; the brake \
             belongs in front of the work it bounds"
        );
    }

    /// The must-not that keeps the early shed from becoming a key-farming axis.
    ///
    /// The early check is a READ. An author the limiter has never seen must not
    /// gain a map entry from it, or a flood of self-minted signed DIDs could fill
    /// the bounded author map without ever registering a peer, and legitimate new
    /// authors would then be shed once it was full.
    #[sqlx::test]
    async fn the_early_author_check_does_not_track_an_unseen_did(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        let stranger = Keypair::generate();
        // Deliberately NOT seeded: an unregistered DID must be refused by the peer
        // lookup, and must leave no trace in the author limiter on the way.
        let mut e = event_for(&stranger);
        sign_ref_update(&stranger, &mut e).unwrap();

        let before = limiters.author.tracked_keys().await;
        let outcome = ingest_ref_update(
            &db,
            &limiters,
            &ReplayGuard::new(),
            true,
            true,
            &bytes_of(&e),
            &PeerId::random(),
        )
        .await;
        assert!(
            matches!(outcome, IngestOutcome::Rejected(_)),
            "an unregistered DID is refused by the peer lookup, got {outcome:?}"
        );
        assert_eq!(
            limiters.author.tracked_keys().await,
            before,
            "the early check must not allocate a map entry for a DID it has never \
             seen, or the shed becomes its own memory-fill surface"
        );
    }

    /// Exhaust one edge's unsigned budget and hand back the source that was
    /// spent, so the callers below can assert what happens next.
    async fn spend_unsigned_budget(db: &Db, limiters: &IngestLimiters, claim: &[u8]) -> PeerId {
        let source = PeerId::random();
        for i in 0..GOSSIP_UNSIGNED_SOURCE_MAX_EVENTS {
            let outcome = ingest_ref_update(
                db,
                limiters,
                &ReplayGuard::new(),
                false,
                true,
                claim,
                &source,
            )
            .await;
            assert!(
                matches!(outcome, IngestOutcome::UnsignedAdmitted),
                "unsigned event {i} is inside the unsigned budget and must be admitted, got {outcome:?}"
            );
        }
        source
    }

    /// Taking the author debit off unsigned traffic must not leave that traffic
    /// unbounded. It is charged to the forwarder instead, which is the only
    /// identity an unsigned event actually establishes.
    ///
    /// The last assertion is the half that keeps the new bucket honest: a spent
    /// unsigned budget must not gate VERIFIED traffic down the same edge. That
    /// is what fails if the charge is put in both signature arms rather than
    /// only the unsigned one.
    #[sqlx::test]
    async fn the_unsigned_path_is_bounded_on_the_forwarder(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        let author = Keypair::generate();
        seed_peer(&pool, &author.did().to_string()).await;

        let claim = bytes_of(&event_for(&author));
        let source = spend_unsigned_budget(&db, &limiters, &claim).await;
        let spent = GOSSIP_UNSIGNED_SOURCE_MAX_EVENTS as i64;
        assert_eq!(
            count(&pool, "received_ref_updates").await,
            spent,
            "every admitted unsigned event must land its row"
        );
        assert_eq!(
            count(&pool, "sync_queue").await,
            spent,
            "every admitted unsigned event must land its queue entry"
        );

        let outcome = ingest_ref_update(
            &db,
            &limiters,
            &ReplayGuard::new(),
            false,
            true,
            &claim,
            &source,
        )
        .await;
        match &outcome {
            IngestOutcome::UnsignedSourceRateLimited(named) => assert_eq!(
                named,
                &source.to_string(),
                "the refusal must name the forwarder it was charged to"
            ),
            other => panic!("the event past the unsigned budget must be shed, got {other:?}"),
        }
        assert_eq!(
            count(&pool, "received_ref_updates").await,
            spent,
            "a shed unsigned event must write no received_ref_updates row"
        );
        assert_eq!(
            count(&pool, "sync_queue").await,
            spent,
            "a shed unsigned event must enqueue no sync_queue row"
        );

        let mut signed = event_for(&author);
        signed.ref_name = "refs/heads/signed".into();
        sign_ref_update(&author, &mut signed).unwrap();
        let outcome = ingest_ref_update(
            &db,
            &limiters,
            &ReplayGuard::new(),
            false,
            true,
            &bytes_of(&signed),
            &source,
        )
        .await;
        assert!(
            matches!(outcome, IngestOutcome::Accepted),
            "the unsigned budget must not gate verified traffic down the same edge, got {outcome:?}"
        );
        assert_eq!(
            count(&pool, "received_ref_updates").await,
            spent + 1,
            "the signed event must land its own row"
        );
    }

    /// The unsigned bucket keys on the FORWARDER, not on the DID the event
    /// claims. Keying it on `node_did` would pass the victim must-not above
    /// while rebuilding the same victim-selection hole one layer down: an
    /// attacker would again spend a named victim's budget with events nobody
    /// proved they authored.
    #[sqlx::test]
    async fn the_unsigned_budget_keys_on_the_forwarder_not_the_claimed_did(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        let author = Keypair::generate();
        seed_peer(&pool, &author.did().to_string()).await;

        let claim = bytes_of(&event_for(&author));
        let spent_source = spend_unsigned_budget(&db, &limiters, &claim).await;
        assert!(matches!(
            ingest_ref_update(
                &db,
                &limiters,
                &ReplayGuard::new(),
                false,
                true,
                &claim,
                &spent_source
            )
            .await,
            IngestOutcome::UnsignedSourceRateLimited(_)
        ));

        // Same bytes, same claimed DID, a different forwarder.
        let fresh_source = PeerId::random();
        let outcome = ingest_ref_update(
            &db,
            &limiters,
            &ReplayGuard::new(),
            false,
            true,
            &claim,
            &fresh_source,
        )
        .await;
        assert!(
            matches!(outcome, IngestOutcome::UnsignedAdmitted),
            "the claimed DID must not carry a spent budget between forwarders, got {outcome:?}"
        );
        assert_eq!(
            count(&pool, "received_ref_updates").await,
            GOSSIP_UNSIGNED_SOURCE_MAX_EVENTS as i64 + 1,
            "the event from the fresh forwarder must land its own row"
        );
    }

    /// The honest-relay cost of keying on the forwarder, made explicit rather
    /// than discovered later: once an edge has spent its unsigned budget, a
    /// perfectly legitimate unsigned event from a DIFFERENT author arriving
    /// down that edge is shed too.
    ///
    /// This is the tradeoff the 1500 cap is sized against, and it is why the
    /// cap is three times the largest legitimate single-author burst rather
    /// than equal to it.
    #[sqlx::test]
    async fn a_spent_unsigned_edge_sheds_a_second_unsigned_author_too(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        let noisy = Keypair::generate();
        let bystander = Keypair::generate();
        seed_peer(&pool, &noisy.did().to_string()).await;
        seed_peer(&pool, &bystander.did().to_string()).await;

        let claim = bytes_of(&event_for(&noisy));
        let source = spend_unsigned_budget(&db, &limiters, &claim).await;

        let mut other = event_for(&bystander);
        other.repo = "zOwner/otherrepo".into();
        let outcome = ingest_ref_update(
            &db,
            &limiters,
            &ReplayGuard::new(),
            false,
            true,
            &bytes_of(&other),
            &source,
        )
        .await;
        match &outcome {
            IngestOutcome::UnsignedSourceRateLimited(named) => assert_eq!(
                named,
                &source.to_string(),
                "the shed must name the forwarder, not the bystanding author"
            ),
            other => panic!(
                "a second unsigned author down a spent edge is shed by design, got {other:?}"
            ),
        }
        assert_eq!(
            count(&pool, "received_ref_updates").await,
            GOSSIP_UNSIGNED_SOURCE_MAX_EVENTS as i64,
            "the shed event must write no row"
        );
    }

    /// A structurally invalid event charges nobody AND costs nothing.
    ///
    /// Both halves are asserted, because they are different properties and only
    /// the second is what the hoist actually buys. Charging nobody would hold
    /// with the slug check merely above the debits; costing nothing needs it
    /// above the `peer_exists` round trip and above the signature verify as
    /// well. The `peer_exists` tally is what tells those two placements apart,
    /// since both return the same `Rejected`.
    ///
    /// Run on both sides, because the two budgets are charged in different
    /// branches: a malformed signed event must leave the author budget intact,
    /// and a malformed unsigned event must leave the forwarder's unsigned
    /// budget intact.
    #[sqlx::test]
    async fn a_malformed_slug_charges_nobody_and_costs_nothing(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        let author = Keypair::generate();
        seed_peer(&pool, &author.did().to_string()).await;

        // ── Signed side: a full author budget of invalid events. ──────────
        let mut bad = event_for(&author);
        bad.repo = "../../x".into();
        sign_ref_update(&author, &mut bad).unwrap();
        let bad_signed = bytes_of(&bad);
        let signed_edge = PeerId::random();
        reset_peer_exists_calls();
        for i in 0..GOSSIP_AUTHOR_MAX_EVENTS {
            let outcome = ingest_ref_update(
                &db,
                &limiters,
                &ReplayGuard::new(),
                false,
                true,
                &bad_signed,
                &signed_edge,
            )
            .await;
            assert!(
                matches!(outcome, IngestOutcome::Rejected(_)),
                "malformed-slug event {i} must be rejected, got {outcome:?}"
            );
        }
        assert_nothing_written(&pool, "signed malformed-slug flood").await;
        assert_eq!(
            peer_exists_calls(),
            0,
            "a malformed event must cost no peer lookup: the slug check has to run above the \
             round trip, not merely above the debit"
        );

        let mut good = event_for(&author);
        sign_ref_update(&author, &mut good).unwrap();
        let outcome = ingest_ref_update(
            &db,
            &limiters,
            &ReplayGuard::new(),
            false,
            true,
            &bytes_of(&good),
            &signed_edge,
        )
        .await;
        assert!(
            matches!(outcome, IngestOutcome::Accepted),
            "the author budget must be untouched by its own malformed events, got {outcome:?}"
        );
        assert_eq!(
            count(&pool, "received_ref_updates").await,
            1,
            "the valid signed event must land its row"
        );
        assert_eq!(count(&pool, "sync_queue").await, 1);

        // ── Unsigned side: a full unsigned budget of invalid events. ──────
        let mut bad_unsigned = event_for(&author);
        bad_unsigned.repo = "../../x".into();
        let bad_unsigned = bytes_of(&bad_unsigned);
        let unsigned_edge = PeerId::random();
        reset_peer_exists_calls();
        for i in 0..GOSSIP_UNSIGNED_SOURCE_MAX_EVENTS {
            let outcome = ingest_ref_update(
                &db,
                &limiters,
                &ReplayGuard::new(),
                false,
                true,
                &bad_unsigned,
                &unsigned_edge,
            )
            .await;
            assert!(
                matches!(outcome, IngestOutcome::Rejected(_)),
                "unsigned malformed-slug event {i} must be rejected, got {outcome:?}"
            );
        }
        assert_eq!(
            peer_exists_calls(),
            0,
            "a malformed unsigned event must cost no peer lookup either"
        );

        let valid_unsigned = bytes_of(&event_for(&author));
        let outcome = ingest_ref_update(
            &db,
            &limiters,
            &ReplayGuard::new(),
            false,
            true,
            &valid_unsigned,
            &unsigned_edge,
        )
        .await;
        assert!(
            matches!(outcome, IngestOutcome::UnsignedAdmitted),
            "the forwarder's unsigned budget must be untouched by malformed events, got {outcome:?}"
        );
        assert_eq!(
            count(&pool, "received_ref_updates").await,
            2,
            "the valid unsigned event must land its row"
        );
    }

    /// FINDING 1: one push, many refs. `api::repos` publishes ONE gossip event
    /// per updated ref, so a tag-heavy push, an initial import, or a mirror
    /// backfill arrives as a burst of N events down a single mesh edge inside
    /// one window. The HTTP twin batches the same push into a single
    /// `/sync/notify`, so the brake is the only thing that makes the two
    /// transports disagree about whether the push federated.
    ///
    /// 61 distinct refs is the smallest burst that exceeded the original
    /// 60-per-source bound, and the tail was dropped with no back-pressure
    /// signal to the publisher: a silent federation miss. Both budgets have to
    /// clear it, and every event has to reach both sinks.
    #[sqlx::test]
    async fn a_sixty_one_ref_push_from_one_known_peer_is_accepted_whole(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        let source = PeerId::random();
        let keypair = Keypair::generate();
        seed_peer(&pool, &keypair.did().to_string()).await;

        const REFS: usize = 61;
        for i in 0..REFS {
            let mut event = event_for(&keypair);
            event.ref_name = format!("refs/tags/v{i}");
            sign_ref_update(&keypair, &mut event).unwrap();
            let outcome = ingest_ref_update(
                &db,
                &limiters,
                &ReplayGuard::new(),
                true,
                true,
                &bytes_of(&event),
                &source,
            )
            .await;
            assert!(
                matches!(outcome, IngestOutcome::Accepted),
                "ref {i} of a {REFS}-ref push must be accepted, got {outcome:?}"
            );
        }

        assert_eq!(
            count(&pool, "received_ref_updates").await,
            REFS as i64,
            "every ref in the push must land a received_ref_updates row"
        );
        assert_eq!(
            count(&pool, "sync_queue").await,
            REFS as i64,
            "every ref in the push must be enqueued for sync"
        );
    }

    #[test]
    fn an_unresolvable_did_key_is_rejected_with_the_shared_sentence() {
        let keypair = Keypair::generate();
        let mut event = populated_event();
        // A did:key whose method id is not a decodable ed25519 multibase key.
        event.node_did = "did:key:zNotARealKey".into();
        sign_ref_update(&keypair, &mut event).unwrap();

        let err = verify_ref_update(&event).expect_err("an unresolvable did:key must be refused");
        assert!(
            err.starts_with("cannot resolve DID 'did:key:zNotARealKey': "),
            "expected the shared unresolvable-DID sentence, got: {err}"
        );
        assert!(
            !err.ends_with(": "),
            "the sentence must carry the underlying reason, got: {err}"
        );
    }

    #[derive(Clone, Default)]
    struct CapturedWarnings(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl CapturedWarnings {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).to_string()
        }
        fn saw_warn(&self) -> bool {
            self.text().contains("accepted unsigned gossip ref-update")
        }
    }
    impl std::io::Write for CapturedWarnings {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedWarnings {
        type Writer = CapturedWarnings;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }
    fn capture_warnings() -> (CapturedWarnings, tracing::subscriber::DefaultGuard) {
        let logs = CapturedWarnings::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (logs, guard)
    }

    #[sqlx::test]
    async fn the_unsigned_warn_fires_only_on_admission(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let author = Keypair::generate();
        let event = event_for(&author);
        let claim = bytes_of(&event);

        // A: unsigned, peer NOT registered -> refused by peer_exists, no warn.
        {
            let (logs, _g) = capture_warnings();
            let outcome =
                ingest_with_fresh_limiter(&db, false, true, &claim, &PeerId::random()).await;
            assert!(
                matches!(outcome, IngestOutcome::Rejected(_)),
                "A outcome {outcome:?}"
            );
            assert!(!logs.saw_warn(), "A must not warn, got: {}", logs.text());
        }

        seed_peer(&pool, &event.node_did).await;

        // B: unsigned, registered peer -> admitted, warn fires exactly once.
        {
            let (logs, _g) = capture_warnings();
            let outcome =
                ingest_with_fresh_limiter(&db, false, true, &claim, &PeerId::random()).await;
            assert!(
                matches!(outcome, IngestOutcome::UnsignedAdmitted),
                "B outcome {outcome:?}"
            );
            assert!(logs.saw_warn(), "B must warn, got: {}", logs.text());
            assert_eq!(
                logs.text()
                    .matches("accepted unsigned gossip ref-update")
                    .count(),
                1,
                "B must warn once, got: {}",
                logs.text()
            );
        }

        // C: unsigned budget spent -> shed on the forwarder, no warn.
        {
            let limiters = IngestLimiters::new();
            let source = spend_unsigned_budget(&db, &limiters, &claim).await;
            let (logs, _g) = capture_warnings();
            // A fresh guard: this case drives an UNSIGNED event, which the
            // replay block skips entirely, so the guard is inert here and a
            // shared one would only couple this case to another's state.
            let outcome = ingest_ref_update(
                &db,
                &limiters,
                &ReplayGuard::new(),
                false,
                true,
                &claim,
                &source,
            )
            .await;
            assert!(
                matches!(outcome, IngestOutcome::UnsignedSourceRateLimited(_)),
                "C outcome {outcome:?}"
            );
            assert!(!logs.saw_warn(), "C must not warn, got: {}", logs.text());
        }

        // D: unsigned with enforcement ON -> refused, no warn.
        {
            let (logs, _g) = capture_warnings();
            let outcome =
                ingest_with_fresh_limiter(&db, true, true, &claim, &PeerId::random()).await;
            assert!(
                matches!(outcome, IngestOutcome::Rejected(_)),
                "D outcome {outcome:?}"
            );
            assert!(!logs.saw_warn(), "D must not warn, got: {}", logs.text());
        }

        // E: SIGNED and admitted -> the unsigned warn must not fire.
        {
            let signer = Keypair::generate();
            let mut signed = event_for(&signer);
            sign_ref_update(&signer, &mut signed).unwrap();
            seed_peer(&pool, &signed.node_did).await;
            let (logs, _g) = capture_warnings();
            let outcome =
                ingest_with_fresh_limiter(&db, true, true, &bytes_of(&signed), &PeerId::random())
                    .await;
            assert!(
                matches!(outcome, IngestOutcome::Accepted),
                "E outcome {outcome:?}"
            );
            assert!(!logs.saw_warn(), "E must not warn, got: {}", logs.text());
        }
    }

    // ── Freshness window ──────────────────────────────────────────
    //
    // `check_freshness` takes `now` as a parameter, so every case below pins a
    // literal instant and nothing here sleeps or reads the wall clock. The
    // clock seam (`ingest_now`) is exercised by the ingest-level tests; these
    // are about the comparison itself.

    /// A fixed instant every freshness case is measured against. Chosen to sit
    /// 30 seconds after the frozen legacy artifact's timestamp so the
    /// compatibility case at the bottom is a real admission and not an
    /// accidental equality.
    fn freshness_now() -> DateTime<Utc> {
        "2026-07-02T12:00:30Z"
            .parse()
            .expect("the pinned instant must parse")
    }

    /// Offset `freshness_now()` by `secs` and render it the way a producer
    /// does, through `to_rfc3339`, so the tests drive the same encoding
    /// `api::repos` emits rather than a hand-written string.
    fn stamp(secs: i64) -> String {
        (freshness_now() + chrono::Duration::seconds(secs)).to_rfc3339()
    }

    /// Pin the guard-layer clock for the rest of this test's thread.
    fn pin_ingest_now(at: DateTime<Utc>) {
        INGEST_NOW_OVERRIDE.with(|c| c.set(Some(at)));
    }

    /// The seam itself, asserted rather than assumed. Every expiry and
    /// saturation test below reads its instant back through `ingest_now`, so an
    /// override that silently did nothing would leave those tests measuring the
    /// wall clock and passing for the wrong reason.
    #[test]
    fn freshness_clock_seam_honours_the_pinned_instant() {
        let real = ingest_now();
        pin_ingest_now(freshness_now());
        assert_eq!(ingest_now(), freshness_now());
        assert_ne!(
            freshness_now(),
            real,
            "the pinned instant must differ from the wall clock, or this proves nothing"
        );
        INGEST_NOW_OVERRIDE.with(|c| c.set(None));
        assert!(
            ingest_now() >= real,
            "clearing the override must return the real clock"
        );
    }

    #[test]
    fn freshness_admits_an_event_stamped_now() {
        assert_eq!(check_freshness(&stamp(0), freshness_now()), Ok(()));
    }

    #[test]
    fn freshness_refuses_an_event_older_than_the_window() {
        let window = GOSSIP_REF_UPDATE_FRESHNESS_WINDOW.as_secs() as i64;
        assert_eq!(
            check_freshness(&stamp(-(window + 1)), freshness_now()),
            Err(FreshnessViolation::TooOld(
                freshness_now() - chrono::Duration::seconds(window + 1)
            )),
            "an event one second past the window must be refused as stale-past, carrying the \
             parsed instant"
        );
    }

    #[test]
    fn freshness_admits_an_event_just_inside_the_window() {
        let window = GOSSIP_REF_UPDATE_FRESHNESS_WINDOW.as_secs() as i64;
        assert_eq!(
            check_freshness(&stamp(-(window - 1)), freshness_now()),
            Ok(()),
            "the window edge is inclusive on the admitting side"
        );
    }

    /// The anti-`abs()` witness, and the reason the two directions are two
    /// comparisons rather than one distance.
    ///
    /// An `abs(now - ts) > window` implementation admits everything from here
    /// out to ten minutes in the future, and an admitted future-dated event is
    /// worse than a stale one: it pins its seen-set slot while sitting outside
    /// the past-window check's reach until the clock catches up. Five minutes
    /// ahead is inside `abs`'s tolerance and outside the skew allowance, so it
    /// separates the two implementations by itself.
    #[test]
    fn freshness_refuses_an_event_stamped_beyond_the_future_skew() {
        let skew = GOSSIP_REF_UPDATE_FUTURE_SKEW.as_secs() as i64;
        assert_eq!(
            check_freshness(&stamp(skew + 1), freshness_now()),
            Err(FreshnessViolation::TooFarFuture(
                freshness_now() + chrono::Duration::seconds(skew + 1)
            )),
            "one second past the skew allowance must be refused as stale-future, carrying the \
             parsed instant"
        );
        assert_eq!(
            check_freshness(&stamp(300), freshness_now()),
            Err(FreshnessViolation::TooFarFuture(
                freshness_now() + chrono::Duration::seconds(300)
            )),
            "five minutes ahead is inside abs(delta) < window and must still be refused"
        );
    }

    #[test]
    fn freshness_admits_honest_clock_drift() {
        assert_eq!(
            check_freshness(&stamp(30), freshness_now()),
            Ok(()),
            "the skew allowance exists so a peer half a minute fast is not refused"
        );
    }

    /// Rejecting an unparseable timestamp is safe because every producer emits
    /// RFC-3339: the sole production publish site
    /// (`api::repos::post_receive_replication_tail`) sets
    /// `chrono::Utc::now().to_rfc3339()`, and every test builder in this module
    /// uses the frozen literal below. An event whose timestamp cannot be parsed
    /// cannot be freshness-checked at all, and admitting it would let a
    /// self-signing attacker opt out of the window.
    #[test]
    fn freshness_refuses_an_unparseable_timestamp() {
        assert_eq!(
            check_freshness("not a time", freshness_now()),
            Err(FreshnessViolation::Unparseable)
        );
        assert_eq!(
            check_freshness("", freshness_now()),
            Err(FreshnessViolation::Unparseable)
        );
    }

    /// The refusal detail for an unparseable stamp reaches a `warn!`, and the
    /// string it interpolates is whatever the sender chose. Both properties are
    /// asserted here because either one alone leaves a live sink: a bounded
    /// string full of newlines still forges log lines, and a control-free
    /// megabyte still writes a megabyte per refused event.
    #[test]
    fn an_unparseable_timestamp_is_neither_unbounded_nor_control_bearing_in_the_log() {
        let hostile = format!(
            "2026-07-02T12:00:00Z\n\u{1b}[31mFATAL forged line\r{}",
            "A".repeat(4096)
        );
        let rendered = sanitize_for_log(&hostile);

        assert!(
            !rendered.chars().any(char::is_control),
            "a control character in the log detail forges log lines and drives the operator's \
             terminal, got {rendered:?}"
        );
        assert!(
            rendered.chars().count() <= 64,
            "the detail must be bounded, or one refused event writes as much log as the sender \
             chose to send, got {} chars",
            rendered.chars().count()
        );
        // Multi-byte input, because the cap is what would split a UTF-8
        // sequence if it counted bytes.
        assert_eq!(
            sanitize_for_log(&"é".repeat(100)).chars().count(),
            64,
            "truncation counts characters, not bytes"
        );
        // A legal instant must survive untouched, or the cap would be removing
        // the diagnostic value it exists to preserve.
        let legal = "2026-07-02T12:00:00.123456789+05:30";
        assert_eq!(sanitize_for_log(legal), legal);
    }

    /// The hole this test pins shut: `DateTime::parse_from_rfc3339` accepts
    /// arbitrarily many fractional-second digits, so a timestamp can PARSE and
    /// still be megabytes long on the wire. The first cut of this guard echoed
    /// the wire string raw in the `TooOld` and `TooFarFuture` details on the
    /// reasoning that a successfully parsed string is a legal bounded instant —
    /// a false invariant, because parsing proves the string names an instant,
    /// not that the bytes naming it are bounded. This drives an overlong but
    /// parseable stamp through both refusal directions and asserts the emitted
    /// detail — the exact string the swarm loop logs — is bounded, control-free,
    /// and renders the canonical form of the parsed instant instead of the wire
    /// bytes.
    #[test]
    fn an_overlong_parseable_timestamp_is_rendered_bounded_in_both_directions() {
        let window = GOSSIP_REF_UPDATE_FRESHNESS_WINDOW.as_secs() as i64;
        let skew = GOSSIP_REF_UPDATE_FUTURE_SKEW.as_secs() as i64;

        // A whole-second instant plus a mebibyte of fractional zeros: the
        // fraction changes the wire length and nothing else, so the parsed
        // instant is exactly the offset instant and the stamp is the attack
        // shape verbatim — old instant, enormous fraction, parses fine.
        let overlong = |secs: i64| -> (DateTime<Utc>, String) {
            let instant = freshness_now() + chrono::Duration::seconds(secs);
            let wire = format!(
                "{}.{}Z",
                instant.format("%Y-%m-%dT%H:%M:%S"),
                "0".repeat(1 << 20)
            );
            (instant, wire)
        };

        let (past_instant, past_wire) = overlong(-(window + 1));
        let (future_instant, future_wire) = overlong(skew + 1);
        for (instant, wire, expected) in [
            (
                past_instant,
                past_wire,
                FreshnessViolation::TooOld(past_instant),
            ),
            (
                future_instant,
                future_wire,
                FreshnessViolation::TooFarFuture(future_instant),
            ),
        ] {
            let violation = check_freshness(&wire, freshness_now()).expect_err(
                "an overlong fraction must not smuggle the stamp past the freshness window",
            );
            assert_eq!(
                violation, expected,
                "the violation must carry the parsed instant, because the detail is rendered \
                 from it"
            );

            let detail = freshness_refusal_detail(&violation, &wire);
            assert!(
                detail.chars().count() < 160,
                "the emitted detail must be bounded regardless of wire length, got {} chars",
                detail.chars().count()
            );
            assert!(
                !detail.chars().any(char::is_control),
                "a control character in the detail forges log lines, got {detail:?}"
            );
            assert!(
                detail.contains(&instant.to_rfc3339()),
                "the detail must still name the refused instant, canonically rendered, or the \
                 bound would cost the operator the one diagnostic fact: {detail}"
            );
            assert!(
                !detail.contains(&"0".repeat(64)),
                "the sender's fractional digits must not be echoed: {} chars leaked",
                detail.len()
            );
        }
    }

    /// The frozen legacy artifact's own timestamp, driven through the parser
    /// by execution rather than accepted by inspection. `Z`-suffixed UTC is a
    /// legal RFC-3339 offset, but the guard that would break every event in
    /// flight is exactly a parser that quietly disagrees, so it is observed.
    #[test]
    fn freshness_admits_the_frozen_legacy_artifacts_timestamp() {
        let event: RefUpdateEvent = serde_json::from_slice(LEGACY_SIGNED_EVENT_V0.as_bytes())
            .expect("the frozen artifact must parse");
        assert_eq!(event.timestamp, "2026-07-02T12:00:00Z");
        assert_eq!(
            check_freshness(&event.timestamp, freshness_now()),
            Ok(()),
            "the timestamp form every deployed publisher emits must parse and be admitted"
        );
    }

    // ── Replay key and the seen-set ───────────────────────────────

    /// SHA-256 of the SIGNING bytes of the frozen legacy artifact, hex,
    /// lowercase. Computed once by execution and frozen here.
    ///
    /// Deliberately NOT the same value as `LEGACY_SIGNED_EVENT_V0_SHA256` above,
    /// and the difference is the whole point of the key. That constant pins the
    /// raw wire artifact, `sig` included. This one pins `signing_bytes`, which
    /// re-serializes the parsed struct with `sig` set to None, so the two digests
    /// cover different byte strings and always will.
    ///
    /// Keying on the signing bytes is what makes the key survive encoding
    /// malleability: one signature verifies against many wire encodings, and
    /// only the canonical form collapses that family to a single seen-set slot.
    /// A key derived from raw `msg.data` would give every re-encoding its own
    /// slot, which is the defect this guard exists to close.
    ///
    /// If this fails, key derivation moved. That is a behaviour change for every
    /// node in the mesh, not a constant to re-pin.
    const LEGACY_SIGNED_EVENT_V0_REPLAY_KEY: &str =
        "a2259888c7738bed38db5864428ab7a2ca502ef269eebe80ef5671aba66f92e7";

    fn legacy_event() -> RefUpdateEvent {
        serde_json::from_slice(LEGACY_SIGNED_EVENT_V0.as_bytes())
            .expect("the frozen artifact must parse")
    }

    #[test]
    fn replay_key_of_the_frozen_legacy_artifact_matches_the_golden_digest() {
        let key = replay_key(&legacy_event()).expect("the frozen artifact must re-serialize");
        assert_eq!(
            hex::encode(key),
            LEGACY_SIGNED_EVENT_V0_REPLAY_KEY,
            "the replay key derivation changed; see the comment on \
             LEGACY_SIGNED_EVENT_V0_REPLAY_KEY"
        );
        assert_ne!(
            hex::encode(key),
            LEGACY_SIGNED_EVENT_V0_SHA256,
            "the replay key must be the digest of the signing bytes, not of the raw wire bytes"
        );
    }

    /// The malleability property, at the unit level: two distinct wire
    /// encodings, one key.
    ///
    /// The twin is the frozen artifact with `"v":0` injected. It is six bytes
    /// longer, hashes differently as raw bytes, and carries a distinct
    /// gossipsub message id, so the duplicate cache never sees it as the same
    /// message. It parses to the identical struct, produces identical signing
    /// bytes, and verifies under the identical signature, which is what makes
    /// it a replay rather than a new event.
    #[test]
    fn replay_key_collapses_the_encoding_malleability_twin() {
        let twin_json = LEGACY_SIGNED_EVENT_V0.replacen('{', r#"{"v":0,"#, 1);
        assert_ne!(
            twin_json, LEGACY_SIGNED_EVENT_V0,
            "the twin must be a different wire encoding"
        );

        let twin: RefUpdateEvent =
            serde_json::from_slice(twin_json.as_bytes()).expect("the twin must parse");
        verify_ref_update(&twin)
            .expect("the twin must verify under the same signature, or it is not a replay");

        assert_eq!(
            hex::encode(replay_key(&twin).unwrap()),
            LEGACY_SIGNED_EVENT_V0_REPLAY_KEY,
            "two wire encodings of one signed event must collapse to one seen-set key"
        );
    }

    /// A distinct key per test, so nothing here depends on another test's
    /// state even though each builds its own guard.
    fn key_of(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    /// Serializes every test that can reach `Begin::Saturated`.
    ///
    /// STANDING RULE, because nothing compiles it: a new test that drives the
    /// guard to capacity takes this lock, whether or not it asserts on the
    /// counter. `begin` increments
    /// `gitlawb_gossip_replay_guard_saturated_total` itself, so a saturating
    /// test that skips the lock is a foreign increment landing inside another
    /// test's exact delta, and it does not have to assert anything to break one.
    ///
    /// That counter carries no labels and lives in a process-wide registry, so
    /// concurrent increments are indistinguishable from the one under test.
    /// Every other guard test builds its own `ReplayGuard` and needs no lock;
    /// only the counter is shared state. Holding this lets the tests keep an
    /// exact assertion instead of degrading to a lower bound, which would stay
    /// green if the fail-open branch ever double-counted.
    ///
    /// A tokio mutex rather than `std::sync::Mutex` because one of the two
    /// holders is an `#[sqlx::test]` that awaits `ingest_ref_update` while
    /// holding it, and a std guard held across an await is both a deadlock
    /// risk and a `!Send` future. The sync holder takes it with
    /// `blocking_lock`, which is correct outside a runtime.
    static SATURATION_COUNTER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn pinned() -> DateTime<Utc> {
        freshness_now()
    }

    #[test]
    fn replay_guard_answers_replayed_for_a_key_already_reserved() {
        let guard = ReplayGuard::with_limits(GOSSIP_SEEN_EVENTS_RETENTION, 8);
        let now = pinned();

        let first = guard.begin(key_of(1), now);
        assert!(
            matches!(first, Begin::Reserved(_)),
            "a key never seen before must be reserved"
        );
        assert!(
            matches!(guard.begin(key_of(1), now), Begin::Replayed),
            "a PENDING reservation must already answer Replayed; a check that only counted \
             confirmed entries would admit two concurrent deliveries of the same bytes"
        );

        let Begin::Reserved(reservation) = first else {
            unreachable!("asserted above")
        };
        reservation.confirm();
        assert!(
            matches!(guard.begin(key_of(1), now), Begin::Replayed),
            "a confirmed entry must answer Replayed"
        );
        assert!(
            guard.is_confirmed_for_test(&key_of(1)),
            "confirm must mark the entry, not merely leave it present"
        );
    }

    /// The release path, which is what keeps a transient failure from
    /// permanently burning an event's slot: an event whose write failed must be
    /// re-publishable.
    #[test]
    fn replay_guard_releases_the_slot_when_a_reservation_drops_unconfirmed() {
        let guard = ReplayGuard::with_limits(GOSSIP_SEEN_EVENTS_RETENTION, 8);
        let now = pinned();

        match guard.begin(key_of(2), now) {
            Begin::Reserved(reservation) => drop(reservation),
            other => panic!("expected a reservation, got {other:?}"),
        }
        assert!(
            matches!(guard.begin(key_of(2), now), Begin::Reserved(_)),
            "a reservation dropped unconfirmed must leave no trace"
        );
    }

    #[test]
    fn replay_guard_forgets_a_confirmed_entry_after_retention() {
        let retention = GOSSIP_SEEN_EVENTS_RETENTION;
        let guard = ReplayGuard::with_limits(retention, 8);
        let now = pinned();

        match guard.begin(key_of(3), now) {
            Begin::Reserved(reservation) => reservation.confirm(),
            other => panic!("expected a reservation, got {other:?}"),
        }

        let later = now + chrono::Duration::seconds(retention.as_secs() as i64 + 1);
        guard.cleanup(later);
        assert!(
            matches!(guard.begin(key_of(3), later), Begin::Reserved(_)),
            "an entry past the retention horizon must not answer Replayed"
        );
    }

    /// Saturation, and the inline sweep that is the only thing reclaiming slots
    /// between the swarm loop's 300-second ticks.
    #[test]
    fn replay_guard_answers_saturated_at_capacity_then_reclaims_expired_entries() {
        let retention = GOSSIP_SEEN_EVENTS_RETENTION;
        let guard = ReplayGuard::with_limits(retention, 2);
        let now = pinned();

        // This test reaches `Begin::Saturated`, so it increments the shared
        // counter even though it asserts nothing about it. See
        // `SATURATION_COUNTER_LOCK`.
        let _serial = SATURATION_COUNTER_LOCK.blocking_lock();

        for seed in [10, 11] {
            match guard.begin(key_of(seed), now) {
                Begin::Reserved(reservation) => reservation.confirm(),
                other => panic!("expected a reservation, got {other:?}"),
            }
        }

        assert!(
            matches!(guard.begin(key_of(12), now), Begin::Saturated),
            "a full map must answer Saturated, never Replayed: mapping saturation onto Replayed \
             turns a resource attack into mesh-wide censorship of legitimate events"
        );

        let later = now + chrono::Duration::seconds(retention.as_secs() as i64 + 1);
        assert!(
            matches!(guard.begin(key_of(12), later), Begin::Reserved(_)),
            "begin must sweep expired entries inline before answering Saturated, or the guard \
             stays saturated until the next 300-second tick"
        );
    }

    /// The throttle on the inline sweep, and the case the saturation test above
    /// structurally cannot reach.
    ///
    /// That test advances the clock so the entries EXPIRE, which is the state
    /// where a rescan pays for itself. This one holds the clock still with the
    /// map full of UNEXPIRED entries, which is the state an attacker driving the
    /// guard to capacity actually produces: every sweep retains everything and
    /// reclaims nothing, so an unthrottled `begin` runs an O(capacity) retain
    /// under the mutex once per event and the guard becomes a CPU amplifier in
    /// exactly the condition it was built to survive.
    ///
    /// Asserted on the sweep count rather than on outcomes on purpose. Both
    /// implementations answer `Saturated` to every call here, so no outcome
    /// assertion can tell them apart.
    #[test]
    fn a_saturated_guard_does_not_rescan_the_map_once_per_event() {
        crate::metrics::init("0.0.0-test", "did:key:test");
        let guard = ReplayGuard::with_limits(GOSSIP_SEEN_EVENTS_RETENTION, 2);
        let now = pinned();

        for seed in [40, 41] {
            match guard.begin(key_of(seed), now) {
                Begin::Reserved(reservation) => reservation.confirm(),
                other => panic!("expected a reservation while filling the guard, got {other:?}"),
            }
        }

        // This test increments the saturation counter, so it takes the lock the
        // other saturating tests take. See `SATURATION_COUNTER_LOCK`.
        let _serial = SATURATION_COUNTER_LOCK.blocking_lock();
        let events = 50;
        for seed in 0..events {
            assert!(
                matches!(guard.begin(key_of(100 + seed), now), Begin::Saturated),
                "a full map of unexpired entries must stay saturated"
            );
        }
        assert_eq!(
            guard.inline_sweeps_for_test(),
            1,
            "the inline sweep must be throttled: {events} events at capacity may cost one rescan, \
             not one each, or the guard amplifies the very load it is bounding"
        );

        // The throttle must not disable reclamation, only rate it. One second
        // on, a sweep is owed again.
        let later = now + chrono::Duration::seconds(1);
        assert!(matches!(guard.begin(key_of(200), later), Begin::Saturated));
        assert_eq!(
            guard.inline_sweeps_for_test(),
            2,
            "once the throttle interval has elapsed the next saturating event must sweep again; a \
             throttle that swept only once would leave reclamation entirely to the 300-second tick"
        );
    }

    /// The periodic sweep the swarm loop runs, through the function the
    /// `select!` arm calls.
    ///
    /// Asserted on the entry count, not on what `begin` answers. `begin` treats
    /// an expired entry as absent whether or not anything swept it, so a test
    /// written against outcomes is green with the sweep removed, which is how
    /// the call went untested in the first place.
    ///
    /// This covers the sweep's body. It does NOT cover the `select!` dispatch;
    /// see the note on `run_ingest_sweep` for what remains uncovered and why.
    #[tokio::test]
    async fn the_swarm_loops_sweep_reclaims_expired_seen_set_entries() {
        let retention = GOSSIP_SEEN_EVENTS_RETENTION;
        let limiters = IngestLimiters::new();
        let guard = ReplayGuard::with_limits(retention, 8);
        let now = pinned();

        match guard.begin(key_of(50), now) {
            Begin::Reserved(reservation) => reservation.confirm(),
            other => panic!("expected a reservation, got {other:?}"),
        }
        assert_eq!(guard.len_for_test(), 1);

        // Still inside the horizon: a sweep here must reclaim nothing, or the
        // assertion below would pass under a sweep that simply cleared the map.
        run_ingest_sweep(&limiters, &guard, now + chrono::Duration::seconds(1)).await;
        assert_eq!(
            guard.len_for_test(),
            1,
            "an entry inside its retention horizon must survive a sweep"
        );

        run_ingest_sweep(
            &limiters,
            &guard,
            now + chrono::Duration::seconds(retention.as_secs() as i64 + 1),
        )
        .await;
        assert_eq!(
            guard.len_for_test(),
            0,
            "the periodic sweep is the only thing reclaiming seen-set slots between saturation \
             events, so an entry past the horizon must actually be evicted rather than merely \
             answered as absent"
        );
    }

    /// The saturation signal is what makes the fail-open mode visible. A
    /// saturated guard admits the event, so the existing ingest counter counts
    /// it as accepted and nothing else distinguishes a degraded node from a
    /// healthy one.
    #[test]
    fn replay_guard_counts_each_saturation() {
        crate::metrics::init("0.0.0-test", "did:key:test");
        let guard = ReplayGuard::with_limits(GOSSIP_SEEN_EVENTS_RETENTION, 1);
        let now = pinned();

        match guard.begin(key_of(20), now) {
            Begin::Reserved(reservation) => reservation.confirm(),
            other => panic!("expected a reservation, got {other:?}"),
        }

        // A before/after delta, not an equality against a literal, because this
        // counter carries no labels and lives in a process-wide registry shared
        // by every test in this binary. The delta alone is not enough: it fixes
        // the baseline but not concurrent increments, and cargo runs these tests
        // on parallel threads. `SATURATION_COUNTER_LOCK` is what actually makes
        // the exact assertion safe, so every test that can saturate takes it.
        let _serial = SATURATION_COUNTER_LOCK.blocking_lock();
        let before = crate::metrics::replay_guard_saturated_count_for_test();
        assert!(matches!(guard.begin(key_of(21), now), Begin::Saturated));
        assert_eq!(
            crate::metrics::replay_guard_saturated_count_for_test(),
            before + 1,
            "each Saturated answer must increment the saturation counter"
        );
    }

    /// A distinct key per index, for the two tests that need more keys than
    /// `key_of`'s single byte can name. The index goes in the low bytes and the
    /// rest stays zero, which is enough for uniqueness; nothing here depends on
    /// the key being well distributed, since the map hashes it again.
    fn key_from_index(i: usize) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[..std::mem::size_of::<usize>()].copy_from_slice(&i.to_le_bytes());
        key
    }

    /// A key that is PRESENT but expired, arriving while the map is full.
    ///
    /// `begin` computes `present` before it looks at capacity, so this case
    /// replaces the entry in place and never consults the capacity bar at all.
    /// The alternative reading, that a full map answers `Saturated` no matter
    /// what is already in it, would take a re-publish of an event whose slot has
    /// merely aged out and hand it the fail-open path: admitted, unrecorded, and
    /// free to replay for as long as the map stays full. The map is full exactly
    /// when the guard is under attack, so that is the moment the guard is least
    /// entitled to forget things.
    ///
    /// Two entries and only ONE of them expired, on purpose. If both were
    /// expired the inline sweep would empty the map and the in-place path would
    /// be indistinguishable from sweep-then-insert. Here the sweep can reclaim
    /// only the target's own slot, so the sweep counter is what separates the
    /// two implementations: the correct one answers from the `present` arm and
    /// runs NO sweep, while a version that treated an expired hit as absent
    /// would pay an O(capacity) rescan to reach the same answer.
    #[test]
    fn replay_guard_replaces_an_expired_entry_in_place_at_capacity() {
        let retention = GOSSIP_SEEN_EVENTS_RETENTION;
        let horizon = chrono::Duration::seconds(retention.as_secs() as i64);
        let guard = ReplayGuard::with_limits(retention, 2);
        let t0 = pinned();

        // The stale one, recorded at t0.
        match guard.begin(key_of(60), t0) {
            Begin::Reserved(reservation) => reservation.confirm(),
            other => panic!("expected a reservation, got {other:?}"),
        }
        // The fresh one, recorded a full horizon later, so it is still inside
        // its own retention at the instant the assertions below run.
        match guard.begin(key_of(61), t0 + horizon) {
            Begin::Reserved(reservation) => reservation.confirm(),
            other => panic!("expected a reservation, got {other:?}"),
        }
        assert_eq!(
            guard.len_for_test(),
            2,
            "the map must be at capacity, or this asserts nothing about the capacity bar"
        );

        let later = t0 + horizon + chrono::Duration::seconds(1);
        let outcome = guard.begin(key_of(60), later);
        assert!(
            matches!(outcome, Begin::Reserved(_)),
            "an expired entry is absent, so re-reserving its key must not have to clear the \
             capacity bar; answering Saturated here fails a re-publish open and unrecorded at \
             precisely the moment the guard is under load, got {outcome:?}"
        );
        assert_eq!(
            guard.inline_sweeps_for_test(),
            0,
            "the expired-key path must answer from the lookup it already did; reaching the \
             capacity branch to sweep the map would make a replaced entry cost an O(capacity) \
             rescan"
        );
        drop(outcome);

        assert!(
            matches!(guard.begin(key_of(61), later), Begin::Replayed),
            "the unexpired neighbour must be untouched: replacing one entry in place must not \
             clear the rest of the map"
        );
    }

    /// `confirm` on a reservation whose entry is already gone.
    ///
    /// Reachable by a sweep landing between the reservation and the write
    /// settling: the sweep evicts on `recorded_at` alone and does not care that
    /// an ingest is still in flight over that key.
    ///
    /// The silent no-op is the right answer, and the alternative is worse in
    /// both directions. Re-inserting would resurrect an entry whose retention
    /// horizon has already passed, which is the one thing the horizon is for.
    /// Panicking would turn a benign schedule into a crash on the swarm loop.
    /// So the entry stays gone and the event is simply admissible again, which
    /// is the same fail-open the guard already takes when it forgets an entry
    /// for any other reason, bounded by the freshness window like every other
    /// admission.
    ///
    /// Unreachable on today's sequential swarm loop, where the sweep tick and
    /// the ingest cannot interleave. It goes live the moment ingest becomes
    /// concurrent, which is the same reason `begin` is one critical section
    /// rather than two.
    #[test]
    fn confirming_a_reservation_whose_entry_was_already_swept_is_a_silent_no_op() {
        let retention = GOSSIP_SEEN_EVENTS_RETENTION;
        let guard = ReplayGuard::with_limits(retention, 8);
        let now = pinned();

        let Begin::Reserved(reservation) = guard.begin(key_of(62), now) else {
            panic!("a key never seen before must be reserved")
        };
        assert_eq!(guard.len_for_test(), 1, "the reservation must be recorded");

        // The sweep evicts the pending entry out from under the reservation.
        guard.cleanup(now + chrono::Duration::seconds(retention.as_secs() as i64 + 1));
        assert_eq!(
            guard.len_for_test(),
            0,
            "the sweep must actually evict, or the confirm below is not the case this test names"
        );

        reservation.confirm();
        assert_eq!(
            guard.len_for_test(),
            0,
            "confirm must not resurrect an entry the sweep already retired; re-inserting would \
             put an entry back past its own retention horizon"
        );
        assert!(
            matches!(guard.begin(key_of(62), now), Begin::Reserved(_)),
            "the key is genuinely forgotten, so the event is admissible again, bounded by the \
             freshness window like any other admission"
        );
    }

    /// The inline sweep at PRODUCTION capacity, which is the size the throttle
    /// was actually written to defend.
    ///
    /// Every other saturation test here fills two slots, so the cost the
    /// throttle bounds is two comparisons and the assertion holds under an
    /// implementation that would be ruinous at the real number. This one builds
    /// the guard through `ReplayGuard::new`, so the capacity is
    /// `GOSSIP_SEEN_EVENTS_MAX` itself and nothing is extrapolated: no argument
    /// is needed that a result at capacity 2 carries to capacity 100,000,
    /// because the test IS at capacity 100,000.
    ///
    /// Asserted on the RATE, not the count. One sweep is not the interesting
    /// number; one sweep for however many events arrive at the same instant is,
    /// because the failing implementation is the one where sweeps track the
    /// event count. Every entry here is unexpired and the clock is held still,
    /// which is the state an attacker driving the guard to capacity produces:
    /// each rescan visits all 100,000 entries under the mutex and reclaims
    /// nothing, so an unthrottled `begin` would turn this burst into 50 million
    /// pointless key visits on the swarm loop.
    #[test]
    fn a_guard_at_production_capacity_sweeps_once_for_a_burst_not_once_per_event() {
        crate::metrics::init("0.0.0-test", "did:key:test");
        let guard = ReplayGuard::new();
        let now = pinned();

        for i in 0..GOSSIP_SEEN_EVENTS_MAX {
            match guard.begin(key_from_index(i), now) {
                Begin::Reserved(reservation) => reservation.confirm(),
                other => panic!("expected a reservation while filling the guard, got {other:?}"),
            }
        }
        assert_eq!(
            guard.len_for_test(),
            GOSSIP_SEEN_EVENTS_MAX,
            "the guard must be at its production capacity before the burst"
        );

        // This test reaches `Begin::Saturated`, so it takes the lock every
        // saturating test takes. See `SATURATION_COUNTER_LOCK`.
        let _serial = SATURATION_COUNTER_LOCK.blocking_lock();
        let events = 500;
        for i in 0..events {
            let outcome = guard.begin(key_from_index(GOSSIP_SEEN_EVENTS_MAX + i), now);
            assert!(
                matches!(outcome, Begin::Saturated),
                "a full map of unexpired entries must stay saturated, got {outcome:?} at event {i}"
            );
        }

        let sweeps = guard.inline_sweeps_for_test();
        assert_eq!(
            sweeps, 1,
            "{events} events into a saturated guard cost {sweeps} rescans of a \
             {GOSSIP_SEEN_EVENTS_MAX}-entry map; the per-event rate must not scale with the \
             burst, or the guard is an amplifier at exactly the size it was built for"
        );
        assert_eq!(
            guard.len_for_test(),
            GOSSIP_SEEN_EVENTS_MAX,
            "nothing was expired, so the one sweep reclaimed nothing: that is the state the \
             throttle exists for, and it is the state this burst was run in"
        );
    }

    /// The race `begin`'s single critical section exists to close, driven
    /// concurrently rather than argued.
    ///
    /// Two OS threads meet at a barrier and call `begin` with the same key. The
    /// property is on the pair, not on either thread: exactly one may hold a
    /// reservation and the other must be told it is a replay. Check-then-insert
    /// with the lock released in between passes every sequential test in this
    /// file and fails here, because both threads look, both miss, and both are
    /// admitted.
    ///
    /// The second barrier is load-bearing. A winner that released its
    /// reservation before the loser called `begin` would hand the loser a
    /// legitimate `Reserved`, and the test would fail on its own scheduling
    /// rather than on the guard; holding both results until both calls have
    /// returned is what makes the assertion about `begin` alone.
    ///
    /// Many rounds because one is not evidence. A torn implementation still
    /// answers correctly whenever the threads happen not to overlap, so a single
    /// round would mostly pass against the bug; the honest claim is that this
    /// raises the odds of catching one, not that it forces the interleaving.
    #[test]
    fn two_concurrent_deliveries_of_one_key_yield_exactly_one_reservation() {
        let guard = ReplayGuard::with_limits(GOSSIP_SEEN_EVENTS_RETENTION, 8);
        let now = pinned();
        let rounds = 200;
        let barrier = std::sync::Barrier::new(2);

        fn label(outcome: &Begin<'_>) -> &'static str {
            match outcome {
                Begin::Reserved(_) => "reserved",
                Begin::Replayed => "replayed",
                Begin::Saturated => "saturated",
            }
        }

        let (left, right) = std::thread::scope(|scope| {
            let run = || {
                let mut labels = Vec::with_capacity(rounds);
                for round in 0..rounds {
                    barrier.wait();
                    let outcome = guard.begin(key_from_index(round), now);
                    labels.push(label(&outcome));
                    // Both calls have returned before either reservation is
                    // released, so the loser cannot have raced a release.
                    barrier.wait();
                    drop(outcome);
                }
                labels
            };
            let left = scope.spawn(run);
            let right = scope.spawn(run);
            (
                left.join().expect("left racer must not panic"),
                right.join().expect("right racer must not panic"),
            )
        });

        for (round, (a, b)) in left.iter().zip(right.iter()).enumerate() {
            let mut pair = [*a, *b];
            pair.sort_unstable();
            assert_eq!(
                pair,
                ["replayed", "reserved"],
                "round {round}: two concurrent deliveries of one key must settle as exactly one \
                 reservation and one replay, got {a} and {b}; two reservations means both copies \
                 were admitted, which is the replay the guard exists to refuse"
            );
        }
    }

    // ---- The replay seen-set and the freshness window, through the real
    // ingest path. Every one of these drives `ingest_ref_update` rather than a
    // helper, because the guards' whole subject is WHERE they sit relative to
    // the other gates, and a helper that calls the pieces in some order of its
    // own would assert against a shape production does not run.

    /// The core case: the same signed bytes twice. The second one must be
    /// refused, and refused ABOVE the database.
    ///
    /// The row count alone would not say that. A second ingest dropped for any
    /// unrelated reason leaves one row too, so the outcome variant, the metric
    /// label, and the `peer_exists` tally are all asserted: the first says it
    /// was the seen-set that refused it, the second says an operator can see
    /// it, and the third says the refusal cost no round trip.
    #[sqlx::test]
    async fn a_replayed_signed_event_is_refused_without_touching_the_database(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        // ONE guard across both calls. A fresh guard per call remembers
        // nothing, which is the shape that keeps this test green while the
        // guard does nothing at all.
        let replay_guard = ReplayGuard::new();
        let source = PeerId::random();
        let keypair = Keypair::generate();
        seed_peer(&pool, &keypair.did().to_string()).await;

        let mut event = event_for(&keypair);
        sign_ref_update(&keypair, &mut event).unwrap();
        let bytes = bytes_of(&event);

        let first =
            ingest_ref_update(&db, &limiters, &replay_guard, true, true, &bytes, &source).await;
        assert!(
            matches!(first, IngestOutcome::Accepted),
            "the first delivery of a signed event from a known peer must be accepted, got {first:?}"
        );
        assert_eq!(count(&pool, "received_ref_updates").await, 1);
        assert_eq!(count(&pool, "sync_queue").await, 1);

        reset_peer_exists_calls();
        let second =
            ingest_ref_update(&db, &limiters, &replay_guard, true, true, &bytes, &source).await;
        assert_eq!(
            second.metric_label(),
            "replayed",
            "the replay must be countable as a replay; folding it into another label hides the \
             one signal that says the mesh is redelivering"
        );
        assert!(
            matches!(second, IngestOutcome::Replayed),
            "the exact same signed bytes must be refused as a replay, got {second:?}"
        );
        assert_eq!(
            count(&pool, "received_ref_updates").await,
            1,
            "a replay must not write a second received_ref_updates row"
        );
        assert_eq!(
            count(&pool, "sync_queue").await,
            1,
            "a replay must not enqueue a second sync"
        );
        assert_eq!(
            peer_exists_calls(),
            0,
            "the seen-set sits above the peer lookup, so a replay must cost no Postgres round \
             trip; a guard placed just above the writes returns the same outcome and this is the \
             only assertion that can tell the two placements apart"
        );
    }

    /// The incident itself, verbatim, not a fixture modelled on it.
    ///
    /// One captured signature reaches this node as two different byte strings,
    /// 454 and 460, because injecting `"v":0` changes the wire form and not the
    /// struct. Any dedup keyed on `msg.data` or on the gossipsub message id
    /// sees two unrelated messages. Keyed on the canonical signing bytes, the
    /// twin is what it is: the same event, arriving twice.
    ///
    /// A rebuilt fixture would inherit the blind spot the original tests had,
    /// so both constants are frozen and digest-pinned and the ingest runs on
    /// their exact bytes.
    #[sqlx::test]
    async fn the_v_zero_twin_of_the_frozen_legacy_artifact_is_refused_as_a_replay(pool: PgPool) {
        use sha2::{Digest, Sha256};
        assert_eq!(
            hex::encode(Sha256::digest(LEGACY_SIGNED_EVENT_V0_TWIN.as_bytes())),
            LEGACY_SIGNED_EVENT_V0_TWIN_SHA256,
            "the frozen twin was edited; it is evidence from the review, not a fixture to \
             regenerate"
        );
        assert_eq!(
            LEGACY_SIGNED_EVENT_V0_TWIN.len(),
            LEGACY_SIGNED_EVENT_V0.len() + r#""v":0,"#.len(),
            "the twin must differ from the original by the injected version key and nothing else"
        );

        // The artifact is stamped 2026-07-02T12:00:00Z and frozen there
        // forever, so the freshness window above the seen-set would refuse it
        // on any real clock. Pinning is what lets the incident bytes reach the
        // gate this test is about.
        pin_ingest_now(freshness_now());

        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        let replay_guard = ReplayGuard::new();
        let source = PeerId::random();

        let original: RefUpdateEvent =
            serde_json::from_str(LEGACY_SIGNED_EVENT_V0).expect("the frozen artifact must parse");
        seed_peer(&pool, &original.node_did).await;

        let first = ingest_ref_update(
            &db,
            &limiters,
            &replay_guard,
            true,
            true,
            LEGACY_SIGNED_EVENT_V0.as_bytes(),
            &source,
        )
        .await;
        assert!(
            matches!(first, IngestOutcome::Accepted),
            "the original 454-byte artifact must be accepted, got {first:?}"
        );

        let second = ingest_ref_update(
            &db,
            &limiters,
            &replay_guard,
            true,
            true,
            LEGACY_SIGNED_EVENT_V0_TWIN.as_bytes(),
            &source,
        )
        .await;
        assert!(
            matches!(second, IngestOutcome::Replayed),
            "the 460-byte twin carries the same signature over the same signing bytes and must be \
             refused as a replay, got {second:?}"
        );
        assert_eq!(
            count(&pool, "received_ref_updates").await,
            1,
            "the twin must not land a second row"
        );
    }

    /// The must-not that rules out the cheap key. A revert is a legitimate
    /// push, and a guard keyed on `(repo, ref_name, new_sha)` censors it.
    ///
    /// Three events, not two, and the third is the whole test. Under that key a
    /// two-event revert never collides: event 1 announces sha A, event 2
    /// announces sha B, the keys differ and both are admitted exactly as
    /// correct code admits them. Only event 3, re-announcing A on the same ref,
    /// collides with event 1. A two-event version of this test is green under
    /// the mutant it exists to catch.
    #[sqlx::test]
    async fn a_legitimate_revert_to_an_earlier_sha_is_not_censored(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        let replay_guard = ReplayGuard::new();
        let source = PeerId::random();
        let keypair = Keypair::generate();
        seed_peer(&pool, &keypair.did().to_string()).await;

        const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        const ZERO: &str = "0000000000000000000000000000000000000000";

        let mut event = event_for(&keypair);
        for (i, (old_sha, new_sha)) in [(ZERO, SHA_A), (SHA_A, SHA_B), (SHA_B, SHA_A)]
            .into_iter()
            .enumerate()
        {
            event.old_sha = old_sha.into();
            event.new_sha = new_sha.into();
            sign_ref_update(&keypair, &mut event).unwrap();
            let outcome = ingest_ref_update(
                &db,
                &limiters,
                &replay_guard,
                true,
                true,
                &bytes_of(&event),
                &source,
            )
            .await;
            assert!(
                matches!(outcome, IngestOutcome::Accepted),
                "event {i} of the revert sequence is a distinct signed event and must be \
                 accepted; refusing it is censorship of a legitimate push, got {outcome:?}"
            );
        }

        assert_eq!(
            count(&pool, "received_ref_updates").await,
            3,
            "all three ref-updates in a revert sequence must land"
        );
    }

    /// Record on `Accepted` only, in its executable form.
    ///
    /// The event reserves a slot, then fails a gate below the seen-set. If the
    /// reservation were recorded at check time the publisher's re-publish would
    /// come back `Replayed` forever and the update would be permanently lost
    /// with nothing left to repair it. The drop guard is what makes the retry
    /// work.
    #[sqlx::test]
    async fn an_event_refused_below_the_seen_set_is_still_republishable(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        let replay_guard = ReplayGuard::new();
        let source = PeerId::random();
        // Resolvable as a did:key, so it clears the method gate and the
        // signature, and NOT seeded as a peer, so it fails at the gate below
        // the reservation.
        let keypair = Keypair::generate();

        let mut event = event_for(&keypair);
        sign_ref_update(&keypair, &mut event).unwrap();
        let bytes = bytes_of(&event);

        let refused =
            ingest_ref_update(&db, &limiters, &replay_guard, true, true, &bytes, &source).await;
        let reason = rejection_reason(refused, "an unregistered author");
        assert!(
            reason.starts_with("unknown peer DID"),
            "the first ingest must fail at the peer gate, below the reservation, got: {reason}"
        );
        assert_nothing_written(&pool, "an event refused at the peer gate").await;

        seed_peer(&pool, &keypair.did().to_string()).await;
        let retried =
            ingest_ref_update(&db, &limiters, &replay_guard, true, true, &bytes, &source).await;
        assert!(
            matches!(retried, IngestOutcome::Accepted),
            "the same bytes must be admitted once the downstream refusal is resolved; a slot \
             burned by an ingest that never succeeded loses the update permanently, got {retried:?}"
        );
        assert_eq!(count(&pool, "received_ref_updates").await, 1);
    }

    /// KTD-1, executable. This is the harm the defect actually names.
    ///
    /// A captured signature replayed to the author cap drains the victim's
    /// budget, and their next genuine push comes back `AuthorRateLimited`. That
    /// is why the seen-set sits ABOVE the author debit and not just above the
    /// writes: with the guard below the debit every assertion here about the
    /// replays still passes and the last one, the victim's fresh push, goes
    /// red.
    #[sqlx::test]
    async fn a_replay_flood_does_not_drain_the_victim_authors_budget(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        let replay_guard = ReplayGuard::new();
        let source = PeerId::random();
        let victim = Keypair::generate();
        seed_peer(&pool, &victim.did().to_string()).await;

        let mut captured = event_for(&victim);
        sign_ref_update(&victim, &mut captured).unwrap();
        let bytes = bytes_of(&captured);

        let first =
            ingest_ref_update(&db, &limiters, &replay_guard, true, true, &bytes, &source).await;
        assert!(
            matches!(first, IngestOutcome::Accepted),
            "the victim's genuine event must be accepted, got {first:?}"
        );

        for i in 0..GOSSIP_AUTHOR_MAX_EVENTS {
            let outcome =
                ingest_ref_update(&db, &limiters, &replay_guard, true, true, &bytes, &source).await;
            assert!(
                matches!(outcome, IngestOutcome::Replayed),
                "replay {i} of a captured signature must be refused by the seen-set, got {outcome:?}"
            );
        }

        let mut fresh = event_for(&victim);
        fresh.ref_name = "refs/heads/after-the-flood".into();
        sign_ref_update(&victim, &mut fresh).unwrap();
        let outcome = ingest_ref_update(
            &db,
            &limiters,
            &replay_guard,
            true,
            true,
            &bytes_of(&fresh),
            &source,
        )
        .await;
        assert!(
            matches!(outcome, IngestOutcome::Accepted),
            "the victim's next genuine push must survive a flood of replays of its own earlier \
             event; anything else means the replays were charged to the victim's budget, got \
             {outcome:?}"
        );
        assert_eq!(
            count(&pool, "received_ref_updates").await,
            2,
            "exactly the two genuine events may land"
        );
    }

    /// The past direction of the freshness window, and the placement assertion
    /// that goes with it: a stale event costs no round trip either.
    #[sqlx::test]
    async fn an_event_older_than_the_freshness_window_is_refused(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        let replay_guard = ReplayGuard::new();
        let source = PeerId::random();
        let keypair = Keypair::generate();
        seed_peer(&pool, &keypair.did().to_string()).await;

        let mut event = event_for(&keypair);
        event.timestamp = (ingest_now()
            - chrono::Duration::seconds(GOSSIP_REF_UPDATE_FRESHNESS_WINDOW.as_secs() as i64 + 1))
        .to_rfc3339();
        sign_ref_update(&keypair, &mut event).unwrap();

        reset_peer_exists_calls();
        let outcome = ingest_ref_update(
            &db,
            &limiters,
            &replay_guard,
            true,
            true,
            &bytes_of(&event),
            &source,
        )
        .await;
        assert_eq!(
            outcome.metric_label(),
            "stale_timestamp",
            "a stale event must count under its own label; sharing one with `replayed` would \
             leave an operator unable to tell a broken clock from an attacker"
        );
        assert!(
            matches!(outcome, IngestOutcome::StaleTimestamp(_)),
            "an event one second past the window must be refused as stale, got {outcome:?}"
        );
        assert_nothing_written(&pool, "an event older than the freshness window").await;
        assert_eq!(
            peer_exists_calls(),
            0,
            "the freshness check sits above the peer lookup, so a stale event must cost no \
             Postgres round trip"
        );
    }

    /// The future direction, which is the one an `abs()` implementation gets
    /// wrong: a distance check admits an event stamped a full window ahead, and
    /// that event then holds its seen-set slot while sitting outside the
    /// past-window check's reach until this node's clock catches up.
    #[sqlx::test]
    async fn an_event_stamped_far_in_the_future_is_refused(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        let replay_guard = ReplayGuard::new();
        let source = PeerId::random();
        let keypair = Keypair::generate();
        seed_peer(&pool, &keypair.did().to_string()).await;

        let mut event = event_for(&keypair);
        event.timestamp = (ingest_now() + chrono::Duration::seconds(300)).to_rfc3339();
        sign_ref_update(&keypair, &mut event).unwrap();

        let outcome = ingest_ref_update(
            &db,
            &limiters,
            &replay_guard,
            true,
            true,
            &bytes_of(&event),
            &source,
        )
        .await;
        assert!(
            matches!(outcome, IngestOutcome::StaleTimestamp(_)),
            "an event stamped five minutes ahead is well past the {}-second skew allowance and \
             must be refused, got {outcome:?}",
            GOSSIP_REF_UPDATE_FUTURE_SKEW.as_secs()
        );
        assert_nothing_written(&pool, "an event stamped far in the future").await;
    }

    /// The third violation, driven through the real path like its two siblings
    /// rather than proven only at the `check_freshness` unit level.
    ///
    /// This is the arm a self-signing attacker reaches for: if an unparseable
    /// stamp were admitted, stamping garbage would opt the event out of the
    /// freshness window entirely, which is a strictly better attack than
    /// stamping a legal instant. So the refusal is asserted at the same four
    /// points the `TooOld` case is, including the `peer_exists` tally, which is
    /// what says the refusal happened ABOVE the database rather than merely
    /// producing the same outcome from somewhere further down.
    ///
    /// The timestamp is set BEFORE signing on purpose. The signature covers the
    /// timestamp, so signing first and overwriting after would produce an event
    /// that fails verification, and the test would then pass without the
    /// freshness check ever running.
    #[sqlx::test]
    async fn an_event_whose_timestamp_is_not_rfc_3339_is_refused(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        let replay_guard = ReplayGuard::new();
        let source = PeerId::random();
        let keypair = Keypair::generate();
        seed_peer(&pool, &keypair.did().to_string()).await;

        let mut event = event_for(&keypair);
        event.timestamp = "yesterday afternoon".to_string();
        sign_ref_update(&keypair, &mut event).unwrap();

        reset_peer_exists_calls();
        let outcome = ingest_ref_update(
            &db,
            &limiters,
            &replay_guard,
            true,
            true,
            &bytes_of(&event),
            &source,
        )
        .await;
        assert_eq!(
            outcome.metric_label(),
            "stale_timestamp",
            "an unparseable stamp must count under the same label as its two siblings; a publisher \
             emitting non-RFC-3339 is a freshness violation an operator reads off one series"
        );
        assert!(
            matches!(outcome, IngestOutcome::StaleTimestamp(_)),
            "a timestamp that cannot be parsed cannot be freshness-checked, so it must be refused \
             rather than admitted, got {outcome:?}"
        );
        assert_nothing_written(&pool, "an event whose timestamp is not RFC-3339").await;
        assert_eq!(
            peer_exists_calls(),
            0,
            "the freshness check sits above the peer lookup, so an unparseable stamp must cost no \
             Postgres round trip"
        );
    }

    /// The composition of the two layers, at the only point where a gap can
    /// open: an event stamped at the maximum future skew.
    ///
    /// Such an event is received at t0 but stays inside the freshness window
    /// until stamp + 600, which is t0 + 660. If the seen-set forgot it at
    /// t0 + 600 there would be a full minute in which it replays clean through
    /// both layers. A past-stamped probe cannot see this: with a stamp of t0
    /// and a re-ingest at t0 + 661, a 600-second retention drops the entry AND
    /// freshness answers `StaleTimestamp`, so the test passes under exactly the
    /// mutant it was written to catch.
    ///
    /// Phase A proves the seen-set outlives the freshness horizon. Phase B
    /// proves the freshness window is what finally closes the event out, so the
    /// two together leave no interval uncovered.
    #[sqlx::test]
    async fn the_seen_set_outlives_the_freshness_horizon_of_a_max_skew_event(pool: PgPool) {
        let t0 = freshness_now();
        pin_ingest_now(t0);

        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        let replay_guard = ReplayGuard::new();
        let source = PeerId::random();
        let keypair = Keypair::generate();
        seed_peer(&pool, &keypair.did().to_string()).await;

        let mut event = event_for(&keypair);
        event.timestamp = (t0
            + chrono::Duration::seconds(GOSSIP_REF_UPDATE_FUTURE_SKEW.as_secs() as i64))
        .to_rfc3339();
        sign_ref_update(&keypair, &mut event).unwrap();
        let bytes = bytes_of(&event);

        let first =
            ingest_ref_update(&db, &limiters, &replay_guard, true, true, &bytes, &source).await;
        assert!(
            matches!(first, IngestOutcome::Accepted),
            "an event at exactly the skew allowance is admissible, got {first:?}"
        );

        // 610 seconds on: the event is 550 seconds old by its own stamp, so it
        // is still fresh, and the entry recorded at t0 is 610 seconds old, so a
        // 660-second retention still holds it. The sweep runs first, because a
        // retention that only survives by never being swept is not a retention.
        pin_ingest_now(t0 + chrono::Duration::seconds(610));
        replay_guard.cleanup(ingest_now());
        let replayed =
            ingest_ref_update(&db, &limiters, &replay_guard, true, true, &bytes, &source).await;
        assert!(
            matches!(replayed, IngestOutcome::Replayed),
            "the event is still inside its freshness window at t0+610, so the seen-set must still \
             hold it; a retention of only the window length forgets it here and the replay lands, \
             got {replayed:?}"
        );

        // 661 seconds on: the event is 601 seconds old by its own stamp, past
        // the window, so freshness is what refuses it now and the seen-set is
        // free to forget it.
        pin_ingest_now(t0 + chrono::Duration::seconds(661));
        replay_guard.cleanup(ingest_now());
        let stale =
            ingest_ref_update(&db, &limiters, &replay_guard, true, true, &bytes, &source).await;
        assert!(
            matches!(stale, IngestOutcome::StaleTimestamp(_)),
            "past its own freshness horizon the event must be refused by the window, which is \
             what bounds how long the seen-set has to remember it, got {stale:?}"
        );

        assert_eq!(
            count(&pool, "received_ref_updates").await,
            1,
            "only the first delivery may land a row"
        );
    }

    /// KTD-6: the guard runs on the verified path only, and this is the
    /// must-not that keeps it there.
    ///
    /// Unsigned event bytes carry no signature, so they are fully predictable.
    /// A node deduplicating them lets an attacker pre-send a victim's expected
    /// unsigned event and have the genuine one dropped as a replay, which is a
    /// censorship primitive handed out for nothing: unsigned traffic gains no
    /// protection from dedup anyway, since the attacker can mint fresh unsigned
    /// events at will. The forwarder brake is the bound on that path.
    #[sqlx::test]
    async fn unsigned_events_bypass_the_seen_set_and_the_freshness_window(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        let replay_guard = ReplayGuard::new();
        let source = PeerId::random();
        let keypair = Keypair::generate();
        seed_peer(&pool, &keypair.did().to_string()).await;

        let event = event_for(&keypair);
        assert!(
            event.sig.is_none(),
            "this test is about the unsigned path; a signed fixture would prove nothing"
        );
        let bytes = bytes_of(&event);

        for i in 0..2 {
            let outcome =
                ingest_ref_update(&db, &limiters, &replay_guard, false, true, &bytes, &source)
                    .await;
            match outcome {
                // `UnsignedAdmitted`, not `Accepted`: this branch predates the
                // outcome split and an unsigned admission now reports itself as
                // one. The property under test is unchanged, that unsigned bytes
                // are admitted twice rather than deduplicated.
                IngestOutcome::UnsignedAdmitted => {}
                IngestOutcome::Replayed => panic!(
                    "delivery {i}: unsigned bytes must never reach the seen-set; deduplicating \
                     them lets an attacker pre-send a victim's predictable event and have the \
                     genuine one dropped"
                ),
                other => panic!("delivery {i}: expected an unsigned admission, got {other:?}"),
            }
        }
        assert_eq!(
            count(&pool, "received_ref_updates").await,
            2,
            "both unsigned deliveries must land in the rolling-upgrade window"
        );

        let mut stale = event_for(&keypair);
        stale.timestamp = (ingest_now()
            - chrono::Duration::seconds(GOSSIP_REF_UPDATE_FRESHNESS_WINDOW.as_secs() as i64 + 1))
        .to_rfc3339();
        let outcome = ingest_ref_update(
            &db,
            &limiters,
            &replay_guard,
            false,
            true,
            &bytes_of(&stale),
            &source,
        )
        .await;
        assert!(
            matches!(outcome, IngestOutcome::UnsignedAdmitted),
            "the freshness window rides on the same verified path as the seen-set, so an unsigned \
             event outside it is admitted rather than refused, got {outcome:?}"
        );
    }

    /// The fail-open branch, which is the one an implementation gets
    /// catastrophically wrong for free.
    ///
    /// Mapping `Saturated` to an early `Replayed` return passes every other
    /// scenario in this file, because nothing else fills the guard, and ships a
    /// node that refuses all fresh gossip the moment its seen-set is full:
    /// mesh-wide censorship, converted from a loud resource attack. So a
    /// saturated guard must admit the event, write it, and say so through the
    /// counter.
    #[sqlx::test]
    async fn a_saturated_guard_admits_the_event_and_counts_the_degradation(pool: PgPool) {
        crate::metrics::init("0.0.0-test", "did:key:test");
        pin_ingest_now(freshness_now());

        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        // Capacity 2 through the same constructor production uses, so the test
        // fills two slots rather than a hundred thousand and still asserts
        // against the real shape.
        let replay_guard = ReplayGuard::with_limits(GOSSIP_SEEN_EVENTS_RETENTION, 2);
        for seed in [30, 31] {
            match replay_guard.begin(key_of(seed), ingest_now()) {
                Begin::Reserved(reservation) => reservation.confirm(),
                other => panic!("expected a reservation while filling the guard, got {other:?}"),
            }
        }

        let source = PeerId::random();
        let keypair = Keypair::generate();
        seed_peer(&pool, &keypair.did().to_string()).await;
        let mut event = event_for(&keypair);
        sign_ref_update(&keypair, &mut event).unwrap();

        let _serial = SATURATION_COUNTER_LOCK.lock().await;
        let before = crate::metrics::replay_guard_saturated_count_for_test();
        let outcome = ingest_ref_update(
            &db,
            &limiters,
            &replay_guard,
            true,
            true,
            &bytes_of(&event),
            &source,
        )
        .await;
        assert!(
            matches!(outcome, IngestOutcome::Accepted),
            "a saturated seen-set must admit a fresh signed event, not refuse it; refusing here \
             is mesh-wide censorship, got {outcome:?}"
        );
        assert_eq!(
            count(&pool, "received_ref_updates").await,
            1,
            "the admitted event must actually be written, not merely reported as accepted"
        );
        // Exact, not a lower bound: `SATURATION_COUNTER_LOCK` above serializes
        // this against every other test that can reach saturation, so exactly
        // one increment is attributable to this ingest. A lower bound would
        // stay green if the fail-open branch counted twice, or if some future
        // path incremented on a non-saturating call.
        assert_eq!(
            crate::metrics::replay_guard_saturated_count_for_test(),
            before + 1,
            "the fail-open branch must be visible exactly once; while this counter is still it \
             is impossible to tell a degraded node from a healthy one, since both count the \
             event as accepted"
        );
    }

    // ── The reservation's release, through the arm it was written for ─────
    //
    // The drop guard is what keeps a transient write failure from permanently
    // burning an event's key, and until now it was proven only through an early
    // return: the unknown-peer gate stops the ingest above both writes, so the
    // reservation is released by a path that never reached the scenario the
    // doc comment names. The two tests below drive the `WriteFailed` arm
    // itself, once per write direction, because the two writes are attempted
    // independently and a release that fired on only one of them would be a
    // release with a hole in it.
    //
    // Each RENAMES its target table rather than dropping it, which is the one
    // difference from the two `WriteFailed` tests above. The re-publish is the
    // property under test, so the sink has to come back: with the table gone
    // for good the second ingest fails too, and the strongest available
    // assertion would be "not Replayed", which is satisfied by a guard that
    // burned the slot and then reported a write failure for its own reasons.

    /// The row write fails, and the publisher's re-publish still gets in.
    #[sqlx::test]
    async fn a_failed_ref_update_insert_releases_the_seen_set_slot(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        // ONE guard across both deliveries. A fresh guard per call is exactly
        // the shape that stays green while the slot is burned forever.
        let replay_guard = ReplayGuard::new();
        let source = PeerId::random();
        let keypair = Keypair::generate();
        seed_peer(&pool, &keypair.did().to_string()).await;

        let mut event = event_for(&keypair);
        sign_ref_update(&keypair, &mut event).unwrap();
        let bytes = bytes_of(&event);

        sqlx::query("ALTER TABLE received_ref_updates RENAME TO received_ref_updates_stashed")
            .execute(&pool)
            .await
            .expect("stash the ref-update sink so its write genuinely fails");

        let failed =
            ingest_ref_update(&db, &limiters, &replay_guard, true, true, &bytes, &source).await;
        match failed {
            IngestOutcome::WriteFailed(reason) => assert!(
                reason.contains("failed to store received ref-update"),
                "the outcome must name the write that failed, got: {reason}"
            ),
            other => panic!(
                "this test is about the WriteFailed arm, so the ingest must reach the write and \
                 fail there rather than being refused above it, got {other:?}"
            ),
        }
        assert_eq!(
            replay_guard.len_for_test(),
            0,
            "an ingest that settled without storing the event must leave no entry behind; the \
             outcome assertion above cannot see this, since a burned slot returns the identical \
             WriteFailed"
        );

        sqlx::query("ALTER TABLE received_ref_updates_stashed RENAME TO received_ref_updates")
            .execute(&pool)
            .await
            .expect("restore the ref-update sink for the re-publish");

        let republished =
            ingest_ref_update(&db, &limiters, &replay_guard, true, true, &bytes, &source).await;
        assert!(
            matches!(republished, IngestOutcome::Accepted),
            "the same bytes must be admitted after a transient failure; refused as a replay, the \
             row is lost permanently and the publisher has no way to repair it, got {republished:?}"
        );
        assert_eq!(
            count(&pool, "received_ref_updates").await,
            1,
            "the re-publish is what finally lands the row the failed ingest lost"
        );
        assert_eq!(
            count(&pool, "sync_queue").await,
            2,
            "the enqueue is a separate write and succeeded on both passes, which is the same \
             independence the WriteFailed pair above asserts"
        );
    }

    /// The mirror: the enqueue fails, and the re-publish still gets in.
    #[sqlx::test]
    async fn a_failed_enqueue_releases_the_seen_set_slot(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let limiters = IngestLimiters::new();
        let replay_guard = ReplayGuard::new();
        let source = PeerId::random();
        let keypair = Keypair::generate();
        seed_peer(&pool, &keypair.did().to_string()).await;

        let mut event = event_for(&keypair);
        sign_ref_update(&keypair, &mut event).unwrap();
        let bytes = bytes_of(&event);

        sqlx::query("ALTER TABLE sync_queue RENAME TO sync_queue_stashed")
            .execute(&pool)
            .await
            .expect("stash the queue sink so its write genuinely fails");

        let failed =
            ingest_ref_update(&db, &limiters, &replay_guard, true, true, &bytes, &source).await;
        match failed {
            IngestOutcome::WriteFailed(reason) => assert!(
                reason.contains("failed to enqueue sync"),
                "the outcome must name the write that failed, got: {reason}"
            ),
            other => panic!(
                "this test is about the WriteFailed arm, so the ingest must reach the enqueue and \
                 fail there rather than being refused above it, got {other:?}"
            ),
        }
        assert_eq!(
            replay_guard.len_for_test(),
            0,
            "a failed enqueue settles the ingest as unstored just as a failed row insert does, so \
             it must release the slot on the same terms"
        );

        sqlx::query("ALTER TABLE sync_queue_stashed RENAME TO sync_queue")
            .execute(&pool)
            .await
            .expect("restore the queue sink for the re-publish");

        let republished =
            ingest_ref_update(&db, &limiters, &replay_guard, true, true, &bytes, &source).await;
        assert!(
            matches!(republished, IngestOutcome::Accepted),
            "the same bytes must be admitted after a transient enqueue failure, or the sync the \
             event exists to trigger never happens, got {republished:?}"
        );
        assert_eq!(
            count(&pool, "sync_queue").await,
            1,
            "the re-publish is what finally lands the queue entry the failed ingest lost"
        );
        assert_eq!(
            count(&pool, "received_ref_updates").await,
            2,
            "the row write is a separate write and succeeded on both passes"
        );
    }

    /// The restart exposure, driven rather than described.
    ///
    /// The seen-set is in-process, so a restart empties it and an event this
    /// node already refused is admissible again. That is stated at length on
    /// `ReplayGuard`, and prose is not a bound. What makes the exposure
    /// tolerable is the composition with the freshness window, so both halves
    /// are asserted here: a fresh guard readmits the event, and a fresh guard
    /// still refuses it once the event's own stamp has aged out. The second
    /// half is what turns "one replay per restart" into a bound, since without
    /// it a crash-looping node would readmit the same captured signature
    /// forever.
    ///
    /// A fresh `ReplayGuard` is the whole of the post-restart state for this
    /// layer, which is what lets the restart be modelled in-process: the guard
    /// holds no handle to anything that survives the process, so a new one is
    /// indistinguishable from a new node.
    #[sqlx::test]
    async fn a_restarted_guard_readmits_a_seen_event_and_the_window_still_bounds_it(pool: PgPool) {
        let t0 = freshness_now();
        pin_ingest_now(t0);

        let db = ingest_db(&pool).await;
        // ONE limiter set across all four deliveries, so nothing below is
        // masked by a budget that was quietly reset alongside the guard.
        let limiters = IngestLimiters::new();
        let source = PeerId::random();
        let keypair = Keypair::generate();
        seed_peer(&pool, &keypair.did().to_string()).await;

        let mut event = event_for(&keypair);
        sign_ref_update(&keypair, &mut event).unwrap();
        let bytes = bytes_of(&event);

        let before_restart = ReplayGuard::new();
        let first =
            ingest_ref_update(&db, &limiters, &before_restart, true, true, &bytes, &source).await;
        assert!(
            matches!(first, IngestOutcome::Accepted),
            "the first delivery must be accepted, got {first:?}"
        );
        let replayed =
            ingest_ref_update(&db, &limiters, &before_restart, true, true, &bytes, &source).await;
        assert!(
            matches!(replayed, IngestOutcome::Replayed),
            "the same process must refuse the second copy, or the readmission below says nothing \
             about the restart, got {replayed:?}"
        );

        // The restart. Same bytes, same clock, same everything else.
        let after_restart = ReplayGuard::new();
        let readmitted =
            ingest_ref_update(&db, &limiters, &after_restart, true, true, &bytes, &source).await;
        assert!(
            matches!(readmitted, IngestOutcome::Accepted),
            "a node that has forgotten the event admits it again; this is the documented \
             exposure, asserted so a claim that a restart is free would fail here, got \
             {readmitted:?}"
        );
        assert_eq!(
            count(&pool, "received_ref_updates").await,
            2,
            "the readmission is a real write, which is exactly what makes it an exposure worth \
             bounding"
        );

        // One second past the event's own freshness horizon, and a guard as
        // empty as the one above. Nothing remembers this event now, so the
        // window is the only thing left to refuse it.
        pin_ingest_now(
            t0 + chrono::Duration::seconds(GOSSIP_REF_UPDATE_FRESHNESS_WINDOW.as_secs() as i64 + 1),
        );
        let after_later_restart = ReplayGuard::new();
        let stale = ingest_ref_update(
            &db,
            &limiters,
            &after_later_restart,
            true,
            true,
            &bytes,
            &source,
        )
        .await;
        assert!(
            matches!(stale, IngestOutcome::StaleTimestamp(_)),
            "past its stamp's window the event is refused however many times the process has \
             cycled, which is what bounds the restart exposure at one replay per restart within \
             ten minutes rather than one per restart forever, got {stale:?}"
        );
        assert_eq!(
            count(&pool, "received_ref_updates").await,
            2,
            "the refused delivery must write nothing"
        );
    }
}
