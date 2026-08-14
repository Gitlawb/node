//! libp2p networking layer — Kademlia DHT + Gossipsub.
//!
//! Provides:
//!   - Peer discovery via Kademlia DHT (DID → multiaddr mapping)
//!   - Real-time ref-update events via Gossipsub
//!
//! The node's PeerId is derived from its Ed25519 identity keypair,
//! so the gitlawb DID and libp2p PeerId share the same key.

use std::collections::{hash_map::DefaultHasher, HashMap};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
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
/// so roughly 8,000 entries per author running flat out. Filling 100,000 takes
/// twelve or thirteen registered DIDs sustaining the author cap for a full
/// horizon, every event individually signed and durably written, which is
/// 100,000 ref-update rows and 100,000 sync enqueues: an attack the database
/// and the accepted counter announce long before this ceiling is reached. At
/// roughly 100 bytes per entry the ceiling is about 10 MB, comparable to the
/// limiters' own 200k-key maps.
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
    /// gitlawb DID of the node publishing the event
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
#[allow(dead_code)] // wired into the ingest path in a follow-up
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
#[allow(dead_code)] // wired into the ingest path in a follow-up
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
    #[cfg_attr(not(test), allow(dead_code))]
    confirmed: bool,
}

/// What [`ReplayGuard::begin`] decided about one key.
#[derive(Debug)]
#[allow(dead_code)] // matched by the ingest path in a follow-up
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
pub(crate) struct ReplayGuard {
    seen: std::sync::Mutex<HashMap<[u8; 32], SeenEntry>>,
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
    #[allow(dead_code)] // constructed by the swarm loop in a follow-up
    pub(crate) fn new() -> Self {
        Self::with_limits(GOSSIP_SEEN_EVENTS_RETENTION, GOSSIP_SEEN_EVENTS_MAX)
    }

    /// The single place a guard is built, so a test can never assert against a
    /// shape production does not run. Both parameters are relations the
    /// constants above document; nothing else about the guard varies.
    fn with_limits(retention: Duration, capacity: usize) -> Self {
        Self {
            seen: std::sync::Mutex::new(HashMap::new()),
            retention,
            capacity,
        }
    }

    /// A poisoned mutex is not a reason to stop deduplicating. Nothing behind
    /// this lock is an invariant a panicking holder could have half-broken: it
    /// is a map of opaque keys to timestamps, and the worst a poisoned state
    /// can hold is one stale entry. Refusing to serve it would turn a panic
    /// somewhere else in the process into a replay window here.
    fn lock_seen(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], SeenEntry>> {
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
    #[allow(dead_code)] // called by the ingest path in a follow-up
    fn begin(&self, key: [u8; 32], now: DateTime<Utc>) -> Begin<'_> {
        let mut seen = self.lock_seen();

        let present = match seen.get(&key) {
            Some(entry) if !self.is_expired(entry, now) => return Begin::Replayed,
            Some(_) => true,
            None => false,
        };

        // Only a NEW key can grow the map, so an expired entry being replaced
        // in place never has to clear the capacity bar.
        if !present && seen.len() >= self.capacity {
            Self::sweep_locked(&mut seen, now, self.retention);
            if seen.len() >= self.capacity {
                drop(seen);
                crate::metrics::record_gossip_replay_guard_saturated();
                return Begin::Saturated;
            }
        }

        seen.insert(
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
    #[allow(dead_code)] // called by the swarm loop in a follow-up
    fn cleanup(&self, now: DateTime<Utc>) {
        let mut seen = self.lock_seen();
        Self::sweep_locked(&mut seen, now, self.retention);
    }

    /// Takes the already-held map rather than locking, so [`begin`] can sweep
    /// inside its own critical section without releasing and reacquiring.
    ///
    /// [`begin`]: ReplayGuard::begin
    fn sweep_locked(
        seen: &mut HashMap<[u8; 32], SeenEntry>,
        now: DateTime<Utc>,
        retention: Duration,
    ) {
        let horizon = chrono::Duration::seconds(retention.as_secs() as i64);
        seen.retain(|_, entry| now.signed_duration_since(entry.recorded_at) <= horizon);
    }
}

#[cfg(test)]
impl ReplayGuard {
    fn is_confirmed_for_test(&self, key: &[u8; 32]) -> bool {
        self.lock_seen().get(key).is_some_and(|e| e.confirmed)
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
    #[allow(dead_code)] // called by the ingest path in a follow-up
    fn confirm(mut self) {
        {
            let mut seen = self.guard.lock_seen();
            if let Some(entry) = seen.get_mut(&self.key) {
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
        self.guard.lock_seen().remove(&self.key);
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
#[allow(dead_code)] // variants are matched by the ingest path in a follow-up
enum FreshnessViolation {
    /// Older than [`GOSSIP_REF_UPDATE_FRESHNESS_WINDOW`].
    TooOld,
    /// Ahead of this node's clock by more than
    /// [`GOSSIP_REF_UPDATE_FUTURE_SKEW`].
    TooFarFuture,
    /// Not parseable as RFC-3339, so it cannot be freshness-checked at all.
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
#[allow(dead_code)] // wired into the ingest path in a follow-up
fn check_freshness(timestamp: &str, now: DateTime<Utc>) -> Result<(), FreshnessViolation> {
    let stamped = DateTime::parse_from_rfc3339(timestamp)
        .map_err(|_| FreshnessViolation::Unparseable)?
        .with_timezone(&Utc);

    let window = chrono::Duration::seconds(GOSSIP_REF_UPDATE_FRESHNESS_WINDOW.as_secs() as i64);
    let skew = chrono::Duration::seconds(GOSSIP_REF_UPDATE_FUTURE_SKEW.as_secs() as i64);

    if now - stamped > window {
        return Err(FreshnessViolation::TooOld);
    }
    if stamped - now > skew {
        return Err(FreshnessViolation::TooFarFuture);
    }
    Ok(())
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
    #[allow(dead_code)] // returned by the ingest path in a follow-up
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
    #[allow(dead_code)] // returned by the ingest path in a follow-up
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
        None if unsigned => IngestOutcome::UnsignedAdmitted,
        None => IngestOutcome::Accepted,
    }
}

/// A DID record stored in the Kademlia DHT — maps a gitlawb DID to a node.
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

/// Start the libp2p swarm. Returns a handle for sending commands and the
/// listening multiaddrs. Runs the event loop as a background tokio task
/// that exits cleanly when `shutdown_rx` flips to `true`.
// Wide, but each argument is a distinct piece of node configuration and there
// is exactly one call site; bundling them would buy nothing.
#[allow(clippy::too_many_arguments)]
pub async fn start(
    node_did: &str,
    listen_port: u16,
    bootstrap_addrs: Vec<Multiaddr>,
    db: Arc<Db>,
    auto_sync: bool,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    keypair: Arc<Keypair>,
    require_signed: bool,
) -> Result<P2pHandle> {
    // Derive a stable libp2p Ed25519 key from a seed based on the node DID.
    // In production you'd load/persist this key alongside the identity PEM.
    // For now we use the DID string as a deterministic seed.
    let seed = {
        let mut h = DefaultHasher::new();
        node_did.hash(&mut h);
        h.finish()
    };
    let mut seed_bytes = [0u8; 32];
    seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
    // Spread the seed across all bytes for better distribution
    for i in 1..4 {
        seed_bytes[i * 8..(i + 1) * 8].copy_from_slice(&seed.wrapping_add(i as u64).to_le_bytes());
    }

    let local_key = identity::Keypair::ed25519_from_bytes(seed_bytes)
        .map_err(|e| anyhow::anyhow!("failed to create p2p keypair: {e}"))?;
    let local_peer_id = PeerId::from(local_key.public());

    info!(peer_id = %local_peer_id, "libp2p identity");

    // Per-source ingest brake, held across the whole swarm loop so budgets
    // accumulate per forwarding peer.
    let ingest_limiters = IngestLimiters::new();

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
                    ingest_limiters.cleanup().await;
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

    /// Build a populated event whose `node_did` is the given keypair's DID.
    fn event_for(keypair: &Keypair) -> RefUpdateEvent {
        let mut event = populated_event();
        event.node_did = keypair.did().to_string();
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
            let outcome =
                ingest_ref_update(&db, &limiters, true, true, b"not json at all", &source).await;
            assert!(
                matches!(outcome, IngestOutcome::Rejected(_)),
                "flood message {i} is inside the budget, so it is admitted and then dropped as malformed, got {outcome:?}"
            );
        }

        let outcome =
            ingest_ref_update(&db, &limiters, true, true, &bytes_of(&event), &source).await;
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
            ingest_ref_update(&db, &limiters, true, true, b"not json at all", &throttled).await;
        }
        let outcome =
            ingest_ref_update(&db, &limiters, true, true, &bytes_of(&event), &throttled).await;
        assert!(
            matches!(outcome, IngestOutcome::SourceRateLimited),
            "the first source must be over budget, got {outcome:?}"
        );

        let outcome =
            ingest_ref_update(&db, &limiters, true, true, &bytes_of(&event), &other).await;
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
            ingest_ref_update(&db, &limiters, true, true, b"not json at all", &neighbour).await;
        }

        let outcome =
            ingest_ref_update(&db, &limiters, true, true, &bytes_of(&event), &neighbour).await;
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
        let source = PeerId::random();
        let noisy = Keypair::generate();
        let quiet = Keypair::generate();
        seed_peer(&pool, &noisy.did().to_string()).await;
        seed_peer(&pool, &quiet.did().to_string()).await;

        let mut event = event_for(&noisy);
        sign_ref_update(&noisy, &mut event).unwrap();
        for i in 0..GOSSIP_AUTHOR_MAX_EVENTS {
            let outcome =
                ingest_ref_update(&db, &limiters, true, true, &bytes_of(&event), &source).await;
            assert!(
                matches!(outcome, IngestOutcome::Accepted),
                "event {i} is inside the author budget and must be accepted, got {outcome:?}"
            );
        }
        let accepted = GOSSIP_AUTHOR_MAX_EVENTS as i64;
        assert_eq!(count(&pool, "received_ref_updates").await, accepted);
        assert_eq!(count(&pool, "sync_queue").await, accepted);

        let outcome =
            ingest_ref_update(&db, &limiters, true, true, &bytes_of(&event), &source).await;
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
        let outcome =
            ingest_ref_update(&db, &limiters, true, true, &bytes_of(&other_event), &source).await;
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
            let outcome =
                ingest_ref_update(&db, &limiters, false, true, &claim, &attacker_edge).await;
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

    /// Exhaust one edge's unsigned budget and hand back the source that was
    /// spent, so the callers below can assert what happens next.
    async fn spend_unsigned_budget(db: &Db, limiters: &IngestLimiters, claim: &[u8]) -> PeerId {
        let source = PeerId::random();
        for i in 0..GOSSIP_UNSIGNED_SOURCE_MAX_EVENTS {
            let outcome = ingest_ref_update(db, limiters, false, true, claim, &source).await;
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

        let outcome = ingest_ref_update(&db, &limiters, false, true, &claim, &source).await;
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
        let outcome =
            ingest_ref_update(&db, &limiters, false, true, &bytes_of(&signed), &source).await;
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
            ingest_ref_update(&db, &limiters, false, true, &claim, &spent_source).await,
            IngestOutcome::UnsignedSourceRateLimited(_)
        ));

        // Same bytes, same claimed DID, a different forwarder.
        let fresh_source = PeerId::random();
        let outcome = ingest_ref_update(&db, &limiters, false, true, &claim, &fresh_source).await;
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
        let outcome =
            ingest_ref_update(&db, &limiters, false, true, &bytes_of(&other), &source).await;
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
            let outcome =
                ingest_ref_update(&db, &limiters, false, true, &bad_signed, &signed_edge).await;
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
        let outcome =
            ingest_ref_update(&db, &limiters, false, true, &bytes_of(&good), &signed_edge).await;
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
            let outcome =
                ingest_ref_update(&db, &limiters, false, true, &bad_unsigned, &unsigned_edge).await;
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
        let outcome =
            ingest_ref_update(&db, &limiters, false, true, &valid_unsigned, &unsigned_edge).await;
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
            let outcome =
                ingest_ref_update(&db, &limiters, true, true, &bytes_of(&event), &source).await;
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
            let outcome = ingest_ref_update(&db, &limiters, false, true, &claim, &source).await;
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
            Err(FreshnessViolation::TooOld),
            "an event one second past the window must be refused as stale-past"
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
            Err(FreshnessViolation::TooFarFuture),
            "one second past the skew allowance must be refused as stale-future"
        );
        assert_eq!(
            check_freshness(&stamp(300), freshness_now()),
            Err(FreshnessViolation::TooFarFuture),
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

        // A before/after delta, not an equality against a literal. This counter
        // carries no labels and lives in a process-wide registry shared by every
        // test in this binary, so an equality would be a hostage to any second
        // test that ever reaches saturation.
        let before = crate::metrics::replay_guard_saturated_count_for_test();
        assert!(matches!(guard.begin(key_of(21), now), Begin::Saturated));
        assert_eq!(
            crate::metrics::replay_guard_saturated_count_for_test(),
            before + 1,
            "each Saturated answer must increment the saturation counter"
        );
    }
}
