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
use chrono::Utc;
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
/// This is the tight bound, and it is where the tightness belongs, because by
/// the time it runs the signature and the known-peer check have established
/// WHO is asking. It bounds the two durable writes per event, charged to the
/// principal that authored them rather than to a mesh edge. `api::repos`
/// publishes one event per updated ref, so the number has to admit a whole
/// large push: 500 covers a tag-heavy push, an initial import, or a mirror
/// backfill of a few hundred refs arriving in one window.
const GOSSIP_AUTHOR_MAX_EVENTS: usize = 500;
/// The pre-parse brake keys on a forwarder that aggregates many authors, so
/// sizing it at or below the per-author budget puts the tight bound back on the
/// mesh edge, which is the shape being fixed here. Enforced at compile time
/// rather than in a test, because it is a relation between two constants and a
/// test can only catch it after someone runs it.
const _: () = assert!(
    GOSSIP_SOURCE_MAX_EVENTS > GOSSIP_AUTHOR_MAX_EVENTS,
    "the forwarder bound must stay looser than the per-author bound"
);
const GOSSIP_INGEST_WINDOW: Duration = Duration::from_secs(60);
/// Ceiling on tracked source peers, matching the bound the HTTP brakes use in
/// `main.rs`. Keeps a source-rotation flood from growing the limiter's own map.
const GOSSIP_INGEST_MAX_SOURCES: usize = 200_000;
/// Ceiling on tracked author DIDs. Reaching this map costs an attacker a
/// registered peer row per key, but registration is open through the announce
/// path, so the bound is not left to that.
const GOSSIP_INGEST_MAX_AUTHORS: usize = 200_000;

/// The two gossip ingest budgets, built the same way for the swarm loop and for
/// the tests so a test can never assert against a budget production does not
/// run.
///
/// They are deliberately separate limiters rather than one: they key on
/// different identities (a forwarder before parsing, an author after
/// authentication) and sit at different points in the path.
pub(crate) struct IngestLimiters {
    /// Keyed on `propagation_source`, checked before the parse.
    source: crate::rate_limit::RateLimiter,
    /// Keyed on the authenticated `node_did`, checked before the writes.
    author: crate::rate_limit::RateLimiter,
}

impl IngestLimiters {
    pub(crate) fn new() -> Self {
        Self {
            source: crate::rate_limit::RateLimiter::new_bounded(
                GOSSIP_SOURCE_MAX_EVENTS,
                GOSSIP_INGEST_WINDOW,
                GOSSIP_INGEST_MAX_SOURCES,
            ),
            author: crate::rate_limit::RateLimiter::new_bounded(
                GOSSIP_AUTHOR_MAX_EVENTS,
                GOSSIP_INGEST_WINDOW,
                GOSSIP_INGEST_MAX_AUTHORS,
            ),
        }
    }
}

/// A ref-update event published to Gossipsub when a push lands.
///
/// The signing bytes are this struct serialized with `sig` set to None (see
/// [`signing_bytes`]), so ANY future field added here changes the signing bytes
/// for every event that carries it. In a mixed fleet, a node that does not know
/// the new field re-serializes without it and computes different bytes, so
/// verification fails. A field addition therefore needs its own rollout plan
/// (ship the field to the whole fleet before anything emits it), not just a
/// struct edit.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RefUpdateEvent {
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

/// What the ingest path decided about one inbound gossip message.
#[derive(Debug)]
pub(crate) enum IngestOutcome {
    /// The event was authenticated AND every write it implies landed.
    Accepted,
    /// The event passed every guard, but a durable write failed. The decision
    /// was still "admit it", so this is not a refusal; it exists because
    /// returning `Accepted` for an event whose row never landed would make the
    /// outcome an observability lie.
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
    // here denies an honest neighbour on someone else's flood; the tight bound
    // lives below, on the authenticated author.
    if !limiters.source.check(&propagation_source.to_string()).await {
        return IngestOutcome::SourceRateLimited;
    }

    let event = match serde_json::from_slice::<RefUpdateEvent>(data) {
        Ok(event) => event,
        Err(e) => return IngestOutcome::Rejected(format!("malformed ref-update event: {e}")),
    };

    // did-method gate first, and in BOTH enforcement modes: a non-did:key peer
    // is unauthenticatable by design, and running this before the flag branch
    // is what keeps the answer independent of flag state.
    if let Err(reason) = resolve_node_did(&event.node_did) {
        return IngestOutcome::Rejected(reason);
    }

    match event.sig {
        // A signature that is present must verify. A present-but-invalid one is
        // forgery, never a peer that has not upgraded yet, so the flag does not
        // enter into it.
        Some(_) => {
            if let Err(reason) = verify_ref_update(&event) {
                return IngestOutcome::Rejected(reason);
            }
        }
        None if require_signed => {
            return IngestOutcome::Rejected("unsigned ref-update event".to_string());
        }
        // Rolling-upgrade window, same posture and same pointer at the flag as
        // the HTTP twin's unsigned-notify warning.
        None => {
            warn!(
                did = %event.node_did,
                "accepted unsigned gossip ref-update; set GITLAWB_REQUIRE_SIGNED_PEER_WRITES=true after all peers upgrade"
            );
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
    match db.peer_exists(&event.node_did).await {
        Ok(true) => {}
        Ok(false) => {
            return IngestOutcome::Rejected(format!("unknown peer DID: {}", event.node_did));
        }
        Err(e) => return IngestOutcome::Rejected(format!("peer lookup failed: {e}")),
    }

    // The tight budget, and the only one keyed on an identity the sender had to
    // prove. Everything above this line establishes WHO is asking; everything
    // below it costs durable writes, so the write budget is charged to the
    // author rather than to whichever neighbour happened to relay the message.
    // In the rolling-upgrade window an unsigned event's `node_did` is asserted
    // rather than proven, but it is still a registered peer, so the key is at
    // worst as strong as the gate above it.
    if !limiters.author.check(&event.node_did).await {
        return IngestOutcome::AuthorRateLimited(event.node_did.clone());
    }

    // #272: the slug reaches a `PathBuf::join` in the sync worker, so it is
    // rejected here, before the ref-update row and the queue row.
    if let Err(e) = crate::git::repo_store::validate_repo_slug(&event.repo) {
        return IngestOutcome::Rejected(format!("invalid repo field: {e}"));
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
        loop {
            tokio::select! {
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
                            match ingest_ref_update(
                                &db,
                                &ingest_limiters,
                                require_signed,
                                auto_sync,
                                &message.data,
                                &propagation_source,
                            ).await {
                                IngestOutcome::Accepted => {}
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
                            match signed_publish_bytes(&keypair, &event) {
                                Ok(bytes) => {
                                    let topic = gossipsub::IdentTopic::new(REF_UPDATES_TOPIC);
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
            IngestOutcome::WriteFailed(reason) => {
                panic!("{context}: the event must be rejected by a guard, not admitted and then failed to write: {reason}")
            }
            IngestOutcome::SourceRateLimited | IngestOutcome::AuthorRateLimited(_) => {
                panic!("{context}: the event must be rejected by a guard, not by a rate brake")
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

        for require_signed in [true, false] {
            let context = format!("foreign-key signature, require_signed={require_signed}");
            let outcome = ingest_with_fresh_limiter(
                &db,
                require_signed,
                true,
                &bytes_of(&event),
                &PeerId::random(),
            )
            .await;
            assert_nothing_written(&pool, &context).await;
            rejection_reason(outcome, &context);
        }
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

        for require_signed in [true, false] {
            let context = format!("tampered event, require_signed={require_signed}");
            let outcome = ingest_with_fresh_limiter(
                &db,
                require_signed,
                true,
                &bytes_of(&event),
                &PeerId::random(),
            )
            .await;
            assert_nothing_written(&pool, &context).await;
            rejection_reason(outcome, &context);
        }
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

        for require_signed in [true, false] {
            let context = format!("did:web node_did, require_signed={require_signed}");
            let outcome = ingest_with_fresh_limiter(
                &db,
                require_signed,
                true,
                &bytes_of(&event),
                &PeerId::random(),
            )
            .await;
            assert_nothing_written(&pool, &context).await;
            assert_eq!(
                rejection_reason(outcome, &context),
                "methodNotSupported: only did:key peers can be registered without a proof of control: did:web:example.com",
                "{context}: the gossip surface must reuse the peers-table refusal sentence"
            );
        }
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

        for require_signed in [true, false] {
            let context = format!("unknown peer DID, require_signed={require_signed}");
            let outcome = ingest_with_fresh_limiter(
                &db,
                require_signed,
                true,
                &bytes_of(&event),
                &PeerId::random(),
            )
            .await;
            assert_nothing_written(&pool, &context).await;
            rejection_reason(outcome, &context);
        }
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

        for require_signed in [true, false] {
            let context = format!("traversal slug, require_signed={require_signed}");
            let outcome = ingest_with_fresh_limiter(
                &db,
                require_signed,
                true,
                &bytes_of(&event),
                &PeerId::random(),
            )
            .await;
            assert_nothing_written(&pool, &context).await;
            rejection_reason(outcome, &context);
        }
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
    /// from a KNOWN peer is still accepted. Turning the flag on is the
    /// operator's step, not a code change, so this path has to keep working
    /// until they take it.
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
            matches!(outcome, IngestOutcome::Accepted),
            "an unsigned known-peer event must survive the rolling-upgrade window, got {outcome:?}"
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

    // ── Ingest rate limits ────────────────────────────────────────────────

    #[test]
    fn the_two_ingest_budgets_are_wired_as_documented() {
        assert_eq!(GOSSIP_SOURCE_MAX_EVENTS, 2000);
        assert_eq!(GOSSIP_AUTHOR_MAX_EVENTS, 500);
        assert_eq!(GOSSIP_INGEST_WINDOW, Duration::from_secs(60));
        assert_eq!(GOSSIP_INGEST_MAX_SOURCES, 200_000);
        assert_eq!(GOSSIP_INGEST_MAX_AUTHORS, 200_000);
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
    fn both_ingest_limiters_carry_their_key_ceiling() {
        let limiters = IngestLimiters::new();
        assert_eq!(
            limiters.source.max_keys(),
            GOSSIP_INGEST_MAX_SOURCES,
            "the source limiter must be built bounded by GOSSIP_INGEST_MAX_SOURCES"
        );
        assert_eq!(
            limiters.author.max_keys(),
            GOSSIP_INGEST_MAX_AUTHORS,
            "the author limiter must be built bounded by GOSSIP_INGEST_MAX_AUTHORS"
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
}
