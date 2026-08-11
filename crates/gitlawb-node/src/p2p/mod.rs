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
#[allow(dead_code)] // wired into the emit path in a later unit
fn sign_ref_update(keypair: &Keypair, event: &mut RefUpdateEvent) -> serde_json::Result<()> {
    let bytes = signing_bytes(event)?;
    event.sig = Some(keypair.sign_b64(&bytes));
    Ok(())
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
    /// The event was authenticated and written.
    Accepted,
    /// The event was dropped. Nothing is stored, so the reason exists only to
    /// be logged and counted.
    Rejected(String),
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
    require_signed: bool,
    auto_sync: bool,
    data: &[u8],
    propagation_source: &PeerId,
) -> IngestOutcome {
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
    // own events perfectly well. Only registered peers may write.
    match db.list_peers().await {
        Ok(peers) => {
            if !peers.iter().any(|p| p.did == event.node_did) {
                return IngestOutcome::Rejected(format!("unknown peer DID: {}", event.node_did));
            }
        }
        Err(e) => return IngestOutcome::Rejected(format!("peer lookup failed: {e}")),
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
    if let Err(e) = db.insert_ref_update(&update).await {
        warn!(err = %e, "failed to store received ref-update");
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
        }
    }
    IngestOutcome::Accepted
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

    // The node identity that signs outgoing publishes. The emit path is wired
    // in a later unit; ingest only ever resolves keys from the claimed DID.
    let _keypair = keypair;

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
                            if let IngestOutcome::Rejected(reason) = ingest_ref_update(
                                &db,
                                require_signed,
                                auto_sync,
                                &message.data,
                                &propagation_source,
                            ).await {
                                warn!(
                                    from = %propagation_source,
                                    reason = %reason,
                                    "dropped gossip ref-update"
                                );
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
                            if let Ok(bytes) = serde_json::to_vec(&event) {
                                let topic = gossipsub::IdentTopic::new(REF_UPDATES_TOPIC);
                                match swarm.behaviour_mut().gossipsub.publish(topic, bytes) {
                                    Ok(id) => info!(msg_id = %id, repo = %event.repo, "published ref-update"),
                                    Err(e) => warn!(err = %e, "failed to publish ref-update"),
                                }
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

        let mut event = populated_event();
        event.sig = Some("c2lnbmF0dXJl".into());
        let bytes = serde_json::to_vec(&event).unwrap();

        let legacy: LegacyRefUpdateEvent = serde_json::from_slice(&bytes)
            .expect("new-code bytes must deserialize under the old field set");
        assert_eq!(legacy.repo, "zOwner/myrepo");
        assert_eq!(legacy.owner_did, Some("did:key:zOwner".into()));
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

    fn rejection_reason(outcome: IngestOutcome, context: &str) -> String {
        match outcome {
            IngestOutcome::Rejected(reason) => reason,
            IngestOutcome::Accepted => panic!("{context}: the event must be rejected"),
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
            ingest_ref_update(&db, true, true, &bytes_of(&event), &PeerId::random()).await;

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
            let outcome = ingest_ref_update(
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
            let outcome = ingest_ref_update(
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
    /// refusal answers in the SAME sentence as the peers-table gate. The DID is
    /// seeded as a known peer on purpose, so the known-peer gate would admit it
    /// and only the did-method gate can be what rejects it.
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
            let outcome = ingest_ref_update(
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
            let outcome = ingest_ref_update(
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
            let outcome = ingest_ref_update(
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

        let outcome = ingest_ref_update(&db, true, true, &bytes_of(&event), &source).await;
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
            ingest_ref_update(&db, true, false, &bytes_of(&event), &PeerId::random()).await;
        assert!(matches!(outcome, IngestOutcome::Accepted));

        assert_eq!(count(&pool, "received_ref_updates").await, 1);
        assert_eq!(
            count(&pool, "sync_queue").await,
            0,
            "auto_sync off must not enqueue"
        );
    }

    /// R7, the rolling-upgrade window: with enforcement off, an unsigned event
    /// from a KNOWN peer is still accepted (and warned about, per the HTTP
    /// twin's wording). Turning the flag on is the operator's step, not a code
    /// change, so this path has to keep working until they take it.
    #[sqlx::test]
    async fn flag_off_unsigned_known_peer_event_is_accepted(pool: PgPool) {
        let db = ingest_db(&pool).await;
        let keypair = Keypair::generate();
        let event = event_for(&keypair);
        assert_eq!(event.sig, None);
        seed_peer(&pool, &event.node_did).await;

        let outcome =
            ingest_ref_update(&db, false, true, &bytes_of(&event), &PeerId::random()).await;
        assert!(
            matches!(outcome, IngestOutcome::Accepted),
            "an unsigned known-peer event must survive the rolling-upgrade window, got {outcome:?}"
        );
        assert_eq!(count(&pool, "received_ref_updates").await, 1);
        assert_eq!(count(&pool, "sync_queue").await, 1);
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
