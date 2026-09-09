//! libp2p networking layer — Kademlia DHT + Gossipsub.
//!
//! Provides:
//!   - Peer discovery via Kademlia DHT (DID → multiaddr mapping)
//!   - Real-time ref-update events via Gossipsub
//!
//! The node's PeerId is derived from its Ed25519 identity keypair,
//! so the gitlawb DID and libp2p PeerId share the same key.

use std::collections::{hash_map::DefaultHasher, HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};

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

use crate::db::{Db, ReceivedRefUpdate};

/// Topic for ref-update notifications published after every push.
pub const REF_UPDATES_TOPIC: &str = "gitlawb/ref-updates/v1";

// Identify is an untrusted address source. Keep enough entries for normal
// multi-homed peers while bounding both one peer and the whole routing table.
const IDENTIFY_ADDRESS_LIMIT: usize = 8;
const IDENTIFY_NEW_ADDRESS_LIMIT: usize = 8;
const IDENTIFY_GLOBAL_ADDRESS_LIMIT: usize = 1024;
const IDENTIFY_ADDRESS_WINDOW: Duration = Duration::from_secs(60);
const IDENTIFY_ADDRESS_TTL: Duration = Duration::from_secs(30 * 60);
const IDENTIFY_ADDRESS_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// A ref-update event published to Gossipsub when a push lands.
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

#[derive(Debug)]
struct IdentifyAddress {
    address: Multiaddr,
    expires_at: Instant,
}

#[derive(Debug)]
struct IdentifyPeerAddresses {
    addresses: VecDeque<IdentifyAddress>,
    window_started: Instant,
    new_addresses: usize,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct IdentifyAddressChanges {
    added: Vec<Multiaddr>,
    removed: Vec<(PeerId, Multiaddr)>,
}

#[derive(Debug, Default)]
struct IdentifyAddressBook {
    peers: HashMap<PeerId, IdentifyPeerAddresses>,
    insertion_order: VecDeque<(PeerId, Multiaddr)>,
    address_count: usize,
}

impl IdentifyAddressBook {
    fn update(
        &mut self,
        peer_id: PeerId,
        now: Instant,
        addresses: &[Multiaddr],
    ) -> IdentifyAddressChanges {
        let mut changes = IdentifyAddressChanges::default();
        if self.peers.contains_key(&peer_id) {
            changes.removed.extend(self.expire_peer(peer_id, now));
        }
        self.peers
            .entry(peer_id)
            .or_insert_with(|| IdentifyPeerAddresses {
                addresses: VecDeque::new(),
                window_started: now,
                new_addresses: 0,
            });

        if let Some(state) = self.peers.get_mut(&peer_id) {
            if now.saturating_duration_since(state.window_started) >= IDENTIFY_ADDRESS_WINDOW {
                state.window_started = now;
                state.new_addresses = 0;
            }
        }

        let reported = addresses
            .iter()
            .filter_map(|address| address.clone().with_p2p(peer_id).ok())
            .collect::<HashSet<_>>();

        // Refresh every address in the report before admitting anything new.
        // This prevents an oversized report from evicting an address merely
        // because it appeared later in the input.
        if let Some(state) = self.peers.get_mut(&peer_id) {
            for existing in &mut state.addresses {
                if reported.contains(&existing.address) {
                    existing.expires_at = now + IDENTIFY_ADDRESS_TTL;
                }
            }
        }

        let mut new_addresses = self
            .peers
            .get(&peer_id)
            .map(|state| {
                reported
                    .iter()
                    .filter(|address| {
                        !state
                            .addresses
                            .iter()
                            .any(|existing| &existing.address == *address)
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| reported.iter().cloned().collect());
        // HashSet iteration is deliberately unordered. Sort new candidates so
        // an oversized Identify report has deterministic admission behavior.
        new_addresses.sort();

        for address in new_addresses {
            if self
                .peers
                .get(&peer_id)
                .is_some_and(|state| state.new_addresses >= IDENTIFY_NEW_ADDRESS_LIMIT)
            {
                break;
            }

            let evicted = self.peers.get_mut(&peer_id).and_then(|state| {
                if state.addresses.len() < IDENTIFY_ADDRESS_LIMIT {
                    return None;
                }
                let index = state
                    .addresses
                    .iter()
                    .position(|existing| !reported.contains(&existing.address))?;
                state.addresses.remove(index)
            });
            if let Some(evicted) = evicted {
                self.remove_insertion_token(peer_id, &evicted.address);
                self.address_count -= 1;
                changes.removed.push((peer_id, evicted.address));
            } else if self
                .peers
                .get(&peer_id)
                .is_some_and(|state| state.addresses.len() >= IDENTIFY_ADDRESS_LIMIT)
            {
                // Every retained address was refreshed in this report. Keep
                // that stable subset and drop surplus new candidates.
                break;
            }

            if self.address_count >= IDENTIFY_GLOBAL_ADDRESS_LIMIT {
                let Some(evicted) = self.evict_oldest(peer_id) else {
                    break;
                };
                changes.removed.push(evicted);
            }

            if let Some(state) = self.peers.get_mut(&peer_id) {
                state.new_addresses += 1;
            }

            if let Some(state) = self.peers.get_mut(&peer_id) {
                state.addresses.push_back(IdentifyAddress {
                    address: address.clone(),
                    expires_at: now + IDENTIFY_ADDRESS_TTL,
                });
                self.insertion_order.push_back((peer_id, address.clone()));
                self.address_count += 1;
                changes.added.push(address);
            }
        }

        changes
    }

    fn expire(&mut self, now: Instant) -> Vec<(PeerId, Multiaddr)> {
        let mut removed = Vec::new();
        let peers = self.peers.keys().copied().collect::<Vec<_>>();
        for peer_id in peers {
            removed.extend(self.expire_peer(peer_id, now));
        }
        removed
    }

    fn expire_peer(&mut self, peer_id: PeerId, now: Instant) -> Vec<(PeerId, Multiaddr)> {
        let expired = self
            .peers
            .get_mut(&peer_id)
            .map(|state| Self::expire_state(state, now))
            .unwrap_or_default();
        for address in &expired {
            self.remove_insertion_token(peer_id, address);
            self.address_count -= 1;
        }
        if self
            .peers
            .get(&peer_id)
            .is_some_and(|state| state.addresses.is_empty())
        {
            self.peers.remove(&peer_id);
        }
        expired
            .into_iter()
            .map(|address| (peer_id, address))
            .collect()
    }

    fn expire_state(state: &mut IdentifyPeerAddresses, now: Instant) -> Vec<Multiaddr> {
        let mut expired = Vec::new();
        let mut retained = VecDeque::with_capacity(state.addresses.len());
        while let Some(address) = state.addresses.pop_front() {
            if address.expires_at <= now {
                expired.push(address.address);
            } else {
                retained.push_back(address);
            }
        }
        state.addresses = retained;
        expired
    }

    fn evict_oldest(&mut self, preserve_peer: PeerId) -> Option<(PeerId, Multiaddr)> {
        while let Some((peer_id, address)) = self.insertion_order.pop_front() {
            let Some(state) = self.peers.get_mut(&peer_id) else {
                continue;
            };
            let Some(index) = state
                .addresses
                .iter()
                .position(|tracked| tracked.address == address)
            else {
                continue;
            };
            let evicted = state.addresses.remove(index)?.address;
            self.address_count -= 1;
            if state.addresses.is_empty() && peer_id != preserve_peer {
                self.peers.remove(&peer_id);
            }
            return Some((peer_id, evicted));
        }
        None
    }

    fn remove_insertion_token(&mut self, peer_id: PeerId, address: &Multiaddr) {
        if let Some(index) = self
            .insertion_order
            .iter()
            .position(|(token_peer, token_address)| {
                token_peer == &peer_id && token_address == address
            })
        {
            self.insertion_order.remove(index);
        }
    }
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
pub async fn start(
    node_did: &str,
    listen_port: u16,
    bootstrap_addrs: Vec<Multiaddr>,
    db: Arc<Db>,
    auto_sync: bool,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
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
    // Keep Identify-derived entries across disconnects so a bootstrap address
    // learned through Identify remains usable for redial. The TTL cleanup below
    // removes entries that are no longer refreshed without touching explicit
    // AddKnownPeer addresses.
    let mut identify_addresses = IdentifyAddressBook::default();
    let mut explicit_addresses: HashMap<PeerId, HashSet<Multiaddr>> = HashMap::new();
    let mut identify_cleanup = tokio::time::interval(IDENTIFY_ADDRESS_CLEANUP_INTERVAL);
    identify_cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Start the event loop as a background task
    tokio::spawn(async move {
        let mut shutdown_rx = shutdown_rx;
        loop {
            tokio::select! {
                _ = identify_cleanup.tick() => {
                    for (peer_id, address) in identify_addresses.expire(Instant::now()) {
                        if !explicit_addresses
                            .get(&peer_id)
                            .is_some_and(|addresses| addresses.contains(&address))
                        {
                            swarm.behaviour_mut().kademlia.remove_address(&peer_id, &address);
                        }
                    }
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
                            if let Ok(event) = serde_json::from_slice::<RefUpdateEvent>(&message.data) {
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
                                    from_peer: propagation_source.to_string(),
                                };
                                let _ = db.insert_ref_update(&update).await;
                                if auto_sync {
                                    let _ = db.enqueue_sync(
                                        &event.repo,
                                        &event.node_did,
                                        &event.ref_name,
                                        &event.new_sha,
                                        event.cid.as_deref(),
                                    ).await;
                                }
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
                            let changes = identify_addresses.update(
                                peer_id,
                                Instant::now(),
                                &info.listen_addrs,
                            );
                            for (removed_peer, addr) in changes.removed {
                                if !explicit_addresses
                                    .get(&removed_peer)
                                    .is_some_and(|addresses| addresses.contains(&addr))
                                {
                                    swarm
                                        .behaviour_mut()
                                        .kademlia
                                        .remove_address(&removed_peer, &addr);
                                }
                            }
                            for addr in changes.added {
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
                            let Ok(addr) = addr.clone().with_p2p(peer_id) else {
                                warn!(%peer_id, %addr, "dropping known-peer address with a foreign peer suffix");
                                continue;
                            };
                            explicit_addresses
                                .entry(peer_id)
                                .or_default()
                                .insert(addr.clone());
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

    fn identify_address(peer_id: PeerId, octet: u8, port: u16) -> Multiaddr {
        format!("/ip4/192.0.2.{octet}/udp/{port}/quic-v1")
            .parse::<Multiaddr>()
            .unwrap()
            .with_p2p(peer_id)
            .unwrap()
    }

    fn identify_address_without_peer(octet: u8, port: u16) -> Multiaddr {
        format!("/ip4/192.0.2.{octet}/udp/{port}/quic-v1")
            .parse::<Multiaddr>()
            .unwrap()
    }

    #[test]
    fn identify_addresses_are_capped_with_fifo_eviction() {
        let peer_id = PeerId::random();
        let now = Instant::now();
        let initial = (0..IDENTIFY_ADDRESS_LIMIT)
            .map(|index| identify_address(peer_id, index as u8 + 1, 10_000 + index as u16))
            .collect::<Vec<_>>();
        let replacement = identify_address(peer_id, 200, 20_000);
        let mut book = IdentifyAddressBook::default();

        let first = book.update(peer_id, now, &initial);
        assert_eq!(first.added, initial);
        assert!(first.removed.is_empty());

        let second = book.update(
            peer_id,
            now + IDENTIFY_ADDRESS_WINDOW,
            std::slice::from_ref(&replacement),
        );
        assert_eq!(second.added, vec![replacement]);
        assert_eq!(second.removed, vec![(peer_id, initial[0].clone())]);
    }

    #[test]
    fn identify_oversized_reports_keep_the_same_refreshed_subset() {
        let peer_id = PeerId::random();
        let now = Instant::now();
        let mut report = (0..IDENTIFY_ADDRESS_LIMIT + 2)
            .map(|index| identify_address(peer_id, index as u8 + 1, 10_000 + index as u16))
            .collect::<Vec<_>>();
        let mut book = IdentifyAddressBook::default();

        let first = book.update(peer_id, now, &report);
        assert_eq!(first.added.len(), IDENTIFY_ADDRESS_LIMIT);
        assert_eq!(first.removed.len(), 0);
        let retained = first.added.clone();

        report.reverse();
        let second = book.update(peer_id, now + IDENTIFY_ADDRESS_WINDOW, &report);
        assert!(second.added.is_empty());
        assert!(second.removed.is_empty());
        let current = book
            .peers
            .get(&peer_id)
            .unwrap()
            .addresses
            .iter()
            .map(|entry| entry.address.clone())
            .collect::<Vec<_>>();
        assert_eq!(current, retained);
    }

    #[test]
    fn identify_addresses_rate_limit_new_entries_across_updates() {
        let peer_id = PeerId::random();
        let now = Instant::now();
        let initial = (0..IDENTIFY_NEW_ADDRESS_LIMIT)
            .map(|index| identify_address(peer_id, index as u8 + 1, 10_000 + index as u16))
            .collect::<Vec<_>>();
        let replacement = identify_address(peer_id, 200, 20_000);
        let mut book = IdentifyAddressBook::default();

        assert_eq!(book.update(peer_id, now, &initial).added, initial);
        assert!(book
            .update(peer_id, now, std::slice::from_ref(&replacement))
            .added
            .is_empty());
        assert_eq!(
            book.update(
                peer_id,
                now + IDENTIFY_ADDRESS_WINDOW,
                std::slice::from_ref(&replacement),
            )
            .added,
            vec![replacement]
        );
    }

    #[test]
    fn identify_addresses_have_a_global_budget_across_peers() {
        let now = Instant::now();
        let mut book = IdentifyAddressBook::default();
        let mut first = None;

        for index in 0..IDENTIFY_GLOBAL_ADDRESS_LIMIT {
            let peer_id = PeerId::random();
            let address = identify_address(peer_id, (index % 254) as u8 + 1, 10_000 + index as u16);
            if first.is_none() {
                first = Some((peer_id, address.clone()));
            }
            assert!(book.update(peer_id, now, &[address]).removed.is_empty());
        }

        let (peer_id, first_address) = first.unwrap();
        let address = identify_address(peer_id, 250, 30_000);
        let changes = book.update(
            peer_id,
            now + IDENTIFY_ADDRESS_WINDOW,
            std::slice::from_ref(&address),
        );
        assert_eq!(changes.added, vec![address]);
        assert_eq!(changes.removed, vec![(peer_id, first_address)]);
    }

    #[test]
    fn identify_addresses_refresh_and_expire() {
        let peer_id = PeerId::random();
        let now = Instant::now();
        let address = identify_address(peer_id, 1, 10_000);
        let mut book = IdentifyAddressBook::default();

        assert_eq!(
            book.update(peer_id, now, std::slice::from_ref(&address))
                .added,
            vec![address.clone()]
        );
        let refreshed = now + IDENTIFY_ADDRESS_TTL - Duration::from_secs(1);
        let refresh = book.update(peer_id, refreshed, std::slice::from_ref(&address));
        assert!(refresh.added.is_empty());
        assert!(refresh.removed.is_empty());
        assert!(book
            .expire(now + IDENTIFY_ADDRESS_TTL + Duration::from_secs(1))
            .is_empty());
        assert_eq!(
            book.expire(refreshed + IDENTIFY_ADDRESS_TTL + Duration::from_secs(1)),
            vec![(peer_id, address)]
        );
    }

    #[test]
    fn identify_addresses_reject_foreign_peer_suffixes() {
        let peer_id = PeerId::random();
        let other_peer_id = PeerId::random();
        let address = identify_address(other_peer_id, 1, 10_000);
        let mut book = IdentifyAddressBook::default();

        assert!(book
            .update(peer_id, Instant::now(), &[address])
            .added
            .is_empty());
    }

    #[test]
    fn identify_addresses_canonicalize_the_peer_suffix_once() {
        let peer_id = PeerId::random();
        let raw = identify_address_without_peer(1, 10_000);
        let canonical = identify_address(peer_id, 1, 10_000);
        let mut book = IdentifyAddressBook::default();

        assert_eq!(
            book.update(peer_id, Instant::now(), &[raw]).added,
            vec![canonical]
        );
    }

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
}
