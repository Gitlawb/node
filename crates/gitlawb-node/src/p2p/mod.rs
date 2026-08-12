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
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
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

/// Combined libp2p behaviour.
#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p_swarm::derive_prelude")]
struct GitlawbBehaviour {
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
}

/// Load the node's persistent libp2p identity from `key_path`, generating and
/// storing a fresh Ed25519 keypair the first time.
pub fn load_or_create_p2p_keypair(key_path: &Path) -> Result<identity::Keypair> {
    // Runs on both the load and the create path: the directory guards the key
    // just as much as the key's own mode does, and an existing directory keeps
    // whatever mode it was made with.
    if let Some(parent) = key_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        ensure_key_dir(parent)?;
    }

    if key_path.exists() {
        return read_p2p_keypair(key_path);
    }

    let kp = identity::Keypair::generate_ed25519();
    let bytes = kp
        .to_protobuf_encoding()
        .map_err(|e| anyhow::anyhow!("failed to serialize p2p key: {e}"))?;

    match write_key_atomically(key_path, &bytes) {
        Ok(()) => {
            info!(
                path = %key_path.display(),
                peer_id = %PeerId::from(kp.public()),
                "generated new p2p identity"
            );
            Ok(kp)
        }
        // Something already occupies the path: another node process won the
        // race between the existence check and the atomic publish, or the path
        // is a symlink. Whatever is on disk is the identity of record, so read
        // it back rather than failing the boot or overwriting it.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => read_p2p_keypair(key_path),
        Err(e) => Err(anyhow::Error::new(e)
            .context(format!("failed to write p2p key to {}", key_path.display()))),
    }
}

/// Create the directory holding the key with owner-only permissions, and
/// tighten it if it already exists with a looser mode. Write permission on this
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
fn ensure_key_dir(dir: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    // On non-unix this is exactly `create_dir_all`; there is no mode to pin.
    builder
        .create(dir)
        .with_context(|| format!("failed to create key directory {}", dir.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(dir)
            .with_context(|| format!("failed to stat key directory {}", dir.display()))?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            warn!(
                dir = %dir.display(),
                mode = format!("{mode:04o}"),
                "key directory grants access beyond its owner; tightening it to 0700"
            );
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).with_context(
                || {
                    format!(
                        "key directory {} has mode {:04o}, which lets other users replace \
                         the keys it holds, and it could not be tightened; run `chmod 700 {}`",
                        dir.display(),
                        mode,
                        dir.display()
                    )
                },
            )?;
        }
    }

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
/// without a check-then-act gap. The scratch file is unlinked either way, so a
/// failed start leaves the key directory as it found it.
fn write_key_atomically(key_path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = key_path.parent().unwrap_or_else(|| Path::new("."));
    let (tmp_path, mut file) = create_scratch_key_file(dir)?;
    let result = fill_and_publish(&mut file, bytes, &tmp_path, key_path);
    drop(file);
    // Unconditional: on success the key is reachable through `key_path`, and on
    // failure nothing may be left behind.
    let _ = std::fs::remove_file(&tmp_path);
    result
}

/// Open a uniquely named scratch file in `dir` with owner-only permissions
/// applied at creation time. The name carries the pid so concurrent node starts
/// do not pick the same one, and `create_new` (`O_EXCL`) plus the retry makes a
/// collision with a leftover or a sibling thread impossible rather than merely
/// unlikely.
fn create_scratch_key_file(dir: &Path) -> std::io::Result<(std::path::PathBuf, std::fs::File)> {
    let pid = std::process::id();
    for attempt in 0..64u32 {
        let tmp_path = dir.join(format!(".p2p.key.{pid}.{attempt}.tmp"));

        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }

        match opts.open(&tmp_path) {
            Ok(file) => return Ok((tmp_path, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!("no free scratch key file name in {}", dir.display()),
    ))
}

fn fill_and_publish(
    file: &mut std::fs::File,
    bytes: &[u8],
    tmp_path: &Path,
    key_path: &Path,
) -> std::io::Result<()> {
    use std::io::Write;

    #[cfg(test)]
    if FAIL_KEY_WRITE.with(|f| f.get()) {
        file.write_all(&bytes[..bytes.len() / 2])?;
        return Err(std::io::Error::other("injected key-write failure"));
    }

    file.write_all(bytes)?;
    // The bytes must be durable before the name that points at them appears,
    // otherwise a crash can leave the entry pointing at an empty file.
    file.sync_all()?;
    std::fs::hard_link(tmp_path, key_path)?;

    // Make the new directory entry itself durable. Best-effort: the key is
    // already written and linked, and not every platform allows this.
    if let Some(dir) = key_path.parent() {
        if let Ok(dir_file) = std::fs::File::open(dir) {
            let _ = dir_file.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    /// Test-only fault injection for the key write. Thread-local so an armed
    /// test cannot disturb the others running beside it.
    static FAIL_KEY_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Read an existing key file, refusing one whose permissions or contents make
/// it untrustworthy. Never regenerates: a node that silently replaces an
/// unreadable key file would change its PeerId without the operator knowing.
fn read_p2p_keypair(key_path: &Path) -> Result<identity::Keypair> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(key_path)
            .with_context(|| format!("failed to stat p2p key at {}", key_path.display()))?
            .permissions()
            .mode()
            & 0o777;
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

    let bytes = std::fs::read(key_path)
        .with_context(|| format!("failed to read p2p key from {}", key_path.display()))?;

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

/// Start the libp2p swarm. Returns a handle for sending commands and the
/// listening multiaddrs. Runs the event loop as a background tokio task
/// that exits cleanly when `shutdown_rx` flips to `true`.
/// `local_key` is the node's libp2p identity, loaded from the persistent key
/// file by [`load_or_create_p2p_keypair`].
pub async fn start(
    local_key: identity::Keypair,
    listen_port: u16,
    bootstrap_addrs: Vec<Multiaddr>,
    db: Arc<Db>,
    auto_sync: bool,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<P2pHandle> {
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

    #[cfg(unix)]
    #[test]
    fn p2p_key_file_is_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys").join("p2p.key");

        // Create the key under a fully permissive umask, otherwise a restrictive
        // ambient umask masks the bits down to 0600 on its own and the assertion
        // below passes whether or not the code pins the mode.
        // SAFETY: `umask` is always safe to call; it only reads and replaces the
        // process-wide value.
        let prev_umask = unsafe { libc::umask(0o000) };
        let result = load_or_create_p2p_keypair(&path);
        unsafe { libc::umask(prev_umask) };
        result.unwrap();

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
    }

    #[cfg(unix)]
    #[test]
    fn p2p_existing_key_dir_with_loose_permissions_is_tightened() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
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
        let dir = tempfile::tempdir().unwrap();
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
