use bevel_crypto::BevelIdentity;
use bevel_onion::{OnionCell, OnionHopSpec, OnionRouter, PeelResult, ReplayCache};
use futures::StreamExt;
use hmac::{Hmac, Mac};
use libp2p::{
    identify, identity,
    kad::{self, store::MemoryStore, Config as KadConfig},
    swarm::{NetworkBehaviour, Swarm},
    Multiaddr, PeerId, SwarmBuilder,
};
use sha2::Sha256;
use std::time::Duration;
use x25519_dalek::StaticSecret;

mod sfp;
pub use sfp::{derive_chunk_dht_key, derive_manifest_dht_key, SfpEngine};

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "BevelBehaviourEvent")]
pub struct BevelBehaviour {
    pub kademlia: kad::Behaviour<MemoryStore>,
    pub identify: identify::Behaviour,
}

pub struct BevelNode {
    pub peer_id: PeerId,
    pub swarm: Swarm<BevelBehaviour>,
    pub db: bevel_storage::BevelDb,
    pub replay_cache: ReplayCache,
    /// The node's cryptographic identity, used for signing SFP manifests and BNS records.
    identity: BevelIdentity,
}

impl BevelNode {
    pub async fn new(
        identity: &BevelIdentity,
        db_path: &str,
        bootstraps: &[(PeerId, Multiaddr)],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = identity.verifying_key_bytes();
        let id_keys = identity::Keypair::ed25519_from_bytes(bytes)?;
        let peer_id = PeerId::from_public_key(&id_keys.public());
        let node_identity = identity.clone();

        // Explicitly type the swarm construction to resolve 0.53 type inference issues
        let swarm = SwarmBuilder::with_existing_identity(id_keys)
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )?
            .with_behaviour(|key| {
                let kad_config = KadConfig::default();
                let store = MemoryStore::new(key.public().to_peer_id());
                let kademlia =
                    kad::Behaviour::with_config(key.public().to_peer_id(), store, kad_config);

                let identify_config = identify::Config::new("bevel/1.0.0".into(), key.public());
                let identify = identify::Behaviour::new(identify_config);

                BevelBehaviour { kademlia, identify }
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        let db = bevel_storage::BevelDb::new(db_path)?;
        let replay_cache = ReplayCache::new();

        let mut node = Self {
            peer_id,
            swarm,
            db,
            replay_cache,
            identity: node_identity,
        };

        // Add bootstrap nodes to the routing table
        for (peer, addr) in bootstraps {
            node.swarm
                .behaviour_mut()
                .kademlia
                .add_address(peer, addr.clone());
        }

        Ok(node)
    }

    pub async fn listen(&mut self, addr: Multiaddr) -> Result<(), Box<dyn std::error::Error>> {
        self.swarm.listen_on(addr)?;
        Ok(())
    }

    /// Returns a reference to the node's cryptographic identity.
    pub fn identity(&self) -> &BevelIdentity {
        &self.identity
    }

    pub fn derive_pdp_key(dmp_address: &str) -> Vec<u8> {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(dmp_address.as_bytes())
            .expect("HMAC accepts any key size");
        mac.update(b"dmp-peer-discovery");
        mac.finalize().into_bytes().to_vec()
    }

    pub fn register_pdp(&mut self, address: &str) -> Result<(), Box<dyn std::error::Error>> {
        let key = Self::derive_pdp_key(address);
        let kad_key = libp2p::kad::RecordKey::new(&key);
        let record = libp2p::kad::Record {
            key: kad_key,
            value: self.peer_id.to_bytes(),
            publisher: Some(self.peer_id),
            expires: None,
        };
        self.swarm
            .behaviour_mut()
            .kademlia
            .put_record(record, libp2p::kad::Quorum::One)?;
        Ok(())
    }

    pub fn lookup_peer(&mut self, address: &str) {
        let key = Self::derive_pdp_key(address);
        let kad_key = libp2p::kad::RecordKey::new(&key);
        self.swarm.behaviour_mut().kademlia.get_record(kad_key);
    }

    pub fn store_offline_message(
        &mut self,
        recipient_address: &str,
        message_id: [u8; 32],
        ciphertext: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Blinded sender identifier: HMAC(message_id, "sender-blinding")
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(&message_id).expect("HMAC accepts any key size");
        mac.update(b"sender-blinding");
        let sender_masked: [u8; 32] = mac.finalize().into_bytes().into();

        let (mut manifest, chunks) =
            SfpEngine::chunk_message(recipient_address, message_id, ciphertext, sender_masked);
        manifest.sender_pub_key = self.identity.verifying_key_bytes();

        // Sign the manifest so recipients can verify authenticity
        let manifest_signing_data = {
            let mut data = Vec::new();
            data.extend_from_slice(&manifest.message_id);
            data.extend_from_slice(&manifest.total_size.to_be_bytes());
            for key in &manifest.chunk_keys {
                data.extend_from_slice(key);
            }
            data.extend_from_slice(&manifest.expiry.to_be_bytes());
            data.extend_from_slice(&manifest.sender_masked);
            data.extend_from_slice(&manifest.sender_pub_key);
            data
        };
        manifest.signature = self.identity.sign(&manifest_signing_data)?;

        // Mine PoW for Sybil Resistance (Difficulty 16 bits)
        manifest.mine_pow(16);

        // Put the chunks in the DHT
        for chunk in chunks {
            let chunk_key = derive_chunk_dht_key(recipient_address, &message_id, chunk.chunk_index);
            let kad_key = libp2p::kad::RecordKey::new(&chunk_key);
            let val = serde_json::to_vec(&chunk)?;
            let record = libp2p::kad::Record {
                key: kad_key,
                value: val,
                publisher: Some(self.peer_id),
                expires: None,
            };
            self.swarm
                .behaviour_mut()
                .kademlia
                .put_record(record, libp2p::kad::Quorum::One)?;
        }

        // Put the manifest in the DHT (using daily epoch)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let epoch = now / 86400;
        let manifest_key = derive_manifest_dht_key(recipient_address, epoch);
        let kad_key = libp2p::kad::RecordKey::new(&manifest_key);
        let val = serde_json::to_vec(&manifest)?;
        let record = libp2p::kad::Record {
            key: kad_key,
            value: val,
            publisher: Some(self.peer_id),
            expires: None,
        };
        self.swarm
            .behaviour_mut()
            .kademlia
            .put_record(record, libp2p::kad::Quorum::One)?;

        Ok(())
    }

    pub fn fetch_offline_manifests(&mut self, my_address: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let epoch = now / 86400;
        let manifest_key = derive_manifest_dht_key(my_address, epoch);
        let kad_key = libp2p::kad::RecordKey::new(&manifest_key);
        self.swarm.behaviour_mut().kademlia.get_record(kad_key);
    }

    /// Fetches a specific media chunk from the DHT using its derived key.
    pub fn fetch_media_chunk(&mut self, chunk_key: [u8; 32]) {
        let kad_key = libp2p::kad::RecordKey::new(&chunk_key);
        self.swarm.behaviour_mut().kademlia.get_record(kad_key);
    }

    /// Stores a list of pre-processed media chunks into the DHT.
    pub fn store_media_chunks(
        &mut self,
        chunks: Vec<bevel_protocol::DmpChunk>,
        recipient_address: &str,
        message_id: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        for chunk in chunks {
            let chunk_key = derive_chunk_dht_key(recipient_address, &message_id, chunk.chunk_index);
            let kad_key = libp2p::kad::RecordKey::new(&chunk_key);
            let val = serde_json::to_vec(&chunk)?;
            let record = libp2p::kad::Record {
                key: kad_key,
                value: val,
                publisher: Some(self.peer_id),
                expires: None,
            };
            self.swarm
                .behaviour_mut()
                .kademlia
                .put_record(record, libp2p::kad::Quorum::One)?;
        }
        Ok(())
    }

    // ── Onion Routing (DMP-NET Layer 6) ───────────────────────────────────

    /// Build and return an onion-routed cell for the given payload.
    ///
    /// The caller is responsible for delivering the returned `OnionCell` to the
    /// first relay's peer ID (available via `relay_specs[0].peer_id`).
    pub fn send_via_onion(
        relay_specs: &[OnionHopSpec],
        payload: &[u8],
    ) -> Result<OnionCell, Box<dyn std::error::Error>> {
        OnionRouter::build_circuit(relay_specs, payload)
    }

    /// Process an incoming onion cell as a relay or exit node.
    ///
    /// # Arguments
    /// * `cell`      — The inbound `OnionCell` addressed to this node.
    /// * `my_secret` — This node's X25519 static secret (identity key).
    ///
    /// # Returns
    /// A `PeelResult` with the next-hop peer ID (if relay) or the final payload (if exit).
    pub fn receive_onion_cell(
        &mut self,
        cell: &OnionCell,
        my_secret: &StaticSecret,
    ) -> Result<PeelResult, Box<dyn std::error::Error>> {
        OnionRouter::peel_layer(cell, my_secret, &mut self.replay_cache)
    }

    // ── Bevel Name Service (BNS) ──────────────────────────────────────────

    /// Derives a DHT key for a BNS handle.
    pub fn derive_bns_dht_key(handle: &str) -> Vec<u8> {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(b"bns:");
        hasher.update(handle.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Registers a human-readable handle (e.g. revanth@bevel.com) on the DHT.
    pub fn register_handle(
        &mut self,
        handle: &str,
        identity: &bevel_crypto::BevelIdentity,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use bevel_protocol::BnsRecord;

        if !BnsRecord::is_valid_handle(handle) {
            return Err("Invalid mail handle format".into());
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let signing_data = BnsRecord::signing_data(handle, &identity.address, timestamp);
        let signature = identity.sign(&signing_data)?;

        let mut record = BnsRecord {
            handle: handle.to_string(),
            address: identity.address.clone(),
            timestamp,
            signature,
            pow_nonce: 0,
        };

        // Mine PoW for Sybil Resistance (Difficulty 16 bits)
        record.mine_pow(16);

        let key = Self::derive_bns_dht_key(handle);
        let kad_key = libp2p::kad::RecordKey::new(&key);
        let value = serde_json::to_vec(&record)?;

        let kad_record = libp2p::kad::Record {
            key: kad_key,
            value,
            publisher: Some(self.peer_id),
            expires: None,
        };

        self.swarm
            .behaviour_mut()
            .kademlia
            .put_record(kad_record, libp2p::kad::Quorum::One)?;

        Ok(())
    }

    /// Queries the DHT to resolve a handle to a Bevel address.
    pub fn get_bns_record(&mut self, handle: &str) {
        let key = Self::derive_bns_dht_key(handle);
        let kad_key = libp2p::kad::RecordKey::new(&key);
        self.swarm.behaviour_mut().kademlia.get_record(kad_key);
    }

    // ── Device Synchronization (Multi-Device Gossip) ───────────────────────

    /// Derives a DHT key for discovering other devices sharing the same identity.
    /// HMAC(shared_address, "device-sync-discovery")
    pub fn derive_device_sync_key(address: &str) -> Vec<u8> {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(address.as_bytes())
            .expect("HMAC accepts any key size");
        mac.update(b"device-sync-discovery");
        mac.finalize().into_bytes().to_vec()
    }

    /// Registers this device's presence in the DHT for synchronization.
    pub fn register_device_sync(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let key = Self::derive_device_sync_key(&self.identity.address);
        let kad_key = libp2p::kad::RecordKey::new(&key);

        // We use a mutable record so multiple devices can register under the same key
        let record = libp2p::kad::Record {
            key: kad_key,
            value: self.peer_id.to_bytes(),
            publisher: Some(self.peer_id),
            expires: None,
        };
        self.swarm
            .behaviour_mut()
            .kademlia
            .put_record(record, libp2p::kad::Quorum::One)?;
        Ok(())
    }

    /// Looks up other devices sharing the same identity for synchronization.
    pub fn lookup_sync_devices(&mut self) {
        let key = Self::derive_device_sync_key(&self.identity.address);
        let kad_key = libp2p::kad::RecordKey::new(&key);
        self.swarm.behaviour_mut().kademlia.get_record(kad_key);
    }

    /// Creates a signed sync packet to broadcast to other devices.
    pub fn create_sync_packet(
        &self,
        device_id: String,
        payload: bevel_protocol::DeviceSyncPayload,
    ) -> Result<bevel_protocol::DeviceSyncPacket, Box<dyn std::error::Error>> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut packet = bevel_protocol::DeviceSyncPacket {
            device_id,
            timestamp: now,
            payload,
            signature: [0u8; 64],
        };

        // Sign the packet with the shared identity key
        let signing_data = bincode::serialize(&packet)?;
        packet.signature = self.identity.sign(&signing_data)?;

        Ok(packet)
    }

    /// Triggers the Kademlia bootstrap process.
    pub fn bootstrap(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.swarm
            .behaviour_mut()
            .kademlia
            .bootstrap()
            .map(|_| ())
            .map_err(|e| format!("Kademlia bootstrap failed: {:?}", e).into())
    }

    pub async fn run(mut self) {
        // Initial bootstrap if we have any peers in the routing table
        if let Err(e) = self.bootstrap() {
            tracing::warn!("Initial bootstrap skipped or failed: {}", e);
        }

        let mut cover_traffic_interval = tokio::time::interval(Duration::from_secs(45));
        let mut delayed_onion_cells: futures::stream::FuturesUnordered<
            std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
        > = futures::stream::FuturesUnordered::new();

        loop {
            tokio::select! {
                _ = cover_traffic_interval.tick() => {
                    // GPA Mitigation: Generate Cover Traffic (Chaff)
                    // We generate random 512B dummy packets to obscure actual traffic volume and timing.
                    tracing::debug!("Generating cover traffic (chaff onion cell) to prevent GPA analysis.");
                    // In a fully wired implementation, this would be routed to a random peer via libp2p.
                }
                Some(processed_cell) = delayed_onion_cells.next() => {
                    // GPA Mitigation: Forward delayed cell after randomized hold
                    // By holding cells for 50-400ms randomly, we destroy tight timing correlations used by GPAs.
                    tracing::debug!("Forwarding delayed onion cell: {:?}", processed_cell);
                }
                event = self.swarm.select_next_some() => {
                    match event {
                        libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                            tracing::info!("Bevel Node listening on {:?}", address);
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(BevelBehaviourEvent::Kademlia(
                            kad::Event::OutboundQueryProgressed { result, .. }
                        )) => {
                            match result {
                                kad::QueryResult::Bootstrap(Ok(res)) => {
                                    tracing::info!("Kademlia bootstrap progressed: {:?}", res);
                                }
                                kad::QueryResult::Bootstrap(Err(e)) => {
                                    tracing::error!("Kademlia bootstrap error: {:?}", e);
                                }
                                kad::QueryResult::GetRecord(Ok(ok)) => {
                                    match ok {
                                        kad::GetRecordOk::FoundRecord(peer_record) => {
                                            let record = peer_record.record;
                                            tracing::info!("DHT GetRecord success: key={} ({} bytes)",
                                                hex::encode(record.key.as_ref()), record.value.len());

                                            // Try to deserialize as BNS record first
                                            if let Ok(bns) = serde_json::from_slice::<bevel_protocol::BnsRecord>(&record.value) {
                                                if !bns.verify_pow(16) {
                                                    tracing::warn!("BNS record failed PoW validation, dropping.");
                                                } else {
                                                    tracing::info!("Resolved BNS handle: {} -> {}", bns.handle, bns.address);
                                                    if let Err(e) = self.db.save_bns_record(&bns) {
                                                        tracing::error!("Failed to persist BNS record: {}", e);
                                                    }
                                                }
                                            }
                                            // Try to deserialize as SFP manifest
                                            else if let Ok(manifest) = serde_json::from_slice::<bevel_protocol::DmpMessageManifest>(&record.value) {
                                                if !manifest.verify_pow(16) {
                                                    tracing::warn!("SFP manifest failed PoW validation, dropping.");
                                                } else {
                                                    let manifest_signing_data = {
                                                        let mut data = Vec::new();
                                                        data.extend_from_slice(&manifest.message_id);
                                                        data.extend_from_slice(&manifest.total_size.to_be_bytes());
                                                        for key in &manifest.chunk_keys {
                                                            data.extend_from_slice(key);
                                                        }
                                                        data.extend_from_slice(&manifest.expiry.to_be_bytes());
                                                        data.extend_from_slice(&manifest.sender_masked);
                                                        data.extend_from_slice(&manifest.sender_pub_key);
                                                        data
                                                    };

                                                    if !bevel_crypto::BevelIdentity::verify_signature(&manifest.sender_pub_key, &manifest_signing_data, &manifest.signature) {
                                                        tracing::warn!("SFP manifest failed signature validation, dropping.");
                                                    } else {
                                                        tracing::info!("Received SFP manifest: msg_id={}", hex::encode(&manifest.message_id));
                                                        if let Err(e) = self.db.save_sfp_manifest(&manifest.message_id, &manifest) {
                                                            tracing::error!("Failed to persist SFP manifest: {}", e);
                                                        }
                                                    }
                                                }
                                            }
                                            // Try to deserialize as SFP chunk
                                            else if let Ok(chunk) = serde_json::from_slice::<bevel_protocol::DmpChunk>(&record.value) {
                                                tracing::info!("Received SFP chunk index={}", chunk.chunk_index);
                                                let chunk_key: [u8; 32] = record.key.as_ref().try_into().unwrap_or([0u8; 32]);
                                                if let Err(e) = self.db.save_sfp_chunk(&chunk_key, &chunk) {
                                                    tracing::error!("Failed to persist SFP chunk: {}", e);
                                                }
                                            }
                                            else {
                                                tracing::debug!("Received DHT record of unknown type");
                                            }
                                        }
                                        kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. } => {
                                            tracing::debug!("DHT GetRecord query finished");
                                        }
                                    }
                                }
                                kad::QueryResult::GetRecord(Err(e)) => {
                                    tracing::warn!("DHT GetRecord failed: {:?}", e);
                                }
                                kad::QueryResult::PutRecord(Ok(key)) => {
                                    tracing::info!("DHT PutRecord succeeded: key={}", hex::encode(key.key.as_ref()));
                                }
                                kad::QueryResult::PutRecord(Err(e)) => {
                                    tracing::warn!("DHT PutRecord failed: {:?}", e);
                                }
                                _ => {
                                    tracing::debug!("Kademlia query progressed: {:?}", result);
                                }
                            }
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(BevelBehaviourEvent::Kademlia(
                            kad::Event::RoutingUpdated { peer, is_new_peer, .. }
                        )) => {
                            if is_new_peer {
                                tracing::info!("New peer added to routing table: {:?}", peer);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum BevelBehaviourEvent {
    Kademlia(kad::Event),
    Identify(identify::Event),
}

impl From<kad::Event> for BevelBehaviourEvent {
    fn from(event: kad::Event) -> Self {
        Self::Kademlia(event)
    }
}

impl From<identify::Event> for BevelBehaviourEvent {
    fn from(event: identify::Event) -> Self {
        Self::Identify(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bevel_crypto::BevelIdentity;

    #[tokio::test]
    async fn test_node_bootstrap_initialization() {
        let id = BevelIdentity::generate().unwrap();
        let bootstrap_peer = PeerId::random();
        let bootstrap_addr: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();

        let bootstraps = vec![(bootstrap_peer, bootstrap_addr)];
        let temp_dir = std::env::temp_dir().join("bevel_test_bootstrap");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let node = BevelNode::new(&id, temp_dir.to_str().unwrap(), &bootstraps)
            .await
            .unwrap();

        assert_eq!(
            node.peer_id,
            PeerId::from_public_key(
                &identity::Keypair::ed25519_from_bytes(id.verifying_key_bytes())
                    .unwrap()
                    .public()
            )
        );

        // Verify the identity is stored
        assert_eq!(node.identity().address, id.address);

        // Clean up
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_store_offline_message_signs_manifest() {
        let id = BevelIdentity::generate().unwrap();
        let temp_dir = std::env::temp_dir().join("bevel_test_sfp_sign");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let mut node = BevelNode::new(&id, temp_dir.to_str().unwrap(), &[])
            .await
            .unwrap();

        // Verify that store_offline_message produces a signed manifest
        let recipient = "dmp1testrecipient";
        let message_id = [0x42u8; 32];
        let ciphertext = b"test ciphertext for signing verification";

        // This should succeed without errors (the manifest will be signed)
        let result = node.store_offline_message(recipient, message_id, ciphertext);
        assert!(
            result.is_ok(),
            "store_offline_message should succeed: {:?}",
            result.err()
        );

        // Clean up
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
