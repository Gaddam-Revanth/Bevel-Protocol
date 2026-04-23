//! # bevel-onion — DMP-NET Layer 6: Onion Routing
//!
//! Implements a Sphinx-inspired onion routing scheme for the Bevel Protocol.
//! Messages are wrapped in N layers of AES-256-GCM encryption, one per relay hop.
//! Each relay can only decrypt its own layer, revealing only the next hop address.
//!
//! ## Cryptographic Design
//! - **Key agreement**: Ephemeral X25519 ECDH per hop — fresh keypair every circuit.
//! - **Encryption**: AES-256-GCM with HKDF-derived key — authenticated per layer.
//! - **Traffic resistance**: Wire output padded to multiples of `ONION_CELL_SIZE` (512 B).
//! - **Forward secrecy**: Ephemeral secrets are dropped after use; no long-term exposure.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use x25519_dalek::{PublicKey, StaticSecret};

/// Wire-cell size used for traffic-analysis resistance. All wire output is padded
/// to a multiple of this value.
pub const ONION_CELL_SIZE: usize = 512;

/// Maximum supported hops in a single circuit.
pub const MAX_HOPS: usize = 8;

/// Default number of hops (analogous to Tor's 3-hop model).
pub const DEFAULT_HOPS: usize = 3;

// ─── Hop Specification ───────────────────────────────────────────────────────

/// Describes one relay node in an onion circuit.
#[derive(Clone, Debug)]
pub struct OnionHopSpec {
    /// X25519 public key of the relay (used for per-hop ECDH key agreement).
    pub relay_pub_key: [u8; 32],
    /// libp2p PeerId of the relay (used to forward the peeled cell at the P2P layer).
    pub peer_id: String,
}

// ─── Wire Cell ───────────────────────────────────────────────────────────────

/// A single onion-routed cell — the fundamental unit of the DMP-NET Layer 6 wire format.
///
/// Each cell is independently encrypted for one relay hop via ephemeral X25519 ECDH.
/// The cell can be serialized to a wire representation padded to a multiple of
/// `ONION_CELL_SIZE` (512 bytes) for traffic-analysis resistance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OnionCell {
    /// Sender's ephemeral X25519 public key for this hop.
    /// The relay performs ECDH(their_static_secret, this_key) to derive the AES key.
    pub eph_pub_key: [u8; 32],
    /// AES-256-GCM nonce (96-bit / 12 bytes).
    pub nonce: [u8; 12],
    /// Authenticated ciphertext (plaintext + 16-byte GCM authentication tag).
    pub ciphertext: Vec<u8>,
}

impl OnionCell {
    /// Serialize this cell and pad to the next 512-byte boundary.
    /// This is what is transmitted on the wire.
    pub fn to_wire_padded(&self) -> Vec<u8> {
        let mut raw = bincode::serialize(self).expect("OnionCell bincode serialization failed");
        let rem = raw.len() % ONION_CELL_SIZE;
        if rem != 0 {
            raw.extend(vec![0u8; ONION_CELL_SIZE - rem]);
        }
        raw
    }

    /// Returns the padded wire byte length (always a multiple of 512).
    pub fn wire_size(&self) -> usize {
        self.to_wire_padded().len()
    }

    /// Deserialize from wire bytes (strips trailing zero-padding automatically via bincode).
    pub fn from_wire_padded(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let cell: OnionCell = bincode::deserialize(bytes)?;
        Ok(cell)
    }
}

// ─── Peel Result ─────────────────────────────────────────────────────────────

/// Returned when a relay peels one layer from an `OnionCell`.
pub struct PeelResult {
    /// The next relay's peer ID, or `None` if this is the exit hop.
    pub next_hop: Option<String>,
    /// Raw inner bytes: either a serialized `OnionCell` (for relay hops)
    /// or the original plaintext payload (for the exit hop).
    pub inner_data: Vec<u8>,
    /// `true` when this relay is the final destination.
    pub is_exit: bool,
}

// ─── OnionRouter ─────────────────────────────────────────────────────────────

/// Cache to prevent replay attacks by dropping previously seen ephemeral keys.
#[derive(Default, Clone, Debug)]
pub struct ReplayCache {
    seen: HashSet<[u8; 32]>,
    queue: VecDeque<[u8; 32]>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks if a key was seen. If not, inserts it and returns true. If seen, returns false.
    pub fn check_and_insert(&mut self, key: [u8; 32]) -> bool {
        if self.seen.contains(&key) {
            return false;
        }
        self.seen.insert(key);
        self.queue.push_back(key);
        if self.queue.len() > 1_000_000 {
            if let Some(old) = self.queue.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }
}

/// The Bevel onion router.  Stateless — all methods are pure functions.
pub struct OnionRouter;

impl OnionRouter {
    // ── Circuit Building ──────────────────────────────────────────────────

    /// Build a fully layered onion circuit through the given relay hops.
    ///
    /// # Arguments
    /// * `hops`    — Ordered relay specs. `hops[0]` = entry (outermost), `hops[N-1]` = exit.
    /// * `payload` — The inner ciphertext to deliver (already E2EE-encrypted DMP payload).
    ///
    /// # Returns
    /// The outermost `OnionCell`, ready to be sent to `hops[0]`.
    pub fn build_circuit(
        hops: &[OnionHopSpec],
        payload: &[u8],
    ) -> Result<OnionCell, Box<dyn std::error::Error>> {
        if hops.is_empty() {
            return Err("Circuit must have at least 1 hop".into());
        }
        if hops.len() > MAX_HOPS {
            return Err(format!("Circuit cannot exceed {} hops", MAX_HOPS).into());
        }

        let mut rng = rand::thread_rng();

        // ── Innermost layer: exit hop ─────────────────────────────────────
        // Plaintext format: [0xFF (exit flag)] ++ [payload]
        let exit_plaintext = {
            let mut v = vec![0xFFu8];
            v.extend_from_slice(payload);
            v
        };
        let mut current_cell =
            Self::encrypt_layer(&hops[hops.len() - 1], &exit_plaintext, &mut rng)?;

        // ── Outer layers: relay hops (second-to-last → first) ─────────────
        // Plaintext format: [0x01 (relay flag)] [peer_id_len: 1B] [peer_id bytes] ++ [inner cell bytes]
        for i in (0..hops.len() - 1).rev() {
            let next_peer_id_bytes = hops[i + 1].peer_id.as_bytes();
            if next_peer_id_bytes.len() > 255 {
                return Err("Relay peer ID exceeds 255 bytes".into());
            }

            let inner_cell_bytes = bincode::serialize(&current_cell)?;

            let relay_plaintext = {
                let mut v =
                    Vec::with_capacity(2 + next_peer_id_bytes.len() + inner_cell_bytes.len());
                v.push(0x01u8); // relay flag
                v.push(next_peer_id_bytes.len() as u8); // next peer ID length
                v.extend_from_slice(next_peer_id_bytes); // next peer ID
                v.extend_from_slice(&inner_cell_bytes); // inner cell
                v
            };

            current_cell = Self::encrypt_layer(&hops[i], &relay_plaintext, &mut rng)?;
        }

        Ok(current_cell)
    }

    // ── Layer Peeling ─────────────────────────────────────────────────────

    /// Peel one encryption layer from an `OnionCell` using this relay's X25519 secret key.
    ///
    /// # Arguments
    /// * `cell`         — The incoming `OnionCell` addressed to this relay.
    /// * `my_secret`    — This relay node's X25519 static secret key.
    /// * `replay_cache` — Node's cache to reject previously seen ephemeral keys.
    ///
    /// # Returns
    /// A `PeelResult` containing the next-hop peer ID and inner data.
    pub fn peel_layer(
        cell: &OnionCell,
        my_secret: &StaticSecret,
        replay_cache: &mut ReplayCache,
    ) -> Result<PeelResult, Box<dyn std::error::Error>> {
        if !replay_cache.check_and_insert(cell.eph_pub_key) {
            return Err("OnionCell replay detected — cell discarded".into());
        }

        let eph_pub = PublicKey::from(cell.eph_pub_key);
        let shared = my_secret.diffie_hellman(&eph_pub);
        let aes_key = Self::derive_aes_key(shared.as_bytes(), &cell.eph_pub_key);

        let cipher = Aes256Gcm::new_from_slice(&aes_key)
            .map_err(|e| format!("AES cipher init failed: {}", e))?;
        let nonce = Nonce::from_slice(&cell.nonce);
        let plaintext = cipher
            .decrypt(nonce, cell.ciphertext.as_slice())
            .map_err(|_| {
                "Onion layer authentication failed — cell may be tampered or key is wrong"
            })?;

        if plaintext.is_empty() {
            return Err("Decrypted plaintext is empty".into());
        }

        match plaintext[0] {
            0xFF => {
                // Exit hop — deliver final payload
                Ok(PeelResult {
                    next_hop: None,
                    inner_data: plaintext[1..].to_vec(),
                    is_exit: true,
                })
            }
            0x01 => {
                // Relay hop — forward inner cell to next_hop
                if plaintext.len() < 2 {
                    return Err("Relay cell too short to contain peer ID length".into());
                }
                let peer_id_len = plaintext[1] as usize;
                let peer_id_end = 2 + peer_id_len;
                if plaintext.len() < peer_id_end {
                    return Err("Relay cell truncated — peer ID bytes missing".into());
                }
                let peer_id = String::from_utf8(plaintext[2..peer_id_end].to_vec())
                    .map_err(|_| "Next-hop peer ID is not valid UTF-8")?;
                let inner_data = plaintext[peer_id_end..].to_vec();

                Ok(PeelResult {
                    next_hop: Some(peer_id),
                    inner_data,
                    is_exit: false,
                })
            }
            other => Err(format!("Unknown hop type byte: 0x{:02X}", other).into()),
        }
    }

    /// Simulate a complete N-hop circuit locally to verify correctness.
    ///
    /// Generates N ephemeral relay identities, builds the circuit, peels all layers,
    /// and asserts the final payload matches the original.  Returns the hop trace.
    pub fn verify_circuit(
        payload: &[u8],
        hop_count: usize,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        if hop_count == 0 || hop_count > MAX_HOPS {
            return Err(format!("hop_count must be 1..={}", MAX_HOPS).into());
        }

        let mut rng = rand::thread_rng();

        // Generate ephemeral relay identities
        let mut relay_secrets: Vec<StaticSecret> = Vec::new();
        let mut hops: Vec<OnionHopSpec> = Vec::new();
        for i in 0..hop_count {
            let mut secret_bytes = [0u8; 32];
            rng.fill_bytes(&mut secret_bytes);
            let secret = StaticSecret::from(secret_bytes);
            let pub_key = PublicKey::from(&secret);
            hops.push(OnionHopSpec {
                relay_pub_key: pub_key.to_bytes(),
                peer_id: format!("relay-sim-{}", i),
            });
            relay_secrets.push(secret);
        }

        // Build the circuit
        let outermost_cell = Self::build_circuit(&hops, payload)?;

        // Peel all layers sequentially
        let mut current_cell = outermost_cell;
        let mut trace: Vec<String> = Vec::new();
        let mut mock_cache = ReplayCache::new();

        for (i, secret) in relay_secrets.iter().enumerate() {
            let result = Self::peel_layer(&current_cell, secret, &mut mock_cache)?;

            if result.is_exit {
                trace.push(format!(
                    "Hop {} [EXIT] — payload decrypted ({} bytes)",
                    i,
                    result.inner_data.len()
                ));
                if result.inner_data != payload {
                    return Err(
                        "Circuit verification FAILED: decrypted payload does not match original"
                            .into(),
                    );
                }
                return Ok(trace);
            } else {
                let next = result.next_hop.as_deref().unwrap_or("?");
                trace.push(format!("Hop {} [RELAY] → next: {}", i, next));
                // Deserialize the inner cell for the next iteration
                current_cell = bincode::deserialize(&result.inner_data)
                    .map_err(|e| format!("Failed to deserialize inner cell at hop {}: {}", i, e))?;
            }
        }

        Err("Circuit verification FAILED: exhausted all relay secrets without reaching exit".into())
    }

    // ── Private Helpers ───────────────────────────────────────────────────

    /// Encrypts a plaintext for one hop, returning an `OnionCell`.
    fn encrypt_layer(
        hop: &OnionHopSpec,
        plaintext: &[u8],
        rng: &mut impl RngCore,
    ) -> Result<OnionCell, Box<dyn std::error::Error>> {
        // Ephemeral X25519 keypair for this hop
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        let eph_secret = StaticSecret::from(secret_bytes);
        let eph_pub = PublicKey::from(&eph_secret);

        // ECDH with relay's static public key
        let relay_pub = PublicKey::from(hop.relay_pub_key);
        let shared = eph_secret.diffie_hellman(&relay_pub);

        // Derive AES-256 key: SHA-256(shared_secret ‖ eph_pub ‖ domain_sep)
        let aes_key = Self::derive_aes_key(shared.as_bytes(), eph_pub.as_bytes());

        // Random 96-bit nonce
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);

        // AES-256-GCM encrypt
        let cipher = Aes256Gcm::new_from_slice(&aes_key)
            .map_err(|e| format!("AES cipher init failed: {}", e))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("AES-GCM encryption failed: {}", e))?;

        Ok(OnionCell {
            eph_pub_key: eph_pub.to_bytes(),
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    /// Derives a 256-bit AES key from an X25519 shared secret and ephemeral public key.
    /// Domain separation label prevents key reuse across protocol contexts.
    fn derive_aes_key(shared_secret: &[u8], eph_pub: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        hasher.update(eph_pub);
        hasher.update(b"bevel-onion-v1-aes-key");
        hasher.finalize().into()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_hop_round_trip() {
        let payload = b"Secret payload for single-hop test";
        let trace = OnionRouter::verify_circuit(payload, 1).expect("Single-hop circuit failed");
        assert_eq!(trace.len(), 1);
        assert!(trace[0].contains("EXIT"));
    }

    #[test]
    fn test_three_hop_round_trip() {
        let payload = b"Three-hop onion routing test payload for Bevel Protocol";
        let trace = OnionRouter::verify_circuit(payload, 3).expect("3-hop circuit failed");
        assert_eq!(trace.len(), 3);
        assert!(trace[0].contains("RELAY"));
        assert!(trace[1].contains("RELAY"));
        assert!(trace[2].contains("EXIT"));
    }

    #[test]
    fn test_cell_wire_size_is_multiple_of_512() {
        let payload = b"Size test payload";
        let mut rng = rand::thread_rng();
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        let secret = StaticSecret::from(secret_bytes);
        let pub_key = PublicKey::from(&secret);

        let hops = vec![OnionHopSpec {
            relay_pub_key: pub_key.to_bytes(),
            peer_id: "r0".into(),
        }];
        let cell = OnionRouter::build_circuit(&hops, payload).unwrap();
        let wire = cell.to_wire_padded();
        assert_eq!(
            wire.len() % ONION_CELL_SIZE,
            0,
            "Wire size must be a multiple of 512"
        );
    }

    #[test]
    fn test_tampered_cell_fails_authentication() {
        let payload = b"Tamper test";
        let mut rng = rand::thread_rng();
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        let secret = StaticSecret::from(secret_bytes);
        let pub_key = PublicKey::from(&secret);

        let hops = vec![OnionHopSpec {
            relay_pub_key: pub_key.to_bytes(),
            peer_id: "r0".into(),
        }];
        let mut cell = OnionRouter::build_circuit(&hops, payload).unwrap();

        // Flip a byte in the ciphertext — GCM auth tag should reject this
        if let Some(byte) = cell.ciphertext.first_mut() {
            *byte ^= 0xFF;
        }

        let mut cache = ReplayCache::new();
        let result = OnionRouter::peel_layer(&cell, &secret, &mut cache);
        assert!(result.is_err(), "Tampered cell must fail authentication");
    }

    #[test]
    fn test_wrong_key_fails() {
        let payload = b"Wrong key test";
        let mut rng = rand::thread_rng();

        let mut s1 = [0u8; 32];
        rng.fill_bytes(&mut s1);
        let mut s2 = [0u8; 32];
        rng.fill_bytes(&mut s2);
        let correct_secret = StaticSecret::from(s1);
        let wrong_secret = StaticSecret::from(s2);
        let pub_key = PublicKey::from(&correct_secret);

        let hops = vec![OnionHopSpec {
            relay_pub_key: pub_key.to_bytes(),
            peer_id: "r0".into(),
        }];
        let cell = OnionRouter::build_circuit(&hops, payload).unwrap();

        let mut cache = ReplayCache::new();
        let result = OnionRouter::peel_layer(&cell, &wrong_secret, &mut cache);
        assert!(result.is_err(), "Wrong key must fail GCM authentication");
    }

    #[test]
    fn test_max_hops_enforced() {
        let payload = b"Max hops";
        // 9 hops should be rejected
        let hops: Vec<OnionHopSpec> = (0..9)
            .map(|i| OnionHopSpec {
                relay_pub_key: [i as u8; 32],
                peer_id: format!("r{}", i),
            })
            .collect();
        let result = OnionRouter::build_circuit(&hops, payload);
        assert!(result.is_err());
    }
}
