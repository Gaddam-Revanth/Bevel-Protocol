use serde::{Serialize, Deserialize};
use serde_big_array::BigArray;

pub const DMP_MAGIC: [u8; 4] = [0x44, 0x4D, 0x50, 0x00];
pub const HEADER_SIZE: usize = 148;

/// Layer ID assigned to the DMP-NET onion routing layer.
pub const DMP_LAYER_ONION: u8 = 0x06;

/// Wire header prepended to onion-routed DMP packets (Layer 6).
/// Relays inspect this header to decide forwarding without decrypting the payload.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct OnionCellHeader {
    /// Always `DMP_LAYER_ONION` (0x06).
    pub layer_id: u8,
    /// Protocol version — currently 0x01.
    pub version: u8,
    /// Random 128-bit circuit identifier (same across all cells in a circuit).
    pub circuit_id: [u8; 16],
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct DmpHeader {
    pub magic: [u8; 4],            // 0x444D5000
    pub version: u8,               // 0x01
    pub layer_id: u8,              // 0x01-0x06
    pub protocol_id: u16,          // Sub-protocol identifier
    pub payload_length: u32,       // Big-endian length
    pub sender_addr_hash: [u8; 32], // SHA-256 of sender public key
    pub recipient_addr_hash: [u8; 32], // SHA-256 of recipient public key
    pub timestamp: u64,            // Unix epoch ms (rounded to 10s)
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],       // Ed25519 sig
}


impl Default for DmpHeader {
    fn default() -> Self {
        Self {
            magic: DMP_MAGIC,
            version: 0x01,
            layer_id: 1,
            protocol_id: 0,
            payload_length: 0,
            sender_addr_hash: [0u8; 32],
            recipient_addr_hash: [0u8; 32],
            timestamp: 0,
            signature: [0u8; 64],
        }
    }
}

/// A complete DMP packet
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DmpPacket {
    pub header: DmpHeader,
    pub payload: Vec<u8>,
}

/// DMP-MSG Canonical Message Format (Layer 5)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DmpMessage {
    pub dmp_msg_version: String,
    pub message_id: String,
    pub thread_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub subject: Option<String>,
    pub body: DmpMessageBody,
    pub attachments: Vec<DmpAttachmentRef>,
    pub sent_at: u64,
    pub flags: DmpMessageFlags,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DmpMessageBody {
    pub text_plain: String,
    pub text_html: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DmpAttachmentRef {
    pub content_hash: String,
    pub encryption_key: String,
    pub size: u64,
    pub mime_type: String,
    pub file_name: String,
    pub is_folder: bool,
}

/// A manifest for a folder blob.
/// Lists all files and their relative paths within the folder.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlobFolderManifest {
    pub entries: Vec<BlobFolderEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlobFolderEntry {
    pub relative_path: String,
    pub content_hash: String, // Each file in folder is its own blob
    pub size: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DmpMessageFlags {
    pub request_delivery_receipt: bool,
    pub ephemeral: bool,
    pub expiry_seconds: Option<u64>,
}

impl DmpMessage {
    /// Factory method to create a new DMP message with a cryptographically secure message ID.
    pub fn new(
        subject: Option<String>,
        body: DmpMessageBody,
        flags: DmpMessageFlags,
    ) -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let uuid: [u8; 16] = rng.gen();
        let message_id = hex::encode(uuid); // 128-bit random ID
        
        Self {
            dmp_msg_version: "1.0".to_string(),
            message_id,
            thread_id: None,
            in_reply_to: None,
            subject,
            body,
            attachments: vec![],
            sent_at: round_timestamp(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64
            ),
            flags,
        }
    }
}

/// A manifest for an offline message (SFP). 
/// Stored on the DHT to allow discovery of all chunks.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DmpMessageManifest {
    pub message_id: [u8; 32],
    pub total_size: u64,
    pub chunk_keys: Vec<[u8; 32]>, // DHT keys for individual chunks
    pub expiry: u64,               // Unix timestamp
    pub sender_masked: [u8; 32],   // Blinded sender identifier
    pub sender_pub_key: [u8; 32],  // Public key for verifying the signature
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],       // Ed25519 signature by sender
    pub pow_nonce: u64,            // Anti-Sybil Proof of Work nonce
}

impl DmpMessageManifest {
    pub fn pow_hash_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.message_id);
        data.extend_from_slice(&self.total_size.to_be_bytes());
        for key in &self.chunk_keys {
            data.extend_from_slice(key);
        }
        data.extend_from_slice(&self.expiry.to_be_bytes());
        data.extend_from_slice(&self.sender_masked);
        data.extend_from_slice(&self.sender_pub_key);
        data.extend_from_slice(&self.pow_nonce.to_be_bytes());
        data
    }

    pub fn mine_pow(&mut self, difficulty: u32) {
        use sha2::{Sha256, Digest};
        loop {
            let data = self.pow_hash_data();
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let hash = hasher.finalize();
            if check_difficulty(&hash, difficulty) {
                break;
            }
            self.pow_nonce = self.pow_nonce.wrapping_add(1);
        }
    }

    pub fn verify_pow(&self, difficulty: u32) -> bool {
        use sha2::{Sha256, Digest};
        let data = self.pow_hash_data();
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = hasher.finalize();
        check_difficulty(&hash, difficulty)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DmpChunk {
    pub chunk_index: u32,
    pub data: Vec<u8>,
}



/// Delivery status for Layer 4 (DRP).
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum DeliveryStatus {
    Delivered = 0x01,
    Decrypted = 0x02,
    Failed = 0x03,
}

/// A receipt for a message (DRP/RRP).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DmpReceipt {
    pub message_id: [u8; 32],
    pub timestamp: u64,
    pub status: DeliveryStatus,
    pub hmac: [u8; 32], // HMAC-SHA256(msg_id || timestamp, session_key)
}

/// DMP-ADDR Canonical Contact Format
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DmpContact {
    pub dmp_address: String,
    pub bns_handle: Option<String>,
    pub display_name: Option<String>,
    pub profile_picture_hash: Option<String>, // Blob hash
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub last_interaction_at: u64,
    pub is_trusted: bool,
    pub public_identity_key: [u8; 32],
}

/// A packet for syncing data between devices sharing the same seed phrase.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeviceSyncPacket {
    pub device_id: String,
    pub timestamp: u64,
    pub payload: DeviceSyncPayload,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64], // Signed with the shared identity key
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum DeviceSyncPayload {
    MessageSummary(Vec<String>), // List of message IDs
    ContactSummary(Vec<String>), // List of contact DMP addresses
    FullMessage(DmpMessage),
    FullContact(DmpContact),
}

/// A W3C compliant DID Document for a DMP identity.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: String,
    pub id: String, // did:dmp:<address>
    pub verification_method: Vec<VerificationMethod>,
    pub service: Vec<DmpService>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerificationMethod {
    pub id: String,
    pub r#type: String, // Ed25519VerificationKey2020
    pub controller: String,
    pub public_key_multibase: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DmpService {
    pub id: String,
    pub r#type: String, // DmpDiscoveryService
    pub service_endpoint: String,
}

impl DidDocument {
    pub fn new(address: &str, public_key_hex: &str) -> Self {
        Self {
            context: "https://www.w3.org/ns/did/v1".to_string(),
            id: format!("did:dmp:{}", address),
            verification_method: vec![VerificationMethod {
                id: format!("did:dmp:{}#key-1", address),
                r#type: "Ed25519VerificationKey2020".to_string(),
                controller: format!("did:dmp:{}", address),
                public_key_multibase: public_key_hex.to_string(),
            }],
            service: vec![DmpService {
                id: format!("did:dmp:{}#discovery", address),
                r#type: "DmpDiscoveryService".to_string(),
                service_endpoint: "dmp://p2p.bevel".to_string(),
            }],
        }
    }
}

/// Local reputation score for a contact or address.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DmpReputation {
    pub dmp_address: String,
    pub trust_score: i32, // -100 to 100
    pub message_count: u64,
    pub last_interaction_at: u64,
    pub is_blocked: bool,
}

/// User-defined spam policy.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DmpSpamPolicy {
    pub min_pow_difficulty: u32,
    pub block_unknown_senders: bool,
    pub auto_junk_threshold: i32,
    pub trusted_domains: Vec<String>,
}

impl DmpSpamPolicy {
    /// Returns true if a message should be classified as spam based on sender reputation and manifest.
    pub fn is_spam(&self, reputation: &DmpReputation, manifest: &DmpMessageManifest) -> bool {
        if reputation.is_blocked {
            return true;
        }

        // Check PoW difficulty
        if manifest.pow_nonce < (self.min_pow_difficulty as u64) {
            return true;
        }

        // Check if unknown sender is blocked
        if self.block_unknown_senders && reputation.message_count == 0 {
            // Check if sender is trusted domain based on public key or masked id
            // In a real implementation, we'd lookup the BNS domain for the sender_pub_key
            let is_trusted = self.trusted_domains.iter().any(|d| {
                reputation.dmp_address.ends_with(d) // Use the resolved address from reputation
            });
            if !is_trusted {
                return true;
            }
        }

        // Check trust score threshold
        if reputation.trust_score < self.auto_junk_threshold {
            return true;
        }

        false
    }
}

/// A BNS record for address lookup.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BnsRecord {
    /// Human-readable handle (e.g., "revanth@bevel.com").
    pub handle: String,
    /// The canonical Bevel address (dmp1...).
    pub address: String,
    /// Unix timestamp of registration.
    pub timestamp: u64,
    /// Ed25519 signature of (handle || address || timestamp) by the address owner.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
    /// Anti-Sybil Proof of Work nonce
    pub pow_nonce: u64,
}

impl BnsRecord {
    pub fn is_valid_handle(handle: &str) -> bool {
        let parts: Vec<&str> = handle.split('@').collect();
        if parts.len() != 2 {
            return false;
        }
        let user = parts[0];
        let domain = parts[1];
        
        !user.is_empty() 
            && !domain.is_empty() 
            && domain.contains('.') 
            && !domain.starts_with('.') 
            && !domain.ends_with('.')
            && handle.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '@')
    }

    /// Prepares the data for signing/verification.
    pub fn signing_data(handle: &str, address: &str, timestamp: u64) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(handle.as_bytes());
        data.extend_from_slice(address.as_bytes());
        data.extend_from_slice(&timestamp.to_be_bytes());
        data
    }

    pub fn pow_hash_data(&self) -> Vec<u8> {
        let mut data = Self::signing_data(&self.handle, &self.address, self.timestamp);
        data.extend_from_slice(&self.pow_nonce.to_be_bytes());
        data
    }

    pub fn mine_pow(&mut self, difficulty: u32) {
        use sha2::{Sha256, Digest};
        loop {
            let data = self.pow_hash_data();
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let hash = hasher.finalize();
            if check_difficulty(&hash, difficulty) {
                break;
            }
            self.pow_nonce = self.pow_nonce.wrapping_add(1);
        }
    }

    pub fn verify_pow(&self, difficulty: u32) -> bool {
        use sha2::{Sha256, Digest};
        let data = self.pow_hash_data();
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = hasher.finalize();
        check_difficulty(&hash, difficulty)
    }
}

pub fn check_difficulty(hash: &[u8], difficulty: u32) -> bool {
    let mut leading_zeros = 0;
    for &byte in hash.iter() {
        if byte == 0 {
            leading_zeros += 8;
        } else {
            leading_zeros += byte.leading_zeros();
            break;
        }
    }
    leading_zeros >= difficulty
}

/// Rounds a timestamp to the nearest 10-second interval (10,000ms).
pub fn round_timestamp(ms: u64) -> u64 {
    ms - (ms % 10_000)
}

/// Pads a payload to the nearest 1KB boundary.
pub fn pad_payload(mut payload: Vec<u8>) -> Vec<u8> {
    let padding_needed = 1024 - (payload.len() % 1024);
    if padding_needed > 0 && padding_needed < 1024 {
        payload.extend(vec![0u8; padding_needed]);
    }
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_header_serialization() {
        let header = DmpHeader::default();
        let encoded = bincode::serialize(&header).unwrap();
        assert_eq!(encoded.len(), 148);
        
        let decoded: DmpHeader = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn test_timestamp_rounding() {
        let ts = 1713600000 + 5432;
        let rounded = round_timestamp(ts);
        assert_eq!(rounded % 10_000, 0);
    }

    #[test]
    fn test_payload_padding() {
        let payload = vec![0u8; 500];
        let padded = pad_payload(payload);
        assert_eq!(padded.len(), 1024);
        
        let payload2 = vec![0u8; 1024];
        let padded2 = pad_payload(payload2);
        assert_eq!(padded2.len(), 1024); // No extra padding needed
        
        let payload3 = vec![0u8; 1025];
        let padded3 = pad_payload(payload3);
        assert_eq!(padded3.len(), 2048);
    }
    
    #[test]
    fn test_json_serialization() {
        let msg = DmpMessage {
            dmp_msg_version: "1.0".to_string(),
            message_id: "msg_999".to_string(),
            thread_id: None,
            in_reply_to: None,
            subject: Some("Test JSON".to_string()),
            body: DmpMessageBody {
                text_plain: "Hello JSON".to_string(),
                text_html: None,
            },
            attachments: vec![],
            sent_at: 10000,
            flags: DmpMessageFlags {
                request_delivery_receipt: true,
                ephemeral: false,
                expiry_seconds: None,
            },
        };
        
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("msg_999"));
        assert!(json.contains("Test JSON"));
        
        let deserialized: DmpMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.message_id, msg.message_id);
    }

    #[test]
    fn test_bns_handle_validation() {
        assert!(BnsRecord::is_valid_handle("user@bevel.com"));
        assert!(BnsRecord::is_valid_handle("test.name@provider.net"));
        assert!(!BnsRecord::is_valid_handle("invalid-handle"));
        assert!(!BnsRecord::is_valid_handle("user@"));
        assert!(!BnsRecord::is_valid_handle("@domain.com"));
    }

    #[test]
    fn test_bns_signing_data_consistency() {
        let handle = "alice@bevel.com";
        let addr = "dmp1-test-addr";
        let ts = 123456789;
        
        let data1 = BnsRecord::signing_data(handle, addr, ts);
        let data2 = BnsRecord::signing_data(handle, addr, ts);
        
        assert_eq!(data1, data2);
        
        let data3 = BnsRecord::signing_data("bob@bevel.com", addr, ts);
        assert_ne!(data1, data3);
    }
}
