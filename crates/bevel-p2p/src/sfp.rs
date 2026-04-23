use bevel_protocol::{DmpMessageManifest, DmpChunk};
use hmac::{Hmac, Mac};
use sha2::Sha256;


pub const CHUNK_SIZE: usize = 256 * 1024; // 256KB

pub struct SfpEngine;

impl SfpEngine {
    /// Chunks a ciphertext into fixed-size DmpChunks and derives DHT keys.
    pub fn chunk_message(
        recipient_address: &str,
        message_id: [u8; 32],
        ciphertext: &[u8],
        sender_masked: [u8; 32],
    ) -> (DmpMessageManifest, Vec<DmpChunk>) {
        let mut chunks = Vec::new();
        let mut chunk_keys = Vec::new();
        
        for (index, raw_chunk) in ciphertext.chunks(CHUNK_SIZE).enumerate() {
            let chunk = DmpChunk {
                chunk_index: index as u32,
                data: raw_chunk.to_vec(),
            };
            
            // Derive DHT key for this specific chunk
            let key = derive_chunk_dht_key(recipient_address, &message_id, index as u32);
            chunk_keys.push(key);
            chunks.push(chunk);
        }

        // sender_masked is now provided by the caller to ensure anonymity
        let sender_masked = sender_masked;        
        let manifest = DmpMessageManifest {
            message_id,
            total_size: ciphertext.len() as u64,
            chunk_keys,
            expiry: 0, // Set by caller
            sender_masked,
            sender_pub_key: [0u8; 32], // Set by caller
            signature: [0u8; 64], // Signed by caller
            pow_nonce: 0,
        };

        (manifest, chunks)
    }

    /// Reassembles chunks in order to reconstruct the original ciphertext.
    pub fn reassemble_message(chunks: Vec<DmpChunk>) -> Vec<u8> {
        let mut sorted_chunks = chunks;
        sorted_chunks.sort_by_key(|c| c.chunk_index);
        
        let mut result = Vec::new();
        for chunk in sorted_chunks {
            result.extend(chunk.data);
        }
        result
    }
}

/// Derives a DHT lookup key for a specific chunk.
/// HMAC(recipient_address, message_id || chunk_index)
pub fn derive_chunk_dht_key(
    recipient_address: &str,
    message_id: &[u8; 32],
    index: u32,
) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(recipient_address.as_bytes()).expect("HMAC accepts any key size");
    mac.update(message_id);
    mac.update(&index.to_be_bytes());
    mac.finalize().into_bytes().into()
}

/// Derives the DHT lookup key for the message manifest.
/// HMAC(recipient_address, "sfp-manifest" || epoch)
/// Epoch allows rolling the inbox key to prevent indefinite traffic correlation.
pub fn derive_manifest_dht_key(recipient_address: &str, epoch: u64) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(recipient_address.as_bytes()).expect("HMAC accepts any key size");
    mac.update(b"sfp-manifest");
    mac.update(&epoch.to_be_bytes());
    mac.finalize().into_bytes().into()
}
