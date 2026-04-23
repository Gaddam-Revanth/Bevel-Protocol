use sled::Db;
use bincode::{serialize, deserialize};
use bevel_crypto::{BevelIdentity, RatchetState};
use bevel_protocol::{DmpMessage, DmpChunk, DmpMessageManifest};
use serde::{de::DeserializeOwned, Serialize};
use crate::models::SerRatchetState;

#[derive(Clone)]
pub struct BevelDb {
    pub db: Db,
}

impl BevelDb {
    pub fn new(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    /// Helper for saving generic bincode-serializable items
    fn save_item<T: Serialize>(&self, tree_name: &str, key: &[u8], item: &T) -> Result<(), Box<dyn std::error::Error>> {
        let tree = self.db.open_tree(tree_name)?;
        let data = serialize(item)?;
        tree.insert(key, data)?;
        Ok(())
    }

    /// Helper for getting generic bincode-serializable items
    fn get_item<T: DeserializeOwned>(&self, tree_name: &str, key: &[u8]) -> Result<Option<T>, Box<dyn std::error::Error>> {
        let tree = self.db.open_tree(tree_name)?;
        if let Some(data) = tree.get(key)? {
            let item: T = deserialize(&data)?;
            Ok(Some(item))
        } else {
            Ok(None)
        }
    }

    // --- Identities ---
    pub fn save_identity(&self, identity: &BevelIdentity) -> Result<(), Box<dyn std::error::Error>> {
        self.save_item("identities", identity.address.as_bytes(), identity)
    }

    pub fn get_identity(&self, address: &str) -> Result<Option<BevelIdentity>, Box<dyn std::error::Error>> {
        if let Some(ident) = self.get_item::<BevelIdentity>("identities", address.as_bytes())? {
            // Reconstruct private keys from the seed phrase since they are excluded from serialization
            let fully_loaded = BevelIdentity::from_seed_phrase(ident.seed_phrase())?;
            Ok(Some(fully_loaded))
        } else {
            Ok(None)
        }
    }

    // --- Ratchet States ---
    pub fn save_ratchet_state(&self, remote_address: &str, state: &RatchetState) -> Result<(), Box<dyn std::error::Error>> {
        let ser_state = SerRatchetState::from(state);
        self.save_item("ratchets", remote_address.as_bytes(), &ser_state)
    }

    pub fn get_ratchet_state(&self, remote_address: &str) -> Result<Option<RatchetState>, Box<dyn std::error::Error>> {
        if let Some(ser_state) = self.get_item::<SerRatchetState>("ratchets", remote_address.as_bytes())? {
            Ok(Some(RatchetState::from(ser_state)))
        } else {
            Ok(None)
        }
    }

    // --- Messages ---
    pub fn save_message(&self, msg: &DmpMessage) -> Result<(), Box<dyn std::error::Error>> {
        self.save_item("messages", msg.message_id.as_bytes(), msg)
    }

    pub fn get_message(&self, message_id: &str) -> Result<Option<DmpMessage>, Box<dyn std::error::Error>> {
        self.get_item("messages", message_id.as_bytes())
    }
    
    // --- Offline SFP Chunks Cache ---
    pub fn save_sfp_chunk(&self, chunk_key: &[u8; 32], chunk: &DmpChunk) -> Result<(), Box<dyn std::error::Error>> {
        self.save_item("sfp_chunks", chunk_key, chunk)
    }

    pub fn get_sfp_chunk(&self, chunk_key: &[u8; 32]) -> Result<Option<DmpChunk>, Box<dyn std::error::Error>> {
        self.get_item("sfp_chunks", chunk_key)
    }

    // --- Offline SFP Manifest Cache ---
    pub fn save_sfp_manifest(&self, message_id: &[u8; 32], manifest: &DmpMessageManifest) -> Result<(), Box<dyn std::error::Error>> {
        self.save_item("sfp_manifests", message_id, manifest)
    }

    pub fn get_sfp_manifest(&self, message_id: &[u8; 32]) -> Result<Option<DmpMessageManifest>, Box<dyn std::error::Error>> {
        self.get_item("sfp_manifests", message_id)
    }

    // --- BNS (Bevel Name Service) Records ---
    pub fn save_bns_record(&self, record: &bevel_protocol::BnsRecord) -> Result<(), Box<dyn std::error::Error>> {
        self.save_item("bns_records", record.handle.as_bytes(), record)
    }

    pub fn get_bns_record(&self, handle: &str) -> Result<Option<bevel_protocol::BnsRecord>, Box<dyn std::error::Error>> {
        self.get_item("bns_records", handle.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bevel_protocol::{DmpMessageBody, DmpMessageFlags};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn get_temp_db_path() -> String {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("bevel_storage_test_{}", nanos));
        path.to_str().unwrap().to_string()
    }

    #[test]
    fn test_save_and_retrieve_identity() {
        let path = get_temp_db_path();
        let db = BevelDb::new(&path).unwrap();
        
        let id = BevelIdentity::generate().unwrap();
        db.save_identity(&id).unwrap();
        
        let retrieved = db.get_identity(&id.address).unwrap().unwrap();
        assert_eq!(id.address, retrieved.address);
        assert_eq!(id.seed_phrase(), retrieved.seed_phrase());
        assert_eq!(id.public_identity_key, retrieved.public_identity_key);
        
        // Clean up
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn test_save_and_retrieve_message() {
        let path = get_temp_db_path();
        let db = BevelDb::new(&path).unwrap();
        
        let msg = DmpMessage {
            dmp_msg_version: "1.0".to_string(),
            message_id: "msg_test_123".to_string(),
            thread_id: None,
            in_reply_to: None,
            subject: Some("Test Subj".to_string()),
            body: DmpMessageBody {
                text_plain: "Hello".to_string(),
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
        
        db.save_message(&msg).unwrap();
        
        let retrieved = db.get_message(&msg.message_id).unwrap().unwrap();
        assert_eq!(msg.message_id, retrieved.message_id);
        assert_eq!(msg.subject, retrieved.subject);
        assert_eq!(msg.body.text_plain, retrieved.body.text_plain);
        
        // Clean up
        let _ = std::fs::remove_dir_all(path);
    }
}
