use sled::Db;
use bincode::{serialize, deserialize};
use bevel_crypto::{BevelIdentity, RatchetState};
use bevel_protocol::{DmpMessage, DmpChunk, DmpMessageManifest, DmpContact, DmpReputation, DmpSpamPolicy};
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

    // --- Contacts ---
    pub fn save_contact(&self, contact: &DmpContact) -> Result<(), Box<dyn std::error::Error>> {
        self.save_item("contacts", contact.dmp_address.as_bytes(), contact)
    }

    pub fn get_contact(&self, address: &str) -> Result<Option<DmpContact>, Box<dyn std::error::Error>> {
        self.get_item("contacts", address.as_bytes())
    }

    pub fn list_contacts(&self) -> Result<Vec<DmpContact>, Box<dyn std::error::Error>> {
        let tree = self.db.open_tree("contacts")?;
        let mut contacts = Vec::new();
        for item in tree.iter() {
            let (_, data) = item?;
            let contact: DmpContact = deserialize(&data)?;
            contacts.push(contact);
        }
        Ok(contacts)
    }

    // --- Search Index ---
    /// Tokenizes and indexes a message for local search.
    pub fn index_message(&self, msg: &DmpMessage) -> Result<(), Box<dyn std::error::Error>> {
        let tree = self.db.open_tree("search_index")?;
        
        let mut text = msg.body.text_plain.to_lowercase();
        if let Some(ref subject) = msg.subject {
            text.push(' ');
            text.push_str(&subject.to_lowercase());
        }

        // Simple word-based tokenization
        let tokens: std::collections::HashSet<&str> = text
            .split(|c: char| !c.is_alphanumeric())
            .filter(|s| s.len() > 2)
            .collect();

        for token in tokens {
            let mut message_ids: Vec<String> = if let Some(data) = tree.get(token.as_bytes())? {
                deserialize(&data)?
            } else {
                Vec::new()
            };

            if !message_ids.contains(&msg.message_id) {
                message_ids.push(msg.message_id.clone());
                tree.insert(token.as_bytes(), serialize(&message_ids)?)?;
            }
        }

        Ok(())
    }

    /// Searches for messages containing the given query.
    pub fn search_messages(&self, query: &str) -> Result<Vec<DmpMessage>, Box<dyn std::error::Error>> {
        let tree = self.db.open_tree("search_index")?;
        let query = query.to_lowercase();
        let tokens: Vec<&str> = query
            .split(|c: char| !c.is_alphanumeric())
            .filter(|s| !s.is_empty())
            .collect();

        if tokens.is_empty() {
            return Ok(Vec::new());
        }

        let mut result_ids: Option<std::collections::HashSet<String>> = None;

        for token in tokens {
            if let Some(data) = tree.get(token.as_bytes())? {
                let ids: Vec<String> = deserialize(&data)?;
                let ids_set: std::collections::HashSet<String> = ids.into_iter().collect();
                
                if let Some(ref mut set) = result_ids {
                    *set = set.intersection(&ids_set).cloned().collect();
                } else {
                    result_ids = Some(ids_set);
                }
            } else {
                // If any token is not found, the intersection will be empty
                return Ok(Vec::new());
            }
        }

        let mut results = Vec::new();
        if let Some(ids) = result_ids {
            for id in ids {
                if let Some(msg) = self.get_message(&id)? {
                    results.push(msg);
                }
            }
        }

        Ok(results)
    }

    // --- Reputation & Spam ---
    pub fn save_reputation(&self, rep: &DmpReputation) -> Result<(), Box<dyn std::error::Error>> {
        self.save_item("reputation", rep.dmp_address.as_bytes(), rep)
    }

    pub fn get_reputation(&self, address: &str) -> Result<DmpReputation, Box<dyn std::error::Error>> {
        if let Some(rep) = self.get_item::<DmpReputation>("reputation", address.as_bytes())? {
            Ok(rep)
        } else {
            // Default reputation for unknown address
            Ok(DmpReputation {
                dmp_address: address.to_string(),
                trust_score: 0,
                message_count: 0,
                last_interaction_at: 0,
                is_blocked: false,
            })
        }
    }

    pub fn save_spam_policy(&self, policy: &DmpSpamPolicy) -> Result<(), Box<dyn std::error::Error>> {
        self.save_item("settings", b"spam_policy", policy)
    }

    pub fn get_spam_policy(&self) -> Result<DmpSpamPolicy, Box<dyn std::error::Error>> {
        if let Some(policy) = self.get_item::<DmpSpamPolicy>("settings", b"spam_policy")? {
            Ok(policy)
        } else {
            // Default policy
            Ok(DmpSpamPolicy {
                min_pow_difficulty: 10,
                block_unknown_senders: false,
                auto_junk_threshold: -50,
                trusted_domains: vec!["bevel.net".to_string()],
            })
        }
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

    #[test]
    fn test_save_and_retrieve_contact() {
        let path = get_temp_db_path();
        let db = BevelDb::new(&path).unwrap();
        
        let contact = DmpContact {
            dmp_address: "bv1addr_test_123".to_string(),
            bns_handle: Some("test@bevel.net".to_string()),
            display_name: Some("Test User".to_string()),
            profile_picture_hash: None,
            notes: Some("A test contact".to_string()),
            tags: vec!["friend".to_string()],
            last_interaction_at: 123456789,
            is_trusted: true,
            public_identity_key: [0u8; 32],
        };
        
        db.save_contact(&contact).unwrap();
        
        let retrieved = db.get_contact(&contact.dmp_address).unwrap().unwrap();
        assert_eq!(contact.dmp_address, retrieved.dmp_address);
        assert_eq!(contact.display_name, retrieved.display_name);
        assert_eq!(contact.tags, retrieved.tags);
        
        let list = db.list_contacts().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].dmp_address, contact.dmp_address);
        
        // Clean up
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn test_search_messages() {
        let path = get_temp_db_path();
        let db = BevelDb::new(&path).unwrap();
        
        let msg1 = DmpMessage::new(
            Some("Meeting".to_string()),
            DmpMessageBody { text_plain: "Hello, let's meet at 5pm".to_string(), text_html: None },
            DmpMessageFlags { request_delivery_receipt: false, ephemeral: false, expiry_seconds: None },
        );
        let msg2 = DmpMessage::new(
            Some("Urgent".to_string()),
            DmpMessageBody { text_plain: "Please call me back".to_string(), text_html: None },
            DmpMessageFlags { request_delivery_receipt: false, ephemeral: false, expiry_seconds: None },
        );
        
        db.save_message(&msg1).unwrap();
        db.index_message(&msg1).unwrap();
        db.save_message(&msg2).unwrap();
        db.index_message(&msg2).unwrap();
        
        let results = db.search_messages("meet").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].message_id, msg1.message_id);
        
        let results = db.search_messages("call").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].message_id, msg2.message_id);
        
        let results = db.search_messages("hello call").unwrap();
        assert_eq!(results.len(), 0); // Intersection is empty
        
        // Clean up
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn test_spam_filtering() {
        let path = get_temp_db_path();
        let db = BevelDb::new(&path).unwrap();
        
        let policy = db.get_spam_policy().unwrap();
        
        // 1. Blocked sender
        let mut rep = db.get_reputation("bv1bad").unwrap();
        rep.is_blocked = true;
        db.save_reputation(&rep).unwrap();
        
        let mut manifest = DmpMessageManifest {
            message_id: [0u8; 32],
            total_size: 1024,
            chunk_keys: vec![],
            expiry: 0,
            sender_masked: [0u8; 32],
            sender_pub_key: [0u8; 32],
            signature: [0u8; 64],
            pow_nonce: 100,
        };
        
        assert!(policy.is_spam(&rep, &manifest));
        
        // 2. Low PoW difficulty
        let rep_good = db.get_reputation("bv1good").unwrap();
        manifest.pow_nonce = 1; // Below default 10
        assert!(policy.is_spam(&rep_good, &manifest));
        
        // 3. Trusted domain bypass
        let mut rep_trusted = db.get_reputation("user@bevel.net").unwrap();
        rep_trusted.message_count = 0;
        manifest.pow_nonce = 100;
        
        let mut strict_policy = policy.clone();
        strict_policy.block_unknown_senders = true;
        assert!(!strict_policy.is_spam(&rep_trusted, &manifest)); // Trusted domain
        
        let rep_evil = db.get_reputation("user@evil.com").unwrap();
        assert!(strict_policy.is_spam(&rep_evil, &manifest)); // Not trusted domain
        
        // Clean up
        let _ = std::fs::remove_dir_all(path);
    }
}
