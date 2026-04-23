//! bevel-media — File and folder processing for media sharing.
//!
//! Handles chunking, encryption, and manifest generation for large binary blobs.

use std::path::{Path};
use std::fs;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use rand::RngCore;
use sha2::{Sha256, Digest};
use bevel_protocol::{DmpAttachmentRef, BlobFolderManifest, BlobFolderEntry};
use bevel_p2p::{SfpEngine};
use walkdir::WalkDir;

pub struct BlobEngine;

pub struct BlobResult {
    pub attachment_ref: DmpAttachmentRef,
    pub chunks: Vec<bevel_protocol::DmpChunk>,
    pub manifest: Option<BlobFolderManifest>,
}

impl BlobEngine {
    /// Encrypts and chunks a file at the given path.
    pub fn process_file(
        path: &Path,
        recipient_addr: &str,
    ) -> Result<BlobResult, Box<dyn std::error::Error>> {
        let file_name = path.file_name().ok_or("Invalid filename")?.to_string_lossy().to_string();
        let mime_type = mime_guess::from_path(path).first_or_octet_stream().to_string();
        let raw_data = fs::read(path)?;
        let size = raw_data.len() as u64;

        // Generate a random encryption key for this file
        let mut key_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        
        // Generate nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the entire file
        let cipher = Aes256Gcm::new(key);
        let ciphertext = cipher.encrypt(nonce, raw_data.as_ref())
            .map_err(|_| "Encryption failed")?;

        // Prepend nonce to ciphertext for easier retrieval
        let mut final_payload = nonce_bytes.to_vec();
        final_payload.extend_from_slice(&ciphertext);

        // Generate content hash
        let mut hasher = Sha256::new();
        hasher.update(&final_payload);
        let content_hash = hex::encode(hasher.finalize());

        // Chunk it using SFP
        let mut msg_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut msg_id);
        
        // SFP doesn't need recipient address for chunking itself, but for key derivation
        let (_, chunks) = SfpEngine::chunk_message(
            recipient_addr,
            msg_id,
            &final_payload,
            [0u8; 32], // sender mask not used for raw blob chunks
        );

        let attachment_ref = DmpAttachmentRef {
            content_hash: content_hash.clone(),
            encryption_key: hex::encode(key_bytes),
            size,
            mime_type,
            file_name,
            is_folder: false,
        };

        Ok(BlobResult {
            attachment_ref,
            chunks,
            manifest: None,
        })
    }

    /// Processes an entire directory by recursing through it.
    /// Each file is processed as a blob, and a folder manifest is generated.
    pub fn process_folder(
        path: &Path,
        recipient_addr: &str,
    ) -> Result<BlobResult, Box<dyn std::error::Error>> {
        let folder_name = path.file_name().ok_or("Invalid folder name")?.to_string_lossy().to_string();
        let mut entries = Vec::new();
        let mut all_chunks = Vec::new();
        
        // Use a shared key for the folder manifest itself
        let mut folder_key_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut folder_key_bytes);

        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let rel_path = entry.path().strip_prefix(path)?.to_string_lossy().to_string();
                let res = Self::process_file(entry.path(), recipient_addr)?;
                
                entries.push(BlobFolderEntry {
                    relative_path: rel_path,
                    content_hash: res.attachment_ref.content_hash,
                    size: res.attachment_ref.size,
                });
                
                all_chunks.extend(res.chunks);
            }
        }

        let manifest = BlobFolderManifest { entries };
        let manifest_bytes = serde_json::to_vec(&manifest)?;
        
        // Encrypt the manifest itself
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let key = Key::<Aes256Gcm>::from_slice(&folder_key_bytes);
        let cipher = Aes256Gcm::new(key);
        let encrypted_manifest = cipher.encrypt(Nonce::from_slice(&nonce_bytes), manifest_bytes.as_ref())
            .map_err(|_| "Manifest encryption failed")?;
        
        let mut manifest_payload = nonce_bytes.to_vec();
        manifest_payload.extend_from_slice(&encrypted_manifest);

        let mut hasher = Sha256::new();
        hasher.update(&manifest_payload);
        let content_hash = hex::encode(hasher.finalize());

        // Chunk the manifest itself
        let mut msg_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut msg_id);
        let (_, manifest_chunks) = SfpEngine::chunk_message(
            recipient_addr,
            msg_id,
            &manifest_payload,
            [0u8; 32],
        );
        
        all_chunks.extend(manifest_chunks);

        let attachment_ref = DmpAttachmentRef {
            content_hash,
            encryption_key: hex::encode(folder_key_bytes),
            size: manifest_payload.len() as u64,
            mime_type: "application/x-bevel-folder".to_string(),
            file_name: folder_name,
            is_folder: true,
        };

        Ok(BlobResult {
            attachment_ref,
            chunks: all_chunks,
            manifest: Some(manifest),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_process_file_round_trip() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        let mut file = fs::File::create(&file_path).unwrap();
        let content = b"Hello, Bevel!";
        file.write_all(content).unwrap();

        let res = BlobEngine::process_file(&file_path, "recipient").unwrap();
        
        assert_eq!(res.attachment_ref.file_name, "test.txt");
        assert_eq!(res.attachment_ref.size, content.len() as u64);
        assert!(!res.chunks.is_empty());
    }

    #[test]
    fn test_process_folder() {
        let dir = tempdir().unwrap();
        let folder_path = dir.path().join("my_folder");
        fs::create_dir(&folder_path).unwrap();
        
        let file1_path = folder_path.join("file1.txt");
        fs::write(&file1_path, b"File 1 content").unwrap();
        
        let file2_path = folder_path.join("file2.txt");
        fs::write(&file2_path, b"File 2 content").unwrap();

        let res = BlobEngine::process_folder(&folder_path, "recipient").unwrap();
        
        assert_eq!(res.attachment_ref.file_name, "my_folder");
        assert!(res.attachment_ref.is_folder);
        assert_eq!(res.manifest.unwrap().entries.len(), 2);
        assert!(!res.chunks.is_empty());
    }
}
