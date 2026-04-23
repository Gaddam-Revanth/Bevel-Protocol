use crate::BevelIdentity;
use aes_gcm::{
    aead::{Aead, Payload, KeyInit},
    Aes256Gcm, Nonce as GcmNonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedBlob {
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KeystoreFile {
    pub blobs: Vec<EncryptedBlob>,
}

pub struct IdentityKeystore {
    path: PathBuf,
}

impl IdentityKeystore {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Sets up a new keystore with plausible deniability and a wipe PIN.
    pub fn setup(
        &self,
        primary_id: &BevelIdentity,
        primary_pin: &str,
        dummy_id: &BevelIdentity,
        dummy_pin: &str,
        wipe_pin: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut blobs = Vec::new();

        // Encrypt primary
        blobs.push(Self::encrypt_data(
            primary_id.seed_phrase().as_bytes(),
            primary_pin,
        )?);

        // Encrypt dummy
        blobs.push(Self::encrypt_data(
            dummy_id.seed_phrase().as_bytes(),
            dummy_pin,
        )?);

        // Encrypt wipe marker
        blobs.push(Self::encrypt_data(b"WIPE_MARKER", wipe_pin)?);

        // Shuffle blobs so an attacker doesn't know which is which by index
        use rand::seq::SliceRandom;
        blobs.shuffle(&mut rand::thread_rng());

        let file_data = KeystoreFile { blobs };
        let json = serde_json::to_string(&file_data)?;
        fs::write(&self.path, json)?;

        Ok(())
    }

    /// Attempts to unlock the keystore with a given PIN.
    pub fn unlock(&self, pin: &str) -> Result<BevelIdentity, Box<dyn std::error::Error>> {
        if !self.path.exists() {
            return Err("Keystore file not found".into());
        }

        let json = fs::read_to_string(&self.path)?;
        let file_data: KeystoreFile = serde_json::from_str(&json)?;

        for blob in &file_data.blobs {
            if let Ok(plaintext) = Self::decrypt_blob(blob, pin) {
                if plaintext == b"WIPE_MARKER" {
                    // WIPE PIN entered! Actively destroy the file.
                    let _ = fs::remove_file(&self.path);
                    return Err("Keystore wiped".into());
                }

                // If it's a seed phrase, restore the identity
                let phrase = String::from_utf8(plaintext)?;
                return BevelIdentity::from_seed_phrase(&phrase);
            }
        }

        Err("Invalid PIN".into())
    }

    fn encrypt_data(data: &[u8], pin: &str) -> Result<EncryptedBlob, Box<dyn std::error::Error>> {
        let mut rng = rand::thread_rng();
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);

        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);

        let key = Self::derive_key(pin, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key)?;
        let gcm_nonce = GcmNonce::from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(gcm_nonce, Payload { msg: data, aad: &[] })
            .map_err(|_| "Encryption failed")?;

        Ok(EncryptedBlob {
            salt,
            nonce,
            ciphertext,
        })
    }

    fn decrypt_blob(blob: &EncryptedBlob, pin: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let key = Self::derive_key(pin, &blob.salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key)?;
        let gcm_nonce = GcmNonce::from_slice(&blob.nonce);

        let plaintext = cipher
            .decrypt(gcm_nonce, Payload { msg: &blob.ciphertext, aad: &[] })
            .map_err(|_| "Decryption failed")?;

        Ok(plaintext)
    }

    fn derive_key(pin: &str, salt: &[u8]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let params = Params::new(15360, 2, 1, Some(32)).map_err(|e| e.to_string())?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = [0u8; 32];
        argon2
            .hash_password_into(pin.as_bytes(), salt, &mut key)
            .map_err(|e| e.to_string())?;

        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plausible_deniability_keystore() {
        let temp_path = std::env::temp_dir().join("test_keystore.json");
        let _ = std::fs::remove_file(&temp_path);

        let ks = IdentityKeystore::new(&temp_path);
        
        let primary = BevelIdentity::generate().unwrap();
        let dummy = BevelIdentity::generate().unwrap();

        ks.setup(&primary, "1234", &dummy, "9999", "0000").unwrap();

        // Test Primary
        let unlocked_primary = ks.unlock("1234").unwrap();
        assert_eq!(unlocked_primary.address, primary.address);

        // Test Dummy
        let unlocked_dummy = ks.unlock("9999").unwrap();
        assert_eq!(unlocked_dummy.address, dummy.address);

        // Test Invalid
        assert!(ks.unlock("1111").is_err());

        // Test Wipe
        let wipe_result = ks.unlock("0000");
        assert!(wipe_result.is_err());
        assert!(!temp_path.exists());
    }
}
