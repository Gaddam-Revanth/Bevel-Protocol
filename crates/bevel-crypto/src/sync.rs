use argon2::{Argon2, Params};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BackupEnvelope {
    pub magic: [u8; 4], // 'DMPB'
    pub version: u8,
    pub created_at: u64,
    pub salt: String,
    pub argon2_params: SyncParams,
    pub encrypted_blob: Vec<u8>,
    pub nonce: [u8; 12],
    pub auth_tag: [u8; 16],
    pub hmac: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SyncParams {
    pub time: u32,
    pub memory: u32,
    pub parallelism: u32,
}

impl BackupEnvelope {
    pub fn new_default_params() -> SyncParams {
        SyncParams {
            time: 3,
            memory: 65536,
            parallelism: 4,
        }
    }

    /// Derives a key from a passphrase using Argon2id.
    pub fn derive_backup_key(
        passphrase: &str,
        salt: &str,
        params: &SyncParams,
    ) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let argon2_params = Params::new(params.memory, params.time, params.parallelism, Some(32))
            .map_err(|e| format!("Argon2 params error: {}", e))?;

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2_params,
        );

        let mut key = [0u8; 32];
        argon2
            .hash_password_into(passphrase.as_bytes(), salt.as_bytes(), &mut key)
            .map_err(|e| format!("Argon2 derivation failed: {}", e))?;

        Ok(key)
    }
}
