use wasm_bindgen::prelude::*;
use bevel_crypto::{BevelIdentity as CoreIdentity, compute_x3dh_master_secret, encrypt_payload, decrypt_payload};
use bevel_protocol::{DmpHeader, pad_payload};
use x25519_dalek::{StaticSecret, PublicKey};
use serde::{Serialize, Deserialize};
use tsify::Tsify;
use hex;

#[wasm_bindgen]
#[derive(Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmIdentity {
    pub seed_phrase: String,
    pub address: String,
}

#[wasm_bindgen]
pub fn generate_identity() -> Result<WasmIdentity, JsError> {
    let id = CoreIdentity::generate()
        .map_err(|e| JsError::new(&e.to_string()))?;
    
    Ok(WasmIdentity {
        seed_phrase: id.seed_phrase().to_string(),
        address: id.address,
    })
}

#[wasm_bindgen]
pub fn restore_identity(phrase: &str) -> Result<WasmIdentity, JsError> {
    let id = CoreIdentity::from_seed_phrase(phrase)
        .map_err(|e| JsError::new(&e.to_string()))?;
    
    Ok(WasmIdentity {
        seed_phrase: id.seed_phrase().to_string(),
        address: id.address,
    })
}

#[wasm_bindgen]
pub fn generate_pre_keys(count: usize) -> Result<js_sys::Array, JsError> {
    let keys = CoreIdentity::generate_pre_keys(count);
    let arr = js_sys::Array::new();
    for (sec, pub_k) in keys {
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &JsValue::from_str("secret"), &JsValue::from_str(&hex::encode(sec)))
            .map_err(|_| JsError::new("Failed to reflect secret property"))?;
        js_sys::Reflect::set(&obj, &JsValue::from_str("public"), &JsValue::from_str(&hex::encode(pub_k)))
            .map_err(|_| JsError::new("Failed to reflect public property"))?;
        arr.push(&obj);
    }
    Ok(arr)
}

#[wasm_bindgen]
pub fn compute_shared_secret(ik: &str, ek: &str, remote_pub: &str) -> Result<String, JsError> {
    let ik_bytes = hex::decode(ik).map_err(|e| JsError::new(&e.to_string()))?;
    let ek_bytes = hex::decode(ek).map_err(|e| JsError::new(&e.to_string()))?;
    let remote_pub_bytes = hex::decode(remote_pub).map_err(|e| JsError::new(&e.to_string()))?;
    
    let ik_secret = StaticSecret::from(ik_bytes.try_into().map_err(|_| JsError::new("Invalid IK size"))?);
    let ek_secret = StaticSecret::from(ek_bytes.try_into().map_err(|_| JsError::new("Invalid EK size"))?);
    let remote_pk = PublicKey::from(remote_pub_bytes.try_into().map_err(|_| JsError::new("Invalid Remote Pub size"))?);

    // Provide self generated IK public key for the remote side's expectation
    let ik_pub = PublicKey::from(&ik_secret);
    
    // We compute Master Secret assuming the remote provided spk (and no opk in this simplified exposed func)
    let master_secret = compute_x3dh_master_secret(
        &ik_secret,
        &ek_secret,
        &ik_pub,
        &remote_pk,
        None
    );

    Ok(hex::encode(master_secret))
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmCiphertext {
    pub ciphertext: String, // hex encoded
    pub nonce: String,      // hex encoded
}

#[wasm_bindgen]
pub fn encrypt_payload_wasm(key_hex: &str, plaintext: &[u8]) -> Result<WasmCiphertext, JsError> {
    let key_bytes: [u8; 32] = hex::decode(key_hex)
        .map_err(|e| JsError::new(&e.to_string()))?
        .try_into()
        .map_err(|_| JsError::new("Invalid key length string"))?;
        
    let (ciphertext_bytes, nonce_bytes) = encrypt_payload(&key_bytes, plaintext, b"")
        .map_err(|e| JsError::new(&e.to_string()))?;
        
    Ok(WasmCiphertext {
        ciphertext: hex::encode(ciphertext_bytes),
        nonce: hex::encode(nonce_bytes),
    })
}

#[wasm_bindgen]
pub fn decrypt_payload_wasm(key_hex: &str, nonce_hex: &str, ciphertext_hex: &str) -> Result<Vec<u8>, JsError> {
    let key_bytes: [u8; 32] = hex::decode(key_hex)
        .map_err(|e| JsError::new(&e.to_string()))?
        .try_into()
        .map_err(|_| JsError::new("Invalid key length string"))?;
        
    let nonce_bytes: [u8; 12] = hex::decode(nonce_hex)
        .map_err(|e| JsError::new(&e.to_string()))?
        .try_into()
        .map_err(|_| JsError::new("Invalid nonce length string"))?;
        
    let ciphertext_bytes = hex::decode(ciphertext_hex)
        .map_err(|e| JsError::new(&e.to_string()))?;
    
    let plaintext = decrypt_payload(&key_bytes, &nonce_bytes, &ciphertext_bytes, b"")
        .map_err(|e| JsError::new(&e.to_string()))?;
        
    Ok(plaintext)
}

#[wasm_bindgen]
pub fn pad_payload_wasm(payload: &[u8]) -> Vec<u8> {
    pad_payload(payload.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;
    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_wasm_generate_identity() {
        let id = generate_identity().expect("Failed to generate identity");
        assert!(!id.address.is_empty(), "Address should not be empty");
        assert!(!id.seed_phrase.is_empty(), "Seed phrase should not be empty");
        assert!(id.address.starts_with("dmp1"), "Address should start with dmp1");
    }

    #[wasm_bindgen_test]
    fn test_wasm_encryption_cycle() {
        let key_hex = hex::encode([9u8; 32]);
        let plaintext = b"Hello WASM";
        
        let encrypted = encrypt_payload_wasm(&key_hex, plaintext).expect("Failed to encrypt");
        assert!(!encrypted.ciphertext.is_empty());
        assert!(!encrypted.nonce.is_empty());
        
        let decrypted = decrypt_payload_wasm(&key_hex, &encrypted.nonce, &encrypted.ciphertext).expect("Failed to decrypt");
        assert_eq!(decrypted, plaintext);
    }
}
