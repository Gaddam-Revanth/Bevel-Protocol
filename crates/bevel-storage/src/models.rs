use bevel_crypto::RatchetState;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Serialize, Deserialize)]
pub struct SerRatchetState {
    pub dh_sec_c: [u8; 32],
    pub dh_pub_c: [u8; 32],
    pub dh_pub_remote: [u8; 32],
    pub root_key: [u8; 32],
    pub send_chain_key: Option<[u8; 32]>,
    pub prev_send_chain_key: Option<[u8; 32]>,
    pub recv_chain_key: Option<[u8; 32]>,
    pub send_count: u32,
    pub recv_count: u32,
}

impl From<&RatchetState> for SerRatchetState {
    fn from(rs: &RatchetState) -> Self {
        Self {
            dh_sec_c: rs.dh_sec_c.to_bytes(),
            dh_pub_c: rs.dh_pub_c.to_bytes(),
            dh_pub_remote: rs.dh_pub_remote.to_bytes(),
            root_key: rs.root_key,
            send_chain_key: rs.send_chain_key,
            prev_send_chain_key: rs.prev_send_chain_key,
            recv_chain_key: rs.recv_chain_key,
            send_count: rs.send_count,
            recv_count: rs.recv_count,
        }
    }
}

impl From<SerRatchetState> for RatchetState {
    fn from(srs: SerRatchetState) -> Self {
        RatchetState {
            dh_sec_c: StaticSecret::from(srs.dh_sec_c),
            dh_pub_c: PublicKey::from(srs.dh_pub_c),
            dh_pub_remote: PublicKey::from(srs.dh_pub_remote),
            root_key: srs.root_key,
            send_chain_key: srs.send_chain_key,
            prev_send_chain_key: srs.prev_send_chain_key,
            recv_chain_key: srs.recv_chain_key,
            send_count: srs.send_count,
            recv_count: srs.recv_count,
        }
    }
}
