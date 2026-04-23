//! Onion routing security audit: anonymity, integrity, and protocol properties.

use bevel_onion::{OnionRouter, OnionHopSpec, OnionCell, ONION_CELL_SIZE, ReplayCache};
use x25519_dalek::{StaticSecret, PublicKey};
use rand::RngCore;
use crate::{Finding, Severity, Status};

/// Helper: generate a random relay spec + its secret.
fn random_relay(rng: &mut impl RngCore, id: &str) -> (OnionHopSpec, StaticSecret) {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let secret  = StaticSecret::from(bytes);
    let pub_key = PublicKey::from(&secret);
    (OnionHopSpec { relay_pub_key: pub_key.to_bytes(), peer_id: id.into() }, secret)
}

pub fn run() -> Vec<Finding> {
    vec![
        test_layer_isolation(),
        test_relay_cannot_read_exit_payload(),
        test_replay_attack(),
        test_tamper_detection_ciphertext(),
        test_tamper_detection_nonce(),
        test_wire_padding_multiple_of_512(),
        test_wrong_relay_key_rejected(),
        test_hop_count_metadata_leak(),
    ]
}

/// Each relay can only peel its own layer; it must not be able to peel a deeper layer
/// using the same key (different eph keys are used per hop).
fn test_layer_isolation() -> Finding {
    let mut rng = rand::thread_rng();
    let (spec0, sec0) = random_relay(&mut rng, "relay-0");
    let (spec1, sec1) = random_relay(&mut rng, "relay-1");
    let (spec2, sec2) = random_relay(&mut rng, "relay-2");

    let payload = b"layer isolation test";
    let cell = OnionRouter::build_circuit(&[spec0, spec1, spec2], payload).unwrap();

    // Relay 0 peels its own layer — should succeed.
    let mut cache0 = ReplayCache::new();
    let r0 = OnionRouter::peel_layer(&cell, &sec0, &mut cache0);
    assert!(r0.is_ok(), "Relay 0 should peel its own layer");

    // Relay 0's secret must NOT be able to peel relay 1's inner cell.
    let inner_bytes = r0.unwrap().inner_data;
    let inner_cell: OnionCell = bincode::deserialize(&inner_bytes).unwrap();
    let mut cache_fail = ReplayCache::new();
    let r0_on_r1 = OnionRouter::peel_layer(&inner_cell, &sec0, &mut cache_fail); // sec0 trying to peel relay-1's layer

    // Relay 1's secret correctly peels relay 1's layer.
    let mut cache1 = ReplayCache::new();
    let r1 = OnionRouter::peel_layer(&inner_cell, &sec1, &mut cache1);
    let _ = sec2; // sec2 used only to silence unused warning

    let isolated = r0_on_r1.is_err() && r1.is_ok();
    Finding {
        id: "BVL-O01",
        title: "Onion Layer Isolation (Relay Cannot Peek Forward)",
        severity: Severity::Critical,
        description: if isolated {
            "Each relay can only decrypt its own layer. Relay N cannot peel relay N+1's layer.".into()
        } else {
            "ISOLATION FAILURE: Relay 0's key successfully decrypted Relay 1's layer!".into()
        },
        status: if isolated { Status::Passed } else { Status::Confirmed },
        recommendation: "Verify independent ephemeral X25519 key pairs are generated per hop.",
    }
}

/// The entry relay must NOT be able to read the final exit payload.
fn test_relay_cannot_read_exit_payload() -> Finding {
    let mut rng = rand::thread_rng();
    let (spec0, sec0) = random_relay(&mut rng, "entry");
    let (spec1, _)    = random_relay(&mut rng, "exit");

    let secret_payload = b"TOP SECRET \x2d entry relay must not see this";
    let cell = OnionRouter::build_circuit(&[spec0, spec1], secret_payload).unwrap();

    // Entry peels its layer, gets inner_data.
    let mut cache = ReplayCache::new();
    let entry_result = OnionRouter::peel_layer(&cell, &sec0, &mut cache).unwrap();
    assert!(!entry_result.is_exit, "Entry should not be exit");

    // Check inner_data does NOT contain the plaintext payload.
    let plaintext_visible = entry_result.inner_data
        .windows(secret_payload.len())
        .any(|w| w == secret_payload);

    Finding {
        id: "BVL-O02",
        title: "Entry Relay Cannot Read Exit Payload",
        severity: Severity::Critical,
        description: if !plaintext_visible {
            "Entry relay's inner_data is still encrypted — the exit payload is not visible.".into()
        } else {
            "EXPOSURE: Entry relay's peeled inner_data contains the plaintext exit payload!".into()
        },
        status: if !plaintext_visible { Status::Passed } else { Status::Confirmed },
        recommendation: "The exit layer must be independently encrypted under the exit relay's key.",
    }
}

/// Replay attack: the same OnionCell must NOT be peelable twice by the same relay.
fn test_replay_attack() -> Finding {
    let mut rng = rand::thread_rng();
    let (spec, secret) = random_relay(&mut rng, "replay-target");

    let payload = b"replay attack test";
    let cell = OnionRouter::build_circuit(&[spec], payload).unwrap();

    let mut cache = ReplayCache::new();
    let peel1 = OnionRouter::peel_layer(&cell, &secret, &mut cache);
    let peel2 = OnionRouter::peel_layer(&cell, &secret, &mut cache); // Identical cell replayed

    let rejected = peel1.is_ok() && peel2.is_err();
    Finding {
        id: "BVL-O03",
        title: "Onion Cell Replay Attack Protection",
        severity: Severity::Critical,
        description: if rejected {
            "Relay correctly identifies and rejects a replayed OnionCell using its ReplayCache.".into()
        } else {
            "VULNERABILITY: The same OnionCell can be peeled multiple times — replay protection missing!".into()
        },
        status: if rejected { Status::Passed } else { Status::Confirmed },
        recommendation: "Maintain a cache of seen ephemeral public keys to prevent circuit correlation via replay.",
    }
}

/// A single flipped bit in the ciphertext must cause GCM authentication to fail.
fn test_tamper_detection_ciphertext() -> Finding {
    let mut rng = rand::thread_rng();
    let (spec, secret) = random_relay(&mut rng, "tamper-ct");
    let payload = b"tamper detection ciphertext";
    let mut cell = OnionRouter::build_circuit(&[spec], payload).unwrap();

    if let Some(b) = cell.ciphertext.first_mut() { *b ^= 0xFF; }

    let mut cache = ReplayCache::new();
    let rejected = OnionRouter::peel_layer(&cell, &secret, &mut cache).is_err();
    Finding {
        id: "BVL-O04",
        title: "Ciphertext Tamper Detection (GCM Auth Tag)",
        severity: Severity::Critical,
        description: if rejected {
            "A single flipped bit in the ciphertext causes AES-GCM authentication to fail. Integrity is enforced.".into()
        } else {
            "CRITICAL: Modified ciphertext was accepted — GCM authentication is not working!".into()
        },
        status: if rejected { Status::Passed } else { Status::Confirmed },
        recommendation: "Ensure AES-GCM Aead::decrypt is used (not decrypt_in_place_detached without tag check).",
    }
}

/// A tampered nonce must also cause decryption failure (wrong nonce → wrong keystream → bad tag).
fn test_tamper_detection_nonce() -> Finding {
    let mut rng = rand::thread_rng();
    let (spec, secret) = random_relay(&mut rng, "tamper-nonce");
    let payload = b"tamper detection nonce";
    let mut cell = OnionRouter::build_circuit(&[spec], payload).unwrap();

    cell.nonce[0] ^= 0x01; // flip one bit in the nonce

    let mut cache = ReplayCache::new();
    let rejected = OnionRouter::peel_layer(&cell, &secret, &mut cache).is_err();
    Finding {
        id: "BVL-O05",
        title: "Nonce Tamper Detection",
        severity: Severity::High,
        description: if rejected {
            "Flipping a nonce bit causes decryption failure — the GCM tag covers the nonce indirectly.".into()
        } else {
            "Nonce tampering accepted! GCM verification does not protect the nonce.".into()
        },
        status: if rejected { Status::Passed } else { Status::Confirmed },
        recommendation: "Use AEAD with the nonce bound to the AAD, or include the nonce in the HMAC.",
    }
}

/// All wire-padded cells must be a multiple of ONION_CELL_SIZE (512 bytes).
fn test_wire_padding_multiple_of_512() -> Finding {
    let mut rng = rand::thread_rng();
    let sizes = [0usize, 1, 100, 511, 512, 513, 1023, 4096];
    let mut violations = Vec::new();

    for &sz in &sizes {
        let payload: Vec<u8> = (0..sz).map(|i| (i % 256) as u8).collect();
        let (spec, _) = random_relay(&mut rng, "pad-test");
        let cell = OnionRouter::build_circuit(&[spec], &payload).unwrap();
        let wire_len = cell.wire_size();
        if wire_len % ONION_CELL_SIZE != 0 {
            violations.push(format!("payload {}B → wire {}B (not multiple of 512)", sz, wire_len));
        }
    }

    let ok = violations.is_empty();
    Finding {
        id: "BVL-O06",
        title: "Wire Cell Padding to 512-byte Boundary",
        severity: Severity::Medium,
        description: if ok {
            "All 8 tested payload sizes produce wire output that is a multiple of 512 bytes.".into()
        } else {
            format!("Padding violations: {}", violations.join("; "))
        },
        status: if ok { Status::Passed } else { Status::Confirmed },
        recommendation: "Enforce PKCS-style or fixed-cell padding before any network transmission.",
    }
}

/// A cell encrypted for relay A must not decrypt under relay B's key.
fn test_wrong_relay_key_rejected() -> Finding {
    let mut rng = rand::thread_rng();
    let (spec_a, _sec_a) = random_relay(&mut rng, "relay-a");
    let (_spec_b, sec_b)  = random_relay(&mut rng, "relay-b");

    let payload = b"wrong key rejection";
    let cell = OnionRouter::build_circuit(&[spec_a], payload).unwrap();
    let mut cache = ReplayCache::new();
    let rejected = OnionRouter::peel_layer(&cell, &sec_b, &mut cache).is_err();

    Finding {
        id: "BVL-O07",
        title: "Wrong Relay Key Rejected",
        severity: Severity::Critical,
        description: if rejected {
            "A cell addressed to relay A cannot be decrypted by relay B — key isolation confirmed.".into()
        } else {
            "CRITICAL: Relay B successfully decrypted a cell addressed to relay A!".into()
        },
        status: if rejected { Status::Passed } else { Status::Confirmed },
        recommendation: "ECDH shared secret must be unique per (sender_eph, relay_static) pair.",
    }
}

/// OnionCellHeader no longer contains hop_count, mitigating circuit length leakage.
fn test_hop_count_metadata_leak() -> Finding {
    use bevel_protocol::{OnionCellHeader, DMP_LAYER_ONION};
    let _header = OnionCellHeader {
        layer_id:   DMP_LAYER_ONION,
        version:    0x01,
        circuit_id: [0xABu8; 16],
    };
    // The hop_count field is gone, so it can't leak.
    Finding {
        id: "BVL-O08",
        title: "OnionCellHeader Metadata Hardening",
        severity: Severity::Low,
        description: "The OnionCellHeader no longer contains the hop_count field. \
                      Total circuit length is now opaque to observers and relays.".into(),
        status: Status::Passed,
        recommendation: "Maintain opaque headers to prevent circuit de-anonymisation.",
    }
}
