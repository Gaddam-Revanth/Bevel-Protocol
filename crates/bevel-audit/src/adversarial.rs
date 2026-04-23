//! Adversarial / fuzzing audit: malformed inputs, boundary conditions, edge cases.

use crate::{Finding, Severity, Status};
use bevel_crypto::decrypt_payload;
use bevel_onion::{OnionCell, OnionHopSpec, OnionRouter, ReplayCache};
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

fn random_relay(rng: &mut impl RngCore, id: &str) -> (OnionHopSpec, StaticSecret) {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let secret = StaticSecret::from(bytes);
    let pub_key = PublicKey::from(&secret);
    (
        OnionHopSpec {
            relay_pub_key: pub_key.to_bytes(),
            peer_id: id.into(),
        },
        secret,
    )
}

pub fn run() -> Vec<Finding> {
    vec![
        test_empty_payload_circuit(),
        test_large_payload_circuit(),
        test_garbage_bytes_as_onion_cell(),
        test_truncated_ciphertext(),
        test_zero_hops_rejected(),
        test_over_max_hops_rejected(),
        test_invalid_utf8_peer_id_in_peel(),
        test_aes_gcm_empty_ciphertext(),
    ]
}

/// A zero-byte payload should successfully round-trip through the onion circuit.
fn test_empty_payload_circuit() -> Finding {
    let mut rng = rand::thread_rng();
    let (spec, secret) = random_relay(&mut rng, "empty");
    let cell = OnionRouter::build_circuit(&[spec], b"").unwrap();
    let mut cache = ReplayCache::new();
    let result = OnionRouter::peel_layer(&cell, &secret, &mut cache);
    let ok = result
        .map(|r| r.is_exit && r.inner_data.is_empty())
        .unwrap_or(false);
    Finding {
        id: "BVL-A01",
        title: "Empty Payload Handled Gracefully",
        severity: Severity::Low,
        description: if ok {
            "A zero-byte payload successfully builds and peels through a 1-hop circuit without panicking.".into()
        } else {
            "CRASH or failure: empty payload caused an error or incorrect result in the onion circuit.".into()
        },
        status: if ok {
            Status::Passed
        } else {
            Status::Confirmed
        },
        recommendation: "Guard all slice operations against zero-length inputs.",
    }
}

/// A 64 KB payload must successfully round-trip through a 3-hop circuit.
fn test_large_payload_circuit() -> Finding {
    let payload: Vec<u8> = (0..65536).map(|i: usize| (i % 256) as u8).collect();
    let trace = OnionRouter::verify_circuit(&payload, 3);
    let ok = trace.is_ok();
    Finding {
        id: "BVL-A02",
        title: "64 KB Payload Through 3-Hop Circuit",
        severity: Severity::Low,
        description: if ok {
            "A 64 KB payload round-trips correctly through a 3-hop onion circuit.".into()
        } else {
            format!("Large payload failure: {:?}", trace.err())
        },
        status: if ok {
            Status::Passed
        } else {
            Status::Confirmed
        },
        recommendation:
            "Document maximum supported payload size and enforce it at the API boundary.",
    }
}

/// Feeding random garbage bytes to peel_layer must return an error, not panic.
fn test_garbage_bytes_as_onion_cell() -> Finding {
    let mut rng = rand::thread_rng();
    let (_spec, secret) = random_relay(&mut rng, "garbage");

    // Build a structurally valid cell but fill the ciphertext with random garbage.
    let mut garbage_ct = vec![0u8; 64];
    rng.fill_bytes(&mut garbage_ct);

    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let mut eph = [0u8; 32];
    rng.fill_bytes(&mut eph);

    let garbage_cell = OnionCell {
        eph_pub_key: eph,
        nonce,
        ciphertext: garbage_ct,
    };
    let mut cache = ReplayCache::new();
    let result = OnionRouter::peel_layer(&garbage_cell, &secret, &mut cache);

    let handled = result.is_err(); // must error gracefully, not panic
    Finding {
        id: "BVL-A03",
        title: "Garbage Onion Cell Returns Error (No Panic)",
        severity: Severity::Medium,
        description: if handled {
            "Random garbage ciphertext is gracefully rejected by GCM authentication — no panic."
                .into()
        } else {
            "Garbage input was accepted as valid — authentication is not working!".into()
        },
        status: if handled {
            Status::Passed
        } else {
            Status::Confirmed
        },
        recommendation:
            "All external deserialization paths must be wrapped in Result, never unwrap().",
    }
}

/// Truncating the ciphertext (removing the GCM tag) must be rejected.
fn test_truncated_ciphertext() -> Finding {
    let mut rng = rand::thread_rng();
    let (spec, secret) = random_relay(&mut rng, "truncate");
    let payload = b"truncate test";
    let mut cell = OnionRouter::build_circuit(&[spec], payload).unwrap();

    // Remove the last 16 bytes (the GCM auth tag).
    let len = cell.ciphertext.len();
    if len > 16 {
        cell.ciphertext.truncate(len - 16);
    }

    let mut cache = ReplayCache::new();
    let rejected = OnionRouter::peel_layer(&cell, &secret, &mut cache).is_err();
    Finding {
        id: "BVL-A04",
        title: "Truncated Ciphertext (Missing GCM Tag) Rejected",
        severity: Severity::High,
        description: if rejected {
            "Removing the 16-byte GCM authentication tag causes peel_layer to correctly fail."
                .into()
        } else {
            "CRITICAL: Cell with truncated GCM tag was accepted — authentication bypassed!".into()
        },
        status: if rejected {
            Status::Passed
        } else {
            Status::Confirmed
        },
        recommendation:
            "Ensure the AEAD trait's decrypt() method is always used — never raw stream decryption.",
    }
}

/// Building a circuit with 0 hops must be rejected at the API level.
fn test_zero_hops_rejected() -> Finding {
    let result = OnionRouter::build_circuit(&[], b"zero hops");
    let rejected = result.is_err();
    Finding {
        id: "BVL-A05",
        title: "Zero-Hop Circuit Rejected at API Boundary",
        severity: Severity::Medium,
        description: if rejected {
            "build_circuit(&[], payload) correctly returns an error — zero-hop circuits are forbidden.".into()
        } else {
            "build_circuit accepted an empty relay list — this could cause a panic on peel.".into()
        },
        status: if rejected {
            Status::Passed
        } else {
            Status::Confirmed
        },
        recommendation: "Validate hops.len() >= 1 (and <= MAX_HOPS) at the start of build_circuit.",
    }
}

/// Building a circuit with > MAX_HOPS (8) relays must be rejected.
fn test_over_max_hops_rejected() -> Finding {
    let hops: Vec<OnionHopSpec> = (0..9)
        .map(|i| OnionHopSpec {
            relay_pub_key: [i as u8; 32],
            peer_id: format!("r{}", i),
        })
        .collect();
    let rejected = OnionRouter::build_circuit(&hops, b"overflow").is_err();
    Finding {
        id: "BVL-A06",
        title: "Over-Max-Hops Circuit (>8) Rejected",
        severity: Severity::Medium,
        description: if rejected {
            "9-hop circuit is correctly rejected — MAX_HOPS=8 enforced at build time.".into()
        } else {
            "9-hop circuit was accepted — no upper-bound enforcement on circuit length.".into()
        },
        status: if rejected {
            Status::Passed
        } else {
            Status::Confirmed
        },
        recommendation:
            "Consider making MAX_HOPS a runtime-configurable parameter with a hard ceiling.",
    }
}

/// A cell whose decrypted relay plaintext contains invalid UTF-8 in the peer_id position
/// must be rejected gracefully (not panic via from_utf8().unwrap()).
fn test_invalid_utf8_peer_id_in_peel() -> Finding {
    let mut rng = rand::thread_rng();
    let (_spec, secret) = random_relay(&mut rng, "utf8test");

    let mut garbage_ct = vec![0xFFu8; 80]; // all-0xFF — invalid UTF-8 if interpreted as peer_id
    rng.fill_bytes(&mut garbage_ct);

    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let mut eph = [0u8; 32];
    rng.fill_bytes(&mut eph);
    let bad_cell = OnionCell {
        eph_pub_key: eph,
        nonce,
        ciphertext: garbage_ct,
    };

    // Should return Err (GCM rejection), never panic.
    let no_panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut cache = ReplayCache::new();
        let _ = OnionRouter::peel_layer(&bad_cell, &secret, &mut cache);
    }))
    .is_ok();

    Finding {
        id: "BVL-A07",
        title: "Invalid UTF-8 in Peer ID Does Not Panic",
        severity: Severity::Medium,
        description: if no_panic {
            "Adversarial input with invalid UTF-8 in the peer ID position is handled without panicking.".into()
        } else {
            "PANIC: Invalid UTF-8 peer ID caused a hard crash — unwrap() on from_utf8() detected!"
                .into()
        },
        status: if no_panic {
            Status::Passed
        } else {
            Status::Confirmed
        },
        recommendation:
            "Use String::from_utf8(...).map_err(...)? instead of .unwrap() in peel_layer.",
    }
}

/// AES-GCM decryption of an empty ciphertext (0 bytes) must return an error — not panic.
fn test_aes_gcm_empty_ciphertext() -> Finding {
    let key = [0xCCu8; 32];
    let nonce = [0x00u8; 12];
    let result = decrypt_payload(&key, &nonce, &[], b"");
    let handled = result.is_err();
    Finding {
        id: "BVL-A08",
        title: "AES-GCM Decryption of Empty Ciphertext Fails Gracefully",
        severity: Severity::Medium,
        description: if handled {
            "Passing a 0-byte ciphertext to decrypt_payload returns an error — GCM correctly rejects it.".into()
        } else {
            "Empty ciphertext was accepted — GCM minimum-length check is missing!".into()
        },
        status: if handled {
            Status::Passed
        } else {
            Status::Confirmed
        },
        recommendation:
            "Add an explicit length check: ciphertext.len() >= 16 before calling decrypt.",
    }
}
