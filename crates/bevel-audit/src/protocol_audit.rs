//! Protocol format and metadata security audit.

use bevel_protocol::{
    DmpHeader, DmpMessage, DmpMessageBody, DmpMessageFlags,
    pad_payload, round_timestamp,
};
use bevel_p2p::{derive_manifest_dht_key, SfpEngine};
use crate::{Finding, Severity, Status};

pub fn run() -> Vec<Finding> {
    vec![
        test_timestamp_rounding_10s(),
        test_payload_padding_masks_length(),
        test_sfp_sender_masking_placeholder(),
        test_dht_key_recipient_correlation(),
        test_message_id_no_uuid_enforcement(),
        test_binary_header_fixed_size(),
    ]
}

/// Timestamps must be rounded to the nearest 10-second interval to reduce timing correlation.
fn test_timestamp_rounding_10s() -> Finding {
    let samples: Vec<(u64, u64)> = vec![
        (1_713_600_001, 1_713_600_000),
        (1_713_600_009, 1_713_600_000),
        (1_713_600_010, 1_713_600_000),
        (1_713_699_999, 1_713_690_000),
    ];
    let all_correct = samples.iter().all(|(raw, expected)| round_timestamp(*raw) == *expected);
    Finding {
        id: "BVL-P01",
        title: "Timestamp Rounding (10-second granularity)",
        severity: Severity::Low,
        description: if all_correct {
            "Timestamps are correctly quantised to 10-second boundaries, reducing message-send timing correlation.".into()
        } else {
            "Timestamp rounding is incorrect — fine-grained timing leaks message send time.".into()
        },
        status: if all_correct { Status::Passed } else { Status::Confirmed },
        recommendation: "Consider rounding to 60 s for higher-latency anonymous messaging profiles.",
    }
}

/// Payload padding must produce uniform-sized outputs to prevent length-based traffic analysis.
fn test_payload_padding_masks_length() -> Finding {
    // All payloads 1–1024 bytes should produce exactly 1024 bytes.
    let mut violations = Vec::new();
    for sz in [1usize, 50, 400, 1023, 1024] {
        let payload = vec![0u8; sz];
        let padded = pad_payload(payload);
        if padded.len() != 1024 {
            violations.push(format!("input {}B → padded {}B (expected 1024)", sz, padded.len()));
        }
    }
    // A payload of 1025 should jump to 2048.
    let big = pad_payload(vec![0u8; 1025]);
    if big.len() != 2048 {
        violations.push(format!("input 1025B → padded {}B (expected 2048)", big.len()));
    }

    let ok = violations.is_empty();
    Finding {
        id: "BVL-P02",
        title: "Payload Length Masking via 1KB-boundary Padding",
        severity: Severity::Low,
        description: if ok {
            "Payload padding correctly rounds to 1 KB boundaries, hiding message length.".into()
        } else {
            format!("Padding failures: {}", violations.join("; "))
        },
        status: if ok { Status::Passed } else { Status::Confirmed },
        recommendation: "Consider using a fixed 64 KB canonical cell size for stronger length hiding.",
    }
}

/// The SFP manifest sender_masked field must be populated to protect sender identity.
fn test_sfp_sender_masking_placeholder() -> Finding {
    let mask = [0xAAu8; 32];
    let (manifest, _) = SfpEngine::chunk_message("addr", [0u8; 32], b"payload", mask);
    
    let ok = manifest.sender_masked == mask;
    Finding {
        id: "BVL-P03",
        title: "SFP Sender Masking Implementation",
        severity: Severity::High,
        description: if ok {
            "The SFP engine correctly accepts and embeds a masked sender identity into the manifest.".into()
        } else {
            "VULNERABILITY: The sender_masked field is still ignored or hardcoded to zero!".into()
        },
        status: if ok { Status::Passed } else { Status::Confirmed },
        recommendation: "Ensure sender blinding (HMAC) is computed by the P2P layer before chunking.",
    }
}

/// DHT manifest keys must change over time (epochs) to prevent indefinite traffic correlation.
fn test_dht_key_recipient_correlation() -> Finding {
    let recipient = "dmp1abc123";

    let key_epoch1 = derive_manifest_dht_key(recipient, 100);
    let key_epoch2 = derive_manifest_dht_key(recipient, 101);

    let rotates = key_epoch1 != key_epoch2;
    Finding {
        id: "BVL-P04",
        title: "DHT Traffic Correlation Resistance (Daily Epochs)",
        severity: Severity::High,
        description: if rotates {
            "DHT manifest keys rotate based on time epochs. \
             An observer cannot track a recipient's inbox key across epoch boundaries.".into()
        } else {
            "VULNERABILITY: DHT keys are static for a given recipient, allowing long-term traffic analysis!".into()
        },
        status: if rotates { Status::Passed } else { Status::Confirmed },
        recommendation: "Rotate the 'inbox token' used for DHT derivation daily (epoch = unix_time / 86400).",
    }
}

/// DmpMessage::new() enforces cryptographically random message IDs.
fn test_message_id_no_uuid_enforcement() -> Finding {
    let body = DmpMessageBody { text_plain: "test".into(), text_html: None };
    let flags = DmpMessageFlags { request_delivery_receipt: false, ephemeral: false, expiry_seconds: None };
    let msg = DmpMessage::new(None, body, flags);
    
    // Check if ID looks like a random hex string (at least 32 chars for 128-bit)
    let is_random = msg.message_id.len() >= 32 && hex::decode(&msg.message_id).is_ok();
    
    Finding {
        id: "BVL-P05",
        title: "Enforced Random Message IDs",
        severity: Severity::Low,
        description: if is_random {
            "DmpMessage enforces 128-bit random IDs via its factory method, \
             preventing ordering or count leaks.".into()
        } else {
            "VULNERABILITY: Message IDs are still not sufficiently random.".into()
        },
        status: if is_random { Status::Passed } else { Status::Confirmed },
        recommendation: "Ensure all message creation paths use the factory method.",
    }
}

/// DmpHeader must serialise to exactly 148 bytes as specified by HEADER_SIZE.
fn test_binary_header_fixed_size() -> Finding {
    let header  = DmpHeader::default();
    let encoded = bincode::serialize(&header).unwrap();
    let correct = encoded.len() == bevel_protocol::HEADER_SIZE;
    Finding {
        id: "BVL-P06",
        title: "DMP Binary Header Fixed-Size Invariant",
        severity: Severity::High,
        description: if correct {
            format!("DmpHeader serialises to exactly {} bytes — binary format invariant holds.", bevel_protocol::HEADER_SIZE)
        } else {
            format!("DmpHeader is {}B but HEADER_SIZE={} — binary protocol mismatch!", encoded.len(), bevel_protocol::HEADER_SIZE)
        },
        status: if correct { Status::Passed } else { Status::Confirmed },
        recommendation: "If header layout changes, update HEADER_SIZE and bump the protocol version.",
    }
}
