<p align="center">
  <img src="file:///C:/Users/Revanth/.gemini/antigravity/brain/1cd6e46d-3a3e-4c3b-8b9d-199ce20dc26f/bevel_protocol_logo_1776840465237.png" width="400" alt="Bevel Protocol Logo">
</p>

<h1 align="center">Bevel Protocol</h1>

<p align="center">
  <strong>A Secure, Decentralized, Onion-Routed Messaging Infrastructure</strong>
</p>

<p align="center">
  <a href="#architecture">Architecture</a> •
  <a href="#key-features">Key Features</a> •
  <a href="#crates">Crates</a> •
  <a href="#getting-started">Getting Started</a> •
  <a href="#security">Security</a>
</p>

---

## 🌐 Overview

Bevel Protocol is a high-performance, privacy-first decentralized messaging protocol built in Rust. It implements the **DecentraMail Protocol (DMP)** stack, designed to provide end-to-end encrypted, metadata-resistant communication over a peer-to-peer network.

By combining **Sphinx-inspired onion routing** with a modular **libp2p** core, Bevel ensures that not only is the content of your messages secure, but the very metadata of who is talking to whom remains shielded from network observers. Bevel is designed to be the foundational layer for the next generation of private, censorship-resistant communication applications.

## 🏗 Architecture (The DMP Stack)

Bevel is organized into a 6-layer protocol stack, ensuring clean separation of concerns and robust security at every level.

| Layer | Name | Description |
| :--- | :--- | :--- |
| **L6** | **Onion** | Sphinx-inspired multi-hop routing (AES-256-GCM + X25519). |
| **L5** | **Message** | Canonical message formatting (JSON/Bincode) and ID randomization. |
| **L4** | **Delivery** | HMAC-authenticated delivery receipts and status tracking. |
| **L3** | **Networking** | libp2p P2P core, Kademlia DHT, and Gossipsub. |
| **L2** | **Storage** | Persistent state management using the Sled embedded database. |
| **L1** | **Crypto** | Ed25519 signing, Argon2 hashing, and memory-safe key handling. |

## 🚀 Key Features

- **🛡 Metadata Resistance**: Onion-routed headers are stripped of identifying information at every hop, preventing traffic analysis.
- **🏷 Bevel Name Service (BNS)**: Decentralized DHT-based naming (e.g., `user@bevel.net`) with PoW-protected registration.
- **📁 Rich Media Sharing**: End-to-end encrypted sharing of files and entire folders with native manifest support and chunked P2P distribution.
- **🔍 Encrypted Local Search**: Instant keyword search over your entire encrypted message history without server-side assistance.
- **🔄 Multi-Device Sync**: P2P gossip protocol that keeps message history and contacts in sync across all your devices automatically.
- **� Social Recovery**: Identity backup using **Shamir's Secret Sharing (SSS)**. Split your recovery seed into shards to prevent total data loss.
- **🚫 Advanced Spam Defense**: Multi-layered protection using Proof-of-Work (PoW) nonces, trust scores, and decentralized reputation tracking.
- **📬 Store and Forward (SFP)**: Reliable offline messaging architecture with verifiable cryptographic manifests.
- **🧪 Built-in Auditing**: A dedicated audit suite for adversarial testing, cryptographic verification, and protocol hardening.

## 📦 Crates

The workspace is divided into specialized crates for maximum modularity:

- [**`bevel-crypto`**](file:///c:/Users/Revanth/Downloads/Bevel%20Protocol/crates/bevel-crypto): Core cryptographic primitives, Double Ratchet, X3DH, and Social Recovery (SSS).
- [**`bevel-protocol`**](file:///c:/Users/Revanth/Downloads/Bevel%20Protocol/crates/bevel-protocol): Common types, canonical serialization, and DMP header definitions.
- [**`bevel-onion`**](file:///c:/Users/Revanth/Downloads/Bevel%20Protocol/crates/bevel-onion): Layer 6 implementation, handling circuit building and layer peeling.
- [**`bevel-p2p`**](file:///c:/Users/Revanth/Downloads/Bevel%20Protocol/crates/bevel-p2p): libp2p integration, DHT discovery, and multi-device sync gossip.
- [**`bevel-storage`**](file:///c:/Users/Revanth/Downloads/Bevel%20Protocol/crates/bevel-storage): Persistent database layer using `Sled` with local encrypted search indexing.
- [**`bevel-media`**](file:///c:/Users/Revanth/Downloads/Bevel%20Protocol/crates/bevel-media): Media handling, file/folder chunking, and rich content encryption.
- [**`bevel-audit`**](file:///c:/Users/Revanth/Downloads/Bevel%20Protocol/crates/bevel-audit): Comprehensive security verification tools and adversarial simulation.
- [**`bevel-wasm`**](file:///c:/Users/Revanth/Downloads/Bevel%20Protocol/crates/bevel-wasm): WASM bindings for integrating Bevel into web and mobile environments.

## 🛠 Getting Started

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (latest stable)
- `cargo`

### Build

```bash
cargo build --release
```

### Run Tests

```bash
cargo test --workspace
```

### Security Audit

To run the comprehensive security audit suite (verified 33+ security checks):

```bash
cargo run -p bevel-audit
```

## 🔒 Security & Hardening

Bevel is designed with a "Zero Vulnerability" philosophy. Recent hardening measures include:
- **ID Randomization**: Prevention of traffic correlation through randomized message and circuit IDs.
- **Replay Protection**: Built-in caches to detect and drop replayed onion cells.
- **Memory Safety**: Use of `Zeroize` to ensure sensitive cryptographic keys are wiped from memory after use.
- **Cryptographic Signatures**: Protection against manifest tampering and DHT spoofing using Ed25519 signatures.
- **Reputation Tracking**: Local trust scores to prevent Sybil attacks and spam from unknown peers.
- **GPA Mitigation**: Cover traffic (chaff) and randomized cell delays to resist Global Passive Adversaries.

---

<p align="center">
  Developed by the Bevel Team. 2026.
</p>
