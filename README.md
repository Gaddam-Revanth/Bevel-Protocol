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

By combining **Sphinx-inspired onion routing** with a modular **libp2p** core, Bevel ensures that not only is the content of your messages secure, but the very metadata of who is talking to whom remains shielded from network observers.

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

- **🛡 Metadata Resistance**: Headers are stripped of identifying information until they reach the intended recipient or relay hop.
- **🏷 Bevel Name Service (BNS)**: Support for human-readable handles like `user@bevel.com` through a decentralized DHT-based naming system.
- **🧅 Advanced Onion Routing**: Support for up to 8 hops with ephemeral key exchange for every circuit.
- **⚡ Performance**: Built with `Tokio` for asynchronous I/O and `libp2p` for efficient networking.
- **💾 Durable Storage**: Local database for offline message queuing and identity management.
- **📬 Store and Forward Protocol (SFP)**: Reliable offline messaging architecture with verifiable cryptographic manifests.
- **🌐 Bootstrap Nodes**: Decentralized peer discovery via Kademlia DHT bootstrapping for reliable network entry.
- **🧪 Built-in Auditing**: A dedicated audit suite for adversarial testing and cryptographic verification.
- **🕸 WebAssembly Ready**: Bridge layers to run Bevel nodes directly in modern browsers.

## 📦 Crates

The workspace is divided into specialized crates:

- [**`bevel-crypto`**](file:///c:/Users/Revanth/Downloads/Bevel%20Protocol/crates/bevel-crypto): Core cryptographic primitives with `Zeroize` support for memory safety.
- [**`bevel-protocol`**](file:///c:/Users/Revanth/Downloads/Bevel%20Protocol/crates/bevel-protocol): Common types, canonical serialization, and DMP header definitions.
- [**`bevel-onion`**](file:///c:/Users/Revanth/Downloads/Bevel%20Protocol/crates/bevel-onion): Layer 6 implementation, handling circuit building and layer peeling.
- [**`bevel-p2p`**](file:///c:/Users/Revanth/Downloads/Bevel%20Protocol/crates/bevel-p2p): libp2p integration, including DHT discovery and relay logic.
- [**`bevel-storage`**](file:///c:/Users/Revanth/Downloads/Bevel%20Protocol/crates/bevel-storage): Persistent database layer using `Sled`.
- [**`bevel-audit`**](file:///c:/Users/Revanth/Downloads/Bevel%20Protocol/crates/bevel-audit): Security verification tools and adversarial simulation.
- [**`bevel-media`**](file:///c:/Users/Revanth/Downloads/Bevel%20Protocol/crates/bevel-media): Media handling and protocol extensions for rich content.
- [**`bevel-wasm`**](file:///c:/Users/Revanth/Downloads/Bevel%20Protocol/crates/bevel-wasm): WASM bindings for web client integration.

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

To run the comprehensive security audit suite:

```bash
cargo run -p bevel-audit
```

## 🔒 Security & Hardening

Bevel is designed with a "Zero Vulnerability" philosophy. Recent hardening measures include:
- **ID Randomization**: Prevention of traffic correlation through randomized message and circuit IDs.
- **Replay Protection**: Built-in caches to detect and drop replayed onion cells.
- **Memory Safety**: Use of `Zeroize` to ensure sensitive cryptographic keys are wiped from memory after use.
- **Cryptographic Signatures**: Protection against manifest tampering and DHT spoofing using Ed25519 signatures.
- **Adversarial Testing**: Continuous fuzzing of protocol headers and onion layers.

---

<p align="center">
  Developed by the Bevel Team. 2026.
</p>
