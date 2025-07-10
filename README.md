🔐 Decentralized KYC/AML Verification Network

A privacy-preserving, reusable KYC & AML identity verification system built using Rust, Substrate, and Tokio. This system enables users to complete their KYC once and reuse cryptographically verified credentials across platforms without repeating the process.

---

## 🧠 Overview

This project solves the redundancy and cost of repeated KYC/AML checks by:
- Verifying identity once through trusted verifiers (banks, regulators)
- Storing signed attestations on-chain using Substrate
- Providing reusable KYC tokens for external systems to trust
- Ensuring privacy and auditability

---

## ⚙️ Architecture

- **Rust**: Core language for performance and safety
- **Substrate**: Blockchain layer to store encrypted KYC attestations
- **Tokio**: Async runtime for high-performance APIs
- **Serde**: For serializing data
- **UUID + Hashing**: For secure transaction references

---

## 📁 Project Structure

```

kyc\_aml\_verification/
├── src/
│   ├── main.rs              # App entry point
│   ├── storage.rs           # Key-value store with blockchain logic
│   ├── api.rs               # Document submission & verification endpoints
│   ├── model.rs             # Shared types and data structures
│   ├── substrate.rs         # Optional: interface with Substrate node
│   └── crypto.rs            # (Optional) cryptographic helper functions
├── Cargo.toml
└── README.md

````

---

## 🔄 KYC Workflow

1. **User Submits Documents** to API
2. **Verifier Reviews & Confirms** asynchronously
3. **Blockchain Entry is Created** (block height + transaction hash)
4. **Token is Issued** for the verified user
5. **Token is Shared** across platforms for reuse

---

## 📦 Example API (Pluggable)

| Endpoint               | Method | Description                          |
|------------------------|--------|--------------------------------------|
| `/kyc/submit`          | POST   | Submit KYC documents                 |
| `/kyc/verify/:id`      | POST   | Confirm verification from verifier   |
| `/kyc/token/:user_id`  | GET    | Retrieve reusable verification token |

---

## 🔧 How to Run

### ✅ Prerequisites

- Rust (Install from https://rustup.rs)
- Substrate dev environment (optional for chain integration)

### 🛠 Build & Run

```bash
# Clone and enter project
git clone https://github.com/isakkhar/kyc-aml-verification.git
cd kyc-aml-verification

# Build
cargo build

# Run
cargo run

# Test
cargo test
````

---

## 🚀 Features

* ✅ One-time KYC → Multi-platform Reuse
* 🔒 Privacy-focused & audit-ready design
* ⚡ Fast async verification using Tokio
* ⛓️ Immutable ledger-backed proofs (via Substrate)
* 📎 Key-value query support by block, key, or prefix

---

## 📘 Sample Code

```rust
let storage = BlockchainStorage::new();

let entry = storage.store(
    "user:alice".to_string(),
    json!({"name": "Alice", "passport": "..."}),
).await?;

let token = storage.get("user:alice").await?;
```

---

## 📜 License

MIT License
See [LICENSE](./LICENSE) for more information.


