# Walrus Memory Rust SDK (`memwal`)

Official async Rust client SDK for **Walrus Memory** (`MemWal`), providing portable, privacy-preserving decentralized memory backed by Sui, SEAL threshold encryption, and Walrus blob storage.

## Key Capabilities

1. **Ergonomic Async Client**: `MemWal` wraps an `Arc` internally (`Clone + Send + Sync`) and reuses a single `reqwest` `rustls` connection pool across Tokio tasks.
2. **Automatic Cryptographic Auth**: Signs every relayer request with Ed25519 headers (`x-public-key`, `x-signature`, `x-timestamp`, `x-nonce`, `x-account-id`) and automatically mints, caches, and refreshes 5 minute `x-seal-session` envelopes after verifying Sui package version `1`.
3. **Flexible Key Formats**: Accepts 64 character hex seeds, `0x` prefixed hex seeds, Sui Bech32 `suiprivkey1...` Ed25519 strings, or raw 32 byte seeds (`MemWal::builder_from_seed_bytes`), zeroizing secret key material on drop or explicit `client.destroy()`.
4. **Resilient Write & Polling Lifecycle**: Supports fire and forget `remember` / `remember_bulk`, bounded exponential backoff polling (`remember_and_wait`, `remember_bulk_and_wait`), 30 minute bucketed or content hash idempotency keys, `HTTP 429` `Retry-After` handling, and automatic chunking of bulk status queries above 20 job IDs.
5. **Client-Side Recall Controls**: Supports `RecallParams` builder options for `limit`, `namespace`, `RecallSort` (`Relevance`, `Recent`), `ScoringWeights`, `max_distance`, and `max_tokens` context window budgeting (`HighRelevanceOnly`, `PerHitCap`, `DropTail`).
6. **Zero-Network Unit Testing**: Ships `MemWalMock`, an in-memory thread-safe test double mirroring the async `MemWal` API for fast deterministic unit tests.

## Installation

Add `memwal` and `tokio` to your `Cargo.toml`:

```toml
[dependencies]
memwal = "0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

While developing inside the Walrus Memory monorepo, reference the workspace path directly:

```toml
[dependencies]
memwal = { path = "packages/rust-sdk" }
```

## Environment Presets

| Preset | Enum Variant | Relayer Base URL | Intended Network |
| :--- | :--- | :--- | :--- |
| Production | `Env::Prod` | `https://relayer.memory.walrus.xyz` | Sui Mainnet (default) |
| Development | `Env::Dev` | `https://relayer.dev.memwal.ai` | Sui Testnet |
| Local | `Env::Local` | `http://127.0.0.1:8000` | Local Relayer |

Passing `.server_url(...)` on `MemWalBuilder` always takes precedence over `.env(...)`.

## Quick Start

```rust
use memwal::{Env, MemWal, RecallParams, RecallSort, TruncationStrategy};

#[tokio::main]
async fn main() -> memwal::Result<()> {
    let key = std::env::var("MEMWAL_PRIVATE_KEY").expect("MEMWAL_PRIVATE_KEY");
    let account_id = std::env::var("MEMWAL_ACCOUNT_ID").expect("MEMWAL_ACCOUNT_ID");

    let client = MemWal::builder(key, account_id)
        .env(Env::Dev)
        .namespace("agent-notes")
        .build()?;

    let stored = client
        .remember_and_wait("User prefers concise Rust error types and rustls.")
        .await?;
    println!("Stored blob_id={}", stored.blob_id);

    let recalled = client
        .recall(
            RecallParams::new("Rust preferences")
                .with_limit(5)
                .with_sort(RecallSort::Relevance)
                .with_max_tokens(512)
                .with_truncation_strategy(TruncationStrategy::HighRelevanceOnly),
        )
        .await?;

    for hit in &recalled.results {
        println!("[distance={:.3}] {}", hit.distance, hit.text);
    }

    client.destroy();
    Ok(())
}
```

## Core Methods

| Category | Methods | Description |
| :--- | :--- | :--- |
| Construction & Lifecycle | `MemWal::new`, `MemWal::builder`, `MemWal::builder_from_seed_bytes`, `destroy`, `is_destroyed` | Configure credentials, timeouts, and zeroize secret state when finished. |
| Write & Job Polling | `remember`, `remember_with`, `remember_status`, `wait_for_remember_job`, `remember_and_wait`, `remember_and_wait_with` | Enqueue encrypted memories and optionally poll background jobs until indexed. |
| Bulk Writes | `remember_bulk`, `remember_bulk_with`, `remember_bulk_status`, `wait_for_remember_jobs`, `remember_bulk_and_wait` | Persist batches of up to 20 memories per write and settle per-item statuses. |
| Search & AI | `recall`, `embed`, `analyze`, `analyze_and_wait`, `ask` | Run semantic vector search, generate embeddings, extract facts, and synthesize grounded answers. |
| Namespace & Inventory | `forget`, `restore`, `list_namespaces`, `list_memories`, `whoami` | Reset or rebuild vector indexes from Walrus blobs and paginate owner inventory. |
| Manual Mode | `remember_manual`, `recall_manual` | Upload pre-encrypted SEAL ciphertext and pre-computed vectors without `x-seal-session`. |
| Diagnostics | `health`, `compatibility` | Inspect relayer health and API version compatibility metadata. |

## Testing With `MemWalMock`

```rust
use memwal::MemWalMock;

#[tokio::test]
async fn agent_recalls_saved_preference() -> memwal::Result<()> {
    let mock = MemWalMock::new();
    mock.remember_and_wait("Deploy target is Fly.io in sin region.").await?;

    let hits = mock.recall("Where do we deploy?").await?;
    assert_eq!(hits.results.len(), 1);
    Ok(())
}
```

## Verification Commands

Run formatting, pedantic lint checks, documentation checks, and integration tests from `packages/rust-sdk`:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo test --all-targets
cargo test --doc
```
