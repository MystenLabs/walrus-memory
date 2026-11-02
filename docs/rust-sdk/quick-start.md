---
title: "Quick Start"
description: "Install the Walrus Memory Rust SDK and store, recall, and test portable agent memories with async Tokio and Ed25519 authentication."
keywords: ["Walrus Memory", "MemWal", "Rust SDK", "quick start", "Tokio", "Ed25519", "SEAL"]
goal:
  description: "Add the memwal crate to Cargo.toml, build an authenticated MemWal client, persist a memory with remember_and_wait, and retrieve it with recall."
  requires:
    - has_frontmatter: ["title", "description", "keywords"]
      label: "Has required frontmatter fields"
    - min_words: 300
      label: "Needs more content depth"
    - has_questions: true
      label: "Needs questions for AI search visibility"
    - has_answer: true
      label: "Needs answer summary for AI citation"
questions:
  - "How do I install and configure the Walrus Memory Rust SDK?"
  - "How do I store and recall encrypted memories in Rust with MemWal?"
  - "How do I unit test Rust agents without live network calls using MemWalMock?"
answer: "Add memwal and tokio to Cargo.toml, construct a client with MemWal::builder(key, account_id).env(Env::Dev).build()?, call remember_and_wait() to store an encrypted memory on Walrus, and call recall() to retrieve matching memories."
---

The Walrus Memory Rust SDK (`memwal`) provides an idiomatic, async Tokio client for storing, recalling, and managing encrypted agent memories on Walrus and Sui. It speaks the exact same relayer protocol, Ed25519 request signing scheme, and 5 minute `x-seal-session` flow as the TypeScript and Python SDKs while keeping `unsafe` code forbidden and zeroizing secret key bytes in memory.

| Entry Point | Path | When to Use |
| :--- | :--- | :--- |
| `MemWal` | `use memwal::MemWal;` | Recommended default for async Rust services, CLI tools, and AI agent runtimes. |
| `MemWalBuilder` | `MemWal::builder(key, account_id)` | Custom environment presets, explicit `server_url`, default namespace, or custom timeouts. |
| `MemWalMock` | `use memwal::MemWalMock;` | Deterministic in-memory test double for fast unit tests with zero network or Sui RPC calls. |

## Prerequisites and Installation

The crate targets Rust `1.88` or newer (Edition 2024) and uses `rustls` by default so cross-compilation requires no system OpenSSL headers.

Add `memwal` and `tokio` to your `Cargo.toml`:

```toml
[dependencies]
memwal = "0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Before running against a hosted relayer, create a Walrus Memory account and delegate private key in the web console:

1. **Production (Sui Mainnet)**: `https://memory.walrus.xyz` paired with `Env::Prod`.
2. **Development (Sui Testnet)**: `https://dev.memwal.ai` paired with `Env::Dev`.

## Configuration and Environment Presets

`MemWal` accepts delegate private keys in 64 character hex, `0x` prefixed hex, Sui Bech32 (`suiprivkey1...`), or raw 32 byte seeds via `MemWal::builder_from_seed_bytes`. Both `MemWal` and `MemWalBuilder` redact key material in `Debug` output.

| Builder Method | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `MemWal::builder(key, account_id)` | `(impl Into<String>, impl Into<String>)` | Required | Initializes the builder with your Ed25519 delegate key and Sui `MemWalAccount` ID. |
| `.env(preset)` | `Env` | `Env::Prod` | Selects `Env::Prod` (`https://relayer.memory.walrus.xyz`), `Env::Dev` (`https://relayer.dev.memwal.ai`), or `Env::Local` (`http://127.0.0.1:8000`). |
| `.server_url(url)` | `impl Into<String>` | Preset URL | Explicit relayer URL (`http` or `https`). Always overrides `.env(...)`. |
| `.namespace(ns)` | `impl Into<String>` | `"default"` | Default namespace (`1` to `64` ASCII bytes) for memory isolation. |
| `.request_timeout(dur)` | `Duration` | `30s` | Per-request HTTP timeout for standard operations. |
| `.recall_timeout(dur)` | `Duration` | `15s` | Default timeout and server `deadline_ms` hint for `recall`. |

## Store and Recall Your First Memory

`remember` returns immediately once the relayer enqueues the background job (`RememberAccepted`), whereas `remember_and_wait` polls with bounded exponential backoff until SEAL encryption, Walrus upload, and vector indexing settle (`RememberResult`).

```rust
use memwal::{Env, MemWal, RecallParams, RecallSort, TruncationStrategy};

#[tokio::main]
async fn main() -> memwal::Result<()> {
    let key = std::env::var("MEMWAL_PRIVATE_KEY").expect("set MEMWAL_PRIVATE_KEY");
    let account_id = std::env::var("MEMWAL_ACCOUNT_ID").expect("set MEMWAL_ACCOUNT_ID");

    let client = MemWal::builder(key, account_id)
        .env(Env::Dev)
        .namespace("quickstart")
        .build()?;

    let health = client.health().await?;
    println!("Relayer status={} version={}", health.status, health.version);

    let saved = client
        .remember_and_wait("User prefers dark mode and keyboard-driven navigation.")
        .await?;
    println!("Persisted memory id={} blob_id={}", saved.id, saved.blob_id);

    let recall = client
        .recall(
            RecallParams::new("UI preferences")
                .with_limit(5)
                .with_sort(RecallSort::Relevance)
                .with_max_tokens(400)
                .with_truncation_strategy(TruncationStrategy::HighRelevanceOnly),
        )
        .await?;

    for item in &recall.results {
        println!("[distance={:.3}] {}", item.distance, item.text);
    }

    client.destroy();
    Ok(())
}
```

## Sharing Across Tasks and Deterministic Teardown

`MemWal` wraps its connection pool, caches, and zeroizing signer inside an `Arc`. Clone `MemWal` freely across Tokio tasks instead of constructing a new client per request so every task shares the cached `/version` compatibility preflight and 5 minute `x-seal-session` header.

Calling `client.destroy()` synchronously zeroes the Ed25519 signing seed, clears cached session headers, and causes any subsequent call on the client or its clones to fail immediately with `Error::Destroyed`.

## Offline Unit Testing With `MemWalMock`

Use `MemWalMock` in unit tests to verify prompt assembly, namespace isolation, deduplication, and token budgeting without network sockets or testnet credentials:

```rust
use memwal::{DedupeMode, MemWalMock, RememberOptions, RememberWaitOptions};

#[tokio::test]
async fn deduplicates_repeated_agent_facts() -> memwal::Result<()> {
    let mock = MemWalMock::with_namespace("session-42")?;
    let opts = RememberWaitOptions::new()
        .with_remember(RememberOptions::new().with_dedupe(DedupeMode::ContentHash));

    let first = mock.remember_and_wait_with("Primary DB is PostgreSQL 17", &opts).await?;
    let second = mock.remember_and_wait_with("Primary DB is PostgreSQL 17", &opts).await?;
    assert_eq!(first.blob_id, second.blob_id);

    let recalled = mock.recall("Which database version is primary?").await?;
    assert_eq!(recalled.results.len(), 1);
    Ok(())
}
```
