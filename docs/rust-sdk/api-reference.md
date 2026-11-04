---
title: "API Reference"
description: "Complete type, builder, method, error, cryptographic helper, and mock reference for the Walrus Memory Rust SDK (memwal)."
keywords: ["Walrus Memory", "MemWal", "Rust SDK", "API reference", "MemWalBuilder", "RecallParams", "Error"]
goal:
  description: "Look up exact Rust signatures, option builders, response structs, error variants, and cryptographic utilities in the memwal crate."
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
  - "What methods and types are exported by the memwal Rust crate?"
  - "How does error handling and transient retry classification work in the MemWal Rust SDK?"
  - "How do RecallParams, ScoringWeights, and TruncationStrategy control recall results?"
answer: "The memwal crate exports MemWal, MemWalBuilder, MemWalMock, typed request builders (RecallParams, RememberOptions, WaitOptions, AskOptions, AnalyzeOptions), #[non_exhaustive] response structs, a structured Error enum with is_transient() and retry_after(), and Sui Ed25519 key derivation utilities."
---

Related references:

1. [Quick Start](/rust-sdk/quick-start)
2. [Configuration](/reference/configuration)
3. [Relayer API](/relayer/api-reference)

## Client Construction (`MemWal` & `MemWalBuilder`)

```rust
impl MemWal {
    pub fn new(key: impl Into<String>, account_id: impl Into<String>) -> Result<Self>;
    pub fn builder(key: impl Into<String>, account_id: impl Into<String>) -> MemWalBuilder;
    pub fn builder_from_seed_bytes(seed: &[u8], account_id: impl Into<String>) -> MemWalBuilder;

    pub fn server_url(&self) -> &str;
    pub fn namespace(&self) -> &str;
    pub fn account_id(&self) -> &str;
    pub fn public_key_hex(&self) -> Result<String>;
    pub fn sui_address(&self) -> Result<String>;
    pub fn count_tokens(&self, text: &str) -> usize;
    pub fn is_destroyed(&self) -> bool;
    pub fn destroy(&self);
}
```

`MemWalBuilder` configures optional client settings before `.build()` validates the key, account ID, namespace, and URL scheme:

```rust
impl MemWalBuilder {
    pub fn env(&mut self, env: Env) -> &mut Self;
    pub fn server_url(&mut self, url: impl Into<String>) -> &mut Self;
    pub fn namespace(&mut self, namespace: impl Into<String>) -> &mut Self;
    pub fn request_timeout(&mut self, timeout: Duration) -> &mut Self;
    pub fn recall_timeout(&mut self, timeout: Duration) -> &mut Self;
    pub fn preflight_timeout(&mut self, timeout: Duration) -> &mut Self;
    pub fn http_client(&mut self, client: reqwest::Client) -> &mut Self;
    pub fn build(&self) -> Result<MemWal>;
}
```

## Write and Job Polling Methods

### `remember` and `remember_with`

```rust
pub async fn remember(&self, text: &str) -> Result<RememberAccepted>;
pub async fn remember_with(&self, text: &str, opts: &RememberOptions) -> Result<RememberAccepted>;
```

Submits one memory to the relayer queue and returns `RememberAccepted { job_id, status }` immediately. `RememberOptions` configures an optional `.with_namespace(...)`, `.with_idempotency_key(...)`, or `.with_dedupe(DedupeMode::ContentHash)`. When `idempotency_key` is omitted, the SDK derives a deterministic 30 minute bucketed key (or `dedupe:<sha256>` when `DedupeMode::ContentHash` is active) and reuses it across transient retries of the same payload.

### `remember_and_wait` and `remember_and_wait_with`

```rust
pub async fn remember_and_wait(&self, text: &str) -> Result<RememberResult>;
pub async fn remember_and_wait_with(&self, text: &str, opts: &RememberWaitOptions) -> Result<RememberResult>;
pub async fn remember_status(&self, job_id: &str) -> Result<RememberJobStatus>;
pub async fn wait_for_remember_job(&self, job_id: &str, opts: &WaitOptions) -> Result<RememberResult>;
```

`remember_status` executes a single status read without `x-seal-session` and resolves unknown or malformed IDs to `status == "not_found"` without returning an error. `wait_for_remember_job` polls with bounded `1.5x` exponential backoff plus jitter (`WaitOptions::default()` uses `1500ms` base interval and `60s` timeout) and honors `HTTP 429` `Retry-After` headers.

### Bulk Remember Methods

```rust
pub async fn remember_bulk(&self, items: &[RememberBulkItem]) -> Result<RememberBulkAccepted>;
pub async fn remember_bulk_with(&self, items: &[RememberBulkItem], opts: &RememberBulkOptions) -> Result<RememberBulkAccepted>;
pub async fn remember_bulk_status(&self, job_ids: &[String]) -> Result<RememberBulkStatusResult>;
pub async fn wait_for_remember_jobs(&self, job_ids: &[String], namespaces: &[String], opts: &WaitOptions) -> Result<RememberBulkResult>;
pub async fn remember_bulk_and_wait(&self, items: &[RememberBulkItem], opts: &RememberBulkOptions) -> Result<RememberBulkResult>;
```

`remember_bulk` validates `1..=MAX_BULK_ITEMS` (`20`) non-blank items before signing. `remember_bulk_status` automatically splits slices larger than `20` job IDs into sequential chunks of `20` and preserves input order. `wait_for_remember_jobs` settles per-item `"done"`, `"failed"`, and `"timeout"` entries in `RememberBulkResult` and runs a final confirmation read if every poll timed out unanswered.

## Recall, Search, and AI Methods

### `recall`

```rust
pub async fn recall(&self, params: impl Into<RecallParams>) -> Result<RecallResult>;
```

Accepts `&str`, `String`, or `RecallParams` via `Into<RecallParams>`:

```rust
let result = client
    .recall(
        RecallParams::new("deployment runbook")
            .with_limit(10)
            .with_namespace("ops")
            .with_sort(RecallSort::Relevance)
            .with_scoring_weights(ScoringWeights {
                semantic: 1.0,
                recency: 0.25,
                importance: 0.15,
                recency_half_life_days: 14.0,
            })
            .with_max_distance(0.45)
            .with_max_tokens(1_024)
            .with_truncation_strategy(TruncationStrategy::HighRelevanceOnly),
    )
    .await?;
```

| `TruncationStrategy` Variant | Behavior When `max_tokens` Is Exceeded |
| :--- | :--- |
| `TruncationStrategy::HighRelevanceOnly` | Default. Keeps complete memories ordered by ascending distance until budget is full while preserving original response ordering. |
| `TruncationStrategy::PerHitCap` | Splits `max_tokens` evenly across returned hits (`max_tokens / count`) and trims each memory in place. |
| `TruncationStrategy::DropTail` | Keeps hits in returned order and trims the final boundary memory to fit remaining token capacity. |

### `forget`, `embed`, `analyze`, `analyze_and_wait`, `ask`, and `restore`

```rust
pub async fn forget(&self, namespace: Option<&str>) -> Result<ForgetResult>;
pub async fn embed(&self, text: &str) -> Result<EmbedResult>;
pub async fn analyze(&self, text: &str, opts: &AnalyzeOptions) -> Result<AnalyzeResult>;
pub async fn analyze_and_wait(&self, text: &str, opts: &AnalyzeOptions, wait: &WaitOptions) -> Result<AnalyzeWaitResult>;
pub async fn ask(&self, question: &str, opts: &AskOptions) -> Result<AskResult>;
pub async fn restore(&self, namespace: &str, limit: usize) -> Result<RestoreResult>;
```

1. `forget` removes vector index entries in the target namespace without sending `x-seal-session`. Encrypted Walrus blobs remain immutable on Walrus and can be re-indexed with `restore`.
2. `embed` returns the raw `Vec<f32>` embedding vector for `text` without persisting a memory.
3. `analyze` extracts atomic facts from conversation text (`AnalyzeOptions::with_occurred_at` validates timezone-aware RFC 3339 timestamps and normalizes them to UTC) and enqueues background `remember` jobs; `analyze_and_wait` waits for all extracted fact jobs to settle.
4. `ask` recalls relevant memories and returns a grounded `AskResult { answer, memories_used, memories }`.
5. `restore` re-decrypts and re-indexes Walrus blobs into the vector index, returning `RestoreResult { restored, skipped, failed, total, namespace, owner, truncated }`.

## Owner Inventory, Manual Mode, and Diagnostics

```rust
pub async fn list_namespaces(&self, opts: &ListNamespacesOptions) -> Result<NamespacesPage>;
pub async fn list_memories(&self, opts: &ListMemoriesOptions) -> Result<MemoriesPage>;
pub async fn whoami(&self) -> Result<WhoamiResult>;
pub async fn remember_manual(&self, opts: &RememberManualOptions) -> Result<RememberManualResult>;
pub async fn recall_manual(&self, opts: &RecallManualOptions) -> Result<RecallManualResult>;
pub async fn health(&self) -> Result<HealthResult>;
pub async fn compatibility(&self) -> Result<VersionInfo>;
```

1. `list_namespaces` and `list_memories` resolve the account owner once via `POST /api/stats`, memoize it on the client, and sign the full path plus URL-encoded query string (`updated_after`, `limit`). Always advance pagination while `page.has_more` is `true` using `page.next_cursor`.
2. `remember_manual` (`RememberManualOptions::new(encrypted_data_base64, vector)`) and `recall_manual` (`RecallManualOptions::new(vector)`) validate finite non-empty vectors locally and never transmit `x-seal-session`.

## Error Handling (`memwal::Error`)

All fallible functions return `memwal::Result<T>` (`std::result::Result<T, memwal::Error>`). `Error` is `#[non_exhaustive]` and wraps transport and JSON errors behind `Box<dyn std::error::Error + Send + Sync>` so third-party crate versions never leak into your public signature.

| Variant | HTTP Status | `is_transient()` | When Returned |
| :--- | :--- | :--- | :--- |
| `Error::InvalidKey` | None | `false` | Malformed hex, invalid Bech32 `suiprivkey1` checksum, wrong key length, or non-Ed25519 scheme flag (`0x01` Secp256k1, `0x02` Secp256r1). |
| `Error::InvalidUrl` | None | `false` | Empty URL, missing host, or scheme other than `http` or `https`. |
| `Error::InvalidArgument` | None | `false` | Blank or zero-width text, invalid namespace (`1..=64` bytes), `limit == 0`, out-of-range `ScoringWeights`, `NaN` vectors, or naive timestamps. |
| `Error::Destroyed` | None | `false` | Method called after `client.destroy()` zeroed the key material. |
| `Error::Incompatible` | `426` or preflight | `false` | Relayer `apiVersion` major mismatch or `minSupportedSdk.rust` higher than crate version. |
| `Error::ClockDrift` | `401` | `false` | Local system clock differs from relayer clock beyond the 300 second signing window. |
| `Error::AuthRejected` | `401` / `403` | `false` | Unregistered delegate key, wrong account ID, or rejected signature. |
| `Error::RateLimited` | `429` | `true` | Relayer rate limit exceeded; inspect `err.retry_after()` and `job_ids`. |
| `Error::Server` | `4xx` / `5xx` | `true` on `502`/`503`/`504` | Relayer HTTP error; internal URLs (`localhost`, `127.0.0.1`, `.internal`) are redacted. |
| `Error::JobFailed` | `200` job state | `false` | Background `remember` job settled with `status == "failed"`. |
| `Error::JobNotFound` | `404` job state | `false` | `wait_for_remember_job` polled an unknown or malformed `job_id`. |
| `Error::JobTimeout` | Client deadline | `true` | Background job did not reach `"done"` before `WaitOptions::timeout`. |
| `Error::RequestTimeout` | Client timeout | `true` | Single HTTP request exceeded its configured timeout. |
| `Error::SealSession` | `/config` or Sui RPC | `false` | Missing `/config` fields, unreachable Sui endpoint, or SEAL package object version not equal to `1`. |
| `Error::Transport` | Network | `true` | Connection reset, DNS failure, or TLS handshake error. |
| `Error::Json` | Serialization | `false` | Unexpected non-JSON or schema-mismatched payload. |

## Cryptographic Key Utilities

```rust
pub fn encode_sui_private_key(seed: &[u8; 32]) -> Result<String>;
pub fn decode_sui_private_key(bech32_key: &str) -> Result<Zeroizing<[u8; 32]>>;
pub fn delegate_key_to_public_key_hex(private_key: &str) -> Result<String>;
pub fn delegate_key_to_sui_address(private_key: &str) -> Result<String>;
pub fn estimate_tokens(text: &str) -> usize;
```

1. `delegate_key_to_public_key_hex` derives the 64 character lowercase hex Ed25519 verifying key to pass into on-chain `add_delegate_key`.
2. `delegate_key_to_sui_address` computes `0x` + ` hex(BLAKE2b_256(0x00 || pubkey))` for Sui personal message verification and SEAL session headers.
