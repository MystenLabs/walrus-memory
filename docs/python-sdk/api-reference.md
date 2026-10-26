---
title: "API Reference"
description: >-
  Full method signatures, result dataclasses, exceptions, and utility functions for
  the Walrus Memory Python SDK. Covers MemWal, MemWalSync, middleware, and authentication.
keywords:
  - Walrus Memory
  - MemWal
  - Python SDK
  - API reference
  - method signatures
  - dataclasses
goal:
  description: Look up the exact method signature, parameter types, return value, and exception type for any MemWal Python SDK method before writing code that calls it.
  requires:
    - has_frontmatter:
        - title
        - description
        - keywords
      label: Has required frontmatter fields
    - min_words: 300
      label: Needs more content depth
    - has_questions: true
      label: Needs questions for AI search visibility
    - has_answer: true
      label: Needs answer summary for AI citation
questions:
  - What are the method signatures for the MemWal Python SDK?
  - What exceptions does the MemWal Python SDK raise?
  - How does Ed25519 authentication work in the MemWal Python SDK?
answer: >-
  The MemWal Python SDK API reference documents all methods on MemWal and MemWalSync
  including remember, recall, analyze, ask, restore, list_namespaces, health, and lower-level manual methods.
  It also covers result dataclasses, exception hierarchy, middleware wrappers, utility
  functions for delegate key derivation, and the Ed25519 request signing protocol.
---

See also:

- [Configuration](/reference/configuration)
- [Relayer API](/relayer/api-reference)

## `MemWal.create(...)`

```python
MemWal.create(
    key: str,
    account_id: str,
    server_url: str = "https://relayer.memory.walrus.xyz",
    namespace: str = "default",
    env: str | None = None,
) -> MemWal
```

`MemWalSync.create(...)` has the same signature and returns a synchronous wrapper.

| Argument | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `key` | `str` | Yes | — | Ed25519 delegate private key in hex |
| `account_id` | `str` | Yes | — | Walrus Memory account object ID on Sui |
| `server_url` | `str` | No | `https://relayer.memory.walrus.xyz` | Explicit relayer URL — wins over `env` |
| `namespace` | `str` | No | `"default"` | Default namespace for memory isolation |
| `env` | `str` | No | — | Hosted preset: `staging` for testing or `prod` for production. Unknown → `ValueError` |

You may also build a `MemWalConfig` and call `MemWal(config)` directly; `env` resolution happens in `MemWalConfig.__post_init__`.

## `MemWal` Methods

All methods are coroutines on `MemWal`; `MemWalSync` exposes the same names without `await`.

### `remember(text, namespace=None) -> RememberAcceptedResult`

Submit one memory. Returns after the relayer accepts a background job; embedding, SEAL encryption, Walrus upload, and indexing continue asynchronously. `remember_async` is an alias.

```python
RememberAcceptedResult(job_id: str, status: str)
```

### `remember_and_wait(text, namespace=None, poll_interval_ms=1500, timeout_ms=60_000) -> RememberResult`

Submit one memory and poll until the job completes.

```python
RememberResult(id: str, blob_id: str, owner: str, namespace: str)
```

### `get_remember_status(job_id) -> RememberJobStatus`

One `GET /api/remember/{job_id}`. Accepts 200 and 404 and returns the job state (`pending`, `running`, `uploaded`, `done`, `failed`, or `not_found`) without polling. A job id that is empty or contains whitespace, `/`, `?`, or `#` is `not_found` and is not requested. `MemWalSync` has the same method.

```python
RememberJobStatus(
    job_id: str, status: str, owner: str | None = None,
    namespace: str | None = None, blob_id: str | None = None, error: str | None = None,
)
```

### `wait_for_remember_job(job_id, poll_interval_ms=1500, timeout_ms=60_000) -> RememberResult`

Poll a previously accepted job until `done` or `failed`. Raises `MemWalRememberJobNotFound` / `MemWalRememberJobFailed` / `MemWalRememberJobTimeout`. A job id outside `[A-Za-z0-9_-]+` raises `MemWalRememberJobNotFound` before the request.

### `remember_bulk_async(items) -> RememberBulkAcceptedResult`

Submit up to 20 `RememberBulkItem` in one request. `remember_bulk` is an alias.

```python
RememberBulkAcceptedResult(job_ids: list[str], total: int, status: str)
```

### `get_remember_bulk_status(job_ids) -> RememberBulkStatusResult`

One `RememberBulkStatusItem(job_id, status, blob_id?, error?)` per requested job.

### `wait_for_remember_jobs(job_ids, opts=None) -> RememberBulkResult`

Poll a batch until every job is terminal. `opts` is a `RememberBulkOptions(poll_interval_ms=1500, timeout_ms=120_000)`.

```python
RememberBulkResult(
    results: list[RememberBulkItemResult],  # preserves input order
    total: int, succeeded: int, failed: int, timed_out: int,
)
```

### `remember_bulk_and_wait(items, opts=None) -> RememberBulkResult`

`remember_bulk_async` + `wait_for_remember_jobs` in one call.

### `recall(RecallParams(...)) -> RecallResult`

Search memories matching a natural-language query, scoped to `owner + namespace`.
When `max_distance` is set, the client drops weak matches where `distance >= max_distance`.

Preferred form:

```python
from memwal import RecallParams

result = await memwal.recall(
    RecallParams(query="food allergies", limit=10, namespace="profile")
)
```

The legacy positional form `recall(query, limit=10, namespace=None, max_distance=None)` remains supported for backwards compatibility.

```python
RecallResult(
    results: list[RecallMemory],  # RecallMemory(blob_id, text, distance)
    total: int,
)
```

`distance` is cosine distance — lower is more similar.

### `analyze(text, namespace=None, occurred_at=None) -> AnalyzeResult`

Extract memorable facts via an LLM and enqueue one background remember job per fact.

`occurred_at` is optional. Pass a timezone-aware `datetime`, or an RFC 3339 / ISO-8601 string with a `Z` suffix or a UTC offset. A naive `datetime`, or a string with no offset, raises `ValueError`. Any other type raises `TypeError`. When set, the extractor uses it as a temporal anchor and writes resolved dates into the fact text. The server stores no separate event-time field. Omit it when you have no session time; the server does not fill in the current time.

```python
AnalyzeResult(
    facts: list[AnalyzedFact],  # AnalyzedFact(text, id, blob_id)
    fact_count: int,
    job_ids: list[str],
    status: str,
    owner: str,
)
```

`AnalyzeResult.total` is a backward-compat alias for `fact_count`. Use `analyze_and_wait(text, namespace=None, opts=None, occurred_at=None) -> AnalyzeWaitResult` to wait for every fact job to settle. `occurred_at` means the same thing as on `analyze`.

### `ask(question, limit=5, namespace=None) -> AskResult`

Answer a question using your memories as context.

```python
AskResult(
    answer: str,
    memories_used: int,
    memories: list[AskMemory],  # AskMemory(blob_id, text, distance)
)
```

### `restore(namespace, limit=10) -> RestoreResult`

Rebuild missing indexed entries for one namespace from Walrus. Incremental.

- `limit` defaults to `10` and caps the inspected blob set, newest-first
- `restored` counts blobs re-indexed in this call; `skipped` counts onchain blobs already in the local success index; `failed` counts permanent decrypt/UTF-8 failures (defaults to `0`)
- There is no pagination cursor; use a larger `limit` for larger one-shot restores

```python
RestoreResult(restored: int, skipped: int, total: int, namespace: str, owner: str, truncated: bool = False, failed: int = 0)
```

`truncated=true` is known-retryable-incomplete (this call's `limit`, or a still-expandable sidecar candidate fetch); `truncated=false` is not proof the sidecar saw every onchain blob (a `sourceCapped` field is planned as a follow-up).

### `list_namespaces(cursor=None, limit=None) -> NamespacesResult`

List the namespaces this account holds memories in. Returns metadata only, with no blob fetch or decryption.

Recall needs a namespace to search, so an agent on an unfamiliar account would otherwise have to guess names or fall back to `"default"`. Namespaces are flat and exact-match: to work with a prefix such as `proj/`, filter the names client-side and recall each one.

- `cursor`: the previous page's `next_cursor`, to continue a walk or poll for namespaces changed since then
- `limit`: page size; the relayer defaults to `100` and clamps to `500`

```python
NamespacesResult(
    namespaces: list[NamespaceSummary],  # NamespaceSummary(id, name, memory_count, storage_used, updated_at)
    next_cursor: str | None,
    has_more: bool,
    snapshot_version: int,
)
```

Paginate on `has_more`, not on page length. The relayer clamps `limit`, so a caller asking for more than the cap gets exactly the cap back.

```python
cursor = None
while True:
    page = await memwal.list_namespaces(cursor=cursor)
    for ns in page.namespaces:
        print(ns.name, ns.memory_count)
    cursor = page.next_cursor
    if not page.has_more:
        break
```

### `health() -> HealthResult`

Check relayer health. No authentication — a successful response confirms the relayer is reachable, not that your `key`/`account_id` are valid. A signed call (e.g. `remember()`, `recall()`) can still fail with `401` immediately after a passing `health()`. Raises `MemWalError` on non-200.

```python
HealthResult(
    status: str,
    version: str,
    relayer_version: str | None = None,
    api_version: str | None = None,
    min_supported_sdk: dict[str, str] | None = None,
)
```

### `compatibility() -> dict`

Fetch and validate the relayer compatibility contract from `/version`. Protected SDK calls run this check before signing the first request and raise `MemWalCompatibilityError` when the SDK/relayer pair is unsupported.

### `get_public_key_hex() -> str`

Hex-encoded public key for the current delegate key.

### `close()` / context managers

`await memwal.close()` closes the underlying `httpx` client. `MemWal` supports `async with`; `MemWalSync` supports `with`.

### Lower-level methods

| Method | Description |
| --- | --- |
| `remember_manual(RememberManualOptions)` | Send SEAL-encrypted bytes + a pre-computed vector; the relayer uploads to Walrus → `RememberManualResult` |
| `recall_manual(RecallManualOptions)` | Search with a pre-computed query vector → `RecallManualResult` (blob_id + distance only) |
| `embed(text)` | Embedding vector for text, no storage → `EmbedResult(vector)` |

See [Manual methods](/python-sdk/usage/memwal-manual).

## Middleware

```python
from memwal import with_memwal_langchain, with_memwal_openai
```

Both wrap an existing LLM client with automatic recall + save and accept: `key`, `account_id`, `server_url`, `namespace`, `env`, `max_memories` (5), `auto_save` (True), `min_relevance` (0.3), `debug` (False). The alias `withMemWal` maps to `with_memwal_langchain`. See [with_memwal](/python-sdk/usage/with-memwal).

## Exceptions

```python
from memwal import (
    MemWalError,
    MemWalRememberJobNotFound,
    MemWalRememberJobFailed,
    MemWalRememberJobTimeout,
    MemWalRateLimited,
)
```

| Exception | `.status` | Meaning |
| --- | --- | --- |
| `MemWalError` | — | Base class for all SDK errors |
| `MemWalRememberJobNotFound` | `404` | Job unknown or not owned by the caller |
| `MemWalRememberJobFailed` | `500` | Job reached terminal `failed` (`.error`) |
| `MemWalRememberJobTimeout` | `504` | Polling exceeded `.timeout_ms` |
| `MemWalRateLimited` | `429` | Every bulk status read, the confirming one included, was rate-limited; `.job_ids` are unconfirmed (`.retry_after`) |

## Utility Functions

```python
from memwal import delegate_key_to_sui_address, delegate_key_to_public_key
```

| Function | Description |
| --- | --- |
| `delegate_key_to_sui_address(private_key_hex)` | Derive the `0x`-prefixed Sui address — `blake2b-256(0x00 ‖ pubkey)` |
| `delegate_key_to_public_key(private_key_hex)` | 32-byte Ed25519 public key bytes |

## Authentication

Every request is signed with Ed25519 (PyNaCl). Canonical message:

```
{timestamp}.{method}.{path_and_query}.{body_sha256}.{nonce}.{account_id}
```

Signed requests send `x-public-key`, `x-signature`, `x-timestamp`, `x-nonce` (UUID v4), and `x-account-id`. Relayer-mode requests also send `x-seal-session`; manual-mode requests omit decrypt credentials. SDKs that omit `x-nonce` are rejected by the server with `426 Upgrade Required`.
