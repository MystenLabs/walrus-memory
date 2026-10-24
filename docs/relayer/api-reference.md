---
title: API Reference
description: >-
  Complete HTTP API reference for the Walrus Memory relayer, including authentication headers, public routes, the protected endpoints for remember, recall, analyze, embed, ask, restore, forget, and stats, and the MCP transport endpoints.
keywords:
  - Walrus Memory
  - MemWal
  - API reference
  - relayer API
  - REST endpoints
  - authentication
goal:
  description: Authenticate a request to the relayer using an Ed25519 delegate key, call each API endpoint with the correct parameters, and interpret the response or error codes.
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
  - "What are the Walrus Memory relayer API endpoints?"
  - "How do I authenticate requests to the MemWal relayer?"
  - "What is the request and response format for the remember and recall APIs?"
answer: >-
  The Walrus Memory relayer exposes public routes (health, version, config, metrics, sponsor) and protected routes (remember, recall, analyze, embed, ask, restore, forget, stats) that require Ed25519 signed headers, plus MCP transport endpoints that use bearer authentication. Signed authentication uses x-public-key, x-signature, x-timestamp, and x-nonce headers, with the signature covering the timestamp, method, path, body hash, nonce, and account ID.
---

The Rust relayer exposes these routes. The route table lives in `services/server/src/main.rs`.

See also:

- [Environment Variables](/reference/environment-variables)
- [Configuration](/reference/configuration)
- [Versioning and Compatibility](/relayer/versioning-and-compatibility)

## Authentication

The routes below require signed headers, except the [MCP transports](#mcp-transports), which use bearer authentication. The SDK handles the signing automatically.

Not every `/api/*` route works this way. Account existence checks and the quarantine routes below need no authentication. The security-delete families use their own challenge and bearer flows, and `/api/admin/*` requires an `ADMIN_API_KEY`. Security-delete and the admin dashboard stay out of scope here. `GET /api/admin/unblock-requests` is the one admin route documented with the quarantine routes.

### Required headers

| **Header** | **Description** |
|--------|-------------|
| `x-public-key` | Hex-encoded Ed25519 public key (32 bytes) |
| `x-signature` | Hex-encoded Ed25519 signature (64 bytes) |
| `x-timestamp` | Unix timestamp in seconds (5-minute validity window) |
| `x-nonce` | UUID v4 nonce. The relayer records it in Redis for replay protection |

### Optional headers

| **Header** | **Description** |
|--------|-------------|
| `x-account-id` | MemWalAccount object ID hint. Official SDKs always send it and include it in the canonical signature |
| `x-seal-session` | Base64-encoded Seal SessionKey for relayer-managed decrypt flows. The TypeScript and Python SDKs use it |
| `x-delegate-key` | Legacy delegate private key credential for relayer-managed decrypt flows. Deprecated; use `x-seal-session` where supported |

### Signature format

The signed message is:

```text
{timestamp}.{method}.{path_and_query}.{body_sha256}.{nonce}.{account_id}
```

For `GET` requests, `body_sha256` is the SHA-256 of an empty byte string. If a raw client omits `x-account-id`, it must sign the empty string in the final `account_id` position. Official SDKs send `x-account-id`. A cold delegate key with no account id is rejected with `401`. The relayer does not search `AccountRegistry`. A key already in the relayer's delegate-key cache, or a server with `MEMWAL_ACCOUNT_ID` set, can still authenticate without the header.

The relayer verifies the Ed25519 signature, then resolves the owner by looking up the public key in onchain `MemWalAccount.delegate_keys`.

## Public routes

These routes require no authentication.

### `GET /health`

Service liveness check. `status` is `"ok"` when the relayer process is up. HTTP 200 means the process is running, not that writes are accepted.

`writes` is `"ok"`, `"degraded"`, or `"paused"`.

- `"paused"` when `WRITES_PAUSED` is set (`1` / `true` / `yes`). That flag is write-path admission, not a health-only signal: `POST /api/remember`, `/api/remember/manual`, `/api/remember/bulk`, and `/api/analyze` then return HTTP 503 with `{"error":"writes are paused"}`. `/health` itself stays HTTP 200 with `status: "ok"` and `writes: "paused"`, so clients can distinguish an intentional pause from an integrator bug. Reads (`recall`, `restore`, remember job status) stay available.
- `"degraded"` when recent durable writes (last 15 minutes) have **failed at least three times and none have landed**. The relayer still accepts and queues a write (`write_ready` stays `true`; HTTP 200), but Walrus is not storing it — expect the job to fail rather than queue more. A single success in that window keeps `"ok"` even if other writes failed: this is a total-outage detector, not a per-request verdict. `memwal_health` prints `writes=degraded` when this is set.
- `"ok"` otherwise (including a quiet window with no finished writes).

`write_ready` is `true` when the encryption sidecar process answered its own `/health` **and** Postgres can accept writes (cached a few seconds). Postgres is considered not writable when Neon cluster size (`pg_cluster_size`, not `pg_database_size` of this database) is at or within 1MB of `neon.max_cluster_size`. If `pg_cluster_size()` is missing (no `neon` extension), the probe falls back to `sum(pg_database_size)` against that GUC. Self-hosted Postgres without the GUC keeps the sidecar-only check. Probe errors and timeouts fail open (`write_ready` stays true) so CI is not blocked; timeouts log at warn. A sidecar outage or a disk/project-size write outage can still return HTTP 200 with `write_ready: false`. Use `writes`, not `write_ready`, for the pause or Walrus-outage signal. `write_ready: true` is not a guarantee that remember or analyze succeed.

**Response:**

```json
{
  "status": "ok",
  "version": "0.1.0",
  "relayerVersion": "0.1.0",
  "apiVersion": "1.0.0",
  "minSupportedSdk": {
    "typescript": "0.0.4",
    "python": "0.1.0",
    "mcp": "0.0.1"
  },
  "featureFlags": {
    "auth.accountBoundNonce": true,
    "auth.sealSessionHeader": true,
    "runtime.versionEndpoint": true
  },
  "deprecations": [],
  "build": {},
  "mode": "production",
  "prompt_versions": {
    "extract": "extract.v1",
    "ask": "ask.v1"
  },
  "write_ready": true,
  "writes": "ok"
}
```

### `GET /version`

Stable relayer/API compatibility metadata.

**Response:** the compatibility object documented in [Versioning and Compatibility](/relayer/versioning-and-compatibility#runtime-metadata).

### `GET /config`

Public deployment parameters that the SDK reads to build a Seal SessionKey client-side. The endpoint returns no secrets.

**Response:**

```json
{
  "packageId": "0x...",
  "registryId": "0x...",
  "network": "testnet",
  "suiRpcUrl": "https://fullnode.testnet.sui.io",
  "suiGrpcUrl": "https://fullnode.testnet.sui.io",
  "suiTransport": "grpc",
  "rateLimitDisabled": false
}
```

This example shows the fields a client needs to select a transport and build a session key. A deployment can return more, so read fields by name rather than assuming the shape is exhaustive.

`registryId` is the `AccountRegistry` shared object for `packageId`, the first argument to `account::create_account`.

`suiGrpcUrl` is the preferred gRPC endpoint, and `suiTransport` names the transport the relayer prefers for Sui reads. Newer SDKs read both; a client might fall back to `suiRpcUrl` while a deployment migrates. `rateLimitDisabled` mirrors the server's benchmark-bypass setting so benchmark scripts can pre-flight the configuration.

### `GET /metrics`

Prometheus metrics for scraping. See [Observability](/relayer/observability) for the exported series and how to wire a scraper.

### `POST /sponsor`

Proxy to the Seal/Walrus sidecar's `/sponsor` endpoint for sponsored transactions. The request must include `authTimestamp`, a UUID-v4 `authNonce`, and `authSignature`: a Sui personal-message signature over the sender, transaction-kind hash, timestamp, and nonce. Only one allowlisted Walrus Memory `account` call qualifies for sponsorship.

### `POST /sponsor/execute`

Proxy to the sidecar's `/sponsor/execute` endpoint. `sender` must match the short-lived, one-time Redis binding that the authenticated `/sponsor` call creates.

### `GET /api/accounts/:owner/delegate-keys`

Public read of one owner's delegate keys from Sui RPC. The relayer resolves that owner through `AccountRegistry`'s dynamic field, then reads the `MemWalAccount`. It does not use the indexer or the delegate-key cache. The response has no private key.

No authentication. Same per-IP limit as `GET /api/accounts/:owner/exists`: 20 requests per minute and 120 per hour. `owner` is `0x` plus 64 hex characters. A bad address is HTTP 400. An RPC failure is HTTP 503.

An owner with no account returns HTTP 200:

```json
{ "account_id": null, "keys": [] }
```

Otherwise each on-chain key is listed. `public_key` is 64 lowercase hex characters and has no `0x` prefix.

```json
{
  "account_id": "0x...",
  "keys": [
    {
      "public_key": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
      "sui_address": "0x...",
      "label": "Noter",
      "created_at": 10
    }
  ]
}
```

### `GET /api/accounts/:owner/incident`

Public answer for the owner in the path. The dashboard uses it to decide whether to show the quarantine banner. The response names no other owner. `affected_public_keys` lists only this account's current delegate public keys that are in `MEMWAL_LEAKED_DELEGATE_PUBLIC_KEYS`. On testnet, one preview owner is reported locked. When that list is empty, the preview response pins one current key whose label contains `migrat` for the life of the process. A non-empty list does not pin a replacement.

```json
{
  "account_id": "0x...",
  "affected": true,
  "quarantined": true,
  "active": false,
  "affected_public_keys": ["00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"]
}
```

`affected` is true when the owner is listed in `MEMWAL_AFFECTED_OWNERS`, a current delegate public key is listed in `MEMWAL_LEAKED_DELEGATE_PUBLIC_KEYS`, or the account is `admin_quarantined`. With both lists empty, `affected` follows the on-chain flag. An owner with no account still returns HTTP 200: `account_id` is null, `quarantined` and `active` are false, and `affected` is true only when that owner is in `MEMWAL_AFFECTED_OWNERS`.

### `POST /api/accounts/:owner/unblock-requests`

The owner signs a Sui personal message. The relayer stores one request. Clearing quarantine stays an `AdminCap` transaction. After an operator clears it, the owner calls `reactivate_account`. One `reactivate_account` call is on the sponsored-transaction allowlist.

The signed text uses the lowercased owner and the account id read from chain, not a value from the body:

```text
Walrus Memory unblock request
owner:0x...
account:0x...
```

```json
{ "signature": "<base64 personal-message signature>" }
```

HTTP 200 returns `{ "status": "requested", "requested_at": "<RFC3339>" }`. A second request from the same owner refreshes `requested_at`. HTTP 409 when the account is not quarantined. HTTP 401 when the signature is not the owner's. HTTP 400 when the owner has no account, or the signature is empty or longer than 4096 characters. HTTP 503 when the signature check cannot reach RPC.

### `GET /api/admin/unblock-requests`

Requires `ADMIN_API_KEY`, the same gate as the other admin routes. Returns the newest 200 requests, each with `owner`, `account_id`, and `requested_at`. The dashboard does not call the POST route. Operators clear quarantine with `admin_clear_quarantine` after the highlighted keys are gone, and the owner reactivates from the dashboard.

## Protected routes

Every route below requires the signed headers described in [Authentication](#authentication).

### `GET /api/whoami`

Return the account identity the caller's delegate key resolves to. Takes no request body.

Authentication already resolves the account before any handler runs, so this route just hands back what the middleware computed. Returning `account_id` is safe here precisely because the route is authenticated. The caller has proven it holds a delegate key registered against this account, so it only ever learns about itself. The public `GET /api/accounts/:owner/exists` route deliberately withholds it.

The motivating use is rebuilding local credentials: a client that holds a working delegate key but has lost the surrounding metadata (an interrupted sign-in, a wiped config file) needs `account_id`, `owner`, and `package_id` to write a usable credentials file, and the key alone proves entitlement to all three.

**Response:**

```json
{
  "account_id": "0x...",
  "owner": "0x...",
  "package_id": "0x..."
}
```

The caller sends `x-account-id` on every network. Authentication does not scan `AccountRegistry` to discover it. A request with no account id returns `401` unless that delegate key is already in the relayer's cache or the server has `MEMWAL_ACCOUNT_ID` set. A client that has lost its account id cannot recover it from this route.

### `POST /api/remember`

Submit text as an encrypted memory job. The relayer returns after creating a background job; embedding, Seal encryption, Walrus upload, and vector indexing continue asynchronously.

**Request:**

```json
{
  "text": "User prefers dark mode",
  "namespace": "demo",
  "idempotency_key": "my-idempotency-key"
}
```

`namespace` defaults to `"default"` if omitted and is limited to 255 UTF-8 bytes. `idempotency_key` is an optional string (up to 255 UTF-8 bytes); when supplied, repeated calls with the same key collapse onto the existing job row.

**Response:** `202 Accepted`

```json
{
  "job_id": "uuid",
  "status": "running"
}
```

### `GET /api/remember/:job_id`

Poll a remember job. `status` is one of `pending`, `running`, `uploaded`, `done`, or `failed`. Failed jobs include an `error` message. Unknown job IDs and jobs that belong to another owner return `404`, so callers cannot enumerate job IDs.

**Response:**

```json
{
  "job_id": "uuid",
  "status": "done",
  "owner": "0x...",
  "namespace": "demo",
  "blob_id": "walrus-blob-id"
}
```

### `POST /api/remember/bulk`

Submit up to 20 memories in one request. `job_ids[i]` corresponds to `items[i]`. This route accepts request bodies up to 2 MB.

**Request:**

```json
{
  "items": [
    { "text": "User prefers dark mode", "namespace": "demo" },
    { "text": "User works in TypeScript", "namespace": "demo" }
  ],
  "idempotency_key": "my-bulk-idempotency-key"
}
```

`idempotency_key` is an optional string (up to 255 UTF-8 bytes). When provided, each item in the batch is assigned `bulk:{idempotency_key}:{i}`, so repeated requests with the same batch key collapse onto the original jobs.

**Response:** `202 Accepted`

```json
{
  "job_ids": ["uuid-1", "uuid-2"],
  "total": 2,
  "status": "running"
}
```

### `POST /api/remember/bulk/status`

Poll a batch of remember jobs. Unknown job IDs come back with status `not_found`, and failed items include an `error` message.

**Request:**

```json
{
  "job_ids": ["uuid-1", "uuid-2"]
}
```

**Response:**

```json
{
  "results": [
    { "job_id": "uuid-1", "status": "done", "blob_id": "walrus-blob-id" },
    { "job_id": "uuid-2", "status": "running" }
  ]
}
```

### `POST /api/recall`

Search for memories matching a natural language query. Returns decrypted plaintext results.

**Request:**

```json
{
  "query": "What do we know about this user?",
  "limit": 10,
  "namespace": "demo",
  "scoring_weights": {
    "semantic": 1.0,
    "recency": 0.3,
    "recency_half_life_days": 30,
    "importance": 0.2
  }
}
```

`limit` defaults to `10`; the server caps it at `100`. `namespace` defaults to `"default"`. `scoring_weights` takes an optional object; omit it to keep the plain cosine-distance order.

`sort` is optional: `"relevance"` (the cosine order, and the behaviour when omitted) or `"recent"` (the newest among the semantic matches). An explicit `sort`, `"relevance"` included, is the order, and the relayer ignores `scoring_weights` for that request.

`deadline_ms` is optional: how long the caller waits for this response, in milliseconds. When set, the relayer stops about one second before it, counting from when the request arrived, and answers `504` with the step that was still running, so the caller learns where the recall stalled instead of timing out blind. A short deadline still gets at least 2 seconds of work; if the whole deadline went on authentication before the recall started, the relayer answers at once with stage `auth`. Values above `600000` are capped. Omit it to let the recall run to completion. The TypeScript SDK sends `14000`, a second under the 15s it aborts `recall()` at: the relayer's own margin runs from arrival, so it covers the reply's trip back but not the connect the caller's timer already started on.

```json
{
  "error": "Recall timed out after 14001ms during walrus_download",
  "message": "Recall timed out after 14001ms during walrus_download",
  "code": "RECALL_TIMEOUT",
  "stage": "walrus_download",
  "elapsed_ms": 14001
}
```

`stage` is one of `auth`, `embed`, `vector_search`, `walrus_download`, or `seal_decrypt`.

#### Scoring weights

The optional `scoring_weights` object turns on composite ranking. The same object works on `/api/recall`, `/api/recall/manual`, and `/api/ask`.

| **Field** | **Default** | **Description** |
|--------|-------------|-------------|
| `semantic` | `1.0` | Weight for cosine similarity between the query and each memory |
| `recency` | `0` | Weight for how recently the relayer indexed each memory |
| `recency_half_life_days` | `30` | Half-life in days for the recency decay |
| `importance` | `0` | Weight for the per-fact importance score that the extractor assigns at save time |

**Response:**

```json
{
  "results": [
    {
      "blob_id": "walrus-blob-id",
      "text": "User prefers dark mode",
      "distance": 0.15,
      "score": 0.91
    }
  ],
  "total": 1,
  "dropped_count": 0
}
```

`score` only appears when `scoring_weights` sets a nonzero `recency` or `importance` weight and `sort` is omitted. A request that sets only the `semantic` weight keeps the plain cosine order, and the relayer omits `score`. `dropped_count` only appears when at least one match dropped out because its blob download or decryption failed; the relayer omits those matches from `results`.

### `POST /api/remember/manual`

Register a client-encrypted payload. The client sends Seal-encrypted data (base64) and a precomputed embedding vector. The relayer uploads the encrypted bytes to Walrus and stores the vector mapping.

**Request:**

```json
{
  "encrypted_data": "base64-encoded-seal-encrypted-bytes",
  "vector": [0.01, -0.02, ...],
  "namespace": "demo"
}
```

**Response:**

```json
{
  "id": "uuid",
  "blob_id": "walrus-blob-id",
  "owner": "0x...",
  "namespace": "demo"
}
```

### `POST /api/recall/manual`

Search with a precomputed query vector. Returns index hits only; the client handles downloading and decrypting. The request accepts the same optional `scoring_weights` object as [`POST /api/recall`](#scoring-weights), and the server applies the same `limit` cap of `100`.

**Request:**

```json
{
  "vector": [0.01, -0.02, ...],
  "limit": 10,
  "namespace": "demo"
}
```

**Response:**

```json
{
  "results": [
    {
      "blob_id": "walrus-blob-id",
      "distance": 0.15,
      "created_at": "2026-07-23T12:00:00Z",
      "importance": 0.5
    }
  ],
  "total": 1
}
```

`created_at` is the time the relayer indexed the entry. `importance` carries the per-fact importance score that the extractor assigns at save time.

### `POST /api/analyze`

Extract facts from text using an LLM, then enqueue each fact as a separate memory job.

**Request:**

```json
{
  "text": "I live in Hanoi and prefer dark mode.",
  "namespace": "demo",
  "occurred_at": "2026-07-01T00:00:00Z"
}
```

`occurred_at` is an optional RFC 3339 timestamp that anchors the extracted facts in time, for example when you import older conversations. The extractor writes the date into the fact text itself; the relayer stores no separate event-time metadata and cannot filter or rank by event time.

**Response:** `202 Accepted`

```json
{
  "job_ids": ["uuid-1", "uuid-2"],
  "facts": [
    { "text": "User lives in Hanoi", "id": "uuid-1", "job_id": "uuid-1" },
    { "text": "User prefers dark mode", "id": "uuid-2", "job_id": "uuid-2" }
  ],
  "fact_count": 2,
  "status": "pending",
  "owner": "0x..."
}
```

### `POST /api/embed`

Return an embedding vector for `text` without storing a memory. Uses the same model and width as remember, recall, and analyze. Requires signed-header auth.

**Request:**

```json
{
  "text": "hello world"
}
```

`text` must be non-empty and at most 64 KiB.

**Response:**

```json
{
  "vector": [0.01, -0.02]
}
```

### `POST /api/ask`

Recall memories, inject them into an LLM prompt, and return an AI-generated answer with the context used.

**Request:**

```json
{
  "question": "What do you know about my preferences?",
  "limit": 5,
  "namespace": "demo"
}
```

`limit` defaults to `5` and caps at `100`. `namespace` defaults to `"default"`. The request accepts the same optional `scoring_weights` object as [`POST /api/recall`](#scoring-weights).

**Response:**

```json
{
  "answer": "Based on your memories, you prefer dark mode and live in Hanoi.",
  "memories_used": 2,
  "memories": [
    {
      "blob_id": "walrus-blob-id",
      "text": "User prefers dark mode",
      "distance": 0.12
    }
  ]
}
```

### `POST /api/restore`

Rebuild missing vector entries for one namespace. Queries onchain blobs by owner and namespace, downloads from Walrus, decrypts, re-embeds, and re-indexes only the entries missing from the index.

**Request:**

```json
{
  "namespace": "demo",
  "limit": 10
}
```

`limit` defaults to `10` and caps the onchain query itself, newest blobs first. Raise it to cover a larger namespace.

**Response:**

```json
{
  "restored": 3,
  "skipped": 7,
  "failed": 0,
  "total": 10,
  "namespace": "demo",
  "owner": "0x...",
  "truncated": false
}
```

`skipped` is onchain blobs already in the local success index. `failed` is permanent decrypt/UTF-8 failures on this onchain page (negative-cache hits plus new permanent failures this call), so it never exceeds `total`. Transient download, decrypt, or embed errors are not counted in `failed`; when a page yields only those, `truncated` is true so the caller retries.

`truncated=true` means this restore is **known-retryable-incomplete**: more missing blobs than `limit` allowed this call to restore, **or** the sidecar's owner-wide candidate fetch hit its cap **and** raising `limit` can still expand that fetch (`limit < 20`). Once the sidecar cap is saturated (`limit >= 20`, cap pinned at 100), truncation follows this call's missing-blob page length, not onchain `total`. A fully restored namespace does not loop. `truncated=false` is **not** proof the sidecar saw every onchain blob; blobs beyond the owner-wide sidecar candidate cap can still be missing. This response does not include a separate cap flag for that case. Older relayers omit `truncated`; SDKs default it to `false`.

### `POST /api/forget`

Delete every vector index row for one namespace. The Walrus blobs persist, so a later `POST /api/restore` call can re-index them. The relayer resolves the owner from the signed headers and only deletes that owner's rows.

**Request:**

```json
{
  "namespace": "demo"
}
```

`namespace` defaults to `"default"`.

**Response:**

```json
{
  "deleted": 12,
  "namespace": "demo",
  "owner": "0x..."
}
```

`deleted` is the number of index rows the relayer removed.

### `POST /api/stats`

Return the memory count and stored byte total for one namespace, scoped to the authenticated owner.

**Request:**

```json
{
  "namespace": "demo"
}
```

`namespace` defaults to `"default"`.

**Response:**

```json
{
  "memory_count": 42,
  "storage_bytes": 1048576,
  "namespace": "demo",
  "owner": "0x..."
}
```

## MCP transports

The relayer also proxies Model Context Protocol traffic to its Node sidecar. `GET`, `POST`, `DELETE`, and `OPTIONS` on `/api/mcp` serve the Streamable HTTP transport, and `GET /api/mcp/sse` plus `POST /api/mcp/messages` serve the legacy SSE transport. These routes use bearer authentication instead of signed headers. See [Reference](/mcp/reference) for transport details and client configuration.
