# @mysten-incubation/memwal

## 0.1.13

### Added

- `MemWalRecallAllDroppedError` (`name = "MemWalRecallAllDropped"`, `code = "RECALL_ALL_DROPPED"`) is thrown by `recall()` when every vector search match is dropped during Walrus blob download or SEAL decryption. It exposes `total`, `droppedCount`, and `namespace`. (#1036, #1070)
- `RecallResult` includes an optional `degraded?: boolean` flag set to `true` whenever one or more vector matches were dropped. (#1036, #1070)
- `RecallOptions` accepts `onDropped?: "throw" | "ignore"` (defaulting to `"throw"`). Passing `"ignore"` returns `{ results: [], total, dropped_count, degraded: true }` without throwing. (#1036, #1070)

## 0.1.12

### Fixed

- `withMemWal` bounds the recall query (preserving both head context and tail question/instructions via `strategy: "head-tail"`) to 16,384 UTF-8 bytes and auto-save `analyze()` input to 65,536 UTF-8 bytes without splitting multi-byte UTF-8 codepoints across boundaries, while keeping the full user turn in the language model prompt. User turns exceeding the embedder's 16 KiB limit still inject relevant memories without HTTP 400 errors, and auto-save extracts facts across turns up to 64 KiB. (#1037)

## 0.1.11

### Added

- `remember`, `rememberAsync`, and `rememberAndWait` accept `{ dedupe: true }` (`RememberOptions` / `RememberWaitOptions`) for opt-in content-hash deduplication per `(owner, namespace, text)` without a 30-minute time window. When `dedupe: true` is set, the client derives a bucket-less `dedupe:<sha256>` key and sends `dedupe: true` to `POST /api/remember`, collapsing duplicate writes onto the existing live job and `blob_id` while writing fresh if the memory was later forgotten or deleted. `MemWalMock` mirrors the same behavior. (#769)

### Fixed

- `MemWal.create` and `MemWalManual.create` copy a caller-supplied `Uint8Array` key into an internal buffer so `destroy()` zeroes only the client's copy and leaves the caller's `Uint8Array` intact for reuse. `MemWalManual.destroy()` also drops references to `suiPrivateKey`, `embeddingApiKey`, `sealServerConfigs` API keys, `walletSigner`, and cached Sui/SEAL/keypair instances (zeroing any decoded keypair secret buffer) and rejects subsequent or in-flight calls instead of signing with a zeroed key. (#973, #977)
- `formatUntrustedMemories` and `withMemWal` validate that each recalled memory's `distance` is a finite number and clamp similarity relevance (`1 - distance`) to `[0, 1]` before filtering and formatting. Records with `undefined`, `NaN`, or `±Infinity` distances are dropped instead of rendering `"relevance":"NaN"`, and negative or greater-than-one distances are clamped to `1.00` / `0.00`. (#976)
- `MemWal.listNamespaces` and `MemWal.listMemories` reject a `limit` that is not a positive integer before signing the query string, with the same `limit must be a positive integer, got <limit>` `TypeError` as `recall` and `recallManual`. (#1213)
- `analyze()` accepts an optional `signal` in `AnalyzeOptions` and aborts the in-flight `/api/analyze` HTTP request when the caller's `AbortSignal` fires. (#1095)
- `MemWal.rememberManual`, `MemWal.recallManual`, `MemWalManual.rememberManual`, and `MemWalManual.recallManual` reject an empty or non-finite `vector` (including `NaN`, `±Infinity`, non-number elements, and sparse arrays) before signing, and `rememberManual` rejects a missing or blank `encryptedData` string with `TypeError`. (#1211)

## 0.1.10

### Fixed

- `waitForRememberJob` throws the exported `MemWalRememberJobNotFoundError`, `MemWalRememberJobFailedError`, and `MemWalRememberJobTimeoutError` classes, which carry `status` and `jobId` and support `instanceof` checks. `waitForRememberJobs` and `rememberBulkAndWait` throw `MemWalRateLimitedError`, which carries `status` and `jobIds`, when every status read for the batch is rate-limited. (#687)
- `MemWal.recallManual` and `MemWalManual.recallManual` reject a non-finite `scoringWeights` value (`NaN` or `Infinity`) before signing, with the same `scoringWeights.<name> must be a finite number` error as `recall`. `JSON.stringify` rewrote the weight to `null`, so the relayer received `{"semantic": null}` instead of the caller's value. (#1246)
- A 2xx response that is valid JSON of the wrong shape raises an SDK error that names the endpoint, instead of a raw `TypeError`. `recall`, `analyzeAndWait`, `listMemories`, and `getRememberBulkStatus` (so `waitForRememberJobs`) name the missing `results`, `job_ids`, or `memories` array, and the bulk status error is not retried. `getRememberStatus` returns `not_found` and `waitForRememberJob` throws `MemWalRememberJobNotFoundError` when the status body is null or not an object. (#1247)
- `remember`, `rememberBulk`, `analyze`, `embed`, and `recall` reject text made only of whitespace and zero-width format characters (U+200B, U+200C, U+200D, U+2060, U+FEFF) before signing, with the same error as blank text. The relayer still accepts that text, and the call used to sit until the client timed out. `MemWalMock` rejects the same set. (#1156)

## 0.1.9

### Fixed

- `rememberBulk` and `rememberBulkAsync` send an idempotency key derived from the batch (a 30-minute bucket plus each item's namespace and text). A retry inside that window returns the same jobs instead of storing the batch again. An explicit `idempotencyKey` still wins. (#1080)
- `listMemories()` pages every stored memory without a similarity query. It returns metadata only: no blob download and no decrypt. An optional namespace filter runs on the client, so a filtered page can be empty while `has_more` is true.
- `withMemWal` does not recall or auto-save on a tool-execution step. A later tool step reuses the recall cached for that user message. Auto-save still runs only on a user turn. (#1079)
- `flush()` raises when a background auto-save failed, and `onSaveError` runs. The chat turn itself still does not fail. (#1117)
- `withMemWal` warns when recall fails and accepts `onRecallError`.
- `MemWal.create` and `MemWalManual.create` reject a blank `accountId`, an empty namespace string, and a private key that is not a 32-byte Ed25519 seed. An omitted namespace still defaults to `"default"`. (#1155, #1200, #1204)
- `recall`, `recallManual`, and `restore` reject a `limit` that is not a positive integer before signing. `recall` also rejects a blank query, a non-finite scoring weight, and a non-finite or negative `maxDistance`. A bad `maxDistance` used to drop every hit and look like an empty namespace. `recall` also rejects a `maxTokens` that is not a number (`TypeError`) or is negative (`RangeError`). (#1086, #1068, #1227, #1228)
- A `maxDistance` filter keeps the relayer's matching `total`. `total` is no longer replaced by the filtered row count, including when every row is dropped.
- When a token budget keeps only high-relevance hits, the lowest-distance hits are kept and the caller's sort order is preserved.
- `waitForRememberJob` and `waitForRememberJobs` do not sleep past the deadline. If the budget runs out during the sleep, they make one more status read. (#1081)
- Package `exports` include a `default` condition and list `types` first, so Next.js, Turbopack, and Node `require(esm)` resolve the subpaths.
- A success response with an empty or non-JSON body raises an SDK error that names the HTTP status, instead of a raw `SyntaxError`. `MemWalManual.restore` sends the SEAL session and keeps its deadline armed across the body read. (#1201, #1137)
- `getRememberBulkStatus` rejects a job id list that is not an array before any request. `MemWalMock.analyze` rejects an invalid date, and `MemWalMock.listNamespaces` rejects a cursor that is not `{updated_at, namespace}` instead of ending the page early. (#1226, #1229, #1203)
- `createAccount`, `addDelegateKey`, `removeDelegateKey`, and `MemWalManual` work again without a caller-supplied `suiClient`. They looked for `SuiClient` in `@mysten/sui/client`, which current `@mysten/sui` no longer exports, and threw `SuiClient not found`. The default is now `SuiGrpcClient` against the public fullnode for `suiNetwork`, because those fullnodes no longer serve JSON-RPC. An explicit `suiClient` still wins. (#300)
- `remember`, `rememberAsync`, and `rememberAndWait` reject a non-string text argument with `TypeError` before signing. An object used to be sent as `text` and the relayer answered 422. (#1058)
- `getRememberStatus` and `waitForRememberJob` reject a job id outside `[A-Za-z0-9_-]+` before signing. `.`, `..`, `\`, and `%2e%2e` used to pass a denylist and be rewritten by `fetch` after the path was signed. Valid UUID job ids are unchanged. (#1087, #1216)
- `/manual` no longer imports `@mysten/walrus`. `getWalrusClient()` and `walrusUpload()` had no callers, but the dynamic import still pulled the WASM client into Turbopack and Vite. Downloads stay on the HTTP aggregator. (#330)
- `MemWal.recallManual()` is typed as `RecallManualHitResult` (blob id and distance, no text) and `MemWalManual.recallManual()` as `RecallManualMemoryResult` (decrypted text). `RecallManualResult` remains a deprecated alias of those two result types, not a mixed-item array. (#298)
- `MemWalMock.listNamespaces` rejects a non-positive or non-integer `limit` with `limit must be positive`, matching the relayer. `limit: 0` used to return `has_more: true` and `next_cursor: null`, so the documented pagination loop never finished, and `limit: -1` silently dropped the last namespace. (#1144, #1145)
- `MemWalMock.rememberBulkAsync` rejects an empty or non-array batch with the same error as `MemWal`. (#1146)
- `MemWalMock` honors `idempotencyKey`. A retry of the same text and namespace returns the original job, a different payload throws, and `forget` / `clear` release the key so the text can be written again. (#1147)
- `MemWalMock` scopes an idempotency key to its namespace, like the relayer.
- `MemWalMock.recall({ sort: "recent" })` orders a bounded semantic window (5× `limit`, at least `limit`, at most 50) by write time before truncating. Relevance order is unchanged. (#1124)
- Positional `recall(query, options, namespace)` uses that namespace when `options.namespace` is omitted, on both `MemWal` and `MemWalMock`. An explicit `options.namespace` still wins. (#1038)
- `remember(text, { idempotencyKey })` and `rememberAndWait(text, { timeoutMs }, { idempotencyKey })` treat a plain object in the namespace slot as options. A third options argument is merged, and its fields win. That call used to send the object as the namespace, or drop the third argument and mint a second blob. An explicit string namespace still wins. (#1142)
- `getRememberStatus("")` returns `not_found` without a request, and `waitForRememberJob("")` fails immediately with status 404. `GET /api/remember/` is not a route; the empty 404 body used to throw `SyntaxError`, and the wait treated that as transient until timeout. (#1087)
- `waitForRememberJobs` settles every slot when the same job id is listed more than once. `indexOf` plus a `Set` of ids left the later copies as `timeout`. (#1121, #1084)
- `rememberBulkAsync` rejects more than 20 items before signing, matching the relayer's `MAX_BULK_ITEMS`. (#1104)
- Remember-job status reads (`getRememberStatus`, `waitForRememberJob`, `getRememberBulkStatus`) no longer attach `x-seal-session`. Status is metadata and does not decrypt. (#1135)
- Bulk status includes each job's `namespace`. `waitForRememberJobs(jobIds)` uses that value when the caller did not pass one, instead of the client default. A caller-supplied namespace still wins. (#1136)
- `getPublicKeyHex()` and any request after `destroy()` throw, including a read already in flight. `getPublicKeyHex()` used to resolve to the zeroed key, or to the well-known key of the wiped seed, and `remember()` still sent `GET /version` before noticing the client was destroyed. (#1090)
- `normalizeServerUrl` no longer warns about plaintext HTTP for IPv6 loopback. `URL.hostname` keeps the brackets on `[::1]`, so the `::1` exemption never matched `http://[::1]:8000`. (#1128)
- `remember`, `rememberBulk`, `analyze`, and `embed` reject whitespace-only text immediately, with the same messages the relayer returns. A blank body used to be accepted and then sit until the client timed out. (#1129)
- A 401 `AUTH_REJECTED` now says a wallet address is not a MemWal account ID. The relayer still returns one 401 for every credential failure, so the message names the mix-up instead of revealing which check failed. (#1132)
- `rememberBulkAndWait` / `waitForRememberJobs` no longer resolve a batch they could not read as if it were still uploading. The status endpoint counts against the delegate-key budget, and a 429 on every poll used to be retried silently until the wait ran out, leaving each item as `timeout` with "polling timed out", even when nothing had been stored. When no poll got through, the wait now makes one confirming read. If that is rate-limited too, it throws `MemWalRateLimited` (`status: 429`, `jobIds`, `retryAfterSeconds`). An item still unsettled at the deadline names its last known status, or says no read got through. (#967)
- A `rememberAndWait` / `waitForRememberJob` that runs out of time now raises `MemWalRememberJobTimeout` (still `status: 504`) carrying `lastStatus` and `serverError`, the last state the relayer reported. Under upload congestion the relayer keeps a job `running` for up to ~25 minutes and says so, but the 504 used to drop that, so a job that was still retrying looked dead and callers dropped their idempotency key to force a new paid write. When no poll got through, the message says the state is unknown instead. (#966)
- Grow `waitForRememberJob` / `waitForRememberJobs` poll delay 1.5× from the caller interval (floor 100ms) toward a 5s cap, with an immediate first poll. Backoff is disabled above the cap.
- A 429 during a remember-job wait is reported on the timeout. Retry-After is still clamped to the caller's remaining budget, and that remainder still buys one status read.

## 0.1.8

### Added

- `recall()` sends its own deadline as `deadline_ms` (14000, a second under the 15s it aborts at, so the relayer's answer beats the abort even on a slow connect) in the request body. A relayer that reads it answers a recall about to miss that deadline with a 504 whose `serverCode` is `RECALL_TIMEOUT` and whose body names the stuck step (`auth`, `embed`, `vector_search`, `walrus_download`, `seal_decrypt`), instead of the request aborting with no cause. Relayers that predate the field ignore it.

### Fixed

- Every relayer request now carries a deadline. `fetch` has none of its own and the SDK passed an abort signal on exactly one method (`recall`, 15s), so the accept POST, every job-status read, and the `/version` and `/config` handshake calls could stay pending for as long as the socket stayed open. A poll loop checks its budget at the *top* of each iteration, which bounds when the next request starts rather than how long one takes — so a single stalled read ran straight past `timeoutMs`, and a `memwal_remember` documented as capping at 90s was observed by an MCP client still running after 120s. Requests default to 30s, matching the relayer's own outbound client; set it with `requestTimeoutMs` on `MemWal.create`, where a non-positive or non-finite value falls back to the default rather than disabling the bound. `restore` (60s) and `analyze` (60s) carry their own, since the route self-bounds at 55s and the extractor LLM runs inline respectively. Inside the wait loops each poll is bounded by the client deadline clamped to the remaining budget, so one stalled poll can neither outlive the wait nor swallow it. An expired request raises `MemWalRequestTimeout` with `status: 504`, which the existing transient-poll handling already retries; a caller's own abort and every other transport error propagate unchanged.
- Generated idempotency keys are derived from the content (a 30-minute bucket plus namespace and text) instead of `crypto.randomUUID()`. The per-instance key map only ever deduped retries that reused one client, and callers such as the MCP sidecar build a fresh client per session — so a replay after a reconnect read as a brand-new write and the relayer minted a second paid Walrus blob for one already in flight. The bucket bounds the collapse, since `remember_jobs` rows are never pruned. Callers passing an explicit `idempotencyKey` are unaffected, and distinct text or namespaces still derive distinct keys.

## 0.1.7

### Added

- `MemWalConfig.recallTimeoutMs` and `RecallOptions.timeoutMs` make recall's abort budget configurable (default: 15000, unchanged). `MemWalConfig.preflightTimeoutMs` / `MemWalManualConfig.preflightTimeoutMs` bound each preflight round-trip (default: 5000).
- `isTimeoutError()` is true for the `MemWalRequestTimeout` recall throws (status 504) and for a preflight `TimeoutError` whose `phase` names the stalled round-trip.
- `restore()` results include `failed` (required like `truncated`; SDK defaults omitted to `0`) for permanent decrypt/UTF-8 failures instead of folding them into `skipped` or dropping them silently.

### Fixed

- Hash request bodies with `@noble/hashes` instead of WebCrypto-or-`node:crypto`, so the package no longer imports a Node builtin on a browser-reachable path. Vite externalises such an import without warning: the app builds clean and the browser crashes the first time the path runs. The fallback could never have helped a browser anyway — `crypto.subtle` is absent precisely when the page is not a secure context, where `node:crypto` is absent too — so it only served Node <19 while being the sole source of the exposure. `sha256hex` sits on the signed-request path, so every remember and recall reached it. (#322)
- Declare `engines.node >= 20.0.0`, matching `memwal-mcp` and `openclaw-memory-memwal`. The SDK was the only published package without a floor.
- `recall()`'s timeout budget covers only the recall request. It previously started before `ensureCompatibleRelayer()` (`GET /version`, falling back to `GET /health`) and `buildSealSession()` (`GET /config` + Sui RPC), so a slow relayer preflight silently consumed the budget and recall raised an `AbortError` even when recall itself was healthy.
- `GET /version`, `GET /health` and `GET /config` carry an `AbortSignal` and a deadline. They previously ran with neither and could hang indefinitely.
- A request's deadline now covers the response body, not just its headers. `fetch()` resolves when headers arrive, so a server that then trickled the body could outlive the budget the caller named.
- Empty-body 401s now use the same AUTH_REJECTED troubleshooting message as credential 401s instead of telling callers to run `memwal_login`. Headless SDK clients do not have that MCP tool.
- `account.ts` and `manual.ts` PTBs use typed `tx.pure` helpers instead of the legacy untyped moveCall argument syntax that fails under modern `@mysten/sui`.
- An explicit `sort` on `recall()`, `"relevance"` included, is now the order: the relayer ignores `scoringWeights` for that request, and weights re-rank only when `sort` is omitted. Setting both used to return neither order, so `sort: "recent"` stopped meaning newest-first once `scoringWeights` carried a recency weight.

## 0.1.6

### Added

- `recall()` results include optional `created_at` (RFC3339 write-time of the stored fact).
- `RecallOptions` accepts `sort: "relevance" | "recent"` and `scoringWeights`. `sort: "recent"` over-fetches semantic candidates (5x `limit`, capped at 50), orders them by write-time descending, then truncates to `limit`.

### Fixed

- HTTP 503 with `x-auth-error: AUTH_UPSTREAM_UNAVAILABLE` is reported as a retryable credential-verification outage, not a sign-in failure. Other 503s keep the generic sanitized body. Empty-body 401s still point at `memwal_login`.
- Positional `recall(query, namespace)` now throws `TypeError` instead of silently ignoring the namespace.

## 0.1.5

### Added

- `recall()` results include `dropped_count` when the relayer omitted matches that failed to download or decrypt.
- `health()` surfaces optional `write_ready` when the relayer reports write-path sidecar liveness.

### Changed

- `rememberManual` now sends `encryptedData` (base64 SEAL ciphertext) instead of a pre-uploaded `blobId`, matching `POST /api/remember/manual`.

### Fixed

- Manual recall decodes SEAL object ids with `hexToBytes` instead of an unguarded `parseInt` / `.match!` path that could coerce `NaN` to `0` or throw on empty input.
- HTTP error messages and remember-job error strings no longer forward `localhost` / `127.0.0.1` URLs to callers.

## 0.1.4

### Fixed

- Empty-body 401s now tell first-time MCP callers to run `memwal_login` instead of showing `<no message>`. Credential 401s still point at the AUTH_REJECTED troubleshooting guide.

## 0.1.3

### Added

- Added client-side token estimation and recall token budgets with configurable truncation strategies.

### Fixed

- Updated the default SDK relayer URL to `https://relayer.memory.walrus.xyz`.

## 0.1.2

### Added

- Added deterministic offline mock clients for credential-free tests.
- Added idempotency keys to collapse retries onto one paid remember job.

### Fixed

- Isolated foreign manual-recall blobs and encoded large encrypted payloads safely.
- Added Zod 3 and Zod 4 peer compatibility.

## 0.1.1

### Added

- Added `flush()` for pending `withMemWal` auto-saves.
- Added `truncated` to restore results for incomplete recovery.

### Fixed

- Linked `AUTH_REJECTED` errors to troubleshooting guidance.

## 0.1.0

### Added

- Added sponsor authorization helpers for sponsored transaction flows.
- Added migration-aware account/manual configuration, including registry and current Sui transaction result support.

### Security

- Recalled AI memory is now nonce-delimited, explicitly untrusted data rather than content injected directly into the system role.

### Fixed

- Improved account transaction result handling and failure diagnostics across legacy and current Sui response shapes.

## 0.0.7

### Patch Changes

- [#218](https://github.com/MystenLabs/MemWal/pull/218) [`333d327`](https://github.com/MystenLabs/MemWal/commit/333d3279f59c2a033225bc99238b7586474333fb) Thanks [@hungtranphamminh](https://github.com/hungtranphamminh)! - Add optional `occurredAt` to `analyze()` and `analyzeAndWait()` for temporal anchoring of extracted facts.

  - New `AnalyzeOptions` overload: `analyze(text, { namespace, occurredAt })` accepts `Date` or RFC-3339 string. The legacy `analyze(text, namespace?)` signature still works unchanged.
  - When `occurredAt` is supplied, the server resolves in-turn relative references ("last Friday", "yesterday") into absolute dates inside the extracted fact text before embedding and encryption.
  - Wire format is RFC-3339 UTC with millisecond precision (e.g. `"2023-05-25T17:50:00.000Z"`).
  - Invalid `Date` instances (constructed from malformed input) now throw a diagnostic `TypeError` from the SDK rather than an opaque `RangeError` from `toISOString()`.
  - Field is omitted from the request body when not supplied — existing callers see byte-identical wire payloads.

## 0.0.6

### Added

- Added `RecallParams` for object-style `recall(...)` calls.

### Changed

- Marked the positional `recall(...)` overload as deprecated in favor of `recall({ query, limit, namespace })`.
- Documented `restore()` response fields, default limit, pagination behavior, and performance expectations.

## 0.0.5

### Added

- Added relayer compatibility metadata checks before protected requests.
- Added `compatibility()` and exported compatibility types/errors so callers can inspect SDK/relayer support explicitly.
- Added `RecallOptions` for `topK`, namespace override, and `maxDistance`.

### Changed

- Prefer Sui gRPC for SEAL sessions, with JSON-RPC fallback.
- Updated docs/examples for `MEMWAL_PRIVATE_KEY` and hosted relayer defaults.
- Rebranded package metadata and documentation from MemWal to Walrus Memory.

### Fixed

- Made `401` relayer errors more actionable.

## 0.0.4

### Added

- Added `getRememberStatus(jobId)` so clients can poll and display the full async remember state machine.
- Added `SealServerConfig` and `sealServerConfigs` for manual-mode SEAL committee aggregator configuration.

### Changed

- Manual mode now normalizes full SEAL server configs, validates optional API key pairs, and caps the default threshold to configured server weight.
- Manual mode keeps testnet defaults on the legacy independent key servers for compatibility with hosted testnet relayer data.

## 0.0.3

### Changed

- Updated `remember()` for the relayer's async `/api/remember` flow. It now returns the accepted job payload immediately.
- Added `rememberAsync()`, `waitForRememberJob()`, and `rememberAndWait()` for callers that need the final `blob_id`.
- Added bulk remember helpers: `rememberBulk()`, `rememberBulkAsync()`, `waitForRememberJobs()`, and `rememberBulkAndWait()`.
- Updated `analyze()` for async fact storage and added `analyzeAndWait()`.

### Compatibility

- `recall()` and `restore()` remain wire-compatible with the existing relayer responses.
- The SDK continues to use `x-seal-session` for relayer-mode decrypt credentials.

## 0.0.2

### Security

- Added per-request `x-nonce` signing to block replay within the timestamp window.
- Added `x-account-id` to the canonical signed message so account hints cannot be rebound in transit.
- Replaced relayer-mode `x-delegate-key` transport with ephemeral `x-seal-session`; manual-mode requests no longer send delegate private key material.
- SDK versions that do not send `x-nonce` are no longer supported by the server and receive `426 Upgrade Required`.

## 0.0.1

### Initial Release

- `MemWal` default client — relayer-handled embedding, SEAL encryption, Walrus upload, vector search
- `MemWalManual` manual client — client-side embedding and SEAL operations
- `withMemWal` Vercel AI SDK middleware — automatic memory recall and save
- Account management utilities — `createAccount`, `addDelegateKey`, `removeDelegateKey`, `generateDelegateKey`
- Ed25519 delegate key authentication
- Namespace-scoped memory isolation
