/**
 * Walrus Memory — Core Types
 *
 * Ed25519 delegate key based SDK that communicates with
 * the Walrus Memory Rust server (TEE).
 */

// ============================================================
// Config
// ============================================================

export interface MemWalConfig {
    /**
     * Ed25519 private key — the Walrus Memory delegate key. Accepts hex (with
     * or without `0x`), a Sui `suiprivkey1...` bech32 string, or raw bytes.
     */
    key: string | Uint8Array;
    /** Walrus Memory account object ID on Sui (ensures correct account when delegate key exists in multiple accounts) */
    accountId: string;
    /** Server URL (default: https://relayer.memory.walrus.xyz) */
    serverUrl?: string;
    /** Default namespace for memory isolation (default: "default") */
    namespace?: string;
    /**
     * Deadline for a single relayer request, in milliseconds (default: 30000).
     *
     * `fetch` has no timeout of its own, so without this a stalled connection
     * keeps a call pending for as long as the socket stays open — which is how
     * a `remember` whose poll budget was 90s could still be running after two
     * minutes. Endpoints that are legitimately slower (`restore`, `analyze`)
     * carry their own larger deadline and ignore this.
     *
     * Raise it only for a genuinely slow link; it is a backstop, not a budget.
     */
    requestTimeoutMs?: number;
    /**
     * Deadline for the `/api/recall` request itself, in milliseconds
     * (default: 15000). Per-call `RecallOptions.timeoutMs` overrides it.
     *
     * This budget covers only the recall round-trip. The preflights that
     * precede it (`/version`, `/config`, the SEAL session build) are bounded
     * separately by `preflightTimeoutMs`, so a slow relayer preflight can no
     * longer consume recall's budget and surface as a spurious abort.
     */
    recallTimeoutMs?: number;
    /**
     * Deadline for each unauthenticated preflight fetch — `GET /version`,
     * `GET /health`, `GET /config` — in milliseconds (default: 5000).
     *
     * Applied per round-trip, not to the preflight phase as a whole.
     */
    preflightTimeoutMs?: number;
}

// ============================================================
// API Types
// ============================================================

/** Options for `remember()` / `rememberAsync()`. */
export interface RememberOptions {
    /**
     * Optional idempotency key to prevent duplicate writes on retries.
     * Idempotency keys are scoped per `(owner, namespace)`, so identical
     * keys across different namespaces will not collide. Retrying within
     * the same namespace with the same key dedupes, while reusing a key
     * with different text in the same namespace produces HTTP 409 Conflict.
     */
    idempotencyKey?: string;
    /**
     * Opt-in content-hash deduplication (#769).
     *
     * When `true`, identical `(owner, namespace, text)` writes resolve to the
     * existing live remember job and `blob_id` without a time window, instead
     * of minting a duplicate Walrus blob and embedding call. If the existing
     * memory was later forgotten or deleted, a fresh write is performed.
     *
     * Defaults to `false` (or omitted), preserving the standard 30-minute
     * retry-window behavior.
     */
    dedupe?: boolean;
}

/** Options for `rememberAndWait()`. */
export interface RememberWaitOptions extends RememberOptions {
    pollIntervalMs?: number;
    timeoutMs?: number;
}

/** Result from remember() / rememberAsync() */
export interface RememberAcceptedResult {
    job_id: string;
    status: string;
}

/** Status returned for an async remember job */
export interface RememberJobStatus {
    job_id: string;
    status: "pending" | "running" | "uploaded" | "done" | "failed" | "not_found";
    owner?: string;
    namespace?: string;
    blob_id?: string;
    error?: string;
}

/** Result from rememberAndWait() / waitForRememberJob() */
export interface RememberResult {
    /** Stable server job_id used as the vector row id. */
    id: string;
    /** Async job id returned by remember(). */
    job_id?: string;
    blob_id: string;
    owner: string;
    namespace: string;
}

/** A single recalled memory */
export interface RecallMemory {
    blob_id: string;
    text: string;
    distance: number;
    /**
     * RFC3339 write-time of the memory, as recorded by the relayer when the
     * fact was stored. Lets a caller implement "newest wins" deterministically
     * instead of re-ranking on a date parsed back out of `text` (WALM-383).
     *
     * This is the *write* time, not any event time the text itself describes.
     *
     * Optional because relayers older than this field omit it. Results are
     * ranked by relevance, not recency, unless you ask for a recency
     * ordering via `RecallOptions.sort`.
     */
    created_at?: string;
}

/**
 * Token-budget metadata attached to a RecallResult when a `maxTokens` budget was
 * requested. Lets callers/telemetry assert "this recall cost ≤ N tokens".
 */
export interface RecallTokenMeta {
    /**
     * Estimated token count of the RETURNED `results` payload (sum of per-hit
     * estimates, after any truncation). This is the value a caller can assert a
     * budget against, e.g. `meta.tokenEstimate <= maxTokens`. It is the
     * post-truncation cost, not the pre-truncation total.
     */
    tokenEstimate: number;
    /** True if any hit was dropped or shortened to fit the `maxTokens` budget. */
    truncated: boolean;
}

/** Result from recall() */
export interface RecallResult {
    results: RecallMemory[];
    total: number;
    /**
     * Present only when a `maxTokens` budget was supplied to recall(). Additive
     * and optional — omitted for budget-less recalls, so existing callers are
     * unaffected.
     */
    meta?: RecallTokenMeta;
    /** Matches omitted because blob download or decrypt failed. Omitted when 0. */
    dropped_count?: number;
}

/**
 * How recall trims recalled memories to fit a `maxTokens` budget.
 *
 * - `high-relevance-only` (default): keep the lowest-distance hits whole, in
 *   order, until the next hit would exceed the budget; drop the rest. No hit is
 *   ever partially shown.
 * - `per-hit-cap`: cap each hit's text to an equal share of the budget
 *   (`floor(maxTokens / hitCount)`). Hits whose share rounds to zero (more hits
 *   than budget tokens) are dropped rather than returned empty.
 * - `drop-tail`: preserve order and keep whole hits from the front, then
 *   truncate the single boundary hit that straddles the budget so the payload
 *   fills to the end of the concatenated budget. The last kept hit may be a
 *   shortened partial (this is what distinguishes it from `high-relevance-only`).
 */
export type TruncationStrategy = "high-relevance-only" | "per-hit-cap" | "drop-tail";

/** Options for recall(). */
export interface RecallOptions {
    /** Max number of nearest memories to request from the relayer (default: 10, relayer caps at 100). Must be a positive integer. */
    limit?: number;
    /** Alias for limit, useful when describing top-K search behaviour. */
    topK?: number;
    /** Namespace override (default: config namespace or "default"). */
    namespace?: string;
    /** Drop memories whose distance is greater than or equal to this value. */
    maxDistance?: number;
    /**
     * Client-side token budget for the returned payload. When set, recall trims
     * the results (per `truncationStrategy`) so their estimated token count fits,
     * and attaches `meta.tokenEstimate` / `meta.truncated`. Omit for the current
     * (unbudgeted) behavior. Counting is an estimate — see `countTokens`.
     */
    maxTokens?: number;
    /**
     * Strategy used when `maxTokens` is set. Default: `high-relevance-only`.
     * Ignored when `maxTokens` is not set.
     */
    truncationStrategy?: TruncationStrategy;
    /**
     * Custom exact token counter (e.g. a tiktoken binding). When omitted, a
     * zero-dependency character-based approximation (~chars/4) is used. Only
     * consulted when `maxTokens` is set.
     */
    countTokens?: (text: string) => number;
    /**
     * Composite-scoring weights applied by the relayer's ranker before results
     * are returned.
     *
     * Omit for the default behaviour: pure semantic ranking by cosine
     * distance, with no recency guarantee. Supply `recency` to blend
     * write-time into the score.
     *
     * IMPORTANT — this re-ranks the candidates the vector search already
     * returned; it does not widen the search. The relayer selects the cosine
     * top-`limit` first and the ranker reorders only those, so a record that
     * fell outside the window (because an older one matched your wording more
     * literally) cannot be recovered by any weighting. Weighting also has to
     * overcome the semantic gap to reorder: with the default 30-day half-life,
     * two records days apart barely differ on the recency term.
     *
     * For newest-wins, use `sort: "recent"` instead. It over-fetches
     * candidates server-side before ordering them by write-time.
     *
     * Ignored when `sort` is set: an explicit `sort`, `"relevance"` included,
     * decides the order, and weights apply only when `sort` is omitted.
     */
    scoringWeights?: ScoringWeights;
    /**
     * How the relayer orders results. Defaults to `"relevance"`.
     *
     * - `"relevance"` — semantic similarity only, the cosine order.
     * - `"recent"` — newest-among-matches. The relayer over-fetches semantic
     *   candidates, orders them by write-time descending, then truncates to
     *   `limit`.
     *
     * Prefer this over `scoringWeights` for anything newest-wins. `sort`
     * widens the candidate set; weights only re-rank the set that was already
     * returned, so weights alone cannot surface a record that fell outside
     * the window.
     *
     * Setting `sort` at all makes the relayer ignore `scoringWeights`.
     */
    sort?: "relevance" | "recent";
    /**
     * Deadline for the `/api/recall` request, in milliseconds. Defaults to
     * `MemWalConfig.recallTimeoutMs`, itself 15000.
     *
     * The clock starts once the preflights (`/version`, `/config`, the SEAL
     * session build) have completed, so this is a budget for recall alone.
     * Pass `0` (or `Infinity`) to opt out of the deadline entirely.
     *
     * On expiry recall throws a `TimeoutError` whose `phase` is
     * `"POST /api/recall"`; a preflight that blows its own budget throws one
     * naming that preflight instead.
     */
    timeoutMs?: number;
}

/** Recommended object-style recall input — preferred over positional args. */
export interface RecallParams extends RecallOptions {
    /** Search query text. */
    query: string;
}

/** Optional composite-scoring weights for recall ranking. */
export interface ScoringWeights {
    /** Weight applied to semantic similarity (`1.0 - distance`). Default: 1. */
    semantic?: number;
    /** Weight applied to recency decay. Default: 0. */
    recency?: number;
    /** Half-life for the recency term, in days. Default: 30. */
    recencyHalfLifeDays?: number;
    /** Weight applied to memory importance. Default: 0. */
    importance?: number;
}

/** Result from rememberBulk() / rememberBulkAsync() */
export interface RememberBulkAcceptedResult {
    job_ids: string[];
    total: number;
    status: string;
}

/** Per-item status returned from the bulk status endpoint */
export interface RememberBulkStatusItem {
    job_id: string;
    status: "pending" | "running" | "uploaded" | "done" | "failed" | "not_found";
    /** Set when the relayer found the job. Absent for `not_found`. */
    namespace?: string;
    blob_id?: string;
    error?: string;
}

/** Result from getRememberBulkStatus() */
export interface RememberBulkStatusResult {
    results: RememberBulkStatusItem[];
}

/** One item in a bulk remember request */
export interface RememberBulkItem {
    /** The text to remember */
    text: string;
    /** Optional per-item namespace override (falls back to client default) */
    namespace?: string;
}

/** Options for rememberBulk / rememberBulkAsync requests */
export interface RememberBulkAsyncOptions {
    /** Optional caller-supplied idempotency key (defaults to derived key based on items) */
    idempotencyKey?: string;
}

/** Options for remember bulk polling behaviour */
export interface RememberBulkOptions extends RememberBulkAsyncOptions {
    /** How often to poll each job_id (default: 1500ms) */
    pollIntervalMs?: number;
    /** Max total wait time before throwing (default: 120_000ms) */
    timeoutMs?: number;
}

/** Per-item result returned from rememberBulkAndWait() / waitForRememberJobs() */
export interface RememberBulkItemResult {
    /** job_id returned by the server */
    id: string;
    /** Walrus blob_id once the job completes ("" if failed) */
    blob_id: string;
    /** Final status reported by the server: "done" | "failed" | "timeout" */
    status: "done" | "failed" | "timeout";
    /** Namespace the memory was stored under */
    namespace: string;
    /** Error message if status !== "done" */
    error?: string;
}

/** Result from rememberBulkAndWait() / waitForRememberJobs() */
export interface RememberBulkResult {
    /** One result per input item, in the same order */
    results: RememberBulkItemResult[];
    /** Total items submitted */
    total: number;
    /** Count of items that reached status=done */
    succeeded: number;
    /** Count of items that failed or timed out */
    failed: number;
}

/** Result from embed() */
export interface EmbedResult {
    vector: number[];
}

/** A single memory used as context by ask() */
export interface AskMemory {
    blob_id: string;
    text: string;
    distance: number;
    score?: number;
    created_at?: string;
}

/** Result from ask() */
export interface AskResult {
    answer: string;
    memories_used: number;
    memories: AskMemory[];
}

/** Options for ask() */
export interface AskOptions {
    /** Max memories to use as context (default: 5, relayer caps at 100). Must be a positive integer. */
    limit?: number;
    /** Namespace override (default: config namespace or "default"). */
    namespace?: string;
    /** Optional composite-scoring weights applied by the relayer's ranker before injecting memories. */
    scoringWeights?: ScoringWeights;
    /** Optional request deadline in milliseconds. */
    timeoutMs?: number;
}

/** Object-style ask() input. */
export interface AskParams extends AskOptions {
    /** The question to ask. */
    question: string;
}

/** Options for analyze() / analyzeAndWait(). */
export interface AnalyzeOptions {
    /** Override the default namespace for this call. */
    namespace?: string;
    /**
     * Optional valid-time timestamp for the analyzed input — when the
     * conversation/event actually happened. When supplied, the server
     * extractor uses it as a temporal anchor and resolves in-turn
     * relative references ("last Friday", "yesterday") into absolute
     * dates inside the resulting fact text (and the embedding) before
     * encryption.
     *
     * Accepts a `Date` object (preferred) or an ISO-8601 / RFC-3339
     * string. The wire format sent to the server is RFC-3339 UTC with
     * a trailing `Z` (e.g. `"2023-05-25T17:50:00Z"`).
     *
     * Omit when no anchor is available — the server will not invent
     * one (no `now()` fallback; silence is honest). The resolved date
     * lives only inside the encrypted fact text + embedding; there is
     * no server-readable metadata column for it (Architecture A).
     */
    occurredAt?: string | Date;
    /**
     * Optional `AbortSignal` to cancel the `/api/analyze` request. When
     * aborted before or during the request, the in-flight HTTP call is aborted
     * immediately and `analyze()` rejects with the signal's abort reason.
     */
    signal?: AbortSignal;
}

/** A fact extracted by analyze() and accepted for background storage. */
export interface AnalyzedFact {
    text: string;
    /** Stable job id/vector row id for this extracted fact. */
    id: string;
    /** Polling id for this extracted fact. */
    job_id?: string;
    /** Walrus blob_id once the background job completes. */
    blob_id?: string;
}

/** Result from analyze() */
export interface AnalyzeResult {
    job_ids: string[];
    facts: AnalyzedFact[];
    fact_count: number;
    status: string;
    owner: string;
}

/** Result from analyzeAndWait() */
export interface AnalyzeWaitResult extends RememberBulkResult {
    facts: AnalyzedFact[];
    owner: string;
}

/** Server health response */
export interface HealthResult extends Partial<RelayerVersionMetadata> {
    status: string;
    /** Backward-compatible relayer package version alias. */
    version: string;
    /** "production" or "benchmark" when returned by modern relayers. */
    mode?: string;
    /** False when writes are not ready; omit means the relayer did not report it. */
    write_ready?: boolean;
    prompt_versions?: {
        extract: string;
        ask: string;
    };
}

/** Minimum SDK versions accepted by a relayer API contract. */
export interface MinSupportedSdk {
    typescript: string;
    python: string;
    mcp: string;
}

/** Public deprecation metadata returned by GET /version and GET /health. */
export interface RelayerDeprecationNotice {
    surface: string;
    deprecatedSince: string;
    removalApiVersion: string;
    guidance: string;
}

/** Public build metadata returned by GET /version and GET /health. */
export interface RelayerBuildMetadata {
    commit?: string;
    buildTimestamp?: string;
}

/** Runtime compatibility metadata returned by GET /version. */
export interface RelayerVersionMetadata {
    relayerVersion: string;
    apiVersion: string;
    minSupportedSdk: MinSupportedSdk;
    featureFlags: Record<string, boolean>;
    deprecations: RelayerDeprecationNotice[];
    build: RelayerBuildMetadata;
}

// ============================================================
// Manual Flow Types — Lightweight (user provides pre-computed data)
// ============================================================

/** Options for rememberManual() on MemWal class */
export interface RememberManualOptions {
    /** Base64-encoded SEAL-encrypted bytes. The relayer uploads them to Walrus. */
    encryptedData: string;
    /** Embedding vector (user already generated) */
    vector: number[];
    /** Namespace (default: config namespace or "default") */
    namespace?: string;
}

/** Result from rememberManual() */
export interface RememberManualResult {
    id: string;
    blob_id: string;
    owner: string;
    namespace: string;
}

/** Options for recallManual() on MemWal class */
export interface RecallManualOptions {
    /** Pre-computed query embedding vector */
    vector: number[];
    /** Max number of results (default: 10, relayer caps at 100). Must be a positive integer. */
    limit?: number;
    /** Namespace (default: config namespace or "default") */
    namespace?: string;
    /** Optional composite-scoring weights applied before returning hits. */
    scoringWeights?: ScoringWeights;
}

/** A single search hit — raw blobId + distance (no decrypted text) */
export interface RecallManualHit {
    blob_id: string;
    distance: number;
}

/** One namespace in a `listNamespaces()` page. Mirrors the relayer wire shape. */
export interface NamespaceSummary {
    id: string;
    name: string;
    memory_count: number;
    storage_used: number;
    /**
     * `MAX(updated_at)` across the namespace's memories — the same value the
     * keyset cursor is built from, surfaced so callers can tell *what*
     * changed rather than only that their watermark moved.
     */
    updated_at: string;
}

/** Result from listNamespaces() */
export interface NamespacesResult {
    namespaces: NamespaceSummary[];
    /**
     * Watermark to hand back as `cursor` on the next call. Populated on every
     * page, including the last, so a caller that has finished syncing still
     * has a checkpoint to poll from later.
     */
    next_cursor: string | null;
    /**
     * Authoritative "keep paginating" signal. Do NOT infer this from page
     * length: the server silently clamps `limit`, so a caller asking for more
     * than the cap gets exactly the cap back and would wrongly conclude it
     * was done.
     */
    has_more: boolean;
    snapshot_version: number;
}

/** Options for listNamespaces() */
export interface ListNamespacesOptions {
    /** Previous page's `next_cursor`, to continue a walk or poll incrementally. */
    cursor?: string;
    /** Page size. Server defaults to 100 and clamps to 500. */
    limit?: number;
}

/** One memory in a `listMemories()` page. Mirrors the relayer wire shape. */
export interface MemorySummary {
    memory_id: string;
    /** The namespace name (the same string passed to `remember()` / `recall()`). */
    namespace_id: string;
    blob_id: string;
    created_at: string;
    /** The row's `updated_at` — the value the keyset cursor is built from. */
    updated_at: string;
    /** Encrypted blob size in bytes. */
    size: number;
    agent_id: string | null;
    package_id: string | null;
    status: string;
    end_epoch: number | null;
    expires_at: string | null;
    importance: number | null;
}

/** A memory removed since the cursor. Never mixed into `memories`. */
export interface DeletedMemorySummary {
    memory_id: string;
    namespace_id: string;
    deleted_at: string;
}

/** Result from listMemories() */
export interface MemoriesResult {
    memories: MemorySummary[];
    /** Watermark to hand back as `cursor` on the next call. */
    next_cursor: string | null;
    /**
     * Authoritative "keep paginating" signal. Do NOT infer this from page
     * length: the server clamps `limit`, and a `namespace` filter can leave a
     * page short or empty while more pages remain.
     */
    has_more: boolean;
    snapshot_version: number;
    /** Tombstones since the cursor, for incremental sync. */
    deleted: DeletedMemorySummary[];
    /**
     * True when the cursor is too old for the relayer to know what was
     * deleted since; restart the walk without a cursor.
     */
    must_resync: boolean;
}

/** Options for listMemories() */
export interface ListMemoriesOptions {
    /** Previous page's `next_cursor`, to continue a walk or poll incrementally. */
    cursor?: string;
    /** Page size, counted before any `namespace` filter. Server defaults to 100 and clamps to 500. */
    limit?: number;
    /**
     * Keep only this namespace. Applied client-side: the relayer lists every
     * namespace, so a filtered page can be empty while `has_more` is true.
     */
    namespace?: string;
}

/** Result from restore() */
export interface RestoreResult {
    restored: number;
    skipped: number;
    /**
     * Permanent decrypt/UTF-8 failures on this on-chain page: negative-cache
     * hits plus any new permanent failures this call. Relayers older than
     * COMG-719 omit this field; the SDK defaults it to `0`.
     */
    failed: number;
    total: number;
    namespace: string;
    owner: string;
    /**
     * True when this restore is known-incomplete: more on-chain blobs were
     * missing locally than `limit` allowed this call to restore, or the
     * sidecar's owner-wide candidate fetch hit its cap *and* raising
     * `limit` can still expand that fetch (`limit < 20`). Once the cap is
     * saturated, truncation follows this call's missing-blob page, not
     * on-chain `total`, so a fully restored namespace does not loop
     * (WALM-431 / GH #762). Also true when an inspected page produced only
     * transients (download/decrypt/embed) so the caller retries (WALM-480).
     *
     * `truncated=false` is not proof the sidecar saw every on-chain blob.
     * Blobs beyond the owner-wide sidecar candidate cap can still be
     * missing. Follow-up field: WALM-451 (`sourceCapped`).
     *
     * Relayers older than WALM-319 don't send this field at all; the SDK
     * defaults it to `false` in that case rather than requiring it.
     */
    truncated: boolean;
}

// ============================================================
// Full Client-Side Manual Flow — MemWalManual class
// ============================================================

/** Full @mysten/seal server config. Committee servers require aggregatorUrl. */
export interface SealServerConfig {
    /** On-chain SEAL key server or committee object ID */
    objectId: string;
    /** Server weight for threshold encryption. Defaults to 1. */
    weight?: number;
    /** Committee aggregator URL. Required for committee mode servers. */
    aggregatorUrl?: string;
    /** Optional API key header name for permissioned key servers */
    apiKeyName?: string;
    /** Optional API key value for permissioned key servers */
    apiKey?: string;
}

/** Config for MemWalManual (full client-side: SEAL + Walrus + embedding) */
export interface MemWalManualConfig {
    /** Ed25519 delegate private key (hex, `suiprivkey1...`, or Uint8Array) for server auth */
    key: string | Uint8Array;
    /** Server URL (default: https://relayer.memory.walrus.xyz) */
    serverUrl?: string;
    /**
     * Sui private key (bech32 suiprivkey1...) for SEAL + Walrus signing.
     * Provide EITHER this OR `walletSigner` — not both.
     */
    suiPrivateKey?: string;
    /**
     * Connected wallet signer (e.g. from dapp-kit).
     * Use this when the user's wallet is already connected in the browser.
     * Provide EITHER this OR `suiPrivateKey` — not both.
     */
    walletSigner?: WalletSigner;
    /**
     * Pre-configured Sui client instance (e.g. from dapp-kit's useSuiClient()).
     * If omitted, the SDK creates a gRPC client against the public fullnode
     * for `suiNetwork`. Pass one to use a different endpoint or transport.
     */
    suiClient?: any;
    /** OpenAI/OpenRouter API key for embeddings (required for client-side embedding) */
    embeddingApiKey: string;
    /** OpenAI-compatible API base URL (default: https://api.openai.com/v1) */
    embeddingApiBase?: string;
    /** Embedding model name (default: text-embedding-3-small) */
    embeddingModel?: string;
    /** Immutable first-published package ID used by SEAL encryption and SessionKey */
    packageId: string;
    /** Current package containing account::seal_approve (defaults to packageId) */
    sealPolicyPackageId?: string;
    /** Walrus Memory account object ID (for SEAL seal_approve) */
    accountId: string;
    /** AccountRegistry shared object ID passed to SEAL seal_approve */
    registryId: string;
    /** Sui network (default: mainnet) */
    suiNetwork?: "testnet" | "mainnet";
    /**
     * Full SEAL server configs, including committee aggregators.
     * Takes priority over legacy sealKeyServers when provided.
     */
    sealServerConfigs?: SealServerConfig[];
    /**
     * Legacy custom SEAL independent key server object IDs.
     * Array of on-chain object IDs, e.g. ["0x..."].
     * If omitted, uses sealServerConfigs or built-in defaults for the selected suiNetwork.
     */
    sealKeyServers?: string[];
    /**
     * SEAL threshold — number of key server shares required for encrypt/decrypt.
     * Must be ≤ the total configured SEAL server weight.
     * Default: 2, capped to the total configured SEAL server weight.
     */
    sealThreshold?: number;
    /** Walrus storage epochs (default: 50) */
    walrusEpochs?: number;
    /** Walrus aggregator URL for direct blob downloads (default: mainnet aggregator) */
    walrusAggregatorUrl?: string;
    /** Walrus publisher URL for direct blob uploads (default: mainnet publisher) */
    walrusPublisherUrl?: string;
    /** Default namespace for memory isolation (default: "default") */
    namespace?: string;
    /**
     * Deadline for the unauthenticated compatibility preflight (`GET /version`,
     * falling back to `GET /health`), in milliseconds (default: 5000).
     * Applied per round-trip.
     */
    preflightTimeoutMs?: number;
}

/**
 * Wallet signer interface — pass a connected wallet adapter.
 * Compatible with @mysten/dapp-kit's useSignAndExecuteTransaction.
 */
export interface WalletSigner {
    /** Wallet address (Sui address, 0x...) */
    address: string;
    /** Sign and execute a transaction, returning either the legacy or v2 result shape */
    signAndExecuteTransaction: (input: {
        transaction: any;
    }) => Promise<
        | { digest: string }
        | { $kind: "Transaction"; Transaction: { digest: string }; FailedTransaction?: never }
        | { $kind: "FailedTransaction"; Transaction?: never; FailedTransaction: { digest: string } }
    >;
    /** Sign a personal message (for SEAL SessionKey) */
    signPersonalMessage: (input: {
        message: Uint8Array;
    }) => Promise<{ signature: string }>;
}

/** Options for MemWalManual.recallManual(). */
export interface MemWalManualRecallOptions {
    /** Max number of results (default: 10). */
    limit?: number;
    /** Namespace (default: config namespace or "default"). */
    namespace?: string;
    /** Optional composite-scoring weights applied before returning hits. */
    scoringWeights?: ScoringWeights;
}

/** A recalled memory with decrypted text (from MemWalManual.recallManual) */
export interface RecallManualMemory {
    blob_id: string;
    text: string;
    distance: number;
}

/** `MemWal.recallManual()` — blob id and distance, no decrypted text. */
export interface RecallManualHitResult {
    results: RecallManualHit[];
    total: number;
}

/** `MemWalManual.recallManual()` — decrypted memories. */
export interface RecallManualMemoryResult {
    results: RecallManualMemory[];
    total: number;
}

/**
 * @deprecated Use {@link RecallManualHitResult} or {@link RecallManualMemoryResult}.
 * Each method returns one of those, not a mixed list of hits and memories.
 */
export type RecallManualResult = RecallManualHitResult | RecallManualMemoryResult;

// ============================================================
// Account Management Types
// ============================================================

/** Base options for on-chain account transactions */
interface AccountTxOpts {
    /** Walrus Memory contract package ID on Sui */
    packageId: string;
    /**
     * Sui private key (bech32 suiprivkey1...) for signing.
     * Provide EITHER this OR `walletSigner` — not both.
     */
    suiPrivateKey?: string;
    /**
     * Connected wallet signer (e.g. from dapp-kit).
     * Provide EITHER this OR `suiPrivateKey` — not both.
     */
    walletSigner?: WalletSigner;
    /**
     * Pre-configured Sui client instance.
     * If omitted, the SDK creates a gRPC client against the public fullnode
     * for `suiNetwork`. Pass one to use a different endpoint or transport.
     */
    suiClient?: any;
    /** Sui network (default: mainnet) */
    suiNetwork?: "testnet" | "mainnet";
}

/** Options for createAccount() */
export interface CreateAccountOpts extends AccountTxOpts {
    /** AccountRegistry shared object ID */
    registryId: string;
}

/** Result from createAccount() */
export interface CreateAccountResult {
    /** Created Walrus Memory account object ID */
    accountId: string;
    /** Owner Sui address */
    owner: string;
    /** Transaction digest */
    digest: string;
}

/** Options for addDelegateKey() */
export interface AddDelegateKeyOpts extends AccountTxOpts {
    /** Walrus Memory account object ID */
    accountId: string;
    /** AccountRegistry shared object ID */
    registryId: string;
    /** Ed25519 public key (32 bytes Uint8Array or hex string) */
    publicKey: Uint8Array | string;
    /** Human-readable label (e.g. "MacBook Pro", "Production Server") */
    label: string;
}

/** Result from addDelegateKey() */
export interface AddDelegateKeyResult {
    /** Transaction digest */
    digest: string;
    /** Public key hex */
    publicKey: string;
    /** Derived Sui address for this delegate key */
    suiAddress: string;
}

/** Options for removeDelegateKey() */
export interface RemoveDelegateKeyOpts extends AccountTxOpts {
    /** Walrus Memory account object ID */
    accountId: string;
    /** AccountRegistry shared object ID */
    registryId: string;
    /** Ed25519 public key to remove (32 bytes Uint8Array or hex string) */
    publicKey: Uint8Array | string;
}
