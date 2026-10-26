/**
 * Walrus Memory — SDK Client
 *
 * Ed25519 delegate key based client that communicates with the Walrus Memory
 * Rust server (TEE). All data processing (encryption, embedding, Walrus)
 * happens server-side — the SDK just signs requests and sends text.
 *
 * The SDK only needs a single Ed25519 private key (the "delegate key").
 * The server derives the owner address from the public key via onchain
 * lookup in MemWalAccount.delegate_keys.
 *
 * @example
 * ```typescript
 * import { MemWal } from "@mysten-incubation/memwal"
 *
 * const memwal = MemWal.create({
 *     key: process.env.MEMWAL_PRIVATE_KEY,  // Ed25519 private key (hex)
 *     accountId: process.env.MEMWAL_ACCOUNT_ID, // Walrus Memory account object ID
 * })
 *
 * // Remember — returns an accepted background job immediately
 * const accepted = await memwal.remember("I'm allergic to peanuts")
 * await memwal.waitForRememberJob(accepted.job_id)
 *
 * // Recall — server: verify → embed query → search → download → decrypt
 * const result = await memwal.recall({ query: "food allergies" })
 * console.log(result.results[0].text) // "I'm allergic to peanuts"
 * ```
 */

import type {
    MemWalConfig,
    RememberResult,
    RecallResult,
    RecallMemory,
    RecallOptions,
    RecallParams,
    EmbedResult,
    AnalyzeOptions,
    AnalyzeResult,
    AnalyzeWaitResult,
    HealthResult,
    RememberManualOptions,
    RememberManualResult,
    RecallManualOptions,
    RecallManualHitResult,
    RestoreResult,
    NamespacesResult,
    ListNamespacesOptions,
    MemoriesResult,
    ListMemoriesOptions,
    RememberBulkItem,
    RememberBulkOptions,
    RememberBulkAsyncOptions,
    RememberBulkResult,
    RememberAcceptedResult,
    RememberJobStatus,
    RememberBulkAcceptedResult,
    RememberBulkStatusResult,
    RememberBulkStatusItem,
    RememberBulkItemResult,
    RelayerVersionMetadata,
} from "./types.js";
import {
    sha256hex,
    hexToBytes,
    bytesToHex,
    normalizePrivateKey,
    normalizeServerUrl,
    assertNonBlankText,
    sanitizeServerError,
    redactInternalUrls,
    clockDriftErrorFromResponse,
    assertFiniteScoringWeights,
    scoringWeightsToWire,
    derivedIdempotencyKey,
    derivedBulkIdempotencyKey,
    DEFAULT_PREFLIGHT_TIMEOUT_MS,
    DEFAULT_RECALL_TIMEOUT_MS,
    RESTORE_REQUEST_TIMEOUT_MS,
} from "./utils.js";
import {
    assertCompatibleRelayer,
    compatibilityErrorFromStatus,
} from "./compatibility.js";
import { applyTokenBudget, estimateTokens, validateMaxTokens } from "./tokens.js";
import { pollingDelayMs } from "./polling-delay.js";
import { resolveRecallCall } from "./recall-args.js";
import {
    MemWalRateLimitedError,
    MemWalRememberJobFailedError,
    MemWalRememberJobNotFoundError,
    MemWalRememberJobTimeoutError,
} from "./errors.js";

// ============================================================
// Ed25519 Signing (lazy-loaded)
// ============================================================

let _ed: typeof import("@noble/ed25519") | null = null;
async function getEd() {
    if (!_ed) {
        _ed = await import("@noble/ed25519");
    }
    return _ed;
}

// ============================================================
// MemWal Client
// ============================================================

// ENG-1697: SEAL SessionKey cache layout. `bytes` holds the
// base64(JSON(ExportedSessionKey)) envelope transmitted in the
// `x-seal-session` header. `expiresAt` is an absolute epoch-millis
// deadline with a safety margin applied so we refresh before the SEAL
// key servers observe the session as expired.
interface SessionCacheEntry {
    bytes: string;
    expiresAt: number;
}

interface ServerConfig {
    packageId: string;
    network: string;
    suiRpcUrl?: string;
    suiGrpcUrl?: string;
    suiTransport: "grpc" | "jsonrpc";
}

const SEAL_SESSION_TTL_MIN = 5;
// Refresh 30 seconds before SEAL's 5-minute TTL to avoid the window where
// the client thinks the session is valid but a just-received request hits
// a key server that sees it as expired.
const SEAL_SESSION_SAFETY_MARGIN_MS = 30_000;

/** Per-call knobs for `MemWal.signedRequest`. */
interface SignedRequestOptions {
    /** ENG-1696: omit the SEAL credential on Manual-mode routes. */
    includeDelegateKey?: boolean;
    /** Caller-owned cancellation, honoured alongside `timeoutMs`. */
    signal?: AbortSignal;
    /**
     * Deadline for the signed request itself. The clock starts after the
     * preflights resolve. Omit this to use the client `requestTimeoutMs`.
     * `0`, a negative number, or a non-finite value disables the deadline.
     */
    timeoutMs?: number;
}

type RememberStatusResponse = RememberJobStatus | { error?: string };

/** Path for one remember-job read, or undefined when `jobId` is not one safe segment.
 *
 * `fetch` rewrites the path after the request is signed. `.` becomes
 * `/api/remember/`, `..` and `%2e%2e` become `/api/`, and a backslash becomes
 * a slash. An allowlist keeps those from leaving the client. A UUID is
 * unchanged. (#1087, #1216)
 */
function rememberStatusPath(jobId: string): string | undefined {
    if (typeof jobId !== "string" || !/^[A-Za-z0-9_-]+$/.test(jobId)) {
        return undefined;
    }
    return `/api/remember/${jobId}`;
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}


/** Deadline for a request that names no other.
 *
 * `fetch` imposes none, and a poll loop checks its budget only between polls —
 * so one stalled read ran past `timeoutMs` entirely. 30s mirrors the relayer's
 * own outbound client. */
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;

/** The one confirming read a bulk wait makes after its budget is spent. It
 * runs past the caller's deadline by design, so it gets a short bound of its
 * own rather than the 30s default a stalled socket would hold it for. */
const CONFIRM_READ_TIMEOUT_MS = 5_000;

/** Matches the relayer's `MAX_BULK_ITEMS`. Reject before a signed request. */
const MAX_BULK_ITEMS = 20;

interface RememberCallOptions {
    /**
     * Optional idempotency key to prevent duplicate writes on retries.
     * Idempotency keys are scoped per (owner, namespace), so identical
     * keys across different namespaces will not collide. Retrying within
     * the same namespace with the same key dedupes, while reusing a key
     * with different text in the same namespace produces HTTP 409 Conflict.
     */
    idempotencyKey?: string;
    pollIntervalMs?: number;
    timeoutMs?: number;
}

/**
 * `remember(text, { idempotencyKey })` is the natural call when the namespace
 * stays at the client default. A plain object in the namespace slot is those
 * options, not a namespace name. (#1142)
 */
function splitRememberArgs(
    namespaceOrOptions?: string | RememberCallOptions,
    options?: RememberCallOptions,
): { namespace?: string; options: RememberCallOptions } {
    // The third argument is the dedicated options bag. When the namespace
    // slot is also an object, keep both and let the bag win on a clash.
    // `rememberAndWait(text, { timeoutMs }, { idempotencyKey })` is typed
    // and used to drop the key, so a retry minted a second blob. (#1142)
    if (typeof namespaceOrOptions === "object" && namespaceOrOptions !== null) {
        return { namespace: undefined, options: { ...namespaceOrOptions, ...options } };
    }
    return { namespace: namespaceOrOptions, options: options ?? {} };
}

function requireRememberText(text: unknown): asserts text is string {
    if (typeof text !== "string") {
        throw new TypeError(
            `remember() expects text as a string, received ${typeof text}. ` +
            `Did you mean remember(text, namespace)? Unlike recall(), remember* does not take an options object.`,
        );
    }
}

function destroyedClientError(): Error {
    return new Error(
        "Walrus Memory client was destroyed; its keys are zeroed. Create a new one.",
    );
}

/** `POST /api/analyze` runs the extractor LLM inline before it accepts, so it
 * is the one write that legitimately outruns the default. */
const ANALYZE_REQUEST_TIMEOUT_MS = 60_000;



/** How far under the client's own abort `recall()` asks the relayer to stop,
 * so the 504 naming the stuck stage arrives before the abort rather than
 * after it. A second, because the two clocks start at different moments: this
 * timer starts before `fetch`, the relayer's when the request lands, and the
 * margin the relayer keeps for its reply cannot also cover DNS, TCP and TLS. */
const RECALL_DEADLINE_MARGIN_MS = 1_000;

/**
 * Abort signal that fires after `ms`, or when `caller` aborts — whichever is
 * first. Built by hand rather than with `AbortSignal.any`, which lands too
 * recently to rely on across Node, browsers and Workers alike.
 *
 * Returns the signal plus a `dispose` the caller must run in a `finally`, so a
 * pending timer never outlives its request.
 */
function deadlineSignal(
    ms: number,
    caller?: AbortSignal,
): { signal: AbortSignal; timedOut: () => boolean; dispose: () => void } {
    const controller = new AbortController();
    let expired = false;

    const onCallerAbort = () => controller.abort(caller?.reason);
    if (caller) {
        if (caller.aborted) controller.abort(caller.reason);
        else caller.addEventListener("abort", onCallerAbort, { once: true });
    }

    const timer = setTimeout(() => {
        expired = true;
        controller.abort();
    }, ms);
    // Deliberately NOT unref'd. A deadline is the one timer somebody IS
    // waiting on: unref'd, it stops firing the moment nothing else holds the
    // loop open, and the stalled request it was meant to bound hangs forever
    // instead. `dispose()` runs in the caller's `finally`, so the timer cannot
    // outlive its request either way.

    return {
        signal: controller.signal,
        timedOut: () => expired,
        dispose: () => {
            clearTimeout(timer);
            caller?.removeEventListener("abort", onCallerAbort);
        },
    };
}

/**
 * The error a request deadline produces.
 *
 * `status: 504` is load-bearing, not decoration: `isTransientPollingStatus`
 * treats it as retryable, so one stalled poll inside a wait loop is abandoned
 * and retried against the remaining budget instead of failing the whole wait.
 *
 * `phase` names the round-trip that actually stalled — `"preflight GET
 * /version"`, `"POST /api/recall"` — so WALM-598's diagnostic question ("which
 * step ate the budget?") is answerable from the error alone. The name stays
 * `MemWalRequestTimeout`: that is the shipped contract callers and
 * `isTransientPollingStatus` already key off (WALM-648).
 */
function requestTimeoutError(method: string, path: string, ms: number, phase?: string): Error {
    const stage = phase ?? `${method} ${path}`;
    const err = new Error(
        `Walrus Memory request timed out after ${ms}ms during ${stage}. The relayer ` +
            `accepted the connection but did not answer in time.`,
    );
    err.name = "MemWalRequestTimeout";
    (err as Error & { status?: number; phase?: string; timeoutMs?: number }).status = 504;
    (err as Error & { phase?: string }).phase = stage;
    (err as Error & { timeoutMs?: number }).timeoutMs = ms;
    return err;
}

/**
 * The 504 a remember wait raises when its budget runs out.
 *
 * Under upload congestion the relayer keeps a job `running` for tens of
 * minutes, far past a 60s wait, and says so in the job's `error`. Carrying the
 * last status the relayer reported is what lets a caller tell "still retrying,
 * wait on the same job" from "we never got an answer" (GH #966). The wait
 * only times out on a job that is still pending/running/uploaded (a `failed`
 * job throws), so the advice is always to keep waiting on the job id.
 */
function rememberJobTimeoutError(
    jobId: string,
    timeoutMs: number,
    lastSeen: RememberJobStatus | undefined,
    lastRefusal: number | undefined,
    sawRateLimit: boolean,
): Error {
    const serverError = lastSeen?.error ? redactInternalUrls(lastSeen.error) : undefined;
    // "no status read got through (last poll: HTTP 429)" already names the rate limit.
    const rateLimited = sawRateLimit && (lastSeen || lastRefusal !== 429) ? "; wait hit a rate limit (429)" : "";
    const detail = lastSeen
        ? `last status: ${lastSeen.status}${serverError ? ` (${serverError})` : ""}. ` +
          `The job is still in progress: call waitForRememberJob("${jobId}") to keep waiting on it. ` +
          `Sending the text again under a new idempotency key stores it twice; a key you passed ` +
          `as idempotencyKey is not remembered by the client, so pass it again on any retry.`
        : `no status read got through (last poll: HTTP ${lastRefusal ?? 0}), so the job's state is unknown.`;
    return new MemWalRememberJobTimeoutError(
        `remember job timed out after ${timeoutMs}ms (job_id=${jobId})${rateLimited}; ${detail}`,
        jobId,
        timeoutMs,
        lastSeen?.status,
        serverError,
    );
}

function isTransientPollingStatus(status: number): boolean {
    return status === 0 || status === 429 || status >= 500;
}

function jsonBodyError(status: number, message: string): Error {
    return Object.assign(new Error(message), { status });
}

function isJsonObject(value: unknown): boolean {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * The parsed 2xx body must carry `field` as an array. #1207 named the error
 * for a body that is not JSON; this names it for JSON of the wrong shape, so a
 * drifted relayer or proxy does not surface as a raw `TypeError` (#1247).
 */
function requireArrayField<T>(
    body: unknown,
    field: string,
    endpoint: string,
    httpStatus?: number,
): T[] {
    const value = isJsonObject(body) ? (body as Record<string, unknown>)[field] : undefined;
    if (!Array.isArray(value)) {
        const err = new Error(`MemWal: ${endpoint} response is missing a ${field} array`);
        // Polling loops treat a missing `status` as a network error and retry
        // it; a malformed 2xx body is not transient, so carry the real status.
        throw httpStatus === undefined ? err : Object.assign(err, { status: httpStatus });
    }
    return value as T[];
}

/**
 * How long a transient polling rejection asked us to wait, in ms.
 *
 * A 429 from the relayer's rate limiter is not an invitation to poll again in
 * a second. The limiter counts our own status reads, so answering a
 * `retry_after_seconds: 60` with the 10s backoff cap re-trips it on every
 * attempt and the loop starves itself: the job then reads as "still uploading"
 * for as long as the caller is willing to wait — including long after it has
 * actually failed, which is the state that costs a user their fact.
 *
 * Clamped to what is left of the caller's own budget, so a 10-minute backoff
 * costs at most the wait the caller already asked for. The loop then spends
 * that remainder on one final read at the boundary rather than on a backoff
 * curve nobody asked for.
 */
function retryAfterDelayMs(err: unknown, deadline: number): number {
    const seconds =
        (err as { retryAfterSeconds?: number }).retryAfterSeconds
        ?? retryAfterSecondsFromBody((err as { cause?: unknown }).cause);
    if (seconds === undefined || !Number.isFinite(seconds) || seconds <= 0) return 0;
    return Math.max(0, Math.min(seconds * 1000, deadline - Date.now()));
}

/**
 * Thrown when a bulk wait could not read a single status, the confirming read
 * included. The status endpoint counts against the same delegate-key budget
 * as writes, so a batch sent near the limit can have every poll refused. The
 * old result then read as "still uploading" even when nothing had landed
 * (GH #967). A refusal says nothing about the jobs, so do not report it as
 * progress.
 */
function bulkRateLimitedError(err: unknown, jobIds: string[]): Error {
    const retryAfterSeconds =
        (err as { retryAfterSeconds?: number }).retryAfterSeconds
        ?? retryAfterSecondsFromBody((err as { cause?: unknown }).cause);
    const wait = retryAfterSeconds ? ` after ~${Math.ceil(retryAfterSeconds)}s` : "";
    return new MemWalRateLimitedError(
        `Walrus Memory rate-limited every status read for this batch, so none of its ${jobIds.length} writes ` +
            `could be confirmed. Do not treat them as stored: check them with getRememberBulkStatus(jobIds)${wait}. ` +
            `Status reads count against the same delegate-key budget as writes.`,
        jobIds,
        retryAfterSeconds,
    );
}

/**
 * The relayer states the backoff in the 429 body as well as in `Retry-After`.
 * A proxy that strips the header must not cost us the hint.
 */
function retryAfterSecondsFromBody(cause: unknown): number | undefined {
    if (typeof cause !== "string") return undefined;
    try {
        const parsed = JSON.parse(cause) as { retry_after_seconds?: unknown };
        const seconds = Number(parsed?.retry_after_seconds);
        return Number.isFinite(seconds) ? seconds : undefined;
    } catch {
        return undefined;
    }
}

/**
 * Normalise the legacy `(text, namespace)` and new `(text, options)`
 * overloads of `analyze()` / `analyzeAndWait()` into a single
 * `AnalyzeOptions` object. Preserves backwards compatibility — a plain
 * string is treated as the namespace.
 */
function normalizeAnalyzeOptions(
    namespaceOrOptions?: string | AnalyzeOptions,
): AnalyzeOptions {
    if (namespaceOrOptions == null) return {};
    if (typeof namespaceOrOptions === "string") return { namespace: namespaceOrOptions };
    return namespaceOrOptions;
}

/**
 * Render an `occurredAt` argument to the wire format the server
 * expects: RFC-3339 UTC with trailing `Z` and millisecond precision
 * (e.g. `"2023-05-25T17:50:00.000Z"`). `Date` objects are normalised
 * via `toISOString()` (which always emits this exact shape); strings
 * are passed through verbatim — the caller is trusted to have given
 * us a valid RFC-3339 timestamp. Invalid `Date` instances (constructed
 * from garbage input — `Date` silently produces "Invalid Date" rather
 * than throwing) are rejected at the SDK boundary with a diagnostic
 * `TypeError`, so a bad timestamp doesn't surface as an opaque
 * `RangeError: Invalid time value` from `.toISOString()` later.
 * Returns `undefined` when no anchor is supplied so the field is
 * omitted from the request body.
 */
function occurredAtToWire(occurredAt?: string | Date): string | undefined {
    if (occurredAt == null) return undefined;
    if (occurredAt instanceof Date) {
        if (Number.isNaN(occurredAt.getTime())) {
            throw new TypeError(
                "occurredAt is an Invalid Date — likely constructed from a " +
                "malformed string. `Date` accepts garbage silently; check " +
                "the source value before passing it as occurredAt.",
            );
        }
        return occurredAt.toISOString();
    }
    return occurredAt;
}

function normalizeSuiNetworkForGrpc(network: string): string {
    return network === "local" ? "localnet" : network;
}

export class MemWal {
    private privateKey: Uint8Array;
    private publicKey: Uint8Array | null = null;
    private destroyed = false;
    private serverUrl: string;
    private namespace: string;
    private accountId: string;
    /** Deadline applied to any request that does not name its own. */
    private requestTimeoutMs: number;
    /**
     * Recall's abort budget, and the independent per-round-trip budget for the
     * unauthenticated preflights that precede it. Separate so a slow
     * `/version`, `/health` or `/config` is never charged against recall.
     */
    private recallTimeoutMs: number;
    private preflightTimeoutMs: number;

    // ENG-1697 state — all internal, never surfaced to user code.
    // The public API (`MemWal.create({ key, accountId })`) is unchanged.
    private sessionCache: SessionCacheEntry | null = null;
    private serverConfig: ServerConfig | null = null;
    private relayerVersionMetadata: RelayerVersionMetadata | null = null;
    /** Single-flight guard so concurrent requests share one SessionKey build. */
    private sessionBuildPromise: Promise<string> | null = null;
    /** Single-flight guard so concurrent requests share one compatibility probe. */
    private compatibilityPromise: Promise<RelayerVersionMetadata> | null = null;
    /** Resolved owner address for this account. See `resolveOwner()`. */
    private ownerAddress: string | null = null;
    /** Single-flight guard so concurrent reads share one owner resolution. */
    private ownerPromise: Promise<string> | null = null;

    /**
     * Keep a generated idempotency key while a remember request has no
     * acknowledged response. If the transport times out after the server
     * accepted the write, the caller's next identical attempt reuses the key
     * and collapses onto the original paid job.
     */
    private pendingRememberKeys = new Map<string, string>();

    private constructor(config: MemWalConfig) {
        this.privateKey =
            typeof config.key === "string"
                ? hexToBytes(normalizePrivateKey(config.key))
                : config.key;
        if (!(this.privateKey instanceof Uint8Array) || this.privateKey.length !== 32) {
            const got = this.privateKey instanceof Uint8Array
                ? String(this.privateKey.length)
                : typeof this.privateKey;
            throw new Error(`Ed25519 seed must be exactly 32 bytes, got ${got}`);
        }
        if (typeof config.accountId !== "string" || config.accountId.trim().length === 0) {
            throw new TypeError(
                `MemWal.create: "accountId" is required (Walrus Memory object ID, e.g. 0x...); got ${config.accountId}`,
            );
        }
        this.accountId = config.accountId;
        // LOW-22: default to HTTPS for production usage; normalizeServerUrl
        // warns (does not throw) if a user passes plain http:// for a
        // non-localhost host.
        this.serverUrl = normalizeServerUrl(config.serverUrl ?? "https://relayer.memory.walrus.xyz");
        if (config.namespace !== undefined && !config.namespace) {
            throw new Error("namespace cannot be empty");
        }
        this.namespace = config.namespace ?? "default";
        // A non-positive or non-finite override would disable the backstop
        // entirely, which is the bug this exists to prevent.
        this.requestTimeoutMs =
            Number.isFinite(config.requestTimeoutMs) && (config.requestTimeoutMs as number) > 0
                ? (config.requestTimeoutMs as number)
                : DEFAULT_REQUEST_TIMEOUT_MS;
        this.recallTimeoutMs = config.recallTimeoutMs ?? DEFAULT_RECALL_TIMEOUT_MS;
        this.preflightTimeoutMs = config.preflightTimeoutMs ?? DEFAULT_PREFLIGHT_TIMEOUT_MS;
    }

    /**
     * Create a new Walrus Memory client instance.
     *
     * @param config.key - Ed25519 private key (hex or `suiprivkey1...`) — the delegate key
     * @param config.serverUrl - Server URL (default: https://relayer.memory.walrus.xyz)
     */
    static create(config: MemWalConfig): MemWal {
        return new MemWal(config);
    }

    /**
     * Securely wipe the private and public keys from memory.
     * Prevents key extraction from V8 heap dumps.
     */
    destroy(): void {
        this.destroyed = true;
        if (this.privateKey) {
            this.privateKey.fill(0);
        }
        if (this.publicKey) {
            this.publicKey.fill(0);
        }
        // ENG-1697: drop cached session material too — once destroyed the
        // instance must not leak authorization tokens either.
        this.sessionCache = null;
        this.serverConfig = null;
        this.relayerVersionMetadata = null;
        this.compatibilityPromise = null;
        this.pendingRememberKeys.clear();
    }

    // ============================================================
    // Core API
    // ============================================================

    /**
     * Submit a remember request and return as soon as the server accepts the job.
     */
    async rememberAsync(
        text: string,
        namespaceOrOptions?: string | { idempotencyKey?: string },
        options?: { idempotencyKey?: string },
    ): Promise<RememberAcceptedResult> {
        requireRememberText(text);
        assertNonBlankText(text);
        const split = splitRememberArgs(namespaceOrOptions, options);
        const resolvedNamespace = split.namespace ?? this.namespace;
        const requestIdentity = `${resolvedNamespace}\0${text}`;
        const generatedKey = split.options.idempotencyKey === undefined;
        const idempotencyKey = split.options.idempotencyKey
            ?? this.pendingRememberKeys.get(requestIdentity)
            ?? (await derivedIdempotencyKey(requestIdentity));
        if (generatedKey) this.pendingRememberKeys.set(requestIdentity, idempotencyKey);

        const accepted = await this.signedRequest<RememberAcceptedResult>(
            "POST",
            "/api/remember",
            { text, namespace: resolvedNamespace, idempotency_key: idempotencyKey },
            [200, 202],
        );
        if (generatedKey) this.pendingRememberKeys.delete(requestIdentity);
        return accepted;
    }

    /**
     * One-shot lookup of a remember job's current state. Returns the
     * full state machine value (`pending` | `running` | `uploaded` |
     * `done` | `failed` | `not_found`) without polling.
     *
     * Useful when the caller wants to drive its own polling loop and
     * surface intermediate states to a UI — `waitForRememberJob` only
     * resolves at the terminal state and hides progress.
     */
    async getRememberStatus(jobId: string): Promise<RememberJobStatus> {
        const path = rememberStatusPath(jobId);
        if (path === undefined) {
            return {
                job_id: jobId,
                status: "not_found",
                error: `Job ${jobId} not found`,
            };
        }
        const status = await this.signedRequest<RememberStatusResponse>(
            "GET",
            path,
            {},
            [200, 404],
            // Status is metadata. No SEAL decrypt, so no session. (#1135)
            { includeDelegateKey: false },
        );

        if (!isJsonObject(status) || !("status" in status)) {
            const raw = isJsonObject(status) ? (status as { error?: unknown }).error : undefined;
            const error = typeof raw === "string" ? raw : undefined;
            return {
                job_id: jobId,
                status: "not_found",
                error: error ?? `remember job not found: ${jobId}`,
            };
        }

        return status;
    }

    /**
     * Poll an accepted remember job until it reaches a terminal state.
     */
    async waitForRememberJob(
        jobId: string,
        opts: { pollIntervalMs?: number; timeoutMs?: number } = {},
    ): Promise<RememberResult> {
        const path = rememberStatusPath(jobId);
        if (path === undefined) {
            throw new MemWalRememberJobNotFoundError(jobId);
        }
        const { pollIntervalMs = 1500, timeoutMs = 60_000 } = opts;
        const deadline = Date.now() + timeoutMs;
        let attempt = 0;
        let retryAfterMs = 0;
        let sawRateLimit = false;
        let lastSeen: RememberJobStatus | undefined;
        let lastRefusal: number | undefined;

        while (true) {
            // A retry-after the server just gave us wins over our own curve;
            // the backoff resumes from where it was on the next normal poll.
            // Clamped to remaining budget so we never sleep past deadline (#1081).
            const remainingBeforeSleep = Math.max(0, deadline - Date.now());
            const requestedDelay = retryAfterMs > 0 ? retryAfterMs : pollingDelayMs(pollIntervalMs, attempt++);
            retryAfterMs = 0;
            const delay = Math.min(requestedDelay, remainingBeforeSleep);
            if (delay > 0) {
                await sleep(delay);
            }

            let status: RememberStatusResponse;

            try {
                status = await this.signedRequest<RememberStatusResponse>(
                    "GET",
                    path,
                    {},
                    [200, 404],
                    // Bound each poll by the client deadline, and never past
                    // what is left of the budget. Without this the loop only
                    // checks the deadline between polls, so one stalled read
                    // runs past `timeoutMs` however small it was — the whole
                    // reason a 90s wait was seen still going at 120s. Taking
                    // the min of the two matters in both directions: the
                    // remaining budget keeps a poll from outliving the wait,
                    // and the client deadline keeps ONE stalled poll from
                    // swallowing the entire budget, so the loop still gets to
                    // retry. An expired poll surfaces as a transient 504.
                    { timeoutMs: this.pollDeadlineMs(deadline), includeDelegateKey: false },
                );
            } catch (err) {
                const httpStatus = (err as { status?: number }).status ?? 0;
                if (isTransientPollingStatus(httpStatus)) {
                    lastRefusal = httpStatus;
                    if (httpStatus === 429) sawRateLimit = true;
                    if (Date.now() >= deadline) {
                        break;
                    }
                    retryAfterMs = retryAfterDelayMs(err, deadline);
                    continue;
                }
                throw err;
            }

            if (!isJsonObject(status) || !("status" in status) || status.status === "not_found") {
                throw new MemWalRememberJobNotFoundError(jobId);
            }
            lastSeen = status;

            if (status.status === "done") {
                return {
                    id: status.job_id,
                    job_id: status.job_id,
                    blob_id: status.blob_id ?? "",
                    owner: status.owner ?? "",
                    namespace: status.namespace ?? this.namespace,
                };
            }
            if (status.status === "failed") {
                throw new MemWalRememberJobFailedError(
                    jobId,
                    redactInternalUrls(status.error ?? "unknown error"),
                );
            }

            if (Date.now() >= deadline) {
                break;
            }
        }

        throw rememberJobTimeoutError(jobId, timeoutMs, lastSeen, lastRefusal, sawRateLimit);
    }

    /**
     * Remember something and wait for the background job to complete.
     */
    async rememberAndWait(
        text: string,
        namespaceOrOptions?: string | RememberCallOptions,
        opts?: RememberCallOptions,
    ): Promise<RememberResult> {
        requireRememberText(text);
        const split = splitRememberArgs(namespaceOrOptions, opts);
        const resolvedNamespace = split.namespace ?? this.namespace;
        const requestIdentity = `${resolvedNamespace}\0${text}`;
        const generatedKey = split.options.idempotencyKey === undefined;
        const idempotencyKey = split.options.idempotencyKey
            ?? this.pendingRememberKeys.get(requestIdentity)
            ?? (await derivedIdempotencyKey(requestIdentity));
        if (generatedKey) this.pendingRememberKeys.set(requestIdentity, idempotencyKey);

        // Pass the resolved string. rememberAsync would otherwise read the
        // options object in this slot as a namespace. (#1142)
        const accepted = await this.rememberAsync(text, resolvedNamespace, { idempotencyKey });
        const completed = await this.waitForRememberJob(accepted.job_id, split.options);
        // Clear only after terminal success. A polling timeout/transport failure
        // keeps the key so retrying the high-level operation reuses the same job.
        if (generatedKey) this.pendingRememberKeys.delete(requestIdentity);
        return completed;
    }

    /**
     * Remember something and return as soon as the server accepts the job.
     *
     * The relayer continues embedding, encrypting, uploading, and indexing in the background.
     * Use rememberAndWait() when the caller needs the final blob_id before continuing.
     *
     * A plain object in the namespace position is options, so
     * `remember(text, { idempotencyKey })` keeps the client namespace. (#1142)
     */
    async remember(
        text: string,
        namespaceOrOptions?: string | { idempotencyKey?: string },
        options?: { idempotencyKey?: string },
    ): Promise<RememberAcceptedResult> {
        return this.rememberAsync(text, namespaceOrOptions, options);
    }

    /**
     * Remember multiple memories in one batched request (ENG-1408).
     *
     * Server handles: verify → embed + SEAL-encrypt all items concurrently →
     * upload N blobs to Walrus in parallel → 1 PTB per wallet slot for
     * set-metadata + transfer. This collapses `N × (2 + 1)` Sui transactions
     * into roughly `2N + K` where K ≤ wallet pool size.
     *
     * Returns `202 Accepted` immediately with `job_ids[]`.
     *
     * @param items - Array of `{ text, namespace? }` items (max 20 per call)
     *
     * @example
     * ```typescript
     * const accepted = await memwal.rememberBulk([
     *     { text: "I love coffee" },
     *     { text: "I live in Tokyo", namespace: "profile" },
     * ])
     * console.log(accepted.job_ids)
     * ```
     */
    async rememberBulkAsync(
        items: RememberBulkItem[],
        options: RememberBulkAsyncOptions = {},
    ): Promise<RememberBulkAcceptedResult> {
        if (!Array.isArray(items) || items.length === 0) {
            throw new Error("rememberBulkAsync: items must be a non-empty array");
        }
        // The relayer rejects this after the request is signed. Say so first. (#1104)
        if (items.length > MAX_BULK_ITEMS) {
            throw new Error(
                `rememberBulkAsync: items exceeds maximum of ${MAX_BULK_ITEMS} per bulk request`,
            );
        }
        items.forEach((item, i) => {
            assertNonBlankText(item?.text, `items[${i}].text cannot be empty`);
        });

        const normalised = items.map((item) => ({
            text: item.text,
            namespace: item.namespace ?? this.namespace,
        }));

        const requestIdentity = `bulk\0${normalised.map((item) => `${item.namespace}\0${item.text}`).join("\0\0")}`;
        const generatedKey = options.idempotencyKey === undefined;
        const idempotencyKey = options.idempotencyKey
            ?? this.pendingRememberKeys.get(requestIdentity)
            ?? (await derivedBulkIdempotencyKey(requestIdentity));
        if (generatedKey) this.pendingRememberKeys.set(requestIdentity, idempotencyKey);

        const accepted = await this.signedRequest<RememberBulkAcceptedResult>(
            "POST",
            "/api/remember/bulk",
            { items: normalised, idempotency_key: idempotencyKey },
            [200, 202],
        );
        if (generatedKey) this.pendingRememberKeys.delete(requestIdentity);

        if (!accepted.job_ids || accepted.job_ids.length !== normalised.length) {
            throw new Error(
                `rememberBulkAsync: server returned ${accepted.job_ids?.length ?? 0} job_ids for ${normalised.length} items`,
            );
        }

        return accepted;
    }

    async getRememberBulkStatus(
        jobIds: string[],
        opts: { timeoutMs?: number } = {},
    ): Promise<RememberBulkStatusResult> {
        if (!Array.isArray(jobIds)) {
            throw new Error("getRememberBulkStatus: jobIds must be an array");
        }
        const result = await this.signedRequest<RememberBulkStatusResult>(
            "POST",
            "/api/remember/bulk/status",
            { job_ids: jobIds },
            [200],
            // Status is metadata. No SEAL decrypt, so no session. (#1135)
            { timeoutMs: opts.timeoutMs, includeDelegateKey: false },
        );
        // Only a 200 is accepted here.
        requireArrayField(result, "results", "POST /api/remember/bulk/status", 200);
        return result;
    }

    async waitForRememberJobs(
        jobIds: string[],
        namespaces: string[] = [],
        opts: RememberBulkOptions = {},
    ): Promise<RememberBulkResult> {
        const { pollIntervalMs = 1500, timeoutMs = 120_000 } = opts;
        const deadline = Date.now() + timeoutMs;
        const results: RememberBulkItemResult[] = jobIds.map((jobId, idx) => ({
            id: jobId,
            blob_id: "",
            status: "timeout",
            namespace: namespaces[idx] ?? this.namespace,
            error: `polling timed out after ${timeoutMs}ms`,
        }));
        const pending = new Set(jobIds);
        let attempt = 0;
        let retryAfterMs = 0;
        let sawRateLimit = false;
        const lastSeen = new Map<string, RememberBulkStatusItem>();
        let lastRefusal: number | undefined;
        // Whether any status read got through. An item missing from an answer
        // was not refused, so it must not be reported as if it had been.
        let answered = false;

        const settle = (jobId: string, status: RememberBulkStatusItem) => {
            lastSeen.set(jobId, status);
            // The same id can occupy more than one slot. `indexOf` updated only
            // the first, and `pending` is a Set, so the copies stayed `timeout`.
            // (#1121, #1084)
            const terminal =
                status.status === "done" ||
                status.status === "failed" ||
                status.status === "not_found";
            for (let idx = 0; idx < jobIds.length; idx++) {
                if (jobIds[idx] !== jobId) continue;
                if (namespaces[idx] === undefined && status.namespace) {
                    results[idx].namespace = status.namespace;
                }
                if (!terminal) continue;
                // Caller namespace, then the job's own, then the client default. (#1136)
                const namespace = namespaces[idx] ?? status.namespace ?? this.namespace;
                if (status.status === "done") {
                    results[idx] = {
                        id: jobId,
                        blob_id: status.blob_id ?? "",
                        status: "done",
                        namespace,
                    };
                } else {
                    results[idx] = {
                        id: jobId,
                        blob_id: "",
                        status: "failed",
                        namespace,
                        error:
                            status.status === "not_found"
                                ? "job not found"
                                : redactInternalUrls(status.error ?? "unknown error"),
                    };
                }
            }
            if (terminal) pending.delete(jobId);
        };

        while (pending.size > 0) {
            // A retry-after the server just gave us wins over our own curve;
            // the backoff resumes from where it was on the next normal poll.
            // Clamped to remaining budget so we never sleep past deadline (#1081).
            const remainingBeforeSleep = Math.max(0, deadline - Date.now());
            const requestedDelay = retryAfterMs > 0 ? retryAfterMs : pollingDelayMs(pollIntervalMs, attempt++);
            retryAfterMs = 0;
            const delay = Math.min(requestedDelay, remainingBeforeSleep);
            if (delay > 0) {
                await sleep(delay);
            }

            const pendingIds = jobIds.filter((jobId) => pending.has(jobId));
            if (pendingIds.length === 0) {
                break;
            }

            let batchStatus: RememberBulkStatusResult;

            try {
                // Bounded the same way as the single-job poll.
                batchStatus = await this.getRememberBulkStatus(pendingIds, {
                    timeoutMs: this.pollDeadlineMs(deadline),
                });
            } catch (err) {
                const httpStatus = (err as { status?: number }).status ?? 0;
                if (isTransientPollingStatus(httpStatus)) {
                    lastRefusal = httpStatus;
                    if (httpStatus === 429) sawRateLimit = true;
                    if (Date.now() >= deadline) {
                        break;
                    }
                    retryAfterMs = retryAfterDelayMs(err, deadline);
                    continue;
                }
                throw err;
            }
            answered = true;

            const statusById = new Map<string, RememberBulkStatusItem[]>();
            for (const item of batchStatus.results) {
                const bucket = statusById.get(item.job_id);
                if (bucket) {
                    bucket.push(item);
                } else {
                    statusById.set(item.job_id, [item]);
                }
            }

            for (const jobId of pendingIds) {
                const status = statusById.get(jobId)?.shift();
                if (!status) {
                    continue;
                }

                settle(jobId, status);
            }

            if (pending.size === 0 || Date.now() >= deadline) {
                break;
            }
        }

        // Nothing settled and nothing was even seen: the polls may all have been
        // refused rather than the jobs being slow. Confirm with one direct read,
        // as the MCP bridge does, before reporting anything.
        if (timeoutMs > 0 && pending.size === jobIds.length && lastSeen.size === 0) {
            try {
                const probed = await this.getRememberBulkStatus(jobIds, {
                    timeoutMs: Math.min(this.requestTimeoutMs, CONFIRM_READ_TIMEOUT_MS),
                });
                answered = true;
                for (const item of probed.results) {
                    if (pending.has(item.job_id)) settle(item.job_id, item);
                }
            } catch (err) {
                if ((err as { status?: number }).status === 429) throw bulkRateLimitedError(err, jobIds);
                // Any other probe failure is not evidence about the jobs.
            }
        }

        for (let idx = 0; idx < jobIds.length; idx++) {
            const jobId = jobIds[idx];
            if (!pending.has(jobId)) continue;
            const seen = lastSeen.get(jobId);
            results[idx].error = seen
                ? `still ${seen.status} after ${timeoutMs}ms` + (seen.error ? `: ${redactInternalUrls(seen.error)}` : "")
                : answered
                  ? "not in the relayer's status answer; this item may not be stored"
                  : lastRefusal !== undefined
                    ? `no status read got through (last poll: HTTP ${lastRefusal}); this item may not be stored`
                    : `polling timed out after ${timeoutMs}ms`;
            // Only the "no status read got through" message already names the 429.
            const namesRateLimit = !seen && !answered && lastRefusal === 429;
            if (sawRateLimit && !namesRateLimit) {
                results[idx].error += "; wait hit a rate limit (429)";
            }
        }

        const succeeded = results.filter((r) => r.status === "done").length;

        return {
            results,
            total: results.length,
            succeeded,
            failed: results.length - succeeded,
        };
    }

    /**
     * Remember multiple memories and return as soon as the server accepts the jobs.
     */
    async rememberBulk(
        items: RememberBulkItem[],
        options: RememberBulkAsyncOptions = {},
    ): Promise<RememberBulkAcceptedResult> {
        return this.rememberBulkAsync(items, options);
    }

    /**
     * Remember multiple memories and wait until every job reaches a terminal state.
     */
    async rememberBulkAndWait(
        items: RememberBulkItem[],
        opts: RememberBulkOptions = {},
    ): Promise<RememberBulkResult> {
        if (!Array.isArray(items) || items.length === 0) {
            throw new Error("rememberBulkAsync: items must be a non-empty array");
        }
        if (items.length > MAX_BULK_ITEMS) {
            throw new Error(
                `rememberBulkAsync: items exceeds maximum of ${MAX_BULK_ITEMS} per bulk request`,
            );
        }
        items.forEach((item, i) => {
            assertNonBlankText(item?.text, `items[${i}].text cannot be empty`);
        });

        const normalised = items.map((item) => ({
            text: item.text,
            namespace: item.namespace ?? this.namespace,
        }));
        const requestIdentity = `bulk\0${normalised.map((item) => `${item.namespace}\0${item.text}`).join("\0\0")}`;
        const generatedKey = opts.idempotencyKey === undefined;
        const idempotencyKey = opts.idempotencyKey
            ?? this.pendingRememberKeys.get(requestIdentity)
            ?? (await derivedBulkIdempotencyKey(requestIdentity));
        if (generatedKey) this.pendingRememberKeys.set(requestIdentity, idempotencyKey);

        const namespaces = normalised.map((item) => item.namespace);
        const accepted = await this.rememberBulkAsync(items, { ...opts, idempotencyKey });
        const completed = await this.waitForRememberJobs(accepted.job_ids, namespaces, opts);
        if (generatedKey) this.pendingRememberKeys.delete(requestIdentity);
        return completed;
    }

    /**
     * Estimate the token cost of a string using the SDK's default
     * character-based approximation (~chars/4, code-point aware). Useful to weigh
     * a recall payload before injecting it into a model context:
     *
     * ```ts
     * const hits = await memwal.recall({ query, limit: 8 });
     * const joined = hits.results.map((h) => h.text).join("\n---\n");
     * if (memwal.countTokens(joined) > 2048) { /* re-query with maxTokens *\/ }
     * ```
     *
     * This is an estimate, not an exact tokenizer count — see `estimateTokens`
     * for accuracy caveats. For exact counts, pass your own counter to
     * `recall({ maxTokens, countTokens })`.
     */
    countTokens(text: string): number {
        return estimateTokens(text);
    }

    /**
     * Recall memories similar to a query — server handles:
     * verify → embed query → search → Walrus download → decrypt → return plaintext.
     *
     * **Preferred call style**: pass a single `RecallParams` object
     * so call sites read self-describingly:
     * ```ts
     * memwal.recall({ query: "food allergies", limit: 5, namespace: "profile" })
     * ```
     *
     * The legacy positional forms remain supported for backwards compatibility:
     * - `recall(query)`
     * - `recall(query, limit)`
     * - `recall(query, limit, namespace)`
     * - `recall(query, { limit, namespace, maxDistance, topK })`
     *
     * `recall(query, namespace)` is invalid and throws `TypeError`.
     *
     * `topK` and `limit` are aliases; if both are set, `topK` wins.
     *
     * @returns RecallResult with decrypted text results
     *
     * @example
     * ```typescript
     * // Object style — recommended
     * const result = await memwal.recall({
     *     query: "food allergies",
     *     limit: 5,
     *     namespace: "profile",
     * });
     * for (const memory of result.results) {
     *     console.log(memory.text, memory.distance);
     * }
     *
     * // Positional style — still works
     * const result2 = await memwal.recall("food allergies", 5, "profile");
     * ```
     */
    async recall(params: RecallParams): Promise<RecallResult>;
    /**
     * @deprecated Positional `recall(query, limit, namespace)` is easy to
     * misread as `recall(query, namespace)`, which throws `TypeError`. Prefer
     * `recall({ query, limit, namespace })`. Positional will be removed in a
     * future major version of the SDK.
     */
    async recall(query: string, options: RecallOptions): Promise<RecallResult>;
    /**
     * @deprecated Positional `recall(query, limit, namespace)` is easy to
     * misread as `recall(query, namespace)`, which throws `TypeError`. Prefer
     * `recall({ query, limit, namespace })`. Positional will be removed in a
     * future major version of the SDK.
     */
    async recall(
        query: string,
        limit?: number,
        namespace?: string,
    ): Promise<RecallResult>;
    async recall(
        queryOrParams: string | RecallParams,
        limitOrOptions: number | RecallOptions | undefined = 10,
        namespace?: string,
    ): Promise<RecallResult> {
        const { query, options } = resolveRecallCall(
            queryOrParams,
            limitOrOptions,
            namespace,
        );
        validateMaxTokens(options.maxTokens);
        assertNonBlankText(query, "query cannot be empty");
        const rawLimit = options.topK !== undefined ? options.topK : options.limit;
        const limit = rawLimit !== undefined ? rawLimit : 10;
        if (typeof limit !== "number" || !Number.isInteger(limit) || limit <= 0) {
            throw new TypeError(
                `limit must be a positive integer, got ${limit}`,
            );
        }
        assertFiniteScoringWeights(options.scoringWeights);
        if (
            options.maxDistance !== undefined
            && (typeof options.maxDistance !== "number"
                || !Number.isFinite(options.maxDistance)
                || options.maxDistance < 0)
        ) {
            throw new Error("maxDistance must be a non-negative finite number");
        }
        const resolvedNamespace = options.namespace ?? this.namespace;


        {
            // WALM-598: this budget is handed to `signedRequest`, which starts
            // the clock on the `/api/recall` fetch itself — after
            // `ensureCompatibleRelayer` (`/version`, falling back to `/health`)
            // and `buildSealSession` (`/config` + Sui RPC) have already
            // resolved. Those preflights carry their own independent
            // deadlines, so a relayer whose `/health` p50 had crept to ~9s can
            // no longer eat most of recall's window and make a perfectly
            // healthy recall surface an `AbortError` (GH #438).
            const budget = options.timeoutMs ?? this.recallTimeoutMs;
            const optedOut = typeof budget !== "number" || !Number.isFinite(budget) || budget <= 0;
            const timeoutMs = optedOut ? 0 : budget;
            const wireDeadline = optedOut
                ? undefined
                : (timeoutMs > RECALL_DEADLINE_MARGIN_MS
                    ? timeoutMs - RECALL_DEADLINE_MARGIN_MS
                    : timeoutMs);
            const result = await this.signedRequest<RecallResult>("POST", "/api/recall", {
                query,
                limit,
                namespace: resolvedNamespace,
                scoring_weights: scoringWeightsToWire(options.scoringWeights),
                sort: options.sort,
                ...(wireDeadline === undefined ? {} : { deadline_ms: wireDeadline }),
            }, { timeoutMs });
            requireArrayField(result, "results", "POST /api/recall");

            let processed = result;
            if (typeof options.maxDistance === "number") {
                const filtered = result.results.filter(
                    (memory) =>
                        typeof memory.distance === "number" &&
                        Number.isFinite(memory.distance) &&
                        Math.max(0, memory.distance) < options.maxDistance!,
                );
                // Keep the relayer's matching total so callers can distinguish
                // "no memories exist" from "matches exist but were outside maxDistance" (#1066).
                processed = {
                    ...processed,
                    results: filtered,
                };
            }

            // Client-side token budgeting: trim the payload to fit maxTokens per
            // the chosen strategy, and attach the token estimate + truncated flag.
            // Under high-relevance-only, lowest-distance hits are retained and
            // returned in the caller's requested order (WALM-756).
            // Omitting maxTokens leaves the result byte-identical to the pre-budget
            // behavior (no meta). Total preserves the matching hit count (#1068).
            if (options.maxTokens !== undefined) {
                const { results: budgeted, meta } = applyTokenBudget(
                    processed.results,
                    options.maxTokens,
                    options.truncationStrategy,
                    options.countTokens,
                );
                processed = {
                    ...processed,
                    results: budgeted,
                    meta,
                };
            }

            return processed;
        }
    }

    // ============================================================
    // Manual API (user handles SEAL + embedding + Walrus)
    // ============================================================

    /**
     * Remember (manual mode) — user handles SEAL encrypt and embedding.
     * The relayer uploads the encrypted bytes to Walrus and stores the
     * vector ↔ blobId mapping.
     *
     * Trust boundary (ENG-1696): the delegate private key is NOT transmitted on
     * this request. Manual-mode handlers on the server never invoke SEAL
     * decrypt, so the key stays client-side as the name implies.
     *
     * @param opts.encryptedData - Base64-encoded SEAL-encrypted bytes
     * @param opts.vector - Embedding vector (user already generated, e.g. 1536-dim)
     * @returns RememberManualResult with id, blob_id, owner
     *
     * @example
     * ```typescript
     * const encryptedData = Buffer.from(sealEncryptedBytes).toString("base64")
     * const vector = await myEmbeddingModel.embed(text)
     * const result = await memwal.rememberManual({ encryptedData, vector })
     * ```
     */
    async rememberManual(opts: RememberManualOptions): Promise<RememberManualResult> {
        return this.signedRequest<RememberManualResult>(
            "POST",
            "/api/remember/manual",
            {
                encrypted_data: opts.encryptedData,
                vector: opts.vector,
                namespace: opts.namespace ?? this.namespace,
            },
            { includeDelegateKey: false },
        );
    }

    /**
     * Recall (manual mode) — user provides a pre-computed query vector.
     * Server returns matching blobIds + distances.
     * User then downloads from Walrus + SEAL decrypts on their own.
     *
     * Trust boundary (ENG-1696): the delegate private key is NOT transmitted on
     * this request. Server returns blob IDs only; decryption happens entirely
     * on the client.
     *
     * @param opts.vector - Pre-computed query embedding vector
     * @param opts.limit - Max results (default: 10)
     * @param opts.scoringWeights - Optional composite-scoring weights
     * @returns RecallManualHitResult with blob_id + distance pairs (no decrypted text)
     *
     * @example
     * ```typescript
     * // 1. User generates query embedding
     * const queryVector = await myEmbeddingModel.embed("food allergies")
     *
     * // 2. Search for similar vectors
     * const hits = await memwal.recallManual({ vector: queryVector })
     *
     * // 3. User downloads + decrypts each result
     * for (const hit of hits.results) {
     *     const encrypted = await walrus.download(hit.blob_id)
     *     const plaintext = await seal.decrypt(encrypted)
     *     console.log(plaintext, hit.distance)
     * }
     * ```
     */
    async recallManual(opts: RecallManualOptions): Promise<RecallManualHitResult> {
        const limit = opts.limit !== undefined ? opts.limit : 10;
        if (typeof limit !== "number" || !Number.isInteger(limit) || limit <= 0) {
            throw new TypeError(
                `limit must be a positive integer, got ${limit}`,
            );
        }
        assertFiniteScoringWeights(opts.scoringWeights);
        return this.signedRequest<RecallManualHitResult>(
            "POST",
            "/api/recall/manual",
            {
                vector: opts.vector,
                limit,
                namespace: opts.namespace ?? this.namespace,
                scoring_weights: scoringWeightsToWire(opts.scoringWeights),
            },
            { includeDelegateKey: false },
        );
    }

    /**
     * Generate an embedding vector for text (no storage).
     *
     * @param text - Text to embed
     * @returns EmbedResult with vector
     */
    async embed(text: string): Promise<EmbedResult> {
        assertNonBlankText(text, "text cannot be empty");
        return this.signedRequest<EmbedResult>(
            "POST",
            "/api/embed",
            { text },
            { includeDelegateKey: false },
        );
    }

    /**
     * Analyze conversation text and return as soon as extracted facts are accepted.
     *
     * The relayer extracts facts synchronously, returns one job_id per fact, then
     * embeds, encrypts, uploads, and indexes each fact in the background.
     *
     * @param text - Conversation text to analyze
     * @returns AnalyzeResult with extracted facts and accepted job_ids
     *
     * @example
     * ```typescript
     * const result = await memwal.analyze("I love coffee and live in Tokyo")
     * console.log(result.job_ids)
     * ```
     */
    async analyze(
        text: string,
        namespaceOrOptions?: string | AnalyzeOptions,
    ): Promise<AnalyzeResult> {
        assertNonBlankText(text);
        const options = normalizeAnalyzeOptions(namespaceOrOptions);
        const body: Record<string, unknown> = {
            text,
            namespace: options.namespace ?? this.namespace,
        };
        const wireOccurredAt = occurredAtToWire(options.occurredAt);
        if (wireOccurredAt !== undefined) body.occurred_at = wireOccurredAt;
        return this.signedRequest<AnalyzeResult>("POST", "/api/analyze", body, [200, 202], {
            timeoutMs: ANALYZE_REQUEST_TIMEOUT_MS,
        });
    }

    /**
     * Analyze conversation text and wait until every extracted fact is stored.
     */
    async analyzeAndWait(
        text: string,
        namespaceOrOptions?: string | AnalyzeOptions,
        opts: RememberBulkOptions = {},
    ): Promise<AnalyzeWaitResult> {
        const options = normalizeAnalyzeOptions(namespaceOrOptions);
        const namespace = options.namespace ?? this.namespace;
        const accepted = await this.analyze(text, options);
        requireArrayField(accepted, "job_ids", "POST /api/analyze");
        const namespaces = accepted.job_ids.map(() => namespace);
        const completed = await this.waitForRememberJobs(accepted.job_ids, namespaces, opts);
        return {
            ...completed,
            facts: accepted.facts,
            owner: accepted.owner,
        };
    }

    /**
     * Rebuild missing local index entries for `namespace` from Walrus.
     *
     * The relayer queries Walrus for blobs the caller owns in `namespace`,
     * ignores blobs already indexed locally, downloads the missing ones,
     * SEAL-decrypts them with the delegate key, re-embeds the plaintext,
     * and inserts a fresh vector row per blob.
     *
     * **Response semantics**:
     * - `restored` — blobs that completed the full
     *   download → decrypt → embed → DB insert pipeline this call.
     * - `skipped` — on-chain blobs already in the local success index
     *   (no work needed). Does not include permanent decrypt/UTF-8 failures.
     * - `failed` — permanent decrypt/UTF-8 failures on this on-chain page:
     *   negative-cache hits plus any new permanent failures this call.
     *   Transient download/decrypt/embed errors are not counted here; when
     *   a page yields only those, `truncated` is true so the caller retries.
     * - `total` — on-chain blobs the relayer saw for `(owner, namespace)`
     *   before the limit was applied.
     *
     * **`limit`** caps the *number of missing blobs the relayer selects* from
     * the candidates it sees, in unspecified order. It is not a cap on
     * `restored` directly. The server default is `10` (matches the SDK
     * default).
     *
     * **No pagination cursor** — restore is single-shot. A larger `limit` may
     * help when `truncated` is caused by the request limit, but candidate
     * discovery also has a per-owner source cap shared across namespaces.
     * Hitting that cap requires cursor/pagination support for guaranteed full
     * recovery; increasing `limit` or retrying cannot guarantee it.
     *
     * **Performance** scales linearly in `limit`: up to 10 Walrus downloads
     * in parallel, then 3 SEAL decrypts in parallel, then embeddings.
     * Expect seconds-per-blob on cold caches.
     *
     * @param namespace - Namespace to restore (exact match; no prefix/hierarchy)
     * @param limit - Max blobs to inspect this call (default: 10)
     * @returns RestoreResult with restored / skipped / failed / total counts
     *
     * @example
     * ```typescript
     * const result = await memwal.restore("my-app");
     * console.log(`restored=${result.restored} skipped=${result.skipped} failed=${result.failed} total=${result.total}`);
     * ```
     */
    async restore(namespace: string, limit: number = 10): Promise<RestoreResult> {
        if (typeof limit !== "number" || !Number.isInteger(limit) || limit <= 0) {
            throw new TypeError(
                `limit must be a positive integer, got ${limit}`,
            );
        }
        const result = await this.signedRequest<RestoreResult>(
            "POST",
            "/api/restore",
            { namespace, limit },
            [200],
            { timeoutMs: RESTORE_REQUEST_TIMEOUT_MS },
        );
        // Relayers older than WALM-319 omit `truncated` entirely — treat
        // "not present" as "not known to be truncated" rather than drop
        // the field or require every relayer version to send it.
        // Relayers older than COMG-719 omit `failed`; default to 0.
        return {
            ...result,
            truncated: result.truncated ?? false,
            failed: result.failed ?? 0,
        };
    }

    /**
     * List the namespaces this account holds memories in.
     *
     * Recall is similarity-ranked and needs a namespace to search; without
     * this, an agent connecting to an unfamiliar account has to guess names
     * or fall back to `"default"`. Returns metadata only — no blob fetch, no
     * decryption.
     *
     * Paginate with `has_more`, NOT page length: the server clamps `limit`,
     * so asking for more than the cap returns exactly the cap.
     *
     * ```ts
     * let cursor: string | undefined;
     * let more = true;
     * while (more) {
     *     const page = await memwal.listNamespaces({ cursor });
     *     for (const ns of page.namespaces) console.log(ns.name, ns.memory_count);
     *     cursor = page.next_cursor ?? undefined;
     *     more = page.has_more;
     * }
     * ```
     */
    async listNamespaces(options: ListNamespacesOptions = {}): Promise<NamespacesResult> {
        const owner = await this.resolveOwner();

        const params = new URLSearchParams();
        if (options.cursor !== undefined) params.set("updated_after", options.cursor);
        if (options.limit !== undefined) params.set("limit", String(options.limit));
        const query = params.toString();

        // Query string must be part of the signed path: the server verifies
        // against `path_and_query`, not `path` (see `auth.rs`).
        const path = `/v1/owners/${owner}/namespaces${query ? `?${query}` : ""}`;

        // Metadata-only read — no ciphertext comes back, so no SEAL session
        // is built or transmitted.
        return this.signedRequest<NamespacesResult>("GET", path, {}, [200], {
            includeDelegateKey: false,
        });
    }

    /**
     * List the memories this account holds, without a semantic query.
     *
     * Recall is similarity-ranked and limit-bounded, so it cannot confirm a
     * write or count a namespace. This walks the full inventory instead.
     * Returns metadata only — no blob fetch, no decryption; use `recall()`
     * for content.
     *
     * `namespace` is filtered client-side: the relayer lists every namespace,
     * so a filtered page can be short or empty while `has_more` is true.
     * Paginate with `has_more`, NOT page length.
     *
     * ```ts
     * let cursor: string | undefined;
     * let more = true;
     * let count = 0;
     * while (more) {
     *     const page = await memwal.listMemories({ cursor, namespace: "work" });
     *     count += page.memories.length;
     *     cursor = page.next_cursor ?? undefined;
     *     more = page.has_more;
     * }
     * ```
     */
    async listMemories(options: ListMemoriesOptions = {}): Promise<MemoriesResult> {
        const owner = await this.resolveOwner();

        const params = new URLSearchParams();
        if (options.cursor !== undefined) params.set("updated_after", options.cursor);
        if (options.limit !== undefined) params.set("limit", String(options.limit));
        const query = params.toString();

        // Query string must be part of the signed path (see listNamespaces).
        const path = `/v1/owners/${owner}/memories${query ? `?${query}` : ""}`;

        const raw = await this.signedRequest<MemoriesResult>("GET", path, {}, [200], {
            includeDelegateKey: false,
        });
        requireArrayField(raw, "memories", "GET /v1/owners/{owner}/memories");
        // Relayers older than WALM-363 omit the tombstone fields.
        const page: MemoriesResult = {
            ...raw,
            deleted: raw.deleted ?? [],
            must_resync: raw.must_resync ?? false,
        };
        if (options.namespace === undefined) return page;

        const namespace = options.namespace;
        return {
            ...page,
            memories: page.memories.filter((m) => m.namespace_id === namespace),
            deleted: page.deleted.filter((d) => d.namespace_id === namespace),
        };
    }

    /**
     * Resolve this account's owner address, memoised for the client's life.
     *
     * The owner-scoped read routes take the address in the path and reject a
     * mismatch against the caller's credentials — but `MemWalConfig` carries
     * only the delegate key and account id, so the SDK has to learn its own
     * address from the server.
     *
     * `POST /api/stats` is used because it authenticates with the same
     * delegate scheme, needs nothing but a namespace, is rate-limit weight 1,
     * and returns the owner the server resolved. Using a stats endpoint as a
     * whoami is admittedly indirect; it avoids a server change and keeps this
     * working against relayers older than any such change. If a dedicated
     * self-reference lands (e.g. accepting `me` as the path owner), this
     * method is the only place that needs to change.
     */
    private async resolveOwner(): Promise<string> {
        if (this.ownerAddress) return this.ownerAddress;
        if (this.ownerPromise) return this.ownerPromise;

        this.ownerPromise = (async () => {
            const stats = await this.signedRequest<{ owner?: string }>(
                "POST",
                "/api/stats",
                { namespace: this.namespace },
                [200],
                { includeDelegateKey: false },
            );
            if (!stats.owner) {
                throw new Error(
                    "Walrus Memory could not resolve this account's owner address " +
                        "(POST /api/stats returned no owner).",
                );
            }
            this.ownerAddress = stats.owner;
            return stats.owner;
        })().finally(() => {
            this.ownerPromise = null;
        });

        return this.ownerPromise;
    }

    /**
     * Check server health. The endpoint is public and does not require request signing.
     */
    async health(): Promise<HealthResult> {
        const res = await this.fetchWithDeadline<HealthResult>(
            `${this.serverUrl}/health`,
            {},
            this.preflightTimeoutMs,
            "GET /health",
        );
        if (!res.ok) {
            throw new Error(`Health check failed: ${res.status}`);
        }
        return res.body as HealthResult;
    }

    /**
     * Fetch and validate the relayer compatibility contract.
     */
    async compatibility(): Promise<RelayerVersionMetadata> {
        return this.ensureCompatibleRelayer();
    }

    /**
     * Get the public key (hex string).
     */
    async getPublicKeyHex(): Promise<string> {
        const pk = await this.getPublicKey();
        // `await` yields even when the key was already cached. destroy()
        // zero-fills that cache in place, so encode only after a fresh check
        // or this resolves to 64 zero hex chars. (#1090)
        if (this.destroyed) throw destroyedClientError();
        return bytesToHex(pk);
    }

    // ============================================================
    // Internal: Signed HTTP Requests
    // ============================================================

    private async getPublicKey(): Promise<Uint8Array> {
        // destroy() zero-fills the cache in place, and an uncached key would
        // otherwise derive the well-known key of the all-zero seed. Re-check
        // after every await, and never cache a key derived once wiped. (#1090)
        if (this.destroyed) throw destroyedClientError();
        if (!this.publicKey) {
            const ed = await getEd();
            if (this.destroyed) throw destroyedClientError();
            const derived = await ed.getPublicKeyAsync(this.privateKey);
            if (this.destroyed) throw destroyedClientError();
            this.publicKey = derived;
        }
        return this.publicKey.slice();
    }

    private async ensureCompatibleRelayer(): Promise<RelayerVersionMetadata> {
        if (this.relayerVersionMetadata) return this.relayerVersionMetadata;
        if (this.compatibilityPromise) return this.compatibilityPromise;

        this.compatibilityPromise = this.fetchCompatibilityMetadata().finally(() => {
            this.compatibilityPromise = null;
        });
        return this.compatibilityPromise;
    }

    private async fetchCompatibilityMetadata(): Promise<RelayerVersionMetadata> {
        // WALM-598: both round-trips get their own bounded budget. They run
        // inside whatever signed request triggered the compatibility probe, so
        // leaving them untimed let a stalled relayer silently drain that
        // caller's deadline (and, with no signal at all, hang indefinitely).
        const versionRes = await this.fetchWithDeadline<Partial<RelayerVersionMetadata>>(
            `${this.serverUrl}/version`,
            { method: "GET" },
            this.preflightTimeoutMs,
            "preflight GET /version",
        );
        let body: Partial<RelayerVersionMetadata>;

        if (versionRes.ok) {
            body = versionRes.body as Partial<RelayerVersionMetadata>;
        } else if (versionRes.status === 404 || versionRes.status === 405) {
            const healthRes = await this.fetchWithDeadline<Partial<RelayerVersionMetadata>>(
                `${this.serverUrl}/health`,
                { method: "GET" },
                this.preflightTimeoutMs,
                "preflight GET /health",
            );
            if (!healthRes.ok) {
                throw new Error(
                    `Walrus Memory compatibility check failed: GET /version returned ` +
                        `${versionRes.status}, and GET /health returned ${healthRes.status}`,
                );
            }
            body = healthRes.body as Partial<RelayerVersionMetadata>;
        } else {
            throw new Error(
                `Walrus Memory compatibility check failed: GET /version returned ${versionRes.status}`,
            );
        }

        assertCompatibleRelayer(body, this.serverUrl);
        this.relayerVersionMetadata = body;
        return body;
    }

    // ============================================================
    // ENG-1697: SEAL SessionKey discovery & build
    //
    // The SDK used to transmit the raw delegate private key in
    // `x-delegate-key` on every request. That credential, once captured,
    // lets an attacker retroactively decrypt every ciphertext the account
    // ever produced (until the user rotates on-chain) and sign arbitrary
    // Sui transactions from the delegate address.
    //
    // We now build a SEAL `SessionKey` on the client (ephemeral, scoped to
    // a single `packageId`, 5-minute TTL, signed by the delegate key) and
    // ship only the exported session bytes via `x-seal-session`. The raw
    // private key never leaves the client.
    //
    // `packageId` is fetched from the server's public `/config` endpoint
    // the first time it's needed so the user API (`new MemWal({ key,
    // accountId })`) stays unchanged — past users upgrading to v0.4 do not
    // have to touch their config.
    //
    // Requires `@mysten/seal` and `@mysten/sui` peer dependencies.
    // ============================================================

    private async fetchServerConfig(): Promise<ServerConfig> {
        if (this.serverConfig) return this.serverConfig;
        // WALM-598: bounded like the other preflights — this one is awaited
        // inside `buildSealSession`, itself awaited inside a caller's budget.
        const res = await this.fetchWithDeadline<Record<string, unknown>>(
            `${this.serverUrl}/config`,
            { method: "GET" },
            this.preflightTimeoutMs,
            "preflight GET /config",
        );
        if (!res.ok) {
            throw new Error(`GET /config returned ${res.status}`);
        }
        const body = res.body as Record<string, unknown>;
        if (typeof body.packageId !== "string" || !body.packageId ||
            typeof body.network !== "string" || !body.network) {
            throw new Error("GET /config response missing packageId / network");
        }
        if (body.suiTransport !== undefined &&
            body.suiTransport !== "grpc" && body.suiTransport !== "jsonrpc") {
            throw new Error("GET /config response has invalid suiTransport");
        }
        for (const field of ["suiGrpcUrl", "suiRpcUrl"] as const) {
            if (body[field] !== undefined && (typeof body[field] !== "string" || !body[field])) {
                throw new Error(`GET /config response has invalid ${field}`);
            }
        }
        const transport = body.network === "testnet"
            ? "grpc"
            : (body.suiTransport as "grpc" | "jsonrpc" | undefined) ?? (body.suiGrpcUrl ? "grpc" : "jsonrpc");
        if (transport === "grpc" && !body.suiGrpcUrl && !body.suiRpcUrl) {
            throw new Error(
                `GET /config requires suiGrpcUrl or suiRpcUrl for ${body.network} ${transport} transport`,
            );
        }
        if (transport === "jsonrpc" && !body.suiRpcUrl) {
            throw new Error("GET /config requires suiRpcUrl for explicit non-testnet JSON-RPC transport");
        }
        this.serverConfig = {
            packageId: body.packageId,
            network: body.network,
            suiRpcUrl: body.suiRpcUrl as string | undefined,
            suiGrpcUrl: body.suiGrpcUrl as string | undefined,
            suiTransport: transport,
        };
        return this.serverConfig;
    }

    private async buildSealSessionInner(): Promise<string> {
        const cfg = await this.fetchServerConfig();
        const sealMod = (await import("@mysten/seal")) as any;
        const ed25519Mod = (await import("@mysten/sui/keypairs/ed25519")) as any;
        const SessionKey = sealMod.SessionKey;
        const Ed25519Keypair = ed25519Mod.Ed25519Keypair;

        const clientCandidates: Array<{ name: string; client: any }> = [];

        if (cfg.suiTransport === "grpc" && cfg.suiGrpcUrl) {
            try {
                const mod = (await import("@mysten/sui/grpc")) as any;
                if (typeof mod.SuiGrpcClient === "function") {
                    clientCandidates.push({
                        name: "SuiGrpcClient",
                        client: new mod.SuiGrpcClient({
                            network: normalizeSuiNetworkForGrpc(cfg.network),
                            baseUrl: cfg.suiGrpcUrl,
                        }),
                    });
                }
            } catch {
                /* Try the legacy JSON-RPC client below. */
            }
        }

        // Keep JSON-RPC as a runtime fallback when gRPC is preferred. This is
        // required for rolling SDK/server deployments and prevents a transient
        // gRPC outage from breaking every relayer-mode request while the
        // advertised JSON-RPC endpoint remains healthy.
        if (cfg.suiRpcUrl) {
            let SuiClient: any = undefined;
            try {
                const mod = (await import("@mysten/sui/client")) as any;
                SuiClient = mod.SuiClient;
            } catch {
                /* not present on this version */
            }
            if (typeof SuiClient !== "function") {
                try {
                    const mod = (await import("@mysten/sui/jsonRpc")) as any;
                    SuiClient = mod.SuiJsonRpcClient ?? mod.SuiClient;
                } catch {
                    /* not present on this version either */
                }
            }
            if (typeof SuiClient === "function") {
                clientCandidates.push({
                    name: "SuiClient",
                    client: new SuiClient({ url: cfg.suiRpcUrl }),
                });
            }
        }

        if (clientCandidates.length === 0 || typeof Ed25519Keypair !== "function") {
            throw new Error(
                `Required ${cfg.suiTransport} Sui client or Ed25519Keypair not found in @mysten/sui. ` +
                "Ensure @mysten/sui >=2.5.0 and @mysten/seal >=1.1.0 are installed."
            );
        }

        const keypair = Ed25519Keypair.fromSecretKey(this.privateKey);

        // SessionKey accepts either transport through the shared core client
        // interface. Candidates are ordered by the server's preferred
        // transport, with JSON-RPC retained as a compatibility fallback.
        let session: any = undefined;
        let lastClientError: unknown;
        for (const candidate of clientCandidates) {
            try {
                session = await SessionKey.create({
                    address: keypair.getPublicKey().toSuiAddress(),
                    packageId: cfg.packageId,
                    ttlMin: SEAL_SESSION_TTL_MIN,
                    signer: keypair,
                    suiClient: candidate.client as any,
                });
                break;
            } catch (err) {
                lastClientError = err;
            }
        }
        if (!session) {
            throw lastClientError;
        }

        // Eagerly sign the personal message so the exported envelope is
        // fully self-contained. `SessionKey.create()` defers this signing
        // until first use, which would break the migration: the sidecar
        // imports without a signer and must be able to get a certificate
        // from the exported state alone. Calling
        // setPersonalMessageSignature() here populates the
        // `personalMessageSignature` field in the subsequent export().
        const personalMessage = session.getPersonalMessage();
        const signResult = await keypair.signPersonalMessage(personalMessage);
        await session.setPersonalMessageSignature(signResult.signature);

        const exported = session.export();
        // SEAL intentionally installs a throwing `toJSON` on the
        // exported object to catch accidental serialization. The
        // migration to `x-seal-session` IS the intended on-wire
        // format, so we project the primitive fields into a fresh
        // object before stringifying. The sidecar's
        // `SessionKey.import()` expects this exact shape.
        const jsonStr = JSON.stringify({
            address: exported.address,
            packageId: exported.packageId,
            mvrName: exported.mvrName,
            creationTimeMs: exported.creationTimeMs,
            ttlMin: exported.ttlMin,
            personalMessageSignature: exported.personalMessageSignature,
            sessionKey: exported.sessionKey,
        });
        const bytes =
            typeof btoa === "function"
                ? btoa(jsonStr)
                : Buffer.from(jsonStr, "utf8").toString("base64");

        this.sessionCache = {
            bytes,
            expiresAt:
                Date.now() +
                SEAL_SESSION_TTL_MIN * 60_000 -
                SEAL_SESSION_SAFETY_MARGIN_MS,
        };
        return bytes;
    }

    private async buildSealSession(): Promise<string> {
        // Fast path: cached session still fresh.
        if (this.sessionCache && Date.now() < this.sessionCache.expiresAt) {
            return this.sessionCache.bytes;
        }
        // Single-flight: concurrent requests share one build.
        if (this.sessionBuildPromise) return this.sessionBuildPromise;

        this.sessionBuildPromise = this.buildSealSessionInner().finally(() => {
            this.sessionBuildPromise = null;
        });
        return this.sessionBuildPromise;
    }

    /**
     * Make a signed request to the server.
     *
     * Signature format (LOW-23 updated):
     *   "{timestamp}.{method}.{path_and_query}.{body_sha256}.{nonce}.{account_id}"
     *
     * Headers: x-public-key, x-signature, x-timestamp, x-nonce, x-account-id
     *
     * The nonce is a UUID v4 generated per-request and tracked server-side
     * in Redis (TTL=600s) to prevent replay attacks.
     *
     * LOW-23: x-account-id is now included in the signed canonical message so
     * an intermediary cannot swap the account hint without invalidating the
     * signature. Server-side verification in services/server/src/auth.rs must
     * use the matching message format.
     *
     * ENG-1696: Callers set `includeDelegateKey: false` on Manual-mode routes
     * so the delegate private key is not transmitted. Manual-mode docstrings
     * promise the key stays client-side; the server does not need it on those
     * routes because Manual-mode handlers never invoke SEAL decrypt.
     *
     * ENG-1697: On Relayer-mode routes the SDK builds a SEAL SessionKey
     * client-side (emitted via `x-seal-session`). The SessionKey is ephemeral
     * (5-min TTL, scoped to the server's `packageId`) so a wire capture has
     * a bounded blast radius. Requires `@mysten/seal` and `@mysten/sui`.
     */
    /**
     * Make a signed request to the server.
     *
     * @param acceptedStatuses - HTTP status codes to treat as success (default [200]).
     *   Pass [200, 202] for endpoints that return 202 Accepted.
     */
    /**
     * `fetch` plus the JSON body read, with this client's deadline applied across both.
     *
     * For the handshake endpoints that skip request signing — `/health`,
     * `/version`, `/config`. They are the worst place to leave unbounded: the
     * compatibility probe and config fetch run before the first real call, so
     * one stalled socket there hangs every method on the client, not just one.
     */
    /** Deadline for one status poll: the client deadline, clamped so it can
     * never outlive the wait budget it belongs to, but given a usable minimum
     * at or past the deadline so a boundary check does not fail with an
     * artificial 1ms AbortError (#1081). */
    private pollDeadlineMs(deadline: number): number {
        const remaining = deadline - Date.now();
        const minPollTimeout = Math.min(this.requestTimeoutMs, 1_000);
        if (remaining <= 0) {
            return minPollTimeout;
        }
        return Math.min(this.requestTimeoutMs, Math.max(remaining, minPollTimeout));
    }

    private async fetchWithDeadline<T>(
        url: string,
        init: RequestInit = {},
        timeoutMs?: number,
        phase?: string,
    ): Promise<{ ok: boolean; status: number; body: T | undefined }> {
        const ms = timeoutMs ?? this.requestTimeoutMs;
        const deadline = deadlineSignal(ms);
        try {
            const res = await fetch(url, { ...init, signal: deadline.signal });
            let body: T | undefined;
            if (res.ok) {
                const raw = await res.text();
                if (raw.trim() === "") {
                    throw jsonBodyError(
                        res.status,
                        `MemWal: HTTP ${res.status} response had an empty body; expected JSON`,
                    );
                }
                try {
                    body = JSON.parse(raw) as T;
                } catch (err) {
                    if (err instanceof SyntaxError) {
                        throw jsonBodyError(res.status, `MemWal: HTTP ${res.status} response was not JSON`);
                    }
                    throw err;
                }
            }
            return { ok: res.ok, status: res.status, body };
        } catch (err) {
            if (deadline.timedOut()) {
                throw requestTimeoutError(init.method ?? "GET", url, ms, phase);
            }
            throw err;
        } finally {
            deadline.dispose();
        }
    }

    private async signedRequest<T>(
        method: string,
        path: string,
        body: object,
        acceptedStatusesOrOptions: number[] | SignedRequestOptions = [200],
        requestOptions: SignedRequestOptions = {},
    ): Promise<T> {
        const acceptedStatuses = Array.isArray(acceptedStatusesOrOptions)
            ? acceptedStatusesOrOptions
            : [200];
        const options = Array.isArray(acceptedStatusesOrOptions)
            ? requestOptions
            : acceptedStatusesOrOptions;
        // Before the version probe. A destroyed client must not open GET /version. (#1090)
        if (this.destroyed) throw destroyedClientError();
        await this.ensureCompatibleRelayer();
        const ed = await getEd();

        const timestamp = Math.floor(Date.now() / 1000).toString();
        // Canonical body used for both: (a) the HTTP wire body and
        // (b) the SHA-256 digest inside the signed message. GET requests
        // carry no body, so the server will hash an EMPTY byte string —
        // we must sign the same empty string for the signature to verify.
        const bodyStr = method === "GET" ? "" : JSON.stringify(body);
        const bodySha256 = await sha256hex(bodyStr);

        // MED-1 fix: Generate per-request nonce (UUID v4) for replay protection
        const nonce = crypto.randomUUID();

        // LOW-23: Build message to sign — now includes nonce AND account id
        const message = `${timestamp}.${method}.${path}.${bodySha256}.${nonce}.${this.accountId}`;
        const msgBytes = new TextEncoder().encode(message);

        // Again after the version await. A destroy that lands while that
        // request is in flight must still refuse to sign. (#1090)
        if (this.destroyed) throw destroyedClientError();
        // Sign with Ed25519
        const signature = await ed.signAsync(msgBytes, this.privateKey);
        // destroy() during the sign, or during public-key derivation, must
        // not reach fetch with the wiped seed's well-known key. (#1090)
        if (this.destroyed) throw destroyedClientError();
        const publicKey = await this.getPublicKey();
        if (this.destroyed) throw destroyedClientError();

        // Make HTTP request
        const url = `${this.serverUrl}${path}`;
        const headers: Record<string, string> = {
            "Content-Type": "application/json",
            "x-public-key": bytesToHex(publicKey),
            "x-signature": bytesToHex(signature),
            "x-timestamp": timestamp,
            "x-nonce": nonce,           // MED-1: replay protection
            "x-account-id": this.accountId,
        };
        // ENG-1696 / ENG-1697: attach a SEAL credential only on Relayer-
        // mode routes where the server needs it for server-side SEAL
        // decrypt. Manual-mode methods (rememberManual, recallManual) opt
        // out and transmit no decrypt credential at all.
        if (options.includeDelegateKey !== false) {
            headers["x-seal-session"] = await this.buildSealSession();
        }
        // WALM-598: the caller's deadline starts HERE, not at the top of the
        // call. Everything above — `ensureCompatibleRelayer()` (`/version` ->
        // `/health`) and `buildSealSession()` (`/config`, dynamic imports, a
        // Sui RPC round-trip for `SessionKey.create`) — is preflight work that
        // used to run inside the caller's budget while being unabortable
        // itself. Each of those now carries its own independent deadline.
        //
        // `fetch` never times out on its own, so this deadline is also the only
        // thing standing between a stalled socket and a call that hangs for as
        // long as the connection stays open.
        const explicitTimeout = options.timeoutMs;
        const deadlineOptOut = typeof explicitTimeout === "number"
            && (!Number.isFinite(explicitTimeout) || explicitTimeout <= 0);
        const deadlineMs = deadlineOptOut
            ? undefined
            : (explicitTimeout ?? this.requestTimeoutMs);
        const deadline = deadlineMs === undefined
            ? undefined
            : deadlineSignal(deadlineMs, options.signal);
        try {
            const res = await fetch(url, {
                method,
                headers,
                body: method === "GET" ? undefined : bodyStr,
                signal: deadline?.signal ?? options.signal,
            });

            if (!acceptedStatuses.includes(res.status)) {
                // LOW-26: sanitize server error bodies before surfacing to callers.
                const raw = await res.text();
                const compatibilityError = compatibilityErrorFromStatus(res.status, raw);
                if (compatibilityError) throw compatibilityError;

                // A stale/future-dated signature is rejected with 401 + a machine-
                // readable reason header. Surface it as an actionable clock-drift
                // error rather than an opaque 401 so the caller can fix node time.
                const clockDriftError = clockDriftErrorFromResponse(res);
                if (clockDriftError) throw clockDriftError;

                const { message, serverCode } = sanitizeServerError(
                    res.status,
                    raw,
                    res.headers.get("x-auth-error"),
                );
                const err = new Error(message) as Error & {
                    status?: number;
                    serverCode?: string;
                    retryAfterSeconds?: number;
                    cause?: string;
                };
                err.status = res.status;
                if (serverCode) err.serverCode = serverCode;
                const retryAfter = Number(res.headers.get("retry-after"));
                if (Number.isFinite(retryAfter) && retryAfter > 0) {
                    err.retryAfterSeconds = retryAfter;
                }
                // Preserve raw body on `cause` for in-process debugging only.
                err.cause = raw;
                throw err;
            }

            const rawBody = await res.text();
            if (rawBody.trim() === "") {
                throw jsonBodyError(
                    res.status,
                    `MemWal: HTTP ${res.status} response had an empty body; expected JSON`,
                );
            }
            try {
                return JSON.parse(rawBody) as T;
            } catch (err) {
                if (err instanceof SyntaxError) {
                    throw jsonBodyError(res.status, `MemWal: HTTP ${res.status} response was not JSON`);
                }
                throw err;
            }
        } catch (err) {
            // Translate our own expiry into something a caller can classify.
            // An abort the CALLER asked for is theirs and propagates untouched.
            const status = err && typeof err === "object" && "status" in err
                ? err.status
                : undefined;
            if (deadline?.timedOut() && typeof status !== "number") {
                throw requestTimeoutError(method, path, deadlineMs ?? 0);
            }
            throw err;
        } finally {
            deadline?.dispose();
        }
    }
}
