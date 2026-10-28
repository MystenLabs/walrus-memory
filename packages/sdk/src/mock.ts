import type {
    AnalyzeOptions,
    AnalyzeResult,
    AnalyzeWaitResult,
    EmbedResult,
    HealthResult,
    RecallOptions,
    RecallParams,
    RecallResult,
    RelayerVersionMetadata,
    RememberOptions,
    RememberWaitOptions,
    RememberAcceptedResult,
    RememberBulkAcceptedResult,
    RememberBulkItem,
    RememberBulkItemResult,
    RememberBulkOptions,
    RememberBulkAsyncOptions,
    RememberBulkResult,
    RememberBulkStatusResult,
    RememberJobStatus,
    RememberResult,
    RestoreResult,
    NamespacesResult,
    ListNamespacesOptions,
} from "./types.js";
import { applyTokenBudget, estimateTokens, validateMaxTokens } from "./tokens.js";
import { resolveRecallCall } from "./recall-args.js";
import { derivedBulkIdempotencyKey } from "./utils.js";
import { MemWalRememberJobNotFoundError } from "./errors.js";
import {
    assertValidRememberText,
    validateRemember,
    type RememberValidationResult,
    type ValidateRememberOptions,
} from "./validation.js";

/** Matches the relayer's `MAX_BULK_ITEMS`. */
const MAX_BULK_ITEMS = 20;

interface RememberCallOptions extends RememberWaitOptions {}

/** A plain object in the namespace slot is options, not a namespace.
 * A third options argument is merged, and its fields win. (#1142) */
function splitRememberArgs(
    namespaceOrOptions?: string | RememberCallOptions,
    options?: RememberCallOptions,
): { namespace?: string; options: RememberCallOptions } {
    if (typeof namespaceOrOptions === "object" && namespaceOrOptions !== null) {
        return { namespace: undefined, options: { ...namespaceOrOptions, ...options } };
    }
    return { namespace: namespaceOrOptions, options: options ?? {} };
}

export interface MemWalMockSeed {
    text: string;
    namespace?: string;
    blobId?: string;
}

export interface MemWalMockConfig {
    /** Default namespace, matching MemWalConfig (default: "default"). */
    namespace?: string;
    /** Stable owner value returned by result objects (default: "mock-owner"). */
    owner?: string;
    /** Optional records loaded synchronously when the mock is created. */
    initialMemories?: MemWalMockSeed[];
}

interface MockMemory {
    id: string;
    jobId: string;
    blobId: string;
    text: string;
    namespace: string;
    sequence: number;
}

/**
 * Fixed base for synthesised namespace timestamps. `MockMemory` carries no
 * clock, so `updated_at` is derived from insertion order instead — keeping
 * mock runs reproducible while preserving the real relayer's property that
 * later writes sort later.
 */
const MOCK_NAMESPACE_EPOCH_MS = Date.UTC(2026, 0, 1);

const MOCK_VERSION: RelayerVersionMetadata = {
    relayerVersion: "memwal-mock",
    apiVersion: "1.0.0",
    minSupportedSdk: { typescript: "0.0.0", python: "0.0.0", mcp: "0.0.0" },
    featureFlags: { offlineMock: true },
    deprecations: [],
    build: {},
};

function tokenize(text: string): Set<string> {
    return new Set(
        text
            .normalize("NFKC")
            .toLowerCase()
            .match(/[\p{L}\p{N}]+/gu) ?? []
    );
}

function distance(queryTokens: Set<string>, text: string): number {
    if (queryTokens.size === 0) return 1;
    const memoryTokens = tokenize(text);
    let matches = 0;
    for (const token of queryTokens) {
        if (memoryTokens.has(token)) matches += 1;
    }
    return 1 - matches / queryTokens.size;
}

function requireRememberText(text: unknown): asserts text is string {
    if (typeof text !== "string") {
        throw new TypeError(
            `remember() expects text as a string, received ${typeof text}. ` +
            `Did you mean remember(text, namespace)? Unlike recall(), remember* does not take an options object.`,
        );
    }
}

const ZERO_WIDTH_ONLY = /^[\s\u200B-\u200D\u2060\uFEFF]*$/;

function validateText(text: string, field = "text"): void {
    if (typeof text !== "string" || text.trim().length === 0 || ZERO_WIDTH_ONLY.test(text)) {
        throw new Error(`${field} cannot be empty`);
    }
}

function assertOccurredAt(occurredAt?: string | Date): void {
    if (!(occurredAt instanceof Date) || !Number.isNaN(occurredAt.getTime())) return;
    throw new TypeError(
        "occurredAt is an Invalid Date — likely constructed from a " +
        "malformed string. `Date` accepts garbage silently; check " +
        "the source value before passing it as occurredAt.",
    );
}

const MAX_IDEMPOTENCY_KEY_BYTES = 255;

function validateIdempotencyKey(key: string | undefined): void {
    if (key === undefined) return;
    if (key.length === 0) {
        throw new Error("idempotency_key cannot be empty (omit it instead)");
    }
    if (new TextEncoder().encode(key).length > MAX_IDEMPOTENCY_KEY_BYTES) {
        throw new Error(
            `idempotency_key exceeds maximum length of ${MAX_IDEMPOTENCY_KEY_BYTES} bytes`,
        );
    }
}

/** How many semantic candidates `sort: "recent"` reorders. Mirrors `RecallSort::candidate_limit`. */
function recentCandidateLimit(limit: number): number {
    return Math.max(Math.min(limit * 5, 50), limit);
}

/** Relayer cursors are `{ updated_at, namespace, snapshot_at }`. A decode that
 * is not that shape must fail loudly: `NaN` date comparisons otherwise filter
 * out every namespace and a `while (has_more)` walk stops on the first page. */
function decodeListNamespacesCursor(encoded: string): {
    updated_at: string;
    namespace: string;
    snapshot_at?: string | null;
} {
    let decoded: unknown;
    try {
        decoded = JSON.parse(new TextDecoder().decode(
            Uint8Array.from(
                atob(encoded.replace(/-/g, "+").replace(/_/g, "/")),
                (char) => char.charCodeAt(0),
            ),
        ));
    } catch {
        throw new Error("invalid namespace cursor");
    }
    if (decoded === null || typeof decoded !== "object" || Array.isArray(decoded)) {
        throw new Error("invalid namespace cursor");
    }
    const cursor = decoded as {
        updated_at?: unknown;
        namespace?: unknown;
        snapshot_at?: unknown;
    };
    const updatedAt = cursor.updated_at;
    const namespace = cursor.namespace;
    if (typeof updatedAt !== "string" || !Number.isFinite(Date.parse(updatedAt))) {
        throw new Error("invalid namespace cursor");
    }
    if (typeof namespace !== "string") {
        throw new Error("invalid namespace cursor");
    }
    const snapshotAt = cursor.snapshot_at;
    if (snapshotAt !== undefined && snapshotAt !== null && typeof snapshotAt !== "string") {
        throw new Error("invalid namespace cursor");
    }
    if (typeof snapshotAt === "string" && !Number.isFinite(Date.parse(snapshotAt))) {
        throw new Error("invalid namespace cursor");
    }
    return { updated_at: updatedAt, namespace, snapshot_at: snapshotAt };
}

/**
 * Deterministic, dependency-free in-memory implementation of the core MemWal API.
 * It never opens a socket, reads credentials, or contacts Sui/Walrus. Recall uses
 * token-overlap distance so tests are stable across machines and runs.
 */
export class MemWalMock {
    private readonly owner: string;
    private readonly namespace: string;
    private readonly memories: MockMemory[] = [];
    private readonly jobs = new Map<string, MockMemory>();
    /** idempotency key → job id. Released when that job's memory is forgotten. */
    private readonly idempotency = new Map<string, string>();
    /** content-dedupe key (`namespace\0text`) → job id for `dedupe: true` writes. */
    private readonly dedupe = new Map<string, string>();
    private sequence = 0;

    private constructor(config: MemWalMockConfig = {}) {
        this.owner = config.owner ?? "mock-owner";
        this.namespace = config.namespace ?? "default";
        if (!this.namespace) throw new Error("namespace cannot be empty");
        for (const seed of config.initialMemories ?? []) {
            this.store(seed.text, seed.namespace, seed.blobId);
        }
    }

    static create(config: MemWalMockConfig = {}): MemWalMock {
        return new MemWalMock(config);
    }

    destroy(): void {
        this.memories.length = 0;
        this.jobs.clear();
        this.idempotency.clear();
        this.dedupe.clear();
    }

    validateRemember(
        text: string,
        options?: ValidateRememberOptions,
    ): RememberValidationResult {
        return validateRemember(text, options);
    }

    async rememberAsync(
        text: string,
        namespaceOrOptions?: string | RememberOptions,
        options?: RememberOptions,
    ): Promise<RememberAcceptedResult> {
        requireRememberText(text);
        validateText(text);
        const split = splitRememberArgs(namespaceOrOptions, options);
        assertValidRememberText(text, split.options);
        if (split.options.dryRun === true) {
            return { job_id: "dry-run", status: "dry_run" };
        }
        const memory = this.store(
            text,
            split.namespace,
            undefined,
            split.options.idempotencyKey,
            false,
            split.options.dedupe === true,
        );
        return { job_id: memory.jobId, status: "done" };
    }

    async remember(
        text: string,
        namespaceOrOptions?: string | RememberOptions,
        options?: RememberOptions,
    ): Promise<RememberAcceptedResult> {
        return this.rememberAsync(text, namespaceOrOptions, options);
    }

    async getRememberStatus(jobId: string): Promise<RememberJobStatus> {
        const memory = this.jobs.get(jobId);
        if (!memory) return { job_id: jobId, status: "not_found" };
        return {
            job_id: jobId,
            status: "done",
            owner: this.owner,
            namespace: memory.namespace,
            blob_id: memory.blobId,
        };
    }

    async waitForRememberJob(
        jobId: string,
        _opts: { pollIntervalMs?: number; timeoutMs?: number } = {}
    ): Promise<RememberResult> {
        const memory = this.jobs.get(jobId);
        if (!memory) throw new MemWalRememberJobNotFoundError(jobId);
        return this.toRememberResult(memory);
    }

    async rememberAndWait(
        text: string,
        namespaceOrOptions?: string | RememberCallOptions,
        opts?: RememberCallOptions,
    ): Promise<RememberResult> {
        const split = splitRememberArgs(namespaceOrOptions, opts);
        const accepted = await this.rememberAsync(text, split.namespace, {
            idempotencyKey: split.options.idempotencyKey,
            dedupe: split.options.dedupe,
            allowSecrets: split.options.allowSecrets,
            skipValidation: split.options.skipValidation,
            dryRun: split.options.dryRun,
        });
        if (split.options.dryRun === true) {
            return {
                id: "dry-run",
                job_id: "dry-run",
                blob_id: "",
                owner: this.owner,
                namespace: split.namespace ?? this.namespace,
            };
        }
        return this.waitForRememberJob(accepted.job_id, split.options);
    }

    async rememberBulkAsync(
        items: RememberBulkItem[],
        options: RememberBulkAsyncOptions = {}
    ): Promise<RememberBulkAcceptedResult> {
        if (!Array.isArray(items) || items.length === 0) {
            throw new Error("rememberBulkAsync: items must be a non-empty array");
        }
        if (items.length > MAX_BULK_ITEMS) {
            throw new Error(
                `rememberBulkAsync: items exceeds maximum of ${MAX_BULK_ITEMS} per bulk request`,
            );
        }
        items.forEach((item, i) => {
            validateText(item?.text, `items[${i}].text`);
            assertValidRememberText(item.text, options, `items[${i}].text`);
        });

        validateIdempotencyKey(options.idempotencyKey);
        if (options.dryRun === true) {
            return {
                job_ids: items.map((_, i) => `dry-run-${i + 1}`),
                total: items.length,
                status: "dry_run",
            };
        }
        const normalised = items.map((item) => ({
            text: item.text,
            namespace: item.namespace ?? this.namespace,
        }));
        const requestIdentity = `bulk\0${normalised.map((item) => `${item.namespace}\0${item.text}`).join("\0\0")}`;
        const bulkKey = options.idempotencyKey ?? (await derivedBulkIdempotencyKey(requestIdentity));
        const jobIds = normalised.map(
            (item, index) =>
                this.store(item.text, item.namespace, undefined, `bulk:${bulkKey}:${index}`, true).jobId
        );
        return { job_ids: jobIds, total: jobIds.length, status: "done" };
    }

    async rememberBulk(
        items: RememberBulkItem[],
        options: RememberBulkAsyncOptions = {}
    ): Promise<RememberBulkAcceptedResult> {
        return this.rememberBulkAsync(items, options);
    }

    async getRememberBulkStatus(
        jobIds: string[]
    ): Promise<RememberBulkStatusResult> {
        if (!Array.isArray(jobIds)) {
            throw new Error("getRememberBulkStatus: jobIds must be an array");
        }
        return {
            results: jobIds.map((jobId) => {
                const memory = this.jobs.get(jobId);
                return memory
                    ? {
                          job_id: jobId,
                          status: "done",
                          blob_id: memory.blobId,
                          namespace: memory.namespace,
                      }
                    : { job_id: jobId, status: "not_found" };
            }),
        };
    }

    async waitForRememberJobs(
        jobIds: string[],
        namespaces: string[] = [],
        _opts: RememberBulkOptions = {}
    ): Promise<RememberBulkResult> {
        const results: RememberBulkItemResult[] = jobIds.map((jobId, index) => {
            const memory = this.jobs.get(jobId);
            return memory
                ? {
                      id: jobId,
                      blob_id: memory.blobId,
                      status: "done",
                      namespace: memory.namespace,
                  }
                : {
                      id: jobId,
                      blob_id: "",
                      status: "failed",
                      namespace: namespaces[index] ?? this.namespace,
                      error: "Remember job not found",
                  };
        });
        const succeeded = results.filter(
            (result) => result.status === "done"
        ).length;
        return {
            results,
            total: results.length,
            succeeded,
            failed: results.length - succeeded,
        };
    }

    async rememberBulkAndWait(
        items: RememberBulkItem[],
        opts: RememberBulkOptions = {}
    ): Promise<RememberBulkResult> {
        const accepted = await this.rememberBulkAsync(items, opts);
        const namespaces = items.map(
            (item) => item.namespace ?? this.namespace
        );
        if (opts.dryRun === true) {
            return {
                results: accepted.job_ids.map((id, i) => ({
                    id,
                    blob_id: "",
                    status: "done",
                    namespace: namespaces[i],
                })),
                total: accepted.job_ids.length,
                succeeded: accepted.job_ids.length,
                failed: 0,
            };
        }
        return this.waitForRememberJobs(accepted.job_ids, namespaces, opts);
    }

    countTokens(text: string): number {
        return estimateTokens(text);
    }

    async recall(params: RecallParams): Promise<RecallResult>;
    /**
     * @deprecated Prefer `recall({ query, limit, namespace })`.
     */
    async recall(query: string, options: RecallOptions): Promise<RecallResult>;
    /**
     * @deprecated Prefer `recall({ query, limit, namespace })`.
     */
    async recall(
        query: string,
        limit?: number,
        namespace?: string
    ): Promise<RecallResult>;
    async recall(
        queryOrParams: string | RecallParams,
        limitOrOptions: number | RecallOptions | undefined = 10,
        namespace?: string
    ): Promise<RecallResult> {
        const { query, options } = resolveRecallCall(
            queryOrParams,
            limitOrOptions,
            namespace
        );
        validateText(query, "query");
        validateMaxTokens(options.maxTokens);
        const resolvedNamespace = options.namespace ?? this.namespace;
        const resolvedLimit = options.topK ?? options.limit ?? 10;
        if (!Number.isInteger(resolvedLimit) || resolvedLimit < 0) {
            throw new Error("limit must be a non-negative integer");
        }
        if (
            options.maxDistance !== undefined
            && (typeof options.maxDistance !== "number"
                || !Number.isFinite(options.maxDistance)
                || options.maxDistance < 0)
        ) {
            throw new Error("maxDistance must be a non-negative finite number");
        }

        const queryTokens = tokenize(query);
        const semantic = this.memories
            .filter((memory) => memory.namespace === resolvedNamespace)
            .map((memory) => ({
                memory,
                distance: distance(queryTokens, memory.text),
            }))
            .sort(
                (left, right) =>
                    left.distance - right.distance ||
                    left.memory.sequence - right.memory.sequence
            );
        // `recent` reorders a bounded semantic window by write time, then
        // truncates. Relevance keeps the cosine order. (#1124)
        const ordered =
            options.sort === "recent"
                ? semantic
                      .slice(0, recentCandidateLimit(resolvedLimit))
                      .sort(
                          (left, right) =>
                              right.memory.sequence - left.memory.sequence ||
                              left.distance - right.distance,
                      )
                : semantic;
        const page = ordered.slice(0, resolvedLimit);
        const maxDistance = options.maxDistance;
        const visible =
            maxDistance === undefined
                ? page
                : page.filter((entry) => entry.distance < maxDistance);
        const ranked = visible.map(({ memory, distance: memoryDistance }) => ({
            blob_id: memory.blobId,
            text: memory.text,
            distance: memoryDistance,
        }));

        if (options.maxTokens !== undefined) {
            const { results, meta } = applyTokenBudget(
                ranked,
                options.maxTokens,
                options.truncationStrategy,
                options.countTokens
            );
            return { results, total: ranked.length, meta };
        }

        return { results: ranked, total: page.length };
    }

    async analyze(
        text: string,
        namespaceOrOptions?: string | AnalyzeOptions
    ): Promise<AnalyzeResult> {
        validateText(text);
        // A valid occurredAt is not copied onto the result. The relayer uses
        // it only to rewrite relative dates into the fact text, and this mock
        // has no extractor. Invalid Dates still throw, matching MemWal.
        const occurredAt = typeof namespaceOrOptions === "string"
            ? undefined
            : namespaceOrOptions?.occurredAt;
        assertOccurredAt(occurredAt);
        if (typeof namespaceOrOptions === "object" && namespaceOrOptions?.signal) {
            namespaceOrOptions.signal.throwIfAborted();
        }
        const namespace =
            typeof namespaceOrOptions === "string"
                ? namespaceOrOptions
                : namespaceOrOptions?.namespace;
        const memory = this.store(text, namespace);
        return {
            job_ids: [memory.jobId],
            facts: [
                {
                    text,
                    id: memory.id,
                    job_id: memory.jobId,
                    blob_id: memory.blobId,
                },
            ],
            fact_count: 1,
            status: "done",
            owner: this.owner,
        };
    }

    async analyzeAndWait(
        text: string,
        namespaceOrOptions?: string | AnalyzeOptions,
        opts: RememberBulkOptions = {}
    ): Promise<AnalyzeWaitResult> {
        const analyzed = await this.analyze(text, namespaceOrOptions);
        const namespace =
            typeof namespaceOrOptions === "string"
                ? namespaceOrOptions
                : namespaceOrOptions?.namespace;
        const settled = await this.waitForRememberJobs(
            analyzed.job_ids,
            analyzed.job_ids.map(() => namespace ?? this.namespace),
            opts
        );
        return { ...settled, facts: analyzed.facts, owner: this.owner };
    }

    async embed(text: string): Promise<EmbedResult> {
        validateText(text);
        const vector = new Array<number>(16).fill(0);
        for (const token of tokenize(text)) {
            let hash = 2166136261;
            for (const char of token) {
                hash ^= char.codePointAt(0) ?? 0;
                hash = Math.imul(hash, 16777619);
            }
            vector[(hash >>> 0) % vector.length] += 1;
        }
        const magnitude = Math.hypot(...vector) || 1;
        return { vector: vector.map((value) => value / magnitude) };
    }

    async restore(namespace: string, _limit = 10): Promise<RestoreResult> {
        return {
            restored: 0,
            skipped: 0,
            failed: 0,
            total: 0,
            namespace,
            owner: this.owner,
            truncated: false,
        };
    }

    async listNamespaces(options: ListNamespacesOptions = {}): Promise<NamespacesResult> {
        // The relayer rejects limit < 1 with this message. slice(0, 0) would
        // otherwise report has_more with a null cursor, and slice(0, -1)
        // would drop the last namespace. (#1144, #1145)
        if (
            options.limit !== undefined &&
            (!Number.isInteger(options.limit) || options.limit < 1)
        ) {
            throw new Error("limit must be positive");
        }
        const grouped = new Map<string, { count: number; bytes: number; sequence: number }>();
        for (const memory of this.memories) {
            const entry = grouped.get(memory.namespace) ?? { count: 0, bytes: 0, sequence: 0 };
            entry.count += 1;
            entry.bytes += new TextEncoder().encode(memory.text).length;
            entry.sequence = Math.max(entry.sequence, memory.sequence);
            grouped.set(memory.namespace, entry);
        }

        const all = [...grouped.entries()]
            .map(([name, entry]) => ({
                id: `mock-ns-${name}`,
                name,
                memory_count: entry.count,
                storage_used: entry.bytes,
                updated_at: new Date(
                    MOCK_NAMESPACE_EPOCH_MS + entry.sequence * 1000
                ).toISOString(),
            }))
            .sort((a, b) =>
                a.updated_at === b.updated_at
                    ? a.name.localeCompare(b.name)
                    : a.updated_at.localeCompare(b.updated_at)
            );

        // Match the relayer's URL_SAFE_NO_PAD JSON cursor and snapshot walk.
        const cursor = options.cursor === undefined
            ? null
            : decodeListNamespacesCursor(options.cursor);
        const snapshotAt = cursor?.snapshot_at ?? new Date(
            MOCK_NAMESPACE_EPOCH_MS + this.sequence * 1000,
        ).toISOString();
        const remaining = all.filter((ns) =>
            Date.parse(ns.updated_at) <= Date.parse(snapshotAt) &&
            (!cursor || Date.parse(ns.updated_at) > Date.parse(cursor.updated_at) ||
                (Date.parse(ns.updated_at) === Date.parse(cursor.updated_at) &&
                    ns.name > cursor.namespace))
        );
        const page = remaining.slice(0, options.limit ?? remaining.length);
        const hasMore = remaining.length > page.length;
        const last = page.at(-1);
        const watermark = last ? { updated_at: last.updated_at, namespace: last.name } : cursor;
        const nextCursor = watermark ? btoa(Array.from(new TextEncoder().encode(JSON.stringify({
            updated_at: watermark.updated_at,
            namespace: watermark.namespace,
            snapshot_at: hasMore ? snapshotAt : null,
        })), (byte) => String.fromCharCode(byte)).join(""))
            .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") : null;

        return {
            namespaces: page,
            next_cursor: nextCursor,
            has_more: hasMore,
            // Matches the live relayer's current wire-format version.
            snapshot_version: 2,
        };
    }

    async health(): Promise<HealthResult> {
        return { status: "ok", version: "memwal-mock", ...MOCK_VERSION };
    }

    async compatibility(): Promise<RelayerVersionMetadata> {
        return structuredClone(MOCK_VERSION);
    }

    /** Delete one mock record by blob id. Returns whether a record was removed. */
    forget(blobId: string): boolean {
        const index = this.memories.findIndex(
            (memory) => memory.blobId === blobId
        );
        if (index < 0) return false;
        const [memory] = this.memories.splice(index, 1);
        this.jobs.delete(memory.jobId);
        this.releaseIdempotency(memory.jobId);
        return true;
    }

    /** Clear one namespace, or every mock record when omitted. */
    clear(namespace?: string): number {
        const removed = this.memories.filter(
            (memory) =>
                namespace === undefined || memory.namespace === namespace
        );
        if (namespace === undefined) {
            this.memories.length = 0;
        } else {
            for (let index = this.memories.length - 1; index >= 0; index -= 1) {
                if (this.memories[index].namespace === namespace)
                    this.memories.splice(index, 1);
            }
        }
        for (const memory of removed) {
            this.jobs.delete(memory.jobId);
            this.releaseIdempotency(memory.jobId);
        }
        return removed.length;
    }

    private store(
        text: string,
        namespace?: string,
        blobId?: string,
        idempotencyKey?: string,
        skipKeyValidation: boolean = false,
        dedupe: boolean = false,
    ): MockMemory {
        validateText(text);
        if (!skipKeyValidation) {
            validateIdempotencyKey(idempotencyKey);
        }
        const resolvedNamespace = namespace ?? this.namespace;
        if (!resolvedNamespace) throw new Error("namespace cannot be empty");
        if (dedupe) {
            const dedupeKey = `${resolvedNamespace}\0${text}`;
            const existingId = this.dedupe.get(dedupeKey);
            const existingDedupe = existingId ? this.jobs.get(existingId) : undefined;
            if (existingDedupe) return existingDedupe;
            if (existingId) this.dedupe.delete(dedupeKey);
        } else if (idempotencyKey !== undefined) {
            const mapKey = `${resolvedNamespace}\0${idempotencyKey}`;
            const existingId = this.idempotency.get(mapKey);
            const existing = existingId ? this.jobs.get(existingId) : undefined;
            if (existing) {
                if (existing.text !== text || existing.namespace !== resolvedNamespace) {
                    throw new Error(
                        "idempotency_key was already used for a request with different content",
                    );
                }
                return existing;
            }
            if (existingId) this.idempotency.delete(mapKey);
        }
        this.sequence += 1;
        const suffix = this.sequence.toString().padStart(6, "0");
        const memory: MockMemory = {
            id: `mock-job-${suffix}`,
            jobId: `mock-job-${suffix}`,
            blobId: blobId ?? `mock-blob-${suffix}`,
            text,
            namespace: resolvedNamespace,
            sequence: this.sequence,
        };
        this.memories.push(memory);
        this.jobs.set(memory.jobId, memory);
        if (dedupe) {
            this.dedupe.set(`${resolvedNamespace}\0${text}`, memory.jobId);
        } else if (idempotencyKey !== undefined) {
            this.idempotency.set(`${resolvedNamespace}\0${idempotencyKey}`, memory.jobId);
        }
        return memory;
    }

    private releaseIdempotency(jobId: string): void {
        for (const [key, id] of this.idempotency) {
            if (id === jobId) this.idempotency.delete(key);
        }
        for (const [key, id] of this.dedupe) {
            if (id === jobId) this.dedupe.delete(key);
        }
    }

    private toRememberResult(memory: MockMemory): RememberResult {
        return {
            id: memory.id,
            job_id: memory.jobId,
            blob_id: memory.blobId,
            owner: this.owner,
            namespace: memory.namespace,
        };
    }
}
