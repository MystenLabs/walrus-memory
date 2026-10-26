/**
 * Generic retry wrapper for Sui RPC calls that hit rate limits or
 * transient availability errors.
 */

// gRPC status codes (from @protobuf-ts/runtime-rpc's RpcError.code, used by
// SuiGrpcClient) that map to the same transient conditions the JSON-RPC string
// matching below covers. gRPC errors don't carry "429"/"503"/"timeout" text, so
// without this the write path silently stops retrying once SUI_GRPC_URL is set.
const RETRYABLE_GRPC_CODES = new Set([
    "UNAVAILABLE",
    "RESOURCE_EXHAUSTED",
    "DEADLINE_EXCEEDED",
    "ABORTED",
]);

const RETRYABLE_CONNECTION_CODES = new Set([
    "ECONNREFUSED",
    "ECONNRESET",
    "EAI_AGAIN",
    "ETIMEDOUT",
    "UND_ERR_CONNECT_TIMEOUT",
    "UND_ERR_SOCKET",
]);

export class NoSideEffectError extends Error {
    readonly code: string = "NO_SIDE_EFFECT";

    constructor(message: string) {
        super(message);
        this.name = "NoSideEffectError";
    }
}

export class FinalizedTransactionFailure extends NoSideEffectError {
    readonly code: string = "FINALIZED_TRANSACTION_FAILURE";

    constructor(message: string) {
        super(message);
        this.name = "FinalizedTransactionFailure";
    }
}

/**
 * The transaction finalized as failed because shared objects stayed congested.
 * The digest can never land, so a rebuild may use a new nonce. Every other
 * finalized failure keeps the old digest: re-preparing byte-identical lets the
 * digest lookup find it instead of paying for a second register.
 */
export class CongestionCancelledTransaction extends FinalizedTransactionFailure {
    readonly code = "CONGESTION_CANCELLED_TRANSACTION";

    constructor(message: string) {
        super(message);
        this.name = "CongestionCancelledTransaction";
    }
}

export class DurableSideEffectVerifyError extends Error {
    readonly code = "DURABLE_SIDE_EFFECT_VERIFY_FAILED";

    constructor(message: string) {
        super(message);
        this.name = "DurableSideEffectVerifyError";
    }
}

/**
 * Strict shared-infrastructure classifier: structured status/code checks plus
 * specific outage phrases only. It deliberately does NOT match bare 3-digit
 * numbers in free text — deterministic on-chain failures such as
 * "MoveAbort ... abort code: 503" must never look like a transient outage.
 * The durable side-effect classification path uses this variant so a
 * deterministic failure after a started-marker consumes the retry budget
 * instead of becoming a budget-free infinite retry.
 */
export function isRetryableSharedInfraError(err: any): boolean {
    if (typeof err?.code === "string" && RETRYABLE_GRPC_CODES.has(err.code)) {
        return true;
    }
    const status = err?.status ?? err?.statusCode ?? (typeof err?.code === "number" ? err.code : undefined);
    if (status === 408 || status === 429 || (status >= 500 && status <= 599)) {
        return true;
    }
    const connectionCode = err?.cause?.code ?? err?.code;
    if (typeof connectionCode === "string" && RETRYABLE_CONNECTION_CODES.has(connectionCode)) {
        return true;
    }
    const msg = String(err?.message || err).toLowerCase();
    return msg.includes("rate limit")
        || msg.includes("rate-limit")
        || msg.includes("ratelimit")
        || msg.includes("too many")
        || msg.includes("timeout")
        || msg.includes("timed out")
        || msg.includes("temporarily unavailable");
}

/**
 * Legacy retry classifier for bounded in-process retries (withRpcRetry and
 * the Seal error paths). On top of the strict checks it also matches bare
 * "408"/"429"/"5xx" digits in message text for JSON-RPC transports whose
 * errors surface only as "HTTP 503"-style strings. That looseness is
 * acceptable for a bounded retry loop but not for durable classification —
 * use isRetryableSharedInfraError there.
 */
export function isRetryableRpcError(err: any): boolean {
    if (isRetryableSharedInfraError(err)) {
        return true;
    }
    const msg = String(err?.message || err).toLowerCase();
    return /\b(?:408|429|5\d\d)\b/.test(msg);
}

export function classifyDurableSideEffectError(
    err: unknown,
    phaseCanSubmitSideEffect: boolean,
    submissionStarted: boolean,
): {
    code:
        | "NO_SIDE_EFFECT"
        | "CONGESTION_CANCELLED_TRANSACTION"
        | "SHARED_SERVICE_UNAVAILABLE"
        | "DURABLE_SIDE_EFFECT_VERIFY_FAILED";
    causeCode?: "SHARED_SERVICE_UNAVAILABLE";
} | null {
    if (err instanceof DurableSideEffectVerifyError) {
        return { code: "DURABLE_SIDE_EFFECT_VERIFY_FAILED" };
    }
    if (err instanceof CongestionCancelledTransaction) {
        return { code: "CONGESTION_CANCELLED_TRANSACTION" };
    }
    if (err instanceof NoSideEffectError) {
        return { code: "NO_SIDE_EFFECT" };
    }
    const sharedServiceUnavailable = isRetryableSharedInfraError(err);
    if (phaseCanSubmitSideEffect && !submissionStarted) {
        return {
            code: "NO_SIDE_EFFECT",
            ...(sharedServiceUnavailable
                ? { causeCode: "SHARED_SERVICE_UNAVAILABLE" as const }
                : {}),
        };
    }
    if (phaseCanSubmitSideEffect && submissionStarted && !sharedServiceUnavailable) {
        return { code: "DURABLE_SIDE_EFFECT_VERIFY_FAILED" };
    }
    return sharedServiceUnavailable ? { code: "SHARED_SERVICE_UNAVAILABLE" } : null;
}

/**
 * Retry `fn` with exponential backoff + jitter on retryable RPC errors.
 * `label` is included verbatim in the retry warn log — callers prefix it
 * with their log scope (e.g. "[query-blobs] queryTransactionBlocks").
 */
export async function withRpcRetry<T>(
    label: string,
    fn: () => Promise<T>,
    maxRetries = 4,
): Promise<T> {
    let lastErr: any;
    for (let attempt = 0; attempt < maxRetries; attempt++) {
        try {
            return await fn();
        } catch (err: any) {
            lastErr = err;
            if (!isRetryableRpcError(err) || attempt === maxRetries - 1) throw err;
            const baseDelayMs = 1_000 * Math.pow(2, attempt);
            const jitterMs = Math.floor(Math.random() * Math.floor(baseDelayMs * 0.4));
            const delayMs = Math.min(15_000, baseDelayMs + jitterMs);
            console.warn(`${label} retrying in ${delayMs}ms (attempt ${attempt + 1}/${maxRetries})`);
            await new Promise(r => setTimeout(r, delayMs));
        }
    }
    throw lastErr;
}
