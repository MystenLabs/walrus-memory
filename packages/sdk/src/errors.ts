import type { RememberJobStatus } from "./types.js";

/**
 * Thrown by `waitForRememberJobs` (and `rememberBulkAndWait`, which calls it)
 * when every status read for the batch, including the post-deadline
 * confirming read, was rate-limited (429). `waitForRememberJob` retries a 429
 * instead and ends as `MemWalRememberJobTimeoutError` if the deadline runs
 * out. The status endpoint counts against the same delegate-key budget as
 * writes, so a refusal says nothing about the jobs themselves — do not treat
 * them as stored (GH #967).
 */
export class MemWalRateLimitedError extends Error {
    readonly status = 429 as const;
    readonly jobIds: string[];
    readonly retryAfterSeconds?: number;

    constructor(message: string, jobIds: string[], retryAfterSeconds?: number) {
        super(message);
        this.name = "MemWalRateLimited";
        this.jobIds = jobIds;
        this.retryAfterSeconds = retryAfterSeconds;
    }
}

/** Thrown by `waitForRememberJob` when the relayer has no record of the job id. */
export class MemWalRememberJobNotFoundError extends Error {
    readonly status = 404 as const;
    readonly jobId: string;

    constructor(jobId: string) {
        super(`remember job not found: ${jobId}`);
        this.name = "MemWalRememberJobNotFound";
        this.jobId = jobId;
    }
}

/** Thrown by `waitForRememberJob` when the job reaches the `failed` terminal state. */
export class MemWalRememberJobFailedError extends Error {
    readonly status = 500 as const;
    readonly jobId: string;

    constructor(jobId: string, serverError: string) {
        super(`remember job failed: ${serverError}`);
        this.name = "MemWalRememberJobFailed";
        this.jobId = jobId;
    }
}

/**
 * Thrown by `waitForRememberJob` when its wait budget runs out before the
 * job reaches a terminal state. The job itself may still complete — callers
 * should keep polling the same job id rather than retrying the write.
 */
export class MemWalRememberJobTimeoutError extends Error {
    readonly status = 504 as const;
    readonly jobId: string;
    readonly timeoutMs: number;
    readonly lastStatus?: RememberJobStatus["status"];
    readonly serverError?: string;

    constructor(
        message: string,
        jobId: string,
        timeoutMs: number,
        lastStatus?: RememberJobStatus["status"],
        serverError?: string,
    ) {
        super(message);
        this.name = "MemWalRememberJobTimeout";
        this.jobId = jobId;
        this.timeoutMs = timeoutMs;
        this.lastStatus = lastStatus;
        this.serverError = serverError;
    }
}

/**
 * Thrown by `recall()` when the relayer matched one or more vector entries
 * (`dropped_count > 0` or `degraded: true`), yet every matched blob failed
 * Walrus download, SEAL decrypt, or UTF-8 decode (`results.length === 0`).
 *
 * Pass `onDropped: "ignore"` to `recall()` when you prefer to inspect the
 * degraded `RecallResult` (`degraded: true`, `dropped_count`, `total`)
 * directly without throwing.
 */
export class MemWalRecallAllDroppedError extends Error {
    readonly code = "RECALL_ALL_DROPPED" as const;
    readonly total: number;
    readonly droppedCount: number;
    readonly namespace: string;

    constructor(droppedCount: number, total: number, namespace: string) {
        const noun = total === 1 ? "match" : "matches";
        super(
            `MemWal recall matched ${total} ${noun} in namespace "${namespace}", ` +
                `but all ${droppedCount} failed to download or decrypt`,
        );
        this.name = "MemWalRecallAllDropped";
        this.total = total;
        this.droppedCount = droppedCount;
        this.namespace = namespace;
    }
}
