import type { RememberJobStatus } from "./types.js";
import type {
    RememberValidationCode,
    RememberValidationIssue,
    SecretPatternKind,
} from "./validation.js";

/**
 * Thrown by `remember*` when client-side write validation rejects input text
 * (e.g. `text_too_long` above 1 MiB or `secret_pattern_detected` when
 * `allowSecrets` is not set) (#435).
 */
export class MemWalValidationError extends Error {
    readonly status = 400 as const;
    readonly code: RememberValidationCode;
    readonly issues: RememberValidationIssue[];
    readonly kinds: SecretPatternKind[];

    constructor(
        message: string,
        code: RememberValidationCode,
        issues: RememberValidationIssue[],
        kinds: SecretPatternKind[] = [],
    ) {
        super(message);
        this.name = "MemWalValidationError";
        this.code = code;
        this.issues = issues;
        this.kinds = kinds;
    }
}

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
