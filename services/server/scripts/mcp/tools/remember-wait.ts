/**
 * Shared wait-budget and job-error handling for the two remember tools.
 *
 * `memwal_remember` used to block on `rememberAndWait` until the write reached
 * `done`. Measured against the production relayer that is 30–75s for a single
 * short fact, and the agent can do nothing with the wait: the job is durably
 * accepted ~1s in, and everything after that is upload queue time
 * (`WALRUS_UPLOAD_PER_WALLET_CONCURRENCY` defaults to 1, so a second write
 * waits for the first).
 *
 * So the tool now waits a bounded budget and then hands the caller a job_id.
 * It does NOT claim the fact is saved when it isn't — a job can still fail
 * after acceptance (one observed failure: "Memory encryption backend is
 * unavailable" 31.6s in, from the SEAL sidecar being unreachable).
 */
import { createHash } from "node:crypto";

import { createLogger } from "../logger.js";

const log = createLogger("mcp");

/** Window over which the same (namespace, text) resolves to one key. */
const IDEMPOTENCY_BUCKET_MS = 30 * 60 * 1000;

/**
 * Content-derived idempotency key for a single `remember`.
 *
 * Computed HERE rather than relied on from the SDK. The sidecar installs the
 * published `@mysten-incubation/memwal` (0.1.7), whose `rememberAsync` mints a
 * `crypto.randomUUID()` and caches it per client instance — and the sidecar
 * builds a fresh client per transport session, so a retry after a reconnect
 * gets a brand-new key and the relayer stores the fact a second time at full
 * cost. The accept-timeout message promises the caller a retry is safe, so the
 * key that makes it safe has to exist in the version actually running, not in
 * an unreleased source tree.
 *
 * The bucket bounds the collapse: `remember_jobs` rows are never pruned, so an
 * unbucketed key would dedupe against a job from any point in history and a
 * deliberate re-save of a since-deleted fact would hand back the old blob id.
 * Retries happen seconds after the original, so 30 minutes covers them.
 *
 * `/api/remember/bulk` takes no key at all, which is why the bulk tool stays
 * `idempotent: false` instead of calling this.
 */
export function derivedIdempotencyKey(namespace: string | undefined, text: string): string {
    const resolvedNamespace = namespace || "default";
    const bucket = Math.floor(Date.now() / IDEMPOTENCY_BUCKET_MS);
    const digest = createHash("sha256")
        .update(`${bucket}\0${resolvedNamespace}\0${text}`)
        .digest("hex");
    return `r1-${digest}`;
}

/**
 * Hard ceiling on the wait budget. 90s matches the timeout the tool used
 * while it still blocked to terminal, so an operator can restore the old
 * always-block behaviour but cannot push the call past what MCP clients
 * are willing to wait for.
 */
export const MAX_REMEMBER_WAIT_MS = 90_000;

/**
 * Default wait before `memwal_remember` hands back a job_id.
 *
 * Zero — return at accept. The MCP SDK's default `tools/call` timeout is
 * 60s; a budget that actually waits for Walrus (30–75s) overruns that, and
 * any in-between budget that fits still returns pending on nearly every
 * call. Restore block-until-done with `MEMWAL_MCP_REMEMBER_WAIT_MS=90000`.
 */
const DEFAULT_REMEMBER_WAIT_MS = 0;



/**
 * How long `memwal_remember` waits for the write to land before returning a
 * job_id instead. `0` returns at accept (~1s).
 *
 * Read once — it cannot change mid-process — but validated, because a typo'd
 * value must not silently pick a wait nobody asked for. `Number.parseInt`
 * alone accepts "10s" as 10 (a 10ms wait, effectively fire-and-forget) and
 * yields NaN for "" or "abc", and every NaN comparison is false.
 */
export function parseWaitBudget(raw: string | undefined): number {
    if (raw === undefined || raw.trim() === "") return DEFAULT_REMEMBER_WAIT_MS;
    const parsed = Number(raw);
    if (!Number.isFinite(parsed) || parsed < 0) {
        log.warn("remember.wait_budget_invalid", {
            value: raw,
            usingMs: DEFAULT_REMEMBER_WAIT_MS,
        });
        return DEFAULT_REMEMBER_WAIT_MS;
    }
    if (parsed > MAX_REMEMBER_WAIT_MS) {
        log.warn("remember.wait_budget_clamped", {
            value: raw,
            usingMs: MAX_REMEMBER_WAIT_MS,
        });
        return MAX_REMEMBER_WAIT_MS;
    }
    return Math.floor(parsed);
}

export const REMEMBER_WAIT_MS = parseWaitBudget(
    process.env.MEMWAL_MCP_REMEMBER_WAIT_MS
);

/**
 * Poll interval for a bounded wait.
 *
 * `waitForRememberJob` sleeps BEFORE its first poll and defaults to 1500ms
 * with 1.5^attempt backoff, which spends a 10s budget on ~5 polls and can
 * miss a write that landed at 1.2s. 400ms catches the fast case while
 * staying far below the relayer's 60 weighted-requests/min delegate-key
 * limit — the backoff reaches ~6 polls in 10s, not 25.
 */
export const REMEMBER_POLL_INTERVAL_MS = 400;

/**
 * `waitForRememberJob` signals outcome through `status` on a plain Error:
 * 504 = still running at the deadline, 500 = the job failed, 404 = no such
 * job. Only 504 is a non-error for us — the write is still in flight and the
 * caller gets a job_id to resolve later.
 */
export function isStillRunning(err: unknown): boolean {
    // 504: `waitForRememberJob` hit its own budget — the job is still going.
    if ((err as { status?: number } | null)?.status === 504) return true;
    // Our deadline firing means the RELAYER stopped answering us, not that the
    // job stopped. It was accepted, it is a row in `remember_jobs`, and the
    // caller needs the job_id to settle it. Treating this as a plain error
    // threw that id away — the one thing the pending result exists to return.
    return (err as { name?: string } | null)?.name === "MemWalRelayerUnresponsive";
}

/**
 * Give a job error the name `wrapTool` routes on, so the agent can tell a
 * failed write from a missing one without parsing the message. The SDK throws
 * an unnamed Error with a status code; `wrapTool` cannot classify that.
 */
export function nameJobError(err: unknown): unknown {
    if (!(err instanceof Error)) return err;
    const status = (err as { status?: number }).status;
    if (status === 500) err.name = "MemWalRememberJobFailed";
    else if (status === 404) err.name = "MemWalRememberJobNotFound";
    else if (status === 504) err.name = "MemWalRememberJobTimeout";
    return err;
}

/**
 * The line shown when a write is accepted but has not landed inside the wait
 * budget. Worded so an agent cannot read it as success: the fact is NOT saved
 * yet, and there is exactly one way to find out whether it lands.
 */
export function pendingMessage(jobId: string, waitedMs: number): string {
    // The zero-budget path never waited, so saying "has not finished after
    // 0.0s" would misdescribe it — and that is the default path, the one an
    // agent reads on nearly every call.
    const opening =
        waitedMs === 0
            ? "ACCEPTED, NOT YET SAVED — the relayer has durably queued this write."
            : `NOT SAVED YET — the write was accepted but has not finished after ${(waitedMs / 1000).toFixed(1)}s.`;

    return (
        `${opening}\n` +
        `job_id=${jobId}\n` +
        `Walrus uploads queue, so storing typically takes another 30-60s. Do NOT tell the ` +
        `user the fact is stored — say it is being saved. Call memwal_remember_status with ` +
        `this job_id to get the blob_id once it lands, or to learn that it failed; a job ` +
        `CAN fail after acceptance, and this is the only way to find out. Do not re-send ` +
        `the same fact with memwal_remember — that queues a second copy behind this one.`
    );
}

/** Longest fact echoed back in a pending listing. The line exists so the
 * agent can tell which job_id belongs to which fact, not to reproduce the
 * fact — and 20 of them at full length would crowd out the instructions
 * underneath. */
const PENDING_FACT_PREVIEW_CHARS = 80;

function previewFact(text: string): string {
    const flat = text.replace(/\s+/g, " ").trim();
    return flat.length > PENDING_FACT_PREVIEW_CHARS
        ? `${flat.slice(0, PENDING_FACT_PREVIEW_CHARS - 1)}…`
        : flat;
}

/**
 * The bulk counterpart of `pendingMessage`. Same contract — an agent must not
 * read it as success — with the one addition bulk needs: each job_id is paired
 * with the fact it carries, because "one of these five failed" is only
 * actionable if the agent can tell which.
 */
export function pendingBulkMessage(
    entries: Array<{ jobId: string; text: string }>,
    waitedMs: number,
): string {
    const n = entries.length;
    const opening =
        waitedMs === 0
            ? `ACCEPTED, NOT YET SAVED — the relayer has durably queued ${n} write(s).`
            : `NOT SAVED YET — ${n} write(s) were accepted but had not finished after ${(waitedMs / 1000).toFixed(1)}s.`;

    const lines = entries
        .map((e, i) => `${i + 1}. job_id=${e.jobId} — ${previewFact(e.text)}`)
        .join("\n");

    return (
        `${opening}\n${lines}\n` +
        `Walrus uploads queue and are written one at a time per wallet, so a batch takes ` +
        `longer than a single fact. Do NOT tell the user these facts are stored — say they ` +
        `are being saved. Call memwal_remember_status with job_ids=[...] to get the blob_ids ` +
        `once they land, or to learn that one failed; a job CAN fail after acceptance, and ` +
        `this is the only way to find out. Do not re-send these facts with ` +
        `memwal_remember_bulk — that queues a second copy behind them.`
    );
}

/**
 * Longest we let the relayer take to ACCEPT a write before giving up on it.
 *
 * The SDK's `signedRequest` only aborts a request when the caller hands it a
 * signal, and of the memory methods only `recall()` does (15s). `rememberAsync`
 * and every job-status poll call it with no signal at all, so the underlying
 * `fetch` has no deadline of its own. That makes `timeoutMs` a loop-entry
 * check rather than a bound: `waitForRememberJob` tests `Date.now() < deadline`
 * at the top of each iteration, so one stalled HTTP request runs as long as the
 * socket stays open and a tool documented as capping at 90s is observed past
 * 120s. Returning at accept does not fix that on its own — the accept POST is
 * exactly one of the unbounded calls.
 *
 * 15s matches the only deadline the SDK sets for itself. A healthy accept is
 * ~1.1s, so this fires only when something is genuinely wrong.
 *
 * The SDK grows its own 30s per-request backstop in the release after the
 * pinned 0.1.7, which does not make this redundant: that one is a floor for
 * every consumer, this is the tighter bound an interactive agent needs, and
 * whichever is smaller fires first.
 */
export const DEFAULT_ACCEPT_DEADLINE_MS = 15_000;

/**
 * Read once, validated the same way as the wait budget: a typo must not
 * silently pick a deadline nobody asked for. Exposed as an env knob because an
 * operator on a slow link is the one person who can tell a hung relayer from a
 * merely distant one.
 */
export const ACCEPT_DEADLINE_MS = (() => {
    const raw = process.env.MEMWAL_MCP_ACCEPT_DEADLINE_MS;
    if (raw === undefined || raw.trim() === "") return DEFAULT_ACCEPT_DEADLINE_MS;
    const parsed = Number(raw);
    if (!Number.isFinite(parsed) || parsed <= 0) {
        log.warn("remember.accept_deadline_invalid", {
            value: raw,
            usingMs: DEFAULT_ACCEPT_DEADLINE_MS,
        });
        return DEFAULT_ACCEPT_DEADLINE_MS;
    }
    return Math.floor(parsed);
})();

/**
 * Grace added to a wait budget before we stop believing the SDK will return.
 *
 * The budget bounds when the SDK starts its last poll, not when that poll
 * finishes, so a stalled request can overshoot by an unbounded amount. This
 * caps the overshoot instead.
 */
const WAIT_OVERSHOOT_GRACE_MS = 10_000;

class DeadlineExceededError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "MemWalRelayerUnresponsive";
    }
}

/**
 * Bound an SDK call that has no deadline of its own.
 *
 * The underlying request is NOT cancelled — the SDK gives us no way to pass a
 * signal, so `fetch` keeps running until it settles or the socket dies. What
 * this bounds is how long the agent waits on it, which is the part the user
 * experiences as a hang. The orphaned request costs one socket and resolves
 * into a promise nobody reads.
 */
export async function withDeadline<T>(
    work: Promise<T>,
    ms: number,
    message: string,
): Promise<T> {
    let timer: NodeJS.Timeout | undefined;
    try {
        return await Promise.race([
            work,
            new Promise<never>((_, reject) => {
                timer = setTimeout(() => reject(new DeadlineExceededError(message)), ms);
                // Deliberately NOT unref'd — the same correction a4a94e41 made
                // in the SDK, which this had copied. A deadline is the one
                // timer somebody IS waiting on: unref'd it stops firing the
                // moment nothing else holds the loop open, so the stalled
                // request it exists to bound hangs forever instead. The
                // `finally` below clears it, so it cannot outlive its work.
            }),
        ]);
    } finally {
        if (timer) clearTimeout(timer);
    }
}

/** Bound the accept leg of a write.
 *
 * `idempotent` is not cosmetic. `POST /api/remember` carries a content-derived
 * idempotency_key, so a retry collapses onto the job already in flight.
 * `POST /api/remember/bulk` carries none at all — the handler mints a fresh
 * uuid per item and inserts with no conflict clause — so a retry there is N
 * more paid Walrus blobs for the same N facts.
 *
 * That distinction decides what we may tell the agent, and the deadline makes
 * it urgent rather than theoretical: `withDeadline` does not cancel the
 * underlying request, so when it fires the relayer has usually accepted
 * already. Inviting a blind retry on the bulk path is close to guaranteeing
 * the duplicate.
 *
 * `retryNote` replaces the non-idempotent advice when the caller can be more
 * precise — the bulk tool, whose transport replays reuse a bridge key but
 * whose agent retries are new calls with new keys.
 */
export function withAcceptDeadline<T>(
    work: Promise<T>,
    what: string,
    opts: { idempotent: boolean; deadlineMs?: number; retryNote?: string },
): Promise<T> {
    const ms = opts.deadlineMs ?? ACCEPT_DEADLINE_MS;
    const shared =
        `Walrus Memory did not accept the ${what} within ${ms / 1000}s — the ` +
        `relayer is unreachable or not responding. The write may or may not have been queued, ` +
        `so do NOT tell the user it was saved.`;

    return withDeadline(
        work,
        ms,
        opts.idempotent
            ? `${shared} Retrying is safe: this write carries a content-derived idempotency ` +
              `key, so a retry attaches to the job already in flight instead of queueing a ` +
              `second paid copy.`
            : opts.retryNote
              ? `${shared} ${opts.retryNote}`
              : `${shared} Do NOT retry blindly — this endpoint carries no idempotency key, so a ` +
                `re-send stores every fact a SECOND time at full cost. Check with memwal_recall ` +
                `first, and only re-send what is genuinely missing.`,
    );
}

/**
 * The MCP TypeScript SDK's default `tools/call` timeout —
 * `DEFAULT_REQUEST_TIMEOUT_MSEC` in @modelcontextprotocol/sdk
 * (shared/protocol.js:8, applied at :712 as
 * `options?.timeout ?? DEFAULT_REQUEST_TIMEOUT_MSEC`).
 *
 * A host that does not raise its own ceiling aborts the call at this mark. An
 * abort is strictly worse than a timeout we raise ourselves: the caller gets no
 * message it can act on, and on a non-idempotent endpoint its retry writes
 * everything twice. So every leg this file bounds must finish inside it.
 */
export const MCP_CLIENT_DEFAULT_TIMEOUT_MS = 60_000;

/**
 * Headroom left under the client ceiling for JSON-RPC framing, transport and
 * the relayer's own response write. A leg budgeted at exactly the ceiling loses
 * the race it was meant to win.
 */
const CLIENT_TIMEOUT_HEADROOM_MS = 15_000;

/**
 * Deadline for `memwal_analyze`'s extraction leg.
 *
 * `/api/analyze` runs the extractor LLM inline before it answers, so this leg
 * is real work, not an accept — 15s would cut off healthy extraction on any
 * transcript worth extracting from. But it was budgeted at the full 60_000,
 * exactly the client ceiling, so a slow extraction raced the host's abort and
 * usually lost: the agent saw a dead call instead of a message, and `analyze`
 * is the one endpoint with no idempotency key, so retrying it stores every
 * extracted fact a second time.
 *
 * Derived from the ceiling rather than written as a literal so the two cannot
 * drift apart.
 */
export const ANALYZE_EXTRACTION_DEADLINE_MS =
    MCP_CLIENT_DEFAULT_TIMEOUT_MS - CLIENT_TIMEOUT_HEADROOM_MS;

/** Bound a status wait at its own budget plus the overshoot grace. */
export function withWaitDeadline<T>(work: Promise<T>, budgetMs: number): Promise<T> {
    return withDeadline(
        work,
        budgetMs + WAIT_OVERSHOOT_GRACE_MS,
        `Walrus Memory stopped responding while waiting for the write to land. The job is ` +
            `still queued relayer-side — do NOT tell the user it was saved, and do NOT re-send ` +
            `the fact. Call memwal_remember_status with the job_id to settle it.`,
    );
}

/**
 * Longest we will sit on a relayer-advised cooldown before handing the problem
 * back to the agent.
 *
 * The relayer answers a spent rate-limit budget with `retry_after_seconds: 60`.
 * Sleeping that out inside a tool call is not a fix — it is the 60s hang this
 * whole change set exists to remove, and the MCP client would time out first.
 * So a short cooldown is absorbed and a long one is reported, with the wait
 * named so the agent can come back rather than guess.
 */
export const MAX_ABSORBED_COOLDOWN_MS = 8_000;

/** Attempts, including the first. Two retries is enough for a transient blip;
 * more just delays an answer the agent could act on. */
const RELAYER_RETRY_ATTEMPTS = 3;

/**
 * Errors where the request provably did NOT reach the handler, so re-sending
 * cannot duplicate work.
 *
 * This matters most for `/api/remember/bulk`, which carries no idempotency key
 * — a blind retry there would store every fact twice. Both cases below are
 * rejections BEFORE any job row exists: 429 comes from the rate limiter, and
 * AUTH_UPSTREAM_UNAVAILABLE from the delegate-key lookup failing open. Any
 * other 5xx could have been thrown after a write started, so it is not retried.
 */
function isSafelyRetryable(err: unknown): boolean {
    const e = err as { status?: number; serverCode?: string } | null;
    if (e?.status === 429) return true;
    return e?.status === 503 && e?.serverCode === "AUTH_UPSTREAM_UNAVAILABLE";
}

function advisedCooldownMs(err: unknown): number {
    const secs = (err as { retryAfterSeconds?: number } | null)?.retryAfterSeconds;
    return typeof secs === "number" && secs > 0 ? secs * 1000 : 1_000;
}

/**
 * What the relayer actually said it denied on.
 *
 * `rate_limit_response` (services/server/src/rate_limit.rs) answers a 429 with
 * `{error, layer, limit, retry_after_seconds}`, and the SDK embeds that body
 * verbatim in the error message. Read it rather than asserting a scope: there
 * are three layers with different windows — `delegate_key` and `account_burst`
 * per minute, `account_sustained` per HOUR — and naming the wrong one sends
 * the caller to wait out a window that was never the one it hit.
 */
function rateLimitFacts(err: unknown): { layer?: string; limit?: string } {
    const text = String((err as { message?: string } | null)?.message ?? "");
    const open = text.indexOf("{");
    const close = text.lastIndexOf("}");
    if (open < 0 || close <= open) return {};
    try {
        const body = JSON.parse(text.slice(open, close + 1)) as Record<string, unknown>;
        return {
            layer: typeof body.layer === "string" ? body.layer : undefined,
            limit: typeof body.limit === "string" ? body.limit : undefined,
        };
    } catch {
        // A body we cannot parse is not a reason to lose the 429 itself.
        return {};
    }
}

/** Whose budget the named layer belongs to. */
function scopeOfLayer(layer: string | undefined): string {
    if (layer === "delegate_key") return "per delegate key";
    if (layer === "account_burst" || layer === "account_sustained") return "per account";
    return "on this account";
}

/**
 * The retry advice.
 *
 * `retry_after_seconds` is a refill hint from a token bucket, NOT a reset. On
 * the hourly `account_sustained` layer the relayer still advises ~300s, which
 * buys back only a slice of a 1000/hour budget — waiting it out and retrying
 * re-trips the limit whenever the budget is genuinely spent. Saying "resets in
 * Ns; retry after that" turned that into a retry loop that never converges, so
 * the message now says what the number is worth.
 */
function retryAdvice(secs: number, layer: string | undefined): string {
    return layer === "account_sustained"
        ? `The relayer advises retrying in ~${secs}s, but that is a partial refill of an ` +
          `hourly budget, not a reset — if the budget is spent, a retry then fails again. ` +
          `Report the failure rather than waiting and retrying in a loop.`
        : `Retry after ~${secs}s.`;
}

/** True if the relayer refused this call with a rate limit. */
export function isRateLimited(err: unknown): boolean {
    return (err as { status?: number } | null)?.status === 429;
}

/**
 * The rate-limit error an agent can act on, built from what the relayer said.
 *
 * Shared with `memwal_remember_status` so a throttled poll cannot be reported
 * as "still uploading": a denied poll tells us nothing about the job, and
 * rendering it as progress is what turns a rate limit into an agent that keeps
 * polling and spends more of the budget it has already exhausted.
 */
export function rateLimitedError(err: unknown, what: string): Error {
    const secs = Math.ceil(advisedCooldownMs(err) / 1000);
    const { layer, limit } = rateLimitFacts(err);
    const hit = layer
        ? `Limit hit: ${layer} ${scopeOfLayer(layer)}` + (limit ? ` (${limit})` : "") + ". "
        : "";
    const e = new Error(
        `Walrus Memory rate limit reached while trying to ${what}. ${hit}` +
            `${retryAdvice(secs, layer)} To spend less of the budget, save several facts ` +
            `with one memwal_remember_bulk call instead of repeated memwal_remember calls, ` +
            `and settle a batch with a single memwal_remember_status(job_ids=[...]).`,
    );
    e.name = "MemWalRelayerUnavailable";
    (e as Error & { status?: number }).status = 429;
    return e;
}

/** Honour the relayer's `retry_after` instead of surfacing a raw 429.
 *
 * Once the per-delegate-key budget is spent the write is simply never made,
 * and nothing retried — the quietest failure here. A short cooldown is
 * absorbed; a long one is reported, because sleeping it out inside a tool call
 * is the hang this file exists to remove. */
export async function withRelayerRetry<T>(work: () => Promise<T>, what: string): Promise<T> {
    let last: unknown;
    for (let attempt = 1; attempt <= RELAYER_RETRY_ATTEMPTS; attempt++) {
        try {
            return await work();
        } catch (err) {
            last = err;
            if (!isSafelyRetryable(err)) throw err;

            const cooldown = advisedCooldownMs(err);
            if (attempt === RELAYER_RETRY_ATTEMPTS || cooldown > MAX_ABSORBED_COOLDOWN_MS) {
                const secs = Math.ceil(cooldown / 1000);
                const limited = (err as { status?: number }).status === 429;
                const { layer, limit } = limited ? rateLimitFacts(err) : {};
                const hit = layer
                    ? `Limit hit: ${layer} ${scopeOfLayer(layer)}` +
                      (limit ? ` (${limit})` : "") + ". "
                    : "";
                const e = new Error(
                    limited
                        ? `Walrus Memory rate limit reached while trying to ${what}. THE FACT WAS NOT ` +
                          `SAVED — tell the user it could not be stored rather than that it is being ` +
                          `saved. ${hit}${retryAdvice(secs, layer)} To spend less of the budget, save ` +
                          `several facts with one memwal_remember_bulk call instead of repeated ` +
                          `memwal_remember calls, and settle a batch with a single ` +
                          `memwal_remember_status(job_ids=[...]).`
                        : `Walrus Memory could not ${what}: the relayer's credential check is ` +
                          `temporarily unavailable. THE FACT WAS NOT SAVED. Retry in about ${secs}s.`,
                );
                e.name = "MemWalRelayerUnavailable";
                (e as Error & { status?: number }).status = (err as { status?: number }).status;
                throw e;
            }

            log.warn("remember.relayer_retry", {
                what,
                attempt,
                status: (err as { status?: number }).status,
                cooldownMs: cooldown,
            });
            await new Promise((r) => setTimeout(r, cooldown));
        }
    }
    throw last;
}
