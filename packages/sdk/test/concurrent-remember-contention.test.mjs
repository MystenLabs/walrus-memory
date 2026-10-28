import assert from "node:assert/strict";
import test from "node:test";

import { MemWal, MemWalRememberJobTimeoutError } from "../dist/index.js";

const originalFetch = globalThis.fetch;

test.afterEach(() => {
    globalThis.fetch = originalFetch;
});

function createClient() {
    const memwal = MemWal.create({
        key: new Uint8Array(32).fill(7),
        accountId: "0x1",
        serverUrl: "https://relayer.example",
    });
    memwal.buildSealSession = async () => "test-session";
    return memwal;
}

const CONTENTION_RETRY_MESSAGE =
    "Temporary capacity limit on Walrus Memory infrastructure; the hosted relayer is still retrying this upload. " +
    "This is not caused by your account, wallet, or delegate key, and there is nothing for you to fund. " +
    "Keep polling; do not resubmit unless the job reaches status `failed`.";

test("5x concurrent rememberAndWait under upload contention surfaces MemWalRememberJobTimeoutError with jobId, lastStatus, and serverError (#1130)", async () => {
    let acceptedCount = 0;

    globalThis.fetch = async (url, init = {}) => {
        const parsed = new URL(url);
        const path = parsed.pathname;

        if (path === "/version") {
            return Response.json({
                apiVersion: "1.0.0",
                relayerVersion: "1.0.0",
                minSupportedSdk: { typescript: "0.0.4" },
            });
        }
        if (path === "/api/config") {
            return Response.json({ packageId: "0x1", network: "testnet" });
        }
        if (path === "/api/remember" && init.method === "POST") {
            acceptedCount += 1;
            const jobId = `job-concurrent-${acceptedCount}`;
            return new Response(
                JSON.stringify({ job_id: jobId, status: "pending" }),
                {
                    status: 202,
                    headers: { "content-type": "application/json" },
                },
            );
        }
        if (path.startsWith("/api/remember/job-concurrent-")) {
            const jobId = path.slice("/api/remember/".length);
            return Response.json({
                job_id: jobId,
                status: "running",
                error: CONTENTION_RETRY_MESSAGE,
            });
        }
        throw new Error(`unexpected request ${init.method ?? "GET"} ${path}`);
    };

    const mw = createClient();
    const outcomes = await Promise.allSettled(
        [1, 2, 3, 4, 5].map((i) =>
            mw.rememberAndWait(`Concurrent memory #${i}`, undefined, {
                pollIntervalMs: 5,
                timeoutMs: 60,
            }),
        ),
    );

    assert.equal(acceptedCount, 5, "all 5 concurrent remember calls must be accepted");
    assert.equal(outcomes.length, 5);

    const seenJobIds = new Set();
    for (const outcome of outcomes) {
        assert.equal(outcome.status, "rejected", "contended job should reject with a structured timeout");
        const err = outcome.reason;
        assert.ok(
            err instanceof MemWalRememberJobTimeoutError,
            `expected MemWalRememberJobTimeoutError, got ${err?.constructor?.name}: ${err?.message}`,
        );
        assert.equal(err.status, 504);
        assert.equal(err.timeoutMs, 60);
        assert.match(err.jobId, /^job-concurrent-[1-5]$/);
        assert.equal(err.lastStatus, "running");
        assert.equal(err.serverError, CONTENTION_RETRY_MESSAGE);
        assert.match(err.message, new RegExp(`waitForRememberJob\\("${err.jobId}"\\)`));
        seenJobIds.add(err.jobId);
    }

    assert.equal(seenJobIds.size, 5, "each concurrent call must track its own distinct jobId");
});

test("5x concurrent rememberAndWait resolves all 5 jobs when multi-wallet workers complete within budget (#1130)", async () => {
    let acceptedCount = 0;
    const pollsByJob = new Map();

    globalThis.fetch = async (url, init = {}) => {
        const parsed = new URL(url);
        const path = parsed.pathname;

        if (path === "/version") {
            return Response.json({
                apiVersion: "1.0.0",
                relayerVersion: "1.0.0",
                minSupportedSdk: { typescript: "0.0.4" },
            });
        }
        if (path === "/api/config") {
            return Response.json({ packageId: "0x1", network: "testnet" });
        }
        if (path === "/api/remember" && init.method === "POST") {
            acceptedCount += 1;
            const jobId = `job-ok-${acceptedCount}`;
            pollsByJob.set(jobId, 0);
            return new Response(
                JSON.stringify({ job_id: jobId, status: "pending" }),
                {
                    status: 202,
                    headers: { "content-type": "application/json" },
                },
            );
        }
        if (path.startsWith("/api/remember/job-ok-")) {
            const jobId = path.slice("/api/remember/".length);
            const count = (pollsByJob.get(jobId) ?? 0) + 1;
            pollsByJob.set(jobId, count);
            if (count < 2) {
                return Response.json({ job_id: jobId, status: "running" });
            }
            return Response.json({
                job_id: jobId,
                status: "done",
                blob_id: `blob-${jobId}`,
                owner: "0xabc",
                namespace: "default",
            });
        }
        throw new Error(`unexpected request ${init.method ?? "GET"} ${path}`);
    };

    const mw = createClient();
    const results = await Promise.all(
        [1, 2, 3, 4, 5].map((i) =>
            mw.rememberAndWait(`Concurrent memory #${i}`, undefined, {
                pollIntervalMs: 5,
                timeoutMs: 2_000,
            }),
        ),
    );

    assert.equal(results.length, 5);
    assert.deepEqual(
        results.map((r) => r.job_id).sort(),
        ["job-ok-1", "job-ok-2", "job-ok-3", "job-ok-4", "job-ok-5"],
    );
    for (const res of results) {
        assert.equal(res.blob_id, `blob-${res.job_id}`);
        assert.equal(res.owner, "0xabc");
    }
});
