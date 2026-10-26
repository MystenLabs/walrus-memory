import assert from "node:assert/strict";
import test from "node:test";

import { MemWal, MemWalMock } from "../dist/index.js";
import {
    MemWalRateLimitedError,
    MemWalRememberJobFailedError,
    MemWalRememberJobNotFoundError,
    MemWalRememberJobTimeoutError,
} from "../dist/errors.js";

const originalFetch = globalThis.fetch;

test.afterEach(() => {
    globalThis.fetch = originalFetch;
});

function client() {
    const memwal = MemWal.create({
        key: new Uint8Array(32).fill(1),
        accountId: "0x1",
        serverUrl: "https://relayer.example",
    });
    memwal.buildSealSession = async () => "test-session";
    return memwal;
}

function stub(pathHandler) {
    globalThis.fetch = async (url) => {
        const path = new URL(url).pathname;
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
        return pathHandler(path);
    };
}

test("a remember wait that times out throws MemWalRememberJobTimeoutError, catchable by class", async () => {
    stub((path) => {
        if (path === "/api/remember/job-1") return Response.json({ job_id: "job-1", status: "running" });
        throw new Error(`unexpected request ${path}`);
    });

    await assert.rejects(
        client().waitForRememberJob("job-1", { pollIntervalMs: 1, timeoutMs: 50 }),
        (err) => {
            assert.ok(err instanceof MemWalRememberJobTimeoutError);
            assert.equal(err.status, 504);
            assert.equal(err.jobId, "job-1");
            assert.equal(err.lastStatus, "running");
            return true;
        },
    );
});

test("a remember wait on a failed job throws MemWalRememberJobFailedError, catchable by class", async () => {
    stub((path) => {
        if (path === "/api/remember/job-1") {
            return Response.json({ job_id: "job-1", status: "failed", error: "upload rejected" });
        }
        throw new Error(`unexpected request ${path}`);
    });

    await assert.rejects(
        client().waitForRememberJob("job-1", { pollIntervalMs: 1, timeoutMs: 1_000 }),
        (err) => {
            assert.ok(err instanceof MemWalRememberJobFailedError);
            assert.equal(err.status, 500);
            assert.equal(err.jobId, "job-1");
            assert.match(err.message, /upload rejected/);
            return true;
        },
    );
});

test("a remember wait on an unknown job id throws MemWalRememberJobNotFoundError, catchable by class", async () => {
    await assert.rejects(client().waitForRememberJob(""), (err) => {
        assert.ok(err instanceof MemWalRememberJobNotFoundError);
        assert.equal(err.status, 404);
        return true;
    });
});

test("a bulk remember wait that only sees 429 throws MemWalRateLimitedError, catchable by class", async () => {
    stub((path) => {
        if (path === "/api/remember/bulk/status") {
            return new Response(JSON.stringify({ error: "Rate limit exceeded" }), {
                status: 429,
                headers: { "content-type": "application/json" },
            });
        }
        throw new Error(`unexpected request ${path}`);
    });

    await assert.rejects(
        client().waitForRememberJobs(["job-1"], ["default"], { pollIntervalMs: 1, timeoutMs: 400 }),
        (err) => {
            assert.ok(err instanceof MemWalRateLimitedError);
            assert.equal(err.status, 429);
            assert.deepEqual(err.jobIds, ["job-1"]);
            return true;
        },
    );
});

test("MemWalMock also throws MemWalRememberJobNotFoundError for an unknown job id", async () => {
    const mock = new MemWalMock();
    await assert.rejects(mock.waitForRememberJob("missing-job"), (err) => {
        assert.ok(err instanceof MemWalRememberJobNotFoundError);
        assert.equal(err.status, 404);
        assert.equal(err.jobId, "missing-job");
        return true;
    });
});

test("426 relayer rejection on a write still stays MemWalCompatibilityError, not one of the new classes", async () => {
    stub((path) => {
        if (path === "/api/remember") {
            return new Response("upgrade required", { status: 426, headers: { "content-type": "text/plain" } });
        }
        throw new Error(`unexpected request ${path}`);
    });

    const { MemWalCompatibilityError } = await import("../dist/index.js");
    await assert.rejects(client().remember("hello"), (err) => {
        assert.ok(err instanceof MemWalCompatibilityError);
        assert.ok(!(err instanceof MemWalRateLimitedError));
        return true;
    });
});
