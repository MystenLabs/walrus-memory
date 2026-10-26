import assert from "node:assert/strict";
import test from "node:test";

import { MemWal } from "../dist/memwal.js";

// #1247: #1207 turned empty / non-JSON 2xx bodies into named SDK errors, but
// the parsed value's shape was still trusted. A 200 with valid JSON of the
// wrong shape escaped as a raw TypeError from the read paths below.

const originalFetch = globalThis.fetch;

test.afterEach(() => {
    globalThis.fetch = originalFetch;
});

function client() {
    const memwal = MemWal.create({
        key: "11".repeat(32),
        accountId: "0x1",
        serverUrl: "https://relayer.example",
    });
    memwal.buildSealSession = async () => "test-session";
    memwal.resolveOwner = async () => "0xowner";
    return memwal;
}

function stub(routes) {
    globalThis.fetch = async (url) => {
        const path = new URL(url).pathname;
        if (path === "/version") {
            return Response.json({
                apiVersion: "1.0.0",
                relayerVersion: "1.0.0",
                minSupportedSdk: { typescript: "0.0.4" },
            });
        }
        if (path in routes) {
            const [status, body] = routes[path];
            return new Response(JSON.stringify(body), {
                status,
                headers: { "content-type": "application/json" },
            });
        }
        throw new Error(`unexpected ${path}`);
    };
}

function namedShapeError(pattern) {
    return (err) => {
        assert.ok(!(err instanceof TypeError), `raw TypeError escaped: ${err.message}`);
        assert.match(err.message, pattern);
        return true;
    };
}

for (const body of [null, "a string", 42, true]) {
    test(`getRememberStatus() degrades a ${JSON.stringify(body)} body to not_found`, async () => {
        stub({ "/api/remember/job-1": [200, body] });
        const status = await client().getRememberStatus("job-1");
        assert.equal(status.status, "not_found");
        assert.equal(status.job_id, "job-1");
    });

    test(`waitForRememberJob() reports not-found for a ${JSON.stringify(body)} body`, async () => {
        stub({ "/api/remember/job-1": [200, body] });
        await assert.rejects(
            () => client().waitForRememberJob("job-1", { pollIntervalMs: 1, timeoutMs: 1000 }),
            namedShapeError(/remember job not found: job-1/),
        );
    });
}

for (const body of [{}, { results: null }, { results: "x" }, null]) {
    test(`waitForRememberJobs() names a malformed bulk-status body ${JSON.stringify(body)}`, async () => {
        stub({ "/api/remember/bulk/status": [200, body] });
        await assert.rejects(
            () => client().waitForRememberJobs(["job-1"], [], { pollIntervalMs: 1, timeoutMs: 1000 }),
            namedShapeError(/\/api\/remember\/bulk\/status response is missing a results array/),
        );
    });
}

for (const options of [{}, { maxDistance: 0.5 }, { maxTokens: 100 }]) {
    test(`recall(${JSON.stringify(options)}) names a body without results`, async () => {
        stub({ "/api/recall": [200, {}] });
        await assert.rejects(
            () => client().recall({ query: "coffee", ...options }),
            namedShapeError(/\/api\/recall response is missing a results array/),
        );
    });
}

test("analyzeAndWait() names a 202 body without job_ids", async () => {
    stub({ "/api/analyze": [202, {}] });
    await assert.rejects(
        () => client().analyzeAndWait("I like coffee"),
        namedShapeError(/\/api\/analyze response is missing a job_ids array/),
    );
});

for (const options of [{}, { namespace: "work" }]) {
    test(`listMemories(${JSON.stringify(options)}) names a body without memories`, async () => {
        stub({ "/v1/owners/0xowner/memories": [200, {}] });
        await assert.rejects(
            () => client().listMemories(options),
            namedShapeError(/memories response is missing a memories array/),
        );
    });
}

test("listMemories() still defaults deleted for older relayers", async () => {
    stub({ "/v1/owners/0xowner/memories": [200, { memories: [{ namespace_id: "work" }] }] });
    const page = await client().listMemories({ namespace: "work" });
    assert.equal(page.memories.length, 1);
    assert.deepEqual(page.deleted, []);
});
