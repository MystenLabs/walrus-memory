import assert from "node:assert/strict";
import test from "node:test";

import { MemWal } from "../dist/memwal.js";

// End-to-end coverage of the recall() wiring (not just the pure applyTokenBudget
// function): confirms maxTokens is honored on the real client path and that
// omitting it leaves the response byte-identical to the pre-budget behavior.

const originalFetch = globalThis.fetch;

test.afterEach(() => {
    globalThis.fetch = originalFetch;
});

// Stub the relayer so /api/recall returns a fixed set of hits.
function stubRecall(hits) {
    globalThis.fetch = async (url, init = {}) => {
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
        if (path === "/api/recall" && init.method === "POST") {
            return Response.json({ results: hits, total: hits.length });
        }
        throw new Error(`unexpected request ${path}`);
    };
}

function client() {
    const c = MemWal.create({
        key: new Uint8Array(32).fill(1),
        accountId: "0x1",
        serverUrl: "https://relayer.example",
    });
    c.buildSealSession = async () => "test-session";
    return c;
}

const chars = (n) => "a".repeat(n);

test("recall surfaces dropped_count when the relayer omitted matches", async () => {
    globalThis.fetch = async (url, init = {}) => {
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
        if (path === "/api/recall" && init.method === "POST") {
            return Response.json({ results: [], total: 0, dropped_count: 3 });
        }
        throw new Error(`unexpected request ${path}`);
    };
    const result = await client().recall({ query: "x", namespace: "default" });
    assert.equal(result.dropped_count, 3);
    assert.equal(result.results.length, 0);
});

test("recall preserves dropped_count when maxDistance and maxTokens are applied", async () => {
    const hits = [
        { blob_id: "b1", text: chars(40), distance: 0.1 },
        { blob_id: "b2", text: chars(40), distance: 0.2 },
        { blob_id: "b3", text: chars(40), distance: 0.9 },
    ];
    globalThis.fetch = async (url, init = {}) => {
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
        if (path === "/api/recall" && init.method === "POST") {
            return Response.json({ results: hits, total: 3, dropped_count: 25 });
        }
        throw new Error(`unexpected request ${path}`);
    };
    const result = await client().recall({
        query: "x",
        namespace: "default",
        maxDistance: 0.5,
        maxTokens: 10,
    });
    assert.equal(result.dropped_count, 25);
    assert.equal(result.total, 3);
    assert.equal(result.results.length, 1);
    assert.equal(result.results[0].blob_id, "b1");
    assert.equal(result.meta?.truncated, true);
});

test("recall omits dropped_count when the relayer does", async () => {
    stubRecall([]);
    const result = await client().recall({ query: "x", namespace: "default" });
    assert.equal("dropped_count" in result, false);
});

test("recall without maxTokens: response unchanged, NO meta (backward compatible)", async () => {
    const hits = [
        { blob_id: "b1", text: chars(40), distance: 0.1 },
        { blob_id: "b2", text: chars(40), distance: 0.2 },
    ];
    stubRecall(hits);

    const result = await client().recall({ query: "x", namespace: "default" });
    assert.equal(result.results.length, 2);
    assert.equal(result.total, 2);
    assert.equal("meta" in result, false, "no meta key when maxTokens is omitted");
    assert.deepEqual(result.results, hits);
});

test("recall with maxTokens: budget applied, matching total preserved, meta present", async () => {
    // two 10-token hits (40 chars each); budget 10 → high-relevance-only keeps 1.
    const hits = [
        { blob_id: "b1", text: chars(40), distance: 0.1 },
        { blob_id: "b2", text: chars(40), distance: 0.2 },
    ];
    stubRecall(hits);

    const result = await client().recall({ query: "x", maxTokens: 10 });
    assert.equal(result.results.length, 1, "second hit dropped to fit budget");
    assert.equal(result.total, 2, "total preserves matching count rather than trimmed count");
    assert.equal(result.results[0].blob_id, "b1", "kept the lowest-distance hit");
    assert.ok(result.meta, "meta attached");
    assert.equal(result.meta.truncated, true);
    assert.equal(result.meta.tokenEstimate, 10);
});

test("recall forwards drop-tail strategy and a custom token counter", async () => {
    const hits = [
        { blob_id: "b1", text: "one two three four", distance: 0.1 },
    ];
    stubRecall(hits);
    let counterCalls = 0;
    const wordCount = (text) => {
        counterCalls += 1;
        return text.trim() ? text.trim().split(/\s+/).length : 0;
    };

    const result = await client().recall({
        query: "x",
        maxTokens: 2,
        truncationStrategy: "drop-tail",
        countTokens: wordCount,
    });
    assert.equal(result.results.length, 1);
    assert.ok(wordCount(result.results[0].text) <= 2);
    assert.equal(result.meta.truncated, true);
    assert.equal(result.meta.tokenEstimate, 2);
    assert.ok(counterCalls > 0, "custom counter was used by recall");
});

test("recall maxTokens + maxDistance compose (distance filter then budget)", async () => {
    const hits = [
        { blob_id: "b1", text: chars(40), distance: 0.1 },
        { blob_id: "b2", text: chars(40), distance: 0.9 }, // filtered by maxDistance
    ];
    stubRecall(hits);

    const result = await client().recall({ query: "x", maxDistance: 0.5, maxTokens: 100 });
    assert.equal(result.results.length, 1, "distance filter dropped b2 before budgeting");
    assert.equal(result.results[0].blob_id, "b1");
    assert.equal(result.meta.truncated, false, "within budget after the distance filter");
});
