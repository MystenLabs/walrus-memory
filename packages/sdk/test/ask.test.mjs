import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { MemWal, MemWalMock } from "../dist/index.js";
import { resolveAskCall } from "../dist/recall-args.js";

const originalFetch = globalThis.fetch;

test.afterEach(() => {
    globalThis.fetch = originalFetch;
});

function createClient(namespace) {
    const client = MemWal.create({
        key: "11".repeat(32),
        accountId: "0x1",
        serverUrl: "https://relayer.example",
        ...(namespace ? { namespace } : {}),
    });
    client.buildSealSession = async () => "test-seal-session";
    return client;
}

function stubAsk(responseBody = {
    answer: "Avoid peanuts.",
    memories_used: 1,
    memories: [
        {
            blob_id: "blob-1",
            text: "User is allergic to peanuts",
            distance: 0.12,
            score: 0.88,
            created_at: "2026-07-06T12:00:00Z",
        },
    ],
}) {
    const captured = {};
    globalThis.fetch = async (url, init = {}) => {
        const path = new URL(url).pathname;
        if (path === "/version") {
            return Response.json({
                apiVersion: "1.0.0",
                relayerVersion: "1.0.0",
                minSupportedSdk: { typescript: "0.0.4" },
            });
        }
        if (path === "/api/ask" && init.method === "POST") {
            captured.headers = init.headers;
            captured.body = JSON.parse(init.body);
            return Response.json(responseBody);
        }
        throw new Error(`unexpected request ${path}`);
    };
    return captured;
}

test("resolveAskCall maps object and positional forms with default limit 5", () => {
    assert.deepEqual(
        resolveAskCall({ question: "allergies?", namespace: "profile", limit: 3 }),
        {
            question: "allergies?",
            options: { namespace: "profile", limit: 3 },
        },
    );
    assert.deepEqual(resolveAskCall("allergies?"), {
        question: "allergies?",
        options: { limit: 5, namespace: undefined },
    });
    assert.deepEqual(resolveAskCall("allergies?", 8, "profile"), {
        question: "allergies?",
        options: { limit: 8, namespace: "profile" },
    });
    assert.deepEqual(resolveAskCall("allergies?", { namespace: "profile" }), {
        question: "allergies?",
        options: { namespace: "profile" },
    });
    assert.throws(() => resolveAskCall("allergies?", "profile"), {
        name: "TypeError",
        message:
            "ask() second argument must be a number (limit) or an options object, not a string. " +
            "Namespace belongs in an options object (ask(question, { namespace })) or as the third argument (ask(question, limit, namespace)). " +
            "Preferred form: ask({ question, namespace }).",
    });
});

test("MemWal.ask sends POST /api/ask with SEAL session header and parses response", async () => {
    const captured = stubAsk();
    const client = createClient("default-ns");

    const result = await client.ask({
        question: "What food should I avoid?",
        limit: 4,
        namespace: "health",
        scoringWeights: {
            semantic: 0.6,
            recency: 0.4,
            recencyHalfLifeDays: 14,
            importance: 0.2,
        },
    });

    assert.equal(captured.headers["x-seal-session"], "test-seal-session");
    assert.deepEqual(captured.body, {
        question: "What food should I avoid?",
        limit: 4,
        namespace: "health",
        scoring_weights: {
            semantic: 0.6,
            recency: 0.4,
            recency_half_life_days: 14,
            importance: 0.2,
        },
    });
    assert.equal(result.answer, "Avoid peanuts.");
    assert.equal(result.memories_used, 1);
    assert.deepEqual(result.memories, [
        {
            blob_id: "blob-1",
            text: "User is allergic to peanuts",
            distance: 0.12,
            score: 0.88,
            created_at: "2026-07-06T12:00:00Z",
        },
    ]);
});

test("MemWal.ask supports positional signature ask(question, limit?, namespace?) and defaults limit to 5", async () => {
    const captured = stubAsk();
    const client = createClient("client-default");

    await client.ask("What food should I avoid?");
    assert.deepEqual(captured.body, {
        question: "What food should I avoid?",
        limit: 5,
        namespace: "client-default",
    });
    assert.equal("scoring_weights" in captured.body, false);

    await client.ask("What food should I avoid?", 3, "custom-ns");
    assert.deepEqual(captured.body, {
        question: "What food should I avoid?",
        limit: 3,
        namespace: "custom-ns",
    });

    await client.ask("What food should I avoid?", { limit: 2, namespace: "opts-ns" });
    assert.deepEqual(captured.body, {
        question: "What food should I avoid?",
        limit: 2,
        namespace: "opts-ns",
    });
});

test("MemWal.ask validates question, limit, scoringWeights, and response shape", async () => {
    let called = false;
    globalThis.fetch = async () => {
        called = true;
        return new Response("");
    };
    const client = createClient();

    for (const blank of ["", "   ", "\t\n", "\u200B"]) {
        await assert.rejects(() => client.ask(blank), {
            name: "Error",
            message: "question cannot be empty",
        });
    }
    for (const badLimit of [0, -1, 2.5, NaN, "5", null]) {
        await assert.rejects(() => client.ask({ question: "valid?", limit: badLimit }), {
            name: "TypeError",
            message: /limit must be a positive integer/,
        });
    }
    await assert.rejects(
        () => client.ask({ question: "valid?", scoringWeights: { semantic: Infinity } }),
        {
            name: "Error",
            message: "scoringWeights.semantic must be a finite number",
        },
    );
    assert.equal(called, false);

    stubAsk({});
    await assert.rejects(() => client.ask("valid?"), {
        name: "Error",
        message: /POST \/api\/ask response is missing a memories array/,
    });
});

test("MemWalMock.ask returns joined memory texts or fallback when empty and validates inputs", async () => {
    const mock = MemWalMock.create({ namespace: "default" });

    const empty = await mock.ask("What do I like?");
    assert.deepEqual(empty, {
        answer: "No relevant memories found.",
        memories_used: 0,
        memories: [],
    });

    await mock.rememberAndWait("User loves espresso", "coffee");
    await mock.rememberAndWait("User drinks oat milk", "coffee");
    await mock.rememberAndWait("Unrelated work note", "work");

    const answered = await mock.ask({
        question: "User coffee",
        limit: 2,
        namespace: "coffee",
    });
    assert.equal(answered.memories_used, 2);
    assert.equal(answered.memories.length, 2);
    assert.equal(
        answered.answer,
        "User loves espresso User drinks oat milk",
    );

    const positional = await mock.ask("User coffee", 1, "coffee");
    assert.equal(positional.memories_used, 1);
    assert.equal(positional.answer, "User loves espresso");

    await assert.rejects(() => mock.ask("   "), {
        name: "Error",
        message: "question cannot be empty",
    });
    await assert.rejects(() => mock.ask({ question: "coffee?", limit: 0 }), {
        name: "TypeError",
        message: /limit must be a positive integer/,
    });
    await assert.rejects(
        () => mock.ask({ question: "coffee?", scoringWeights: { recency: NaN } }),
        {
            name: "Error",
            message: "scoringWeights.recency must be a finite number",
        },
    );
});

test("AskMemory, AskResult, AskOptions, and AskParams are emitted in dist/types.d.ts", () => {
    const dts = readFileSync(
        fileURLToPath(new URL("../dist/types.d.ts", import.meta.url)),
        "utf8",
    );
    for (const typeName of ["AskMemory", "AskResult", "AskOptions", "AskParams"]) {
        assert.match(dts, new RegExp(`export interface ${typeName}\\b`));
    }
});
