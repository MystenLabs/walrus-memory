import assert from "node:assert/strict";
import test from "node:test";

import { generateText } from "ai";

import { MemWal, MemWalRecallAllDroppedError } from "../dist/index.js";
import { withMemWal } from "../dist/ai/middleware.js";

const TEST_KEY = "11".repeat(32);
const TEST_ACCOUNT_ID = "0x1";

function fakeLanguageModel() {
    return {
        specificationVersion: "v2",
        provider: "test",
        modelId: "test-model",
        supportedUrls: {},
        doGenerate: async () => ({
            content: [{ type: "text", text: "generated response" }],
            finishReason: "stop",
            usage: { inputTokens: 5, outputTokens: 5, totalTokens: 10 },
            warnings: [],
        }),
        doStream: async () => ({ stream: new ReadableStream() }),
    };
}

test("when recall throws, transformParams emits console.warn by default without debug:true", async () => {
    const originalRecall = MemWal.prototype.recall;
    const originalWarn = console.warn;

    const simulatedError = new Error("simulated relayer 500 error");
    MemWal.prototype.recall = async () => {
        throw simulatedError;
    };

    const warnings = [];
    console.warn = (...args) => {
        warnings.push(args);
    };

    try {
        const model = withMemWal(fakeLanguageModel(), {
            key: TEST_KEY,
            accountId: TEST_ACCOUNT_ID,
            autoSave: false,
        });

        const result = await generateText({
            model,
            prompt: "What do you remember about me?",
        });

        assert.equal(result.text, "generated response");
        assert.ok(warnings.length > 0, "expected console.warn to be called");
        const found = warnings.some((w) =>
            w.some((arg) => typeof arg === "string" && arg.includes("Recall failed during transformParams"))
        );
        assert.ok(found, "expected warning mentioning 'Recall failed during transformParams'");
    } finally {
        MemWal.prototype.recall = originalRecall;
        console.warn = originalWarn;
    }
});

test("when recall throws, onRecallError callback is triggered with the error", async () => {
    const originalRecall = MemWal.prototype.recall;
    const originalWarn = console.warn;

    const simulatedError = new Error("simulated rate limit 429");
    MemWal.prototype.recall = async () => {
        throw simulatedError;
    };

    let caughtError = null;
    console.warn = () => {}; // suppress output during test

    try {
        const model = withMemWal(fakeLanguageModel(), {
            key: TEST_KEY,
            accountId: TEST_ACCOUNT_ID,
            autoSave: false,
            onRecallError: (err) => {
                caughtError = err;
            },
        });

        const result = await generateText({
            model,
            prompt: "What do you know?",
        });

        assert.equal(result.text, "generated response");
        assert.equal(caughtError, simulatedError);
    } finally {
        MemWal.prototype.recall = originalRecall;
        console.warn = originalWarn;
    }
});

test("if onRecallError throws, generation still proceeds", async () => {
    const originalRecall = MemWal.prototype.recall;
    const originalWarn = console.warn;

    MemWal.prototype.recall = async () => {
        throw new Error("recall exploded");
    };

    const warnings = [];
    console.warn = (...args) => {
        warnings.push(args);
    };

    try {
        const model = withMemWal(fakeLanguageModel(), {
            key: TEST_KEY,
            accountId: TEST_ACCOUNT_ID,
            autoSave: false,
            onRecallError: () => {
                throw new Error("handler exploded");
            },
        });

        const result = await generateText({
            model,
            prompt: "What is my name?",
        });

        assert.equal(result.text, "generated response");
        const callbackWarn = warnings.some((w) =>
            w.some((arg) => typeof arg === "string" && arg.includes("onRecallError callback threw"))
        );
        assert.ok(callbackWarn, "expected warning about failing callback");
    } finally {
        MemWal.prototype.recall = originalRecall;
        console.warn = originalWarn;
    }
});

test("all-dropped recall invokes onRecallError and does not cache an empty memory context", async () => {
    const originalFetch = globalThis.fetch;
    const originalBuildSeal = MemWal.prototype.buildSealSession;
    const originalWarn = console.warn;

    let recallCalls = 0;
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
            recallCalls += 1;
            if (recallCalls === 1) {
                return Response.json({ results: [], total: 2, dropped_count: 2, degraded: true });
            }
            return Response.json({
                results: [{ blob_id: "b1", text: "User is allergic to peanuts", distance: 0.1 }],
                total: 1,
            });
        }
        throw new Error(`unexpected request ${path}`);
    };
    MemWal.prototype.buildSealSession = async () => "test-session";
    console.warn = () => {};

    const errors = [];
    try {
        const model = withMemWal(fakeLanguageModel(), {
            key: TEST_KEY,
            accountId: TEST_ACCOUNT_ID,
            serverUrl: "https://relayer.example",
            autoSave: false,
            onRecallError: (err) => errors.push(err),
        });

        await generateText({ model, prompt: "Recommend a snack" });
        assert.equal(errors.length, 1);
        assert.ok(errors[0] instanceof MemWalRecallAllDroppedError);
        assert.equal(errors[0].droppedCount, 2);

        // Same user turn prompt on a subsequent step must retry recall rather than serving cached ""
        await generateText({ model, prompt: "Recommend a snack" });
        assert.equal(recallCalls, 2);
    } finally {
        globalThis.fetch = originalFetch;
        MemWal.prototype.buildSealSession = originalBuildSeal;
        console.warn = originalWarn;
    }
});
