import assert from "node:assert/strict";
import test from "node:test";

import { generateText } from "ai";

import { MemWal } from "../dist/memwal.js";
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

test("withMemWal forwards maxTokens to recall() when configured", async () => {
    const originalRecall = MemWal.prototype.recall;
    const recallCalls = [];

    MemWal.prototype.recall = async (params) => {
        recallCalls.push(params);
        return { results: [], total: 0 };
    };

    try {
        const model = withMemWal(fakeLanguageModel(), {
            key: TEST_KEY,
            accountId: TEST_ACCOUNT_ID,
            autoSave: false,
            maxMemories: 7,
            maxTokens: 256,
        });

        await generateText({
            model,
            prompt: "Summarize my preferences",
        });

        assert.equal(recallCalls.length, 1);
        assert.deepEqual(recallCalls[0], {
            query: "Summarize my preferences",
            limit: 7,
            maxTokens: 256,
        });
    } finally {
        MemWal.prototype.recall = originalRecall;
    }
});
