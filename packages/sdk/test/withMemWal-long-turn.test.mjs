import assert from "node:assert/strict";
import test from "node:test";

import { generateText } from "ai";

import { MemWal } from "../dist/memwal.js";
import {
    MAX_ANALYZE_INPUT_BYTES,
    MAX_EMBED_INPUT_BYTES,
    truncateUtf8Bytes,
    withMemWal,
} from "../dist/ai/middleware.js";

const TEST_KEY = "11".repeat(32);
const TEST_ACCOUNT_ID = "0x1";
const encoder = new TextEncoder();

function utf8ByteLength(text) {
    return encoder.encode(text).byteLength;
}

function fakeLanguageModel(capture = {}) {
    return {
        specificationVersion: "v2",
        provider: "test",
        modelId: "test-model",
        supportedUrls: {},
        doGenerate: async (options) => {
            capture.generatePrompt = options?.prompt;
            return {
                content: [{ type: "text", text: "ok" }],
                finishReason: "stop",
                usage: { inputTokens: 1, outputTokens: 1, totalTokens: 2 },
                warnings: [],
            };
        },
        doStream: async (options) => {
            capture.streamPrompt = options?.prompt;
            return { stream: new ReadableStream() };
        },
    };
}

test("user turns at or under 16,384 UTF-8 bytes are passed unchanged to recall and analyze", async () => {
    const originalRecall = MemWal.prototype.recall;
    const originalAnalyze = MemWal.prototype.analyze;

    const seenRecallQueries = [];
    const seenAnalyzeTexts = [];

    MemWal.prototype.recall = async function (query) {
        seenRecallQueries.push(query);
        return {
            results: [{ text: "The user is studying volcano geology.", distance: 0.1 }],
            total: 1,
        };
    };
    MemWal.prototype.analyze = async function (text) {
        seenAnalyzeTexts.push(text);
        return { facts: [], job_ids: [], status: "pending", total: 0, owner: "0x1" };
    };

    try {
        const model = withMemWal(fakeLanguageModel(), {
            key: TEST_KEY,
            accountId: TEST_ACCOUNT_ID,
            minRelevance: 0,
        });

        const shortText = "What is the user studying? 🌋";
        await generateText({ model, prompt: shortText });
        await model.flush();

        assert.equal(seenRecallQueries.length, 1);
        assert.equal(seenRecallQueries[0], shortText);
        assert.equal(seenAnalyzeTexts.length, 1);
        assert.equal(seenAnalyzeTexts[0], shortText);

        // Exact 16,384-byte boundary turn
        const exact16k = "a".repeat(MAX_EMBED_INPUT_BYTES);
        assert.equal(utf8ByteLength(exact16k), 16_384);
        await model.doGenerate({
            prompt: [{ role: "user", content: [{ type: "text", text: exact16k }] }],
        });
        await model.flush();

        assert.equal(seenRecallQueries[1], exact16k);
        assert.equal(seenAnalyzeTexts[1], exact16k);
    } finally {
        MemWal.prototype.recall = originalRecall;
        MemWal.prototype.analyze = originalAnalyze;
    }
});

test("turns between 16 KiB and 64 KiB keep full auto-save text and bound recall query with head-tail preservation (#1037)", async () => {
    const originalRecall = MemWal.prototype.recall;
    const originalAnalyze = MemWal.prototype.analyze;

    const seenRecallQueries = [];
    const seenAnalyzeTexts = [];

    MemWal.prototype.recall = async function (query) {
        const bytes = utf8ByteLength(query);
        if (bytes > MAX_EMBED_INPUT_BYTES) {
            throw new Error(
                `Walrus Memory server error (400): {"error":"input is over the embedding input limit of ${MAX_EMBED_INPUT_BYTES} bytes"}`,
            );
        }
        seenRecallQueries.push(query);
        return {
            results: [{ text: "The user is studying volcano geology.", distance: 0.1 }],
            total: 1,
        };
    };
    MemWal.prototype.analyze = async function (text) {
        const bytes = utf8ByteLength(text);
        if (bytes > MAX_ANALYZE_INPUT_BYTES) {
            throw new Error(
                `Walrus Memory server error (400): {"error":"text exceeds maximum length of ${MAX_ANALYZE_INPUT_BYTES} bytes"}`,
            );
        }
        seenAnalyzeTexts.push(text);
        return { facts: [], job_ids: [], status: "pending", total: 0, owner: "0x1" };
    };

    try {
        const capture = {};
        const model = withMemWal(fakeLanguageModel(capture), {
            key: TEST_KEY,
            accountId: TEST_ACCOUNT_ID,
            minRelevance: 0,
        });

        // 20 KiB paste with user question at the end
        const pasted = `Here are my detailed research logs:\n${"data log entry line test sample\n".repeat(600)}`;
        const questionAtEnd = "Based on the above, what volcano did I study in 2024?";
        const longTurn20k = pasted + questionAtEnd;
        const turnBytes = utf8ByteLength(longTurn20k);
        assert.ok(turnBytes > 16_384 && turnBytes < MAX_ANALYZE_INPUT_BYTES);

        await generateText({ model, prompt: longTurn20k });
        await model.flush();

        assert.equal(seenRecallQueries.length, 1);
        const recallBytes = utf8ByteLength(seenRecallQueries[0]);
        assert.ok(recallBytes <= MAX_EMBED_INPUT_BYTES);
        // Head-tail strategy preserves both start of turn and question at the end
        assert.ok(
            seenRecallQueries[0].includes("Here are my detailed research logs:"),
            "expected recall query to retain start context",
        );
        assert.ok(
            seenRecallQueries[0].includes(questionAtEnd),
            "expected recall query to preserve question at the tail of the paste",
        );
        assert.equal(seenRecallQueries[0].includes("\uFFFD"), false);

        // Auto-save analyze preserves the full turn up to 64 KiB without dropping facts
        assert.equal(seenAnalyzeTexts.length, 1);
        assert.equal(seenAnalyzeTexts[0], longTurn20k);

        // The prompt delivered to the LLM keeps the full untruncated turn and injected memories
        const userTurnMessage = capture.generatePrompt?.find(
            (m) => m.role === "user" && m.content?.[0]?.text === longTurn20k,
        );
        assert.ok(
            userTurnMessage,
            "expected the full untruncated user turn to remain in the language model prompt",
        );
        const injectedMemoryMessage = capture.generatePrompt?.find(
            (m) => m.role === "user" && m.content?.[0]?.text?.includes("The user is studying volcano geology."),
        );
        assert.ok(
            injectedMemoryMessage,
            "expected relevant memory to be injected on long user turn",
        );
    } finally {
        MemWal.prototype.recall = originalRecall;
        MemWal.prototype.analyze = originalAnalyze;
    }
});

test("turns exceeding 64 KiB bound analyze to MAX_ANALYZE_INPUT_BYTES without splitting UTF-8 characters", async () => {
    const originalRecall = MemWal.prototype.recall;
    const originalAnalyze = MemWal.prototype.analyze;

    const seenRecallQueries = [];
    const seenAnalyzeTexts = [];

    MemWal.prototype.recall = async function (query) {
        if (utf8ByteLength(query) > MAX_EMBED_INPUT_BYTES) {
            throw new Error("recall query exceeded 16,384 bytes");
        }
        seenRecallQueries.push(query);
        return { results: [], total: 0 };
    };
    MemWal.prototype.analyze = async function (text) {
        if (utf8ByteLength(text) > MAX_ANALYZE_INPUT_BYTES) {
            throw new Error(`analyze text exceeded ${MAX_ANALYZE_INPUT_BYTES} bytes`);
        }
        seenAnalyzeTexts.push(text);
        return { facts: [], job_ids: [], status: "pending", total: 0, owner: "0x1" };
    };

    try {
        const model = withMemWal(fakeLanguageModel(), {
            key: TEST_KEY,
            accountId: TEST_ACCOUNT_ID,
            minRelevance: 0,
        });

        // 70 KiB turn with multi-byte emoji straddling the 65,536-byte boundary
        const prefix = "y".repeat(65_534);
        const hugeTurn = `${prefix}🌋${"extra text ".repeat(500)}`;
        assert.ok(utf8ByteLength(hugeTurn) > MAX_ANALYZE_INPUT_BYTES);

        await generateText({ model, prompt: hugeTurn });
        await model.flush();

        assert.equal(seenAnalyzeTexts.length, 1);
        assert.ok(utf8ByteLength(seenAnalyzeTexts[0]) <= MAX_ANALYZE_INPUT_BYTES);
        assert.equal(seenAnalyzeTexts[0], prefix);
        assert.equal(seenAnalyzeTexts[0].includes("\uFFFD"), false);
    } finally {
        MemWal.prototype.recall = originalRecall;
        MemWal.prototype.analyze = originalAnalyze;
    }
});

test("long user turn (>16 KiB) in wrapStream bounds recall to <=16,384 bytes and injects memories", async () => {
    const originalRecall = MemWal.prototype.recall;
    const originalAnalyze = MemWal.prototype.analyze;

    const seenRecallQueries = [];
    const seenAnalyzeTexts = [];

    MemWal.prototype.recall = async function (query) {
        if (utf8ByteLength(query) > MAX_EMBED_INPUT_BYTES) {
            throw new Error("recall query exceeded 16,384 bytes");
        }
        seenRecallQueries.push(query);
        return {
            results: [{ text: "Prefers streaming responses.", distance: 0.05 }],
            total: 1,
        };
    };
    MemWal.prototype.analyze = async function (text) {
        if (utf8ByteLength(text) > MAX_ANALYZE_INPUT_BYTES) {
            throw new Error("analyze text exceeded max analyze bytes");
        }
        seenAnalyzeTexts.push(text);
        return { facts: [], job_ids: [], status: "pending", total: 0, owner: "0x1" };
    };

    try {
        const capture = {};
        const model = withMemWal(fakeLanguageModel(capture), {
            key: TEST_KEY,
            accountId: TEST_ACCOUNT_ID,
            minRelevance: 0,
        });

        const prefix = "x".repeat(16_382);
        const longStreamTurn = `${prefix}🌋${"🌋".repeat(200)}`;
        assert.ok(utf8ByteLength(longStreamTurn) > MAX_EMBED_INPUT_BYTES);

        const prompt = [{ role: "user", content: [{ type: "text", text: longStreamTurn }] }];
        const transformed = await model.doStream({ prompt });
        assert.ok(transformed.stream instanceof ReadableStream);
        await model.flush();

        assert.equal(seenRecallQueries.length, 1);
        assert.ok(utf8ByteLength(seenRecallQueries[0]) <= MAX_EMBED_INPUT_BYTES);
        assert.equal(seenRecallQueries[0].includes("\uFFFD"), false);

        assert.equal(seenAnalyzeTexts.length, 1);
        assert.equal(seenAnalyzeTexts[0], longStreamTurn);

        const serializedStreamPrompt = JSON.stringify(capture.streamPrompt);
        assert.ok(
            serializedStreamPrompt.includes("Prefers streaming responses."),
            "expected relevant memory to be injected on long streaming user turn",
        );
        assert.ok(
            serializedStreamPrompt.includes(longStreamTurn),
            "expected the full untruncated user turn to remain in the stream prompt",
        );
    } finally {
        MemWal.prototype.recall = originalRecall;
        MemWal.prototype.analyze = originalAnalyze;
    }
});

test("truncateUtf8Bytes never splits 2-byte, 3-byte, or 4-byte UTF-8 codepoints across boundaries (head strategy)", () => {
    // 2-byte character: "é" (U+00E9, 0xC3 0xA9)
    {
        const str = "a".repeat(16_383) + "é" + "b".repeat(100);
        const out = truncateUtf8Bytes(str, 16_384);
        assert.equal(utf8ByteLength(out), 16_383);
        assert.equal(out.includes("\uFFFD"), false);
        assert.equal(out, "a".repeat(16_383));
    }

    // 3-byte character: "漢" (U+6F22, 3 UTF-8 bytes) at offsets 16,381..16,383
    for (const offset of [16_381, 16_382, 16_383]) {
        const str = "a".repeat(offset) + "漢" + "b".repeat(100);
        const out = truncateUtf8Bytes(str, 16_384);
        const bytes = utf8ByteLength(out);
        assert.ok(bytes <= 16_384);
        assert.equal(out.includes("\uFFFD"), false);
        if (offset === 16_381) {
            assert.equal(bytes, 16_384);
            assert.ok(out.endsWith("漢"));
        } else {
            assert.equal(bytes, offset);
            assert.equal(out, "a".repeat(offset));
        }
    }

    // 4-byte character: "🌋" (U+1F30B, 4 UTF-8 bytes) at offsets 16,380..16,383
    for (const offset of [16_380, 16_381, 16_382, 16_383]) {
        const str = "a".repeat(offset) + "🌋" + "b".repeat(100);
        const out = truncateUtf8Bytes(str, 16_384);
        const bytes = utf8ByteLength(out);
        assert.ok(bytes <= 16_384);
        assert.equal(out.includes("\uFFFD"), false);
        if (offset === 16_380) {
            assert.equal(bytes, 16_384);
            assert.ok(out.endsWith("🌋"));
        } else {
            assert.equal(bytes, offset);
            assert.equal(out, "a".repeat(offset));
        }
    }

    // Leading whitespace exceeding limit
    {
        const str = " ".repeat(17_000) + "What is my favorite food?";
        const out = truncateUtf8Bytes(str, 16_384);
        assert.equal(out, "What is my favorite food?");
    }
});

test("truncateUtf8Bytes preserves head context and tail question with head-tail strategy", () => {
    const question = "What was my quarterly budget for team Beta?";
    const paste = "lorem ipsum dolor sit amet ".repeat(800); // ~21,600 bytes
    const turn = `${paste}\n\n${question}`;

    const out = truncateUtf8Bytes(turn, 16_384, { strategy: "head-tail" });
    const bytes = utf8ByteLength(out);

    assert.ok(bytes <= 16_384);
    assert.equal(out.includes("\uFFFD"), false);
    assert.ok(out.includes("lorem ipsum dolor"), "expected start of paste to be preserved");
    assert.ok(out.includes(question), "expected tail question to be preserved");
    assert.ok(out.includes("\n...\n"), "expected separator between head and tail");

    // Reverse: question at start, paste at tail
    const turnStartQuestion = `${question}\n\n${paste}`;
    const outStart = truncateUtf8Bytes(turnStartQuestion, 16_384, { strategy: "head-tail" });
    assert.ok(utf8ByteLength(outStart) <= 16_384);
    assert.equal(outStart.includes("\uFFFD"), false);
    assert.ok(outStart.includes(question), "expected head question to be preserved");
    assert.ok(outStart.includes("\n...\n"), "expected separator between head and tail");

    // Multi-byte UTF-8 codepoints straddling boundaries on head-tail strategy
    const multiBytePaste = "漢".repeat(6_000) + "🌋".repeat(4_000);
    const multiByteOut = truncateUtf8Bytes(multiBytePaste, 16_384, { strategy: "head-tail" });
    assert.ok(utf8ByteLength(multiByteOut) <= 16_384);
    assert.equal(multiByteOut.includes("\uFFFD"), false);
});
