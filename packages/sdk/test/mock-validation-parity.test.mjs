import assert from "node:assert/strict";
import test from "node:test";

import { MemWal, MemWalMock } from "../dist/index.js";

const originalFetch = globalThis.fetch;

test.afterEach(() => {
    globalThis.fetch = originalFetch;
});

function createClients() {
    globalThis.fetch = async () => {
        throw new Error("network must not be called on invalid input");
    };
    const real = MemWal.create({
        key: "01".repeat(32),
        accountId: "0x" + "11".repeat(32),
    });
    const mock = MemWalMock.create();
    return { real, mock };
}

async function assertSameRejection(label, runOnClient) {
    const { real, mock } = createClients();
    let realErr;
    let mockErr;

    try {
        await runOnClient(real);
    } catch (err) {
        realErr = err;
    }

    try {
        await runOnClient(mock);
    } catch (err) {
        mockErr = err;
    }

    assert.ok(realErr instanceof Error, `${label}: MemWal must reject`);
    assert.ok(mockErr instanceof Error, `${label}: MemWalMock must reject`);
    assert.notEqual(
        realErr.message,
        "network must not be called on invalid input",
        `${label}: MemWal must validate before touching fetch`,
    );
    assert.equal(mockErr.name, realErr.name, `${label}: error constructor name must match`);
    assert.equal(mockErr.message, realErr.message, `${label}: error message must match`);
}

function assertSameSyncThrow(label, runOnClass) {
    let realErr;
    let mockErr;

    try {
        runOnClass("real");
    } catch (err) {
        realErr = err;
    }

    try {
        runOnClass("mock");
    } catch (err) {
        mockErr = err;
    }

    assert.ok(realErr instanceof Error, `${label}: MemWal.create must throw`);
    assert.ok(mockErr instanceof Error, `${label}: MemWalMock.create must throw`);
    assert.equal(mockErr.name, realErr.name, `${label}: error constructor name must match`);
    assert.equal(mockErr.message, realErr.message, `${label}: error message must match`);
}

test("MemWal and MemWalMock enforce identical text validation on remember*, analyze*, and embed", async () => {
    const blankTexts = ["", "   ", "\t\n", "\u200B", "\uFEFF", " \u200B "];
    const nonStringTexts = [null, undefined, 123, {}];

    for (const badText of [...blankTexts, ...nonStringTexts]) {
        const desc = JSON.stringify(badText);
        await assertSameRejection(`remember(${desc})`, (c) => c.remember(badText));
        await assertSameRejection(`rememberAsync(${desc})`, (c) => c.rememberAsync(badText));
        await assertSameRejection(`rememberAndWait(${desc})`, (c) => c.rememberAndWait(badText));
        await assertSameRejection(`analyze(${desc})`, (c) => c.analyze(badText));
        await assertSameRejection(`analyzeAndWait(${desc})`, (c) => c.analyzeAndWait(badText));
        await assertSameRejection(`embed(${desc})`, (c) => c.embed(badText));
    }
});

test("MemWal and MemWalMock enforce identical validation on rememberBulk*", async () => {
    const tooManyItems = Array.from({ length: 21 }, (_, i) => ({ text: `item ${i}` }));

    for (const method of ["rememberBulk", "rememberBulkAsync", "rememberBulkAndWait"]) {
        await assertSameRejection(`${method}([])`, (c) => c[method]([]));
        await assertSameRejection(`${method}(null)`, (c) => c[method](null));
        await assertSameRejection(`${method}(21 items)`, (c) => c[method](tooManyItems));

        for (const badText of ["", "   ", "\u200B", null]) {
            const desc = JSON.stringify(badText);
            await assertSameRejection(`${method} blank text ${desc}`, (c) =>
                c[method]([{ text: "ok" }, { text: badText }]),
            );
        }

        for (const badNs of ["", "   ", "\u200B"]) {
            const desc = JSON.stringify(badNs);
            await assertSameRejection(`${method} blank item namespace ${desc}`, (c) =>
                c[method]([{ text: "ok", namespace: badNs }]),
            );
        }
    }
});

test("MemWal and MemWalMock enforce identical idempotencyKey validation on remember* and rememberBulk*", async () => {
    const invalidKeys = ["", "k".repeat(256), "é".repeat(128)];

    for (const key of invalidKeys) {
        const desc = key === "" ? '""' : `${key.length} chars`;
        await assertSameRejection(`remember idempotencyKey=${desc}`, (c) =>
            c.remember("valid fact", "ns", { idempotencyKey: key }),
        );
        await assertSameRejection(`rememberAsync idempotencyKey=${desc}`, (c) =>
            c.rememberAsync("valid fact", "ns", { idempotencyKey: key }),
        );
        await assertSameRejection(`rememberAndWait idempotencyKey=${desc}`, (c) =>
            c.rememberAndWait("valid fact", "ns", { idempotencyKey: key }),
        );
        await assertSameRejection(`rememberBulk idempotencyKey=${desc}`, (c) =>
            c.rememberBulk([{ text: "valid fact" }], { idempotencyKey: key }),
        );
        await assertSameRejection(`rememberBulkAsync idempotencyKey=${desc}`, (c) =>
            c.rememberBulkAsync([{ text: "valid fact" }], { idempotencyKey: key }),
        );
        await assertSameRejection(`rememberBulkAndWait idempotencyKey=${desc}`, (c) =>
            c.rememberBulkAndWait([{ text: "valid fact" }], { idempotencyKey: key }),
        );
    }
});

test("MemWal and MemWalMock enforce identical query and positional argument validation on recall", async () => {
    for (const badQuery of ["", "   ", "\u200B", "\uFEFF", null, undefined, 42]) {
        const desc = JSON.stringify(badQuery);
        await assertSameRejection(`recall({ query: ${desc} })`, (c) =>
            c.recall({ query: badQuery }),
        );
    }

    await assertSameRejection('positional recall(query, "ns")', (c) =>
        c.recall("valid query", "ns"),
    );
});

test("MemWal and MemWalMock enforce identical limit validation on recall, restore, and listNamespaces", async () => {
    const invalidLimits = [0, -1, 1.5, NaN, Infinity, -Infinity, "5", null];

    for (const limit of invalidLimits) {
        const desc = String(limit);
        await assertSameRejection(`recall({ limit: ${desc} })`, (c) =>
            c.recall({ query: "valid", limit }),
        );
        await assertSameRejection(`recall({ topK: ${desc} })`, (c) =>
            c.recall({ query: "valid", topK: limit }),
        );
        await assertSameRejection(`restore("ns", ${desc})`, (c) =>
            c.restore("ns", limit),
        );
        await assertSameRejection(`listNamespaces({ limit: ${desc} })`, (c) =>
            c.listNamespaces({ limit }),
        );
    }
});

test("MemWal and MemWalMock enforce identical maxDistance, maxTokens, and scoringWeights validation on recall", async () => {
    for (const maxDistance of [-0.1, -1, NaN, Infinity, -Infinity, "0.5"]) {
        await assertSameRejection(`recall maxDistance=${String(maxDistance)}`, (c) =>
            c.recall({ query: "valid", maxDistance }),
        );
    }

    for (const maxTokens of [-5, -0.1, "400", null, true]) {
        await assertSameRejection(`recall maxTokens=${String(maxTokens)}`, (c) =>
            c.recall({ query: "valid", maxTokens }),
        );
    }

    for (const scoringWeights of [
        { semantic: NaN },
        { recency: Infinity },
        { importance: -Infinity },
        { recencyHalfLifeDays: NaN },
    ]) {
        await assertSameRejection(
            `recall scoringWeights=${JSON.stringify(scoringWeights)}`,
            (c) => c.recall({ query: "valid", scoringWeights }),
        );
    }
});

test("MemWal and MemWalMock enforce identical occurredAt validation on analyze and analyzeAndWait", async () => {
    await assertSameRejection("analyze Invalid Date occurredAt", (c) =>
        c.analyze("valid text", { occurredAt: new Date("not-a-date") }),
    );
    await assertSameRejection("analyzeAndWait Invalid Date occurredAt", (c) =>
        c.analyzeAndWait("valid text", { occurredAt: new Date("not-a-date") }),
    );
});

test("MemWal and MemWalMock enforce identical empty/whitespace namespace validation across constructor and methods", async () => {
    for (const badNs of ["", "   ", "\t", "\u200B"]) {
        const desc = JSON.stringify(badNs);
        assertSameSyncThrow(`create({ namespace: ${desc} })`, (kind) => {
            if (kind === "real") {
                return MemWal.create({
                    key: "01".repeat(32),
                    accountId: "0x" + "11".repeat(32),
                    namespace: badNs,
                });
            }
            return MemWalMock.create({ namespace: badNs });
        });

        await assertSameRejection(`remember("ok", ${desc})`, (c) =>
            c.remember("ok", badNs),
        );
        await assertSameRejection(`rememberAsync("ok", ${desc})`, (c) =>
            c.rememberAsync("ok", badNs),
        );
        await assertSameRejection(`rememberAndWait("ok", ${desc})`, (c) =>
            c.rememberAndWait("ok", badNs),
        );
        await assertSameRejection(`recall({ query: "ok", namespace: ${desc} })`, (c) =>
            c.recall({ query: "ok", namespace: badNs }),
        );
        await assertSameRejection(`analyze("ok", ${desc})`, (c) =>
            c.analyze("ok", badNs),
        );
        await assertSameRejection(`analyze("ok", { namespace: ${desc} })`, (c) =>
            c.analyze("ok", { namespace: badNs }),
        );
        await assertSameRejection(`analyzeAndWait("ok", ${desc})`, (c) =>
            c.analyzeAndWait("ok", badNs),
        );
        await assertSameRejection(`restore(${desc})`, (c) =>
            c.restore(badNs),
        );
    }
});
