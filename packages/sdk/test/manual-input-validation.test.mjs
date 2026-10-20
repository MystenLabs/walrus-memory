import assert from "node:assert/strict";
import test from "node:test";

import { MemWal } from "../dist/memwal.js";

// #1211: rememberManual / recallManual signed and sent whatever they were
// given. JSON.stringify turns NaN/Infinity into null, a missing vector is
// dropped, and a missing encryptedData produced {"namespace":"default"}.

function client(sent) {
    const memwal = MemWal.create({
        key: "11".repeat(32),
        accountId: "0x1",
        serverUrl: "https://relayer.example",
    });
    memwal.signedRequest = async (_m, path, body) => {
        sent.push({ path, body: JSON.parse(JSON.stringify(body)) });
        return path.endsWith("/manual")
            ? { id: "1", blob_id: "b", owner: "0x1", namespace: "default" }
            : { results: [], total: 0 };
    };
    return memwal;
}

const BAD_VECTORS = [
    ["missing", undefined],
    ["null", null],
    ["not an array", "0.1,0.2"],
    ["empty", []],
    ["NaN", [0.1, NaN]],
    ["Infinity", [0.1, Infinity]],
    ["-Infinity", [-Infinity]],
    ["string element", [0.1, "0.2"]],
    ["null element", [0.1, null]],
    ["sparse new Array(3)", new Array(3)],
    // eslint-disable-next-line no-sparse-arrays
    ["sparse hole", [0.1, , 0.2]],
];

for (const [label, vector] of BAD_VECTORS) {
    test(`recallManual() rejects a ${label} vector before signing`, async () => {
        const sent = [];
        await assert.rejects(() => client(sent).recallManual({ vector }), {
            name: "TypeError",
            message: /^vector must be a non-empty array of finite numbers/,
        });
        assert.deepEqual(sent, []);
    });

    test(`rememberManual() rejects a ${label} vector before signing`, async () => {
        const sent = [];
        await assert.rejects(
            () => client(sent).rememberManual({ encryptedData: "AAAA", vector }),
            { name: "TypeError", message: /^vector must be a non-empty array of finite numbers/ },
        );
        assert.deepEqual(sent, []);
    });
}

for (const [label, encryptedData] of [["missing", undefined], ["empty", ""], ["blank", "  "], ["non-string", 42]]) {
    test(`rememberManual() rejects ${label} encryptedData before signing`, async () => {
        const sent = [];
        await assert.rejects(
            () => client(sent).rememberManual({ encryptedData, vector: [0.1] }),
            { name: "TypeError", message: "encryptedData must be a non-empty base64 string" },
        );
        assert.deepEqual(sent, []);
    });
}

test("valid manual calls still send the exact vector and data", async () => {
    const sent = [];
    const c = client(sent);
    await c.rememberManual({ encryptedData: "AAAA", vector: [0.1, -2, 0] });
    await c.recallManual({ vector: [0.5, 0], limit: 3 });
    assert.deepEqual(sent[0].body, { encrypted_data: "AAAA", vector: [0.1, -2, 0], namespace: "default" });
    assert.deepEqual(sent[1].body.vector, [0.5, 0]);
    assert.equal(sent[1].body.limit, 3);
});
