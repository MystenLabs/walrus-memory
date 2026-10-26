import assert from "node:assert/strict";
import test from "node:test";

import { MemWal } from "../dist/memwal.js";
import { MemWalManual } from "../dist/manual.js";

// #1246: #1228 guarded recall() against non-finite scoring weights, but both
// recallManual() implementations still serialized them. JSON.stringify turns
// NaN/Infinity into null, so the signed body silently carried
// {"semantic": null} instead of the caller's value.

function client() {
    return MemWal.create({
        key: new Uint8Array(32).fill(1),
        accountId: "0x1",
        serverUrl: "https://relayer.example",
    });
}

function manualClient() {
    return MemWalManual.create({
        key: new Uint8Array(32).fill(1),
        walletSigner: {
            address: "0x2",
            signAndExecuteTransaction: async () => ({ digest: "0xtx" }),
            signPersonalMessage: async () => ({ signature: "sig" }),
        },
        suiClient: {},
        embeddingApiKey: "test",
        packageId: `0x${"33".repeat(32)}`,
        accountId: "0x1",
        registryId: "0xregistry",
        sealServerConfigs: [{ objectId: "0xserver", weight: 1 }],
    });
}

const BAD_WEIGHTS = [
    [{ semantic: NaN }, "semantic"],
    [{ recency: Infinity }, "recency"],
    [{ importance: -Infinity }, "importance"],
    [{ recencyHalfLifeDays: NaN }, "recencyHalfLifeDays"],
    [{ semantic: "0.5" }, "semantic"],
];

test("MemWal.recallManual() rejects a non-finite scoring weight before signing", async () => {
    const memwal = client();
    const sent = [];
    memwal.signedRequest = async (_method, _path, body) => {
        sent.push(JSON.stringify(body));
        return { results: [], total: 0 };
    };

    for (const [scoringWeights, name] of BAD_WEIGHTS) {
        await assert.rejects(
            () => memwal.recallManual({ vector: [0.1, 0.2], scoringWeights }),
            { name: "Error", message: `scoringWeights.${name} must be a finite number` },
        );
    }
    assert.deepEqual(sent, []);

    await memwal.recallManual({ vector: [0.1, 0.2], scoringWeights: { semantic: 0.7 } });
    assert.match(sent[0], /"scoring_weights":\{"semantic":0\.7\}/);
});

test("MemWalManual.recallManual() rejects a non-finite scoring weight before signing", async () => {
    const manual = manualClient();
    const sent = [];
    manual.signedRequest = async (_method, _path, body) => {
        sent.push(JSON.stringify(body));
        return { results: [], total: 0 };
    };
    manual.embed = async () => [0.1, 0.2];

    for (const [scoringWeights, name] of BAD_WEIGHTS) {
        await assert.rejects(
            () => manual.recallManual("coffee", { scoringWeights }),
            { name: "Error", message: `scoringWeights.${name} must be a finite number` },
        );
    }
    assert.deepEqual(sent, []);

    await manual.recallManual("coffee", { scoringWeights: { importance: 0.2 } });
    assert.match(sent[0], /"scoring_weights":\{"importance":0\.2\}/);
});
