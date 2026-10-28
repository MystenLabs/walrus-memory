import assert from "node:assert/strict";
import test from "node:test";

import { MemWal } from "../dist/memwal.js";

// #1213: listNamespaces / listMemories put options.limit straight into the
// signed query string, so NaN, -1 and 2.5 were signed and sent. The mock
// already rejects them.

const BAD = [NaN, -1, 0, 2.5, Infinity, "5", null, true];

function client(sent) {
    const memwal = MemWal.create({
        key: "11".repeat(32),
        accountId: "0x1",
        serverUrl: "https://relayer.example",
    });
    memwal.resolveOwner = async () => "0xowner";
    memwal.signedRequest = async (_method, path) => {
        sent.push(path);
        return path.includes("/namespaces")
            ? { namespaces: [], has_more: false, snapshot_version: 1 }
            : { memories: [], deleted: [], has_more: false };
    };
    return memwal;
}

for (const method of ["listNamespaces", "listMemories"]) {
    test(`${method}() rejects a limit that is not a positive integer before signing`, async () => {
        const sent = [];
        for (const limit of BAD) {
            await assert.rejects(() => client(sent)[method]({ limit }), {
                name: "TypeError",
                message: `limit must be a positive integer, got ${limit}`,
            });
        }
        assert.deepEqual(sent, []);
    });

    test(`${method}() still forwards a valid limit and omits an absent one`, async () => {
        const sent = [];
        await client(sent)[method]({ limit: 1 });
        await client(sent)[method]({ limit: 500 });
        await client(sent)[method]({});
        assert.match(sent[0], /\?limit=1$/);
        assert.match(sent[1], /\?limit=500$/);
        assert.doesNotMatch(sent[2], /limit=/);
    });
}
