// Accept-and-return path; the dedup under test is about acceptance.
process.env.MEMWAL_MCP_REMEMBER_WAIT_MS = "0";

import assert from "node:assert/strict";
import test, { beforeEach, type TestContext } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { MemWalSession } from "../auth.js";

const { createMcpServer } = await import("../server.js");
const { resetBulkReplayCacheForTests } = await import("../tools/remember-bulk.js");

beforeEach(() => resetBulkReplayCacheForTests());

let owner = 0;
/** A distinct caller identity per session unless one is passed in. */
const identity = (id = ++owner) => ({ accountId: `0xacct${id}`, delegatePubKeyHex: `pub${id}` });

/**
 * #1045: a bridge reconnect replays an in-flight
 * `memwal_remember_bulk` with the same `_idempotency_key`. The replay must not
 * register a second batch (a second paid Walrus blob per fact), and the key
 * must be handed to the SDK so the relayer can dedup too. Reconnects that
 * build a new session through `resolveAuth` are covered on the wire by
 * remember-bulk-key-on-wire.test.ts.
 */
function recordingSession() {
    const calls: Array<{ texts: string[]; options: unknown }> = [];
    let n = 0;
    const session = {
        ...identity(),
        oauthScope: "memwal:read memwal:write",
        namespace: "default",
        memwal: {
            async rememberBulkAsync(items: Array<{ text: string }>, options?: unknown) {
                calls.push({ texts: items.map((i) => i.text), options });
                const ids = items.map(() => `job-${++n}`);
                return { job_ids: ids, total: ids.length, status: "accepted" };
            },
        },
    } as unknown as MemWalSession;
    return { session, calls };
}

async function clientFor(session: MemWalSession, t: TestContext): Promise<Client> {
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const server = createMcpServer(session);
    const client = new Client({ name: "remember-bulk-replay-dedup-test", version: "1.0.0" });
    t.after(async () => {
        await client.close();
        await server.close();
    });
    await Promise.all([server.connect(st), client.connect(ct)]);
    return client;
}

const text = (r: unknown) =>
    ((r as { content: Array<{ text: string }> }).content ?? []).map((c) => c.text).join("\n");

test("reconnect replay with the same key creates no second registration", async (t) => {
    const { session, calls } = recordingSession();
    const args = { facts: ["likes tea", "lives in Hanoi"], _idempotency_key: "replay-key-1" };

    // The original call, then a replay over a fresh connection (as after a
    // bridge reconnect) to the same server process.
    const first = await (await clientFor(session, t)).callTool({ name: "memwal_remember_bulk", arguments: args });
    const replay = await (await clientFor(session, t)).callTool({ name: "memwal_remember_bulk", arguments: args });

    assert.equal(calls.length, 1, "replay must not POST the bulk write again");
    assert.deepEqual(calls[0].options, { idempotencyKey: "replay-key-1" });
    assert.match(text(first), /job-1/);
    assert.match(text(replay), /job-1/);
    assert.doesNotMatch(text(replay), /job-3/);
});

test("concurrent replay while the original is in flight is also deduped", async (t) => {
    const { session, calls } = recordingSession();
    const client = await clientFor(session, t);
    const args = { facts: ["prefers dark mode"], _idempotency_key: "replay-key-2" };
    await Promise.all([
        client.callTool({ name: "memwal_remember_bulk", arguments: args }),
        client.callTool({ name: "memwal_remember_bulk", arguments: args }),
    ]);
    assert.equal(calls.length, 1);
});

test("distinct keys are distinct calls", async (t) => {
    const { session, calls } = recordingSession();
    const client = await clientFor(session, t);
    await client.callTool({ name: "memwal_remember_bulk", arguments: { facts: ["a fact"], _idempotency_key: "k-a" } });
    await client.callTool({ name: "memwal_remember_bulk", arguments: { facts: ["a fact"], _idempotency_key: "k-b" } });
    assert.equal(calls.length, 2);
});

test("a call with no key is never deduped", async (t) => {
    const { session, calls } = recordingSession();
    const client = await clientFor(session, t);
    await client.callTool({ name: "memwal_remember_bulk", arguments: { facts: ["x fact"] } });
    await client.callTool({ name: "memwal_remember_bulk", arguments: { facts: ["x fact"] } });
    assert.equal(calls.length, 2);
    assert.equal(calls[0].options, undefined);
});

test("a key whose accept failed can be retried by a replay", async (t) => {
    let attempts = 0;
    const session = {
        ...identity(),
        oauthScope: "memwal:read memwal:write",
        namespace: "default",
        memwal: {
            async rememberBulkAsync() {
                attempts++;
                if (attempts === 1) throw new Error("400 bad request");
                return { job_ids: ["job-ok"], total: 1, status: "accepted" };
            },
        },
    } as unknown as MemWalSession;
    const client = await clientFor(session, t);
    const args = { facts: ["retry fact"], _idempotency_key: "k-fail" };
    await client.callTool({ name: "memwal_remember_bulk", arguments: args });
    const second = await client.callTool({ name: "memwal_remember_bulk", arguments: args });
    assert.equal(attempts, 2);
    assert.match(text(second), /job-ok/);
});

test("the same key from a different account is not answered from another caller's record", async (t) => {
    const a = recordingSession();
    const b = recordingSession();
    const args = { facts: ["shared fact"], _idempotency_key: "same-key" };
    await (await clientFor(a.session, t)).callTool({ name: "memwal_remember_bulk", arguments: args });
    await (await clientFor(b.session, t)).callTool({ name: "memwal_remember_bulk", arguments: args });
    assert.equal(a.calls.length, 1);
    assert.equal(b.calls.length, 1);
});
