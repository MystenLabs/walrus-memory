/**
 * #1045 / WALM-725, end to end on the wire.
 *
 * A bridge reconnect opens a NEW MCP session: `resolveAuth` runs again and
 * builds a NEW `MemWal` client. The bridge's `_idempotency_key` must still
 * reach the relayer as `idempotency_key` on `POST /api/remember/bulk`, through
 * the SDK this package actually installs (the one the server image runs),
 * so the relayer's `bulk:{key}:{i}` ON CONFLICT path can answer the replay
 * with the jobs it already queued instead of registering a second paid blob.
 *
 * Sessions here are built by the real `resolveAuth` and talk to a stand-in
 * relayer over real HTTP. Only the SEAL session build is stubbed, because it
 * would otherwise dial Sui.
 */
process.env.MEMWAL_MCP_REMEMBER_WAIT_MS = "0";
process.env.SIDECAR_AUTH_TOKEN ??= "bulk-key-on-wire-test-token";

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test, { after, before, beforeEach, type TestContext } from "node:test";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

const { resolveAuth } = await import("../auth.js");
const { createMcpServer } = await import("../server.js");
const { resetBulkReplayCacheForTests } = await import("../tools/remember-bulk.js");

type BulkPost = {
    items: Array<{ text: string; namespace: string }>;
    idempotency_key?: string;
    sealSession?: string;
};

const posts: BulkPost[] = [];
/** Stand-in for the relayer's `(owner, namespace, bulk:{key}:{i})` ON CONFLICT. */
const jobsByKey = new Map<string, string[]>();
let jobSeq = 0;
let relayer: Server;
let relayerUrl: string;

before(async () => {
    const app = express();
    app.use(express.json());
    app.get("/version", (_req, res) => {
        res.json({
            apiVersion: "1.0.0",
            relayerVersion: "1.0.0",
            minSupportedSdk: { typescript: "0.0.4", mcp: "0.0.1" },
        });
    });
    app.post("/api/remember/bulk", (req, res) => {
        const body = req.body as BulkPost;
        posts.push({ ...body, sealSession: req.header("x-seal-session") ?? undefined });
        const key = body.idempotency_key;
        let ids = key ? jobsByKey.get(key) : undefined;
        if (!ids) {
            ids = body.items.map(() => `job-${++jobSeq}`);
            if (key) jobsByKey.set(key, ids);
        }
        res.status(202).json({ job_ids: ids, total: ids.length, status: "accepted" });
    });
    await new Promise<void>((resolve) => {
        relayer = app.listen(0, "127.0.0.1", () => resolve());
    });
    relayerUrl = `http://127.0.0.1:${(relayer.address() as AddressInfo).port}`;
});

after(async () => {
    await new Promise<void>((resolve) => relayer.close(() => resolve()));
});

beforeEach(() => {
    posts.length = 0;
    resetBulkReplayCacheForTests();
});

const creds = { bearer: randomBytes(32).toString("hex"), accountId: "0x" + randomBytes(32).toString("hex") };

/** One MCP session exactly as the sidecar opens it for a (re)connecting bridge. */
async function openSession(t: TestContext): Promise<{ client: Client; memwal: unknown }> {
    const headers = new Headers({
        authorization: `Bearer ${creds.bearer}`,
        "x-memwal-account-id": creds.accountId,
        "x-memwal-internal-sidecar-token": process.env.SIDECAR_AUTH_TOKEN!,
        "x-memwal-internal-oauth-scope": "memwal:read memwal:write",
    });
    const { session } = await resolveAuth(headers, relayerUrl);
    // Building a real SEAL session dials Sui; the header just has to be sent.
    (session.memwal as unknown as { buildSealSession: () => Promise<string> }).buildSealSession =
        async () => "stub-seal-session";
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const server = createMcpServer(session);
    const client = new Client({ name: "remember-bulk-key-on-wire-test", version: "1.0.0" });
    t.after(async () => {
        await client.close();
        await server.close();
    });
    await Promise.all([server.connect(st), client.connect(ct)]);
    return { client, memwal: session.memwal };
}

const text = (r: unknown) =>
    ((r as { content: Array<{ text: string }> }).content ?? []).map((c) => c.text).join("\n");

test("the bridge key reaches POST /api/remember/bulk as idempotency_key", async (t) => {
    const { client } = await openSession(t);
    const res = await client.callTool({
        name: "memwal_remember_bulk",
        arguments: { facts: ["likes tea", "lives in Hanoi"], _idempotency_key: "wire-key-1" },
    });
    assert.equal(posts.length, 1);
    assert.equal(posts[0].idempotency_key, "wire-key-1");
    assert.deepEqual(posts[0].items.map((i) => i.text), ["likes tea", "lives in Hanoi"]);
    // Sent through the SDK's own signed request, so the SEAL session rides along.
    assert.equal(posts[0].sealSession, "stub-seal-session");
    assert.match(text(res), /job-\d+/);
});

test("a replay over a reconnected session (new resolveAuth, new MemWal) does not POST again", async (t) => {
    const args = { facts: ["prefers dark mode"], _idempotency_key: "wire-key-2" };
    const first = await openSession(t);
    const r1 = await first.client.callTool({ name: "memwal_remember_bulk", arguments: args });
    const second = await openSession(t);
    assert.notEqual(first.memwal, second.memwal, "reconnect must build a new MemWal client");
    const r2 = await second.client.callTool({ name: "memwal_remember_bulk", arguments: args });

    assert.equal(posts.length, 1, "the in-process backstop is keyed by account+delegate, not the client object");
    const job = text(r1).match(/job-\d+/)![0];
    assert.match(text(r2), new RegExp(job));
});

test("after a sidecar restart the replay still carries the same key, so the relayer dedups it", async (t) => {
    const args = { facts: ["works at Mysten"], _idempotency_key: "wire-key-3" };
    const first = await openSession(t);
    const r1 = await first.client.callTool({ name: "memwal_remember_bulk", arguments: args });
    resetBulkReplayCacheForTests(); // the in-process record is gone
    const second = await openSession(t);
    const r2 = await second.client.callTool({ name: "memwal_remember_bulk", arguments: args });

    assert.equal(posts.length, 2);
    assert.deepEqual(posts.map((p) => p.idempotency_key), ["wire-key-3", "wire-key-3"]);
    const job = text(r1).match(/job-\d+/)![0];
    assert.match(text(r2), new RegExp(job), "relayer answered the replay with the original job");
});
