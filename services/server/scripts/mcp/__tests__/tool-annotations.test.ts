import assert from "node:assert/strict";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { MemWalSession } from "../auth.js";
import { createMcpServer } from "../server.js";

test("tools/list publishes safe titles and behavior annotations for every remote tool", async (t) => {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    // Full scope so every remote tool is registered — tool registration is
    // scope-gated, and this test is about the annotations each tool publishes.
    const server = createMcpServer({
        oauthScope: "memwal:read memwal:write",
    } as MemWalSession);
    const client = new Client({ name: "annotations-test", version: "1.0.0" });

    t.after(async () => {
        await client.close();
        await server.close();
    });

    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const { tools } = await client.listTools();

    assert.deepEqual(
        Object.fromEntries(
            tools.map(({ name, title, annotations }) => [name, { title, annotations }])
        ),
        {
            memwal_remember: {
                title: "Remember a Fact",
                annotations: { readOnlyHint: false, destructiveHint: false },
            },
            memwal_remember_bulk: {
                title: "Remember Multiple Facts",
                annotations: { readOnlyHint: false, destructiveHint: false },
            },
            memwal_remember_status: {
                title: "Check a Remember Job",
                annotations: { readOnlyHint: true, destructiveHint: false },
            },
            memwal_analyze: {
                title: "Analyze and Remember",
                annotations: { readOnlyHint: false, destructiveHint: true },
            },
            memwal_restore: {
                title: "Restore Memory Index",
                annotations: { readOnlyHint: false, destructiveHint: false },
            },
            memwal_recall: {
                title: "Recall Memories",
                annotations: { readOnlyHint: true, destructiveHint: false },
            },
            memwal_namespaces: {
                title: "List Memory Namespaces",
                annotations: { readOnlyHint: true, destructiveHint: false },
            },
            memwal_health: {
                title: "Check Walrus Memory Health",
                annotations: { readOnlyHint: true, destructiveHint: false },
            },
        }
    );
});
