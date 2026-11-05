import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { MemWalSession } from "../auth.js";
import { createMcpServer } from "../server.js";

const WRITE_TOOLS = [
    "memwal_remember",
    "memwal_remember_bulk",
    "memwal_remember_status",
    "memwal_analyze",
    "memwal_restore",
];
const READ_TOOLS = ["memwal_recall", "memwal_namespaces", "memwal_health"];

async function toolNamesFor(oauthScope: string | undefined, t: TestContext): Promise<string[]> {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createMcpServer({ oauthScope } as MemWalSession);
    const client = new Client({ name: "scope-test", version: "1.0.0" });

    t.after(async () => {
        await client.close();
        await server.close();
    });

    await server.connect(serverTransport);
    await client.connect(clientTransport);

    // With zero tools registered the SDK never declares the `tools` capability,
    // so `tools/list` is an unknown method rather than an empty list. From the
    // client's side both mean the same thing: no tools are available.
    try {
        const { tools } = await client.listTools();
        return tools.map((tool) => tool.name).sort();
    } catch (err) {
        if (err instanceof Error && err.message.includes("Method not found")) return [];
        throw err;
    }
}

test("registerTools grants nothing when the relayer sent no scope", async (t) => {
    assert.deepEqual(await toolNamesFor(undefined, t), []);
});

test("registerTools grants nothing when the scope is empty or whitespace", async (t) => {
    assert.deepEqual(await toolNamesFor("   ", t), []);
});

test("registerTools grants only read tools for memwal:read", async (t) => {
    assert.deepEqual(await toolNamesFor("memwal:read", t), [...READ_TOOLS].sort());
});

test("registerTools grants every tool for the full legacy scope", async (t) => {
    assert.deepEqual(
        await toolNamesFor("memwal:read memwal:write", t),
        [...READ_TOOLS, ...WRITE_TOOLS].sort()
    );
});
