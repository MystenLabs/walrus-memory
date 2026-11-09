import assert from "node:assert/strict";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { MemWalSession } from "../auth.js";
import { createMcpServer } from "../server.js";
import { normalizeMcpNamespace } from "../tools/index.js";

test("normalizeMcpNamespace trims whitespace and preserves mixed case", () => {
    assert.equal(normalizeMcpNamespace("  MyTeam_2026  "), "MyTeam_2026");
    assert.equal(normalizeMcpNamespace("MyTeam_2026"), "MyTeam_2026");
    assert.equal(normalizeMcpNamespace("\t ProjectScope \t"), "ProjectScope");
});

test("normalizeMcpNamespace returns undefined for omitted or whitespace-only inputs", () => {
    assert.equal(normalizeMcpNamespace(undefined), undefined);
    assert.equal(normalizeMcpNamespace(""), undefined);
    assert.equal(normalizeMcpNamespace("   "), undefined);
    assert.equal(normalizeMcpNamespace("\t   \t"), undefined);
});

test("normalizeMcpNamespace rejects control characters and length over 255 bytes", () => {
    assert.throws(
        () => normalizeMcpNamespace("bad\nnamespace"),
        /Namespace cannot contain control characters/
    );
    assert.throws(
        () => normalizeMcpNamespace("bad\rnamespace"),
        /Namespace cannot contain control characters/
    );
    assert.throws(
        () => normalizeMcpNamespace("bad\0namespace"),
        /Namespace cannot contain control characters/
    );
    assert.throws(
        () => normalizeMcpNamespace("\n"),
        /Namespace cannot contain control characters/
    );
    assert.throws(
        () => normalizeMcpNamespace("\r\n"),
        /Namespace cannot contain control characters/
    );

    const longNamespace = "x".repeat(256);
    assert.throws(
        () => normalizeMcpNamespace(longNamespace),
        /Namespace cannot exceed 255 bytes/
    );

    const valid255 = "x".repeat(255);
    assert.equal(normalizeMcpNamespace(valid255), valid255);
});

interface RecordedCall {
    tool: string;
    text?: string;
    query?: string;
    namespace?: string;
    items?: Array<{ text: string; namespace?: string }>;
}

function createTestSession(recorded: RecordedCall[]): MemWalSession {
    return {
        accountId: "0x" + "1".repeat(64),
        delegateKeyHex: "2".repeat(64),
        delegatePubKeyHex: "3".repeat(64),
        oauthScope: "memwal:read memwal:write",
        memwal: {
            async rememberAsync(text: string, namespace?: string) {
                recorded.push({ tool: "memwal_remember", text, namespace });
                return { job_id: "job-1", status: "running" };
            },
            async rememberBulkAsync(items: Array<{ text: string; namespace?: string }>) {
                recorded.push({ tool: "memwal_remember_bulk", items });
                return { job_ids: ["job-1"], total: items.length, status: "running" };
            },
            async recall(query: string, limit: number, namespace?: string) {
                recorded.push({ tool: "memwal_recall", query, namespace });
                return { results: [] };
            },
            async analyze(text: string, namespace?: string) {
                recorded.push({ tool: "memwal_analyze", text, namespace });
                return { facts: ["Extracted fact"], job_ids: ["job-1"] };
            },
            async restore(namespace: string, limit: number) {
                recorded.push({ tool: "memwal_restore", namespace });
                return {
                    namespace,
                    total: 10,
                    restored: 10,
                    skipped: 0,
                    failed: 0,
                    truncated: false,
                };
            },
        },
    } as unknown as MemWalSession;
}

test("MCP write tools trim namespace and preserve mixed case on remember, remember_bulk, analyze", async (t) => {
    const recorded: RecordedCall[] = [];
    const session = createTestSession(recorded);
    const server = createMcpServer(session);

    const client = new Client({ name: "trim-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    t.after(async () => {
        await client.close();
        await server.close();
    });

    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const rememberRes = await client.callTool({
        name: "memwal_remember",
        arguments: {
            text: "Preferred indentation is 4 spaces",
            namespace: "  MyTeam_2026  ",
        },
    });
    assert.equal(rememberRes.isError, undefined);
    assert.equal(recorded[0].tool, "memwal_remember");
    assert.equal(recorded[0].namespace, "MyTeam_2026");

    const bulkRes = await client.callTool({
        name: "memwal_remember_bulk",
        arguments: {
            facts: ["Configured cluster is us-west-2"],
            namespace: "  BulkOps_Namespace  ",
        },
    });
    assert.equal(bulkRes.isError, undefined);
    assert.equal(recorded[1].tool, "memwal_remember_bulk");
    assert.equal(recorded[1].items?.[0].namespace, "BulkOps_Namespace");

    const analyzeRes = await client.callTool({
        name: "memwal_analyze",
        arguments: {
            text: "We decided to keep postgres in us-west-2 for lower latency.",
            namespace: "  AnalyzeZone_V2  ",
        },
    });
    assert.equal(analyzeRes.isError, undefined);
    assert.equal(recorded[2].tool, "memwal_analyze");
    assert.equal(recorded[2].namespace, "AnalyzeZone_V2");
});

test("MCP read tools trim namespace and preserve mixed case on recall and restore", async (t) => {
    const recorded: RecordedCall[] = [];
    const session = createTestSession(recorded);
    const server = createMcpServer(session);

    const client = new Client({ name: "trim-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    t.after(async () => {
        await client.close();
        await server.close();
    });

    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const recallRes = await client.callTool({
        name: "memwal_recall",
        arguments: {
            query: "database latency decision",
            namespace: "  RecallScope_2026  ",
        },
    });
    assert.equal(recallRes.isError, undefined);
    assert.equal(recorded[0].tool, "memwal_recall");
    assert.equal(recorded[0].namespace, "RecallScope_2026");

    const restoreRes = await client.callTool({
        name: "memwal_restore",
        arguments: {
            namespace: "  RestoreZone_Alpha  ",
            limit: 10,
        },
    });
    assert.equal(restoreRes.isError, undefined);
    assert.equal(recorded[1].tool, "memwal_restore");
    assert.equal(recorded[1].namespace, "RestoreZone_Alpha");
});

test("memwal_restore rejects whitespace-only namespace as empty", async (t) => {
    const recorded: RecordedCall[] = [];
    const session = createTestSession(recorded);
    const server = createMcpServer(session);

    const client = new Client({ name: "trim-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    t.after(async () => {
        await client.close();
        await server.close();
    });

    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const restoreRes = await client.callTool({
        name: "memwal_restore",
        arguments: {
            namespace: "   ",
            limit: 10,
        },
    });
    assert.equal(restoreRes.isError, true);
    assert.match(JSON.stringify(restoreRes.content), /Namespace cannot be empty/);
    assert.equal(recorded.length, 0);
});

test("MCP tools reject control characters in namespace", async (t) => {
    const recorded: RecordedCall[] = [];
    const session = createTestSession(recorded);
    const server = createMcpServer(session);

    const client = new Client({ name: "trim-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    t.after(async () => {
        await client.close();
        await server.close();
    });

    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const res = await client.callTool({
        name: "memwal_remember",
        arguments: {
            text: "Valid text",
            namespace: "bad\nnamespace",
        },
    });
    assert.equal(res.isError, true);
    assert.match(JSON.stringify(res.content), /Namespace cannot contain control characters/);
    assert.equal(recorded.length, 0);
});
