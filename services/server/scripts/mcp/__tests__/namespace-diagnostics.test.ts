import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { MemWalSession } from "../auth.js";
import { createMcpServer } from "../server.js";
import {
    editDistance,
    formatNamespacesResult,
    formatNamespaceSuggestionHint,
    isCloseNamespaceMatch,
    type NamespaceEntry,
} from "../tools/namespaces.js";
import { emptyRecallText } from "../tools/recall.js";

async function openTestClient(
    t: TestContext,
    memwalStub: Record<string, unknown>,
    sessionOverrides: Partial<MemWalSession> = {},
): Promise<Client> {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createMcpServer({
        oauthScope: "memwal:read memwal:write",
        memwal: memwalStub,
        ...sessionOverrides,
    } as unknown as MemWalSession);
    const client = new Client({ name: "namespace-diagnostics-test", version: "1.0.0" });
    t.after(async () => {
        await client.close();
        await server.close();
    });
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    return client;
}

function textFromResult(res: unknown): string {
    const content = (res as { content?: Array<{ type: string; text: string }> }).content ?? [];
    return content.map((c) => c.text).join("\n");
}

test("editDistance and isCloseNamespaceMatch detect typos and case/prefix matches", () => {
    assert.equal(editDistance("pcl301", "pcl302"), 1);
    assert.equal(editDistance("study-note", "study-notes"), 1);
    assert.equal(isCloseNamespaceMatch("pcl301", "pcl302"), true);
    assert.equal(isCloseNamespaceMatch("pcl3o2", "pcl302"), true);
    assert.equal(isCloseNamespaceMatch("study", "study-notes"), true);
    assert.equal(isCloseNamespaceMatch("pcl301", "completely-different-bucket"), false);
});

test("formatNamespaceSuggestionHint prioritizes close edit-distance matches", () => {
    const namespaces: NamespaceEntry[] = [
        { name: "work-projects", memory_count: 50 },
        { name: "study-notes", memory_count: 12 },
        { name: "default", memory_count: 3 },
    ];
    const hint = formatNamespaceSuggestionHint("study-note", namespaces);
    assert.match(hint, /Did you mean namespace "study-notes" \(12 memories\)\?/);
    assert.match(
        hint,
        /Existing namespaces: "study-notes" \(12\), "work-projects" \(50\), "default" \(3\)\./,
    );
});

test("emptyRecallText distinguishes empty namespace from populated namespace with 0 semantic hits", () => {
    const namespaces: NamespaceEntry[] = [
        { name: "pcl302", memory_count: 15 },
    ];

    const emptyNs = emptyRecallText(0, 0, {
        activeNamespace: "pcl301",
        namespaces,
    });
    assert.match(
        emptyNs,
        /No matching memories found \(namespace "pcl301" currently holds 0 memories\)\./,
    );
    assert.match(emptyNs, /Did you mean namespace "pcl302" \(15 memories\)\?/);

    const populatedNs = emptyRecallText(0, 0, {
        activeNamespace: "pcl302",
        namespaces,
    });
    assert.equal(
        populatedNs,
        'No matching memories found in namespace "pcl302" (0 matches among 15 memories).',
    );
});

test("memwal_recall on a misspelled namespace suggests close existing namespaces from listNamespaces()", async (t) => {
    const client = await openTestClient(
        t,
        {
            recall: async () => ({ results: [], total: 0 }),
            listNamespaces: async () => ({
                namespaces: [
                    {
                        id: "ns-1",
                        name: "pcl302",
                        memory_count: 15,
                        storage_used: 3200,
                        updated_at: "2026-08-20T10:00:00Z",
                    },
                    {
                        id: "ns-2",
                        name: "default",
                        memory_count: 4,
                        storage_used: 800,
                        updated_at: "2026-08-19T10:00:00Z",
                    },
                ],
                next_cursor: null,
                has_more: false,
                snapshot_version: 1,
            }),
        },
        { namespace: "default" },
    );

    const res = await client.callTool({
        name: "memwal_recall",
        arguments: { query: "pharmacology lecture notes", namespace: "pcl301" },
    });
    const text = textFromResult(res);

    assert.match(text, /namespace "pcl301" currently holds 0 memories/);
    assert.match(text, /Did you mean namespace "pcl302" \(15 memories\)\?/);
    assert.match(text, /Existing namespaces: "pcl302" \(15\), "default" \(4\)\./);
});

test("memwal_recall falls back gracefully when listNamespaces is not stubbed or throws", async (t) => {
    const client = await openTestClient(t, {
        recall: async () => ({ results: [], total: 0 }),
    });

    const res = await client.callTool({
        name: "memwal_recall",
        arguments: { query: "anything" },
    });
    assert.equal(textFromResult(res), "No matching memories found.");
});

test("memwal_restore on a misspelled namespace reports 0 blobs and suggests close existing namespaces", async (t) => {
    const client = await openTestClient(t, {
        restore: async (namespace: string) => ({
            namespace,
            total: 0,
            restored: 0,
            skipped: 0,
            failed: 0,
            truncated: false,
        }),
        listNamespaces: async () => ({
            namespaces: [
                {
                    id: "ns-1",
                    name: "study-notes",
                    memory_count: 12,
                    storage_used: 2400,
                    updated_at: "2026-08-20T10:00:00Z",
                },
            ],
            next_cursor: null,
            has_more: false,
            snapshot_version: 1,
        }),
    });

    const res = await client.callTool({
        name: "memwal_restore",
        arguments: { namespace: "study-note", limit: 10 },
    });
    const text = textFromResult(res);

    assert.match(text, /Namespace "study-note" holds 0 on-chain blobs\./);
    assert.match(text, /Did you mean namespace "study-notes" \(12 memories\)\?/);
    assert.match(text, /Existing namespaces: "study-notes" \(12\)\./);
});

test("memwal_namespaces tool lists namespaces with memory counts and storage used", async (t) => {
    let receivedArgs: { limit?: number; cursor?: string } | undefined;
    const client = await openTestClient(t, {
        listNamespaces: async (opts: { limit?: number; cursor?: string }) => {
            receivedArgs = opts;
            return {
                namespaces: [
                    {
                        id: "ns-1",
                        name: "pcl302",
                        memory_count: 15,
                        storage_used: 4096,
                        updated_at: "2026-08-20T10:00:00Z",
                    },
                    {
                        id: "ns-2",
                        name: "default",
                        memory_count: 1,
                        storage_used: 256,
                        updated_at: "2026-08-18T09:30:00Z",
                    },
                ],
                next_cursor: "cursor-2",
                has_more: true,
                snapshot_version: 3,
            };
        },
    });

    const res = await client.callTool({
        name: "memwal_namespaces",
        arguments: { limit: 25 },
    });
    const text = textFromResult(res);

    assert.deepEqual(receivedArgs, { limit: 25, cursor: undefined });
    assert.match(text, /^Namespaces \(2\+\):/);
    assert.match(text, /- "pcl302": 15 memories, storage_used=4096B, updated=2026-08-20/);
    assert.match(text, /- "default": 1 memory, storage_used=256B, updated=2026-08-18/);
    assert.match(text, /next_cursor="cursor-2"/);
});

test("formatNamespacesResult reports when an account has no populated namespaces", () => {
    assert.equal(
        formatNamespacesResult({ namespaces: [], has_more: false, next_cursor: null }),
        "No namespaces with stored memories found for this account.",
    );
});
