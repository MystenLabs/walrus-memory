process.env.SIDECAR_AUTH_TOKEN = "input-limits-test-token";

import assert from "node:assert/strict";
import test, { after, before } from "node:test";
import { randomBytes } from "node:crypto";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import { z } from "zod";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { MemWalSession } from "../auth.js";
import { mountMcpRoutes, shutdownMcpSessions } from "../index.js";
import { MCP_MAX_REQUEST_BODY_BYTES, MCP_MAX_TOOL_INPUT_ELEMENTS } from "../limits.js";
import { createMcpServer } from "../server.js";

test("tool validation refuses excessive elements before invoking a handler", async (t) => {
    const server = createMcpServer({} as MemWalSession);
    let calls = 0;
    server.registerTool("input_probe", { inputSchema: { items: z.array(z.number()) } }, async () => {
        calls++;
        return { content: [{ type: "text", text: "accepted" }] };
    });
    const client = new Client({ name: "input-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    t.after(async () => { await client.close(); await server.close(); });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const refused = await client.callTool({
        name: "input_probe",
        arguments: { items: Array(MCP_MAX_TOOL_INPUT_ELEMENTS + 1).fill(0) },
    });
    assert.equal(refused.isError, true);
    assert.match(JSON.stringify(refused.content), /maximum.*elements/i);
    assert.equal(calls, 0);

    const accepted = await client.callTool({ name: "input_probe", arguments: { items: Array(20).fill(0) } });
    assert.notEqual(accepted.isError, true);
    assert.equal(calls, 1);
});

let httpServer: Server;
let baseUrl: string;
const headers = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    authorization: `Bearer ${randomBytes(32).toString("hex")}`,
    "x-memwal-account-id": `0x${randomBytes(32).toString("hex")}`,
    "x-memwal-internal-sidecar-token": process.env.SIDECAR_AUTH_TOKEN!,
};
const oversized = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", padding: "x".repeat(MCP_MAX_REQUEST_BODY_BYTES) });

before(async () => {
    const app = express();
    mountMcpRoutes(app, { relayerUrl: "http://127.0.0.1:1" });
    await new Promise<void>((resolve) => { httpServer = app.listen(0, "127.0.0.1", resolve); });
    baseUrl = `http://127.0.0.1:${(httpServer.address() as AddressInfo).port}`;
});

after(async () => {
    await shutdownMcpSessions();
    httpServer.closeAllConnections();
    await new Promise<void>((resolve) => httpServer.close(() => resolve()));
});

test("Streamable HTTP rejects oversized requests and remains usable", async () => {
    const refused = await fetch(`${baseUrl}/mcp`, { method: "POST", headers, body: oversized });
    assert.equal(refused.status, 413);
    await refused.text();
    const accepted = await fetch(`${baseUrl}/mcp`, {
        method: "POST", headers,
        body: JSON.stringify({
            jsonrpc: "2.0", id: 2, method: "initialize",
            params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "input-test", version: "1" } },
        }),
    });
    assert.equal(accepted.status, 200);
    await accepted.text();
});

test("legacy SSE rejects oversized requests after session authentication", async () => {
    const abort = new AbortController();
    const stream = await fetch(`${baseUrl}/mcp/sse`, { headers, signal: abort.signal });
    const reader = stream.body!.getReader();
    try {
        let text = "";
        while (!text.includes("\n\n")) {
            const chunk = await reader.read();
            assert.equal(chunk.done, false);
            text += new TextDecoder().decode(chunk.value);
        }
        const endpoint = text.split("\n").find((line) => line.startsWith("data:"))!.slice(5).trim();
        const sessionId = new URL(endpoint, baseUrl).searchParams.get("sessionId");
        assert.ok(sessionId);
        const refused = await fetch(`${baseUrl}/mcp/messages?sessionId=${sessionId}`, { method: "POST", headers, body: oversized });
        assert.equal(refused.status, 413);
        await refused.text();
    } finally {
        abort.abort();
        await reader.cancel().catch(() => {});
    }
});
