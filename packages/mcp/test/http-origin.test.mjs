import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { fetchMcp, ssePostUrl } from "../dist/http-security.js";
import { openStreamableSession } from "../dist/streamable.js";

async function listen(t, handler) {
    const server = createServer(handler);
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    t.after(async () => {
        server.closeAllConnections();
        await new Promise((resolve) => server.close(resolve));
    });
    return `http://127.0.0.1:${server.address().port}`;
}

test("SSE accepts its own origin and refuses an endpoint on another origin", () => {
    assert.equal(ssePostUrl("https://relayer.example", "/api/mcp/messages?s=1"), "https://relayer.example/api/mcp/messages?s=1");
    assert.equal(ssePostUrl("https://relayer.example", "https://relayer.example/api/mcp/messages"), "https://relayer.example/api/mcp/messages");
    for (const endpoint of ["https://other.example/messages", "http://relayer.example/messages", "https://user:pass@relayer.example/messages"]) {
        assert.throws(() => ssePostUrl("https://relayer.example", endpoint), /configured relayer origin/);
    }
});

test("authenticated SSE requests do not forward custom headers or bodies through redirects", async (t) => {
    let leaked = 0;
    const destination = await listen(t, (_req, res) => { leaked++; res.end("unexpected"); });
    const source = await listen(t, (_req, res) => { res.writeHead(307, { location: destination }); res.end(); });
    for (const method of ["GET", "POST"]) {
        await assert.rejects(fetchMcp(source, {
            method,
            headers: { authorization: "Bearer test-secret", "x-api-key": "custom-secret" },
            ...(method === "POST" ? { body: "private tool arguments" } : {}),
        }));
    }
    assert.equal(leaked, 0);
});

test("Streamable HTTP does not send its account header to a redirected origin", async (t) => {
    let leaked = 0;
    const destination = await listen(t, (_req, res) => { leaked++; res.end("unexpected"); });
    const source = await listen(t, (_req, res) => { res.writeHead(307, { location: destination }); res.end(); });
    const session = await openStreamableSession(source, {
        delegatePrivateKey: "a".repeat(64), accountId: `0x${"b".repeat(64)}`,
    }, { "x-api-key": "custom-secret" });
    try {
        const status = await session.send({
            jsonrpc: "2.0", id: 1, method: "initialize",
            params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "origin-test", version: "1" } },
        });
        assert.notEqual(status, 200);
        assert.equal(leaked, 0);
    } finally {
        session.abort();
    }
});
