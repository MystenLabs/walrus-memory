/**
 * MCP integration test — exercises the actual mounted Express routes via real
 * HTTP. Verifies the three blocker-fixes end-to-end:
 *
 *   1. Per-IP burst rate-limit returns 429 BEFORE a long-lived transport is
 *      allocated.
 *   2. The streamable HTTP `mcp-session-id` is bound to the bearer that
 *      opened it — reusing the id under a different bearer returns 403.
 *   3. The relayer's `x-forwarded-for` is honored — separate IPs get
 *      independent rate-limit buckets.
 *
 * Runs the express app on an ephemeral loopback port. No external services
 * are touched — `MemWal.create()` is pure, `createMcpServer()` is in-memory,
 * and tools are never invoked because we only drive the initialize handshake.
 *
 * IMPORTANT: env vars MUST be set BEFORE importing `mountMcpRoutes` because
 * the rate limiter is constructed at module-load time.
 */
process.env.SIDECAR_AUTH_TOKEN ??= "integration-test-sidecar-token";
process.env.MCP_MAX_TOTAL_SESSIONS = "100";
process.env.MCP_MAX_SESSIONS_PER_IP = "100";
// Tight burst cap so the test can trip it in 3 calls.
process.env.MCP_MAX_NEW_SESSIONS_PER_IP_PER_MIN = "2";

import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import express from "express";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { mountMcpRoutes } from "../index.js";

// ---- helpers --------------------------------------------------------------

function hex(bytes: number): string {
    return randomBytes(bytes).toString("hex");
}

/** Synthesize a valid-shape delegate key + accountId pair. */
function fakeCreds(): { bearer: string; accountId: string } {
    return {
        bearer: hex(32), // 64 hex chars
        accountId: "0x" + hex(32), // 0x + 64 hex
    };
}

let server: Server;
let baseUrl: string;
const apiLog: Array<{ path: string; status: number }> = [];

/** Wait for the bridge's own upstream request to land on the /api mount. */
async function waitForApi(
    pred: (entry: { path: string; status: number }) => boolean,
    timeoutMs = 5000,
): Promise<{ path: string; status: number }> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
        const hit = apiLog.find(pred);
        if (hit) return hit;
        if (Date.now() > deadline) {
            throw new Error(`no matching /api request within ${timeoutMs}ms; saw ${JSON.stringify(apiLog)}`);
        }
        await new Promise((r) => setTimeout(r, 25));
    }
}

before(async () => {
    const app = express();
    app.get("/version", (_req, res) => {
        res.json({
            apiVersion: "1.0.0",
            relayerVersion: "1.0.0",
            minSupportedSdk: { mcp: "0.0.1" },
        });
    });
    mountMcpRoutes(app, { relayerUrl: "http://localhost:1" });
    // The Rust relayer exposes /api/mcp/* and proxies it to these same MCP
    // routes. Mount the real handlers under /api as well so the official
    // stdio bridge can exercise its production URLs without a proxy stub.
    const publicApi = express.Router();
    // Record what the bridge actually got back. A tools/list assertion cannot
    // tell upstream from the bridge's local auth-required fallback, because
    // that fallback advertises the same tool names — so the only honest signal
    // that the upstream connection worked is the response status here.
    publicApi.use((req, res, next) => {
        // Capture the status as headers are written, not on "finish": an SSE
        // response stays open, so "finish" never fires for /mcp/sse.
        const writeHead = res.writeHead.bind(res);
        res.writeHead = ((...args: Parameters<typeof writeHead>) => {
            apiLog.push({ path: req.path, status: args[0] as number });
            return writeHead(...args);
        }) as typeof res.writeHead;
        next();
    });
    // Stand in for the Rust relayer's `apply_internal_headers`. In production
    // /api/mcp/* is served by the proxy, which states the sidecar token and the
    // caller's granted scope on every forwarded request. Without this the
    // official bridge cannot authenticate against the sidecar at all, and the
    // test would silently fall back to the bridge's local tool list.
    publicApi.use((req, _res, next) => {
        req.headers["x-memwal-internal-sidecar-token"] = INTERNAL_TOKEN;
        req.headers["x-memwal-internal-oauth-scope"] = "memwal:read memwal:write";
        next();
    });
    mountMcpRoutes(publicApi, { relayerUrl: "http://localhost:1" });
    app.use("/api", publicApi);
    await new Promise<void>((resolve) => {
        server = app.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = server.address() as AddressInfo;
    baseUrl = `http://127.0.0.1:${addr.port}`;
});

after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
});

function initializeBody(id: number) {
    return JSON.stringify({
        jsonrpc: "2.0",
        id,
        method: "initialize",
        params: {
            protocolVersion: "2025-06-18",
            capabilities: {},
            clientInfo: { name: "memwal-test", version: "0.0.1" },
        },
    });
}

// The relayer proves it is the relayer with the sidecar shared secret; every
// request that expects to get past `resolveAuth` has to carry it.
const INTERNAL_TOKEN_HEADER = "x-memwal-internal-sidecar-token";
const INTERNAL_TOKEN = process.env.SIDECAR_AUTH_TOKEN!;

function mcpHeaders(opts: {
    bearer: string;
    accountId: string;
    xff: string;
    sessionId?: string;
    scope?: string;
}): Record<string, string> {
    const h: Record<string, string> = {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${opts.bearer}`,
        "x-memwal-account-id": opts.accountId,
        "x-forwarded-for": opts.xff,
        [INTERNAL_TOKEN_HEADER]: INTERNAL_TOKEN,
    };
    if (opts.sessionId) h["mcp-session-id"] = opts.sessionId;
    if (opts.scope !== undefined) h["x-memwal-internal-oauth-scope"] = opts.scope;
    return h;
}

async function postInit(opts: {
    bearer: string;
    accountId: string;
    xff: string;
    sessionId?: string;
    scope?: string;
    id?: number;
}): Promise<{ status: number; sessionId: string | null; bodyText: string }> {
    const res = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: mcpHeaders(opts),
        body: initializeBody(opts.id ?? 1),
    });
    return {
        status: res.status,
        sessionId: res.headers.get("mcp-session-id"),
        bodyText: await res.text(),
    };
}

async function openSse(opts: {
    bearer: string;
    accountId: string;
    xff: string;
}): Promise<{
    reader: ReadableStreamDefaultReader<Uint8Array>;
    sessionId: string;
}> {
    const response = await fetch(`${baseUrl}/mcp/sse`, {
        headers: {
            accept: "text/event-stream",
            authorization: `Bearer ${opts.bearer}`,
            "x-memwal-account-id": opts.accountId,
            "x-forwarded-for": opts.xff,
            [INTERNAL_TOKEN_HEADER]: INTERNAL_TOKEN,
        },
    });
    assert.equal(response.status, 200);
    assert(response.body);
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let received = "";
    while (!received.includes("sessionId=")) {
        const chunk = await reader.read();
        assert.equal(chunk.done, false, "SSE stream closed before endpoint event");
        received += decoder.decode(chunk.value, { stream: true });
    }
    const match = received.match(/sessionId=([0-9a-f-]+)/i);
    assert(match, `missing session id in SSE endpoint event: ${received}`);
    return { reader, sessionId: match[1] };
}

// ---- tests ----------------------------------------------------------------

test("POST /mcp initialize creates a session and returns mcp-session-id", async () => {
    const creds = fakeCreds();
    const r = await postInit({ ...creds, xff: "192.0.2.10" });

    assert.equal(r.status, 200, `expected 200, got ${r.status}: ${r.bodyText}`);
    assert.ok(r.sessionId, "mcp-session-id header must be set on initialize response");
});

test("burst cap denies third initialize from same IP within window", async () => {
    // Use a fresh IP to isolate from other tests.
    const xff = "192.0.2.20";

    const a = await postInit({ ...fakeCreds(), xff });
    assert.equal(a.status, 200, `1st should succeed, got ${a.status}`);

    const b = await postInit({ ...fakeCreds(), xff });
    assert.equal(b.status, 200, `2nd should succeed, got ${b.status}`);

    // Third hits the burst cap (MCP_MAX_NEW_SESSIONS_PER_IP_PER_MIN=2).
    const c = await postInit({ ...fakeCreds(), xff });
    assert.equal(c.status, 429, `3rd should be rate-limited, got ${c.status}`);
    const json = JSON.parse(c.bodyText);
    assert.equal(json.error.code, -32000);
    assert.match(json.error.message, /ip_burst_cap/);
});

test("separate XFF IPs get independent rate-limit buckets", async () => {
    // Saturate IP A's burst.
    const aXff = "192.0.2.30";
    await postInit({ ...fakeCreds(), xff: aXff });
    await postInit({ ...fakeCreds(), xff: aXff });
    const aDenied = await postInit({ ...fakeCreds(), xff: aXff });
    assert.equal(aDenied.status, 429);

    // IP B is fresh — must succeed.
    const bOk = await postInit({ ...fakeCreds(), xff: "192.0.2.31" });
    assert.equal(bOk.status, 200, `IP B should be unaffected, got ${bOk.status}`);
});

test("reusing mcp-session-id under a different bearer returns 403", async () => {
    // Fresh IP so we don't collide with earlier burst counters.
    const xff = "192.0.2.40";

    // Open a session as caller A.
    const credsA = fakeCreds();
    const opened = await postInit({ ...credsA, xff });
    assert.equal(opened.status, 200);
    const sid = opened.sessionId;
    assert.ok(sid);

    // Caller B (different bearer + accountId) tries to drive A's session.
    const credsB = fakeCreds();
    const stolen = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: mcpHeaders({ ...credsB, xff, sessionId: sid! }),
        body: JSON.stringify({ jsonrpc: "2.0", id: 99, method: "ping" }),
    });

    assert.equal(stolen.status, 403, `expected 403, got ${stolen.status}`);
    const json = await stolen.json();
    assert.equal((json as any).error.code, -32603);
    assert.match((json as any).error.message, /does not match authenticated caller/);
});

test("reusing mcp-session-id under a narrower scope returns 403", async () => {
    // The tool set is bound at session-open time, so a session opened with
    // write scope keeps its write tools registered. If the session key ignores
    // scope, a later read-only request routes into that write-capable
    // transport and the fail-closed guarantee stops holding after init.
    const xff = "192.0.2.80";
    const creds = fakeCreds();

    const opened = await postInit({ ...creds, xff, scope: "memwal:read memwal:write" });
    assert.equal(opened.status, 200);
    const sid = opened.sessionId;
    assert.ok(sid);

    const narrowed = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: mcpHeaders({ ...creds, xff, sessionId: sid!, scope: "memwal:read" }),
        body: JSON.stringify({ jsonrpc: "2.0", id: 98, method: "ping" }),
    });

    assert.equal(narrowed.status, 403, `expected 403, got ${narrowed.status}`);
});

test("reusing mcp-session-id with the scope header dropped returns 403", async () => {
    const xff = "192.0.2.81";
    const creds = fakeCreds();

    const opened = await postInit({ ...creds, xff, scope: "memwal:read memwal:write" });
    assert.equal(opened.status, 200);
    const sid = opened.sessionId;
    assert.ok(sid);

    const dropped = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: mcpHeaders({ ...creds, xff, sessionId: sid! }),
        body: JSON.stringify({ jsonrpc: "2.0", id: 97, method: "ping" }),
    });

    assert.equal(dropped.status, 403, `expected 403, got ${dropped.status}`);
});

test("reusing mcp-session-id under SAME bearer is accepted (sanity check)", async () => {
    const xff = "192.0.2.50";
    const creds = fakeCreds();

    const opened = await postInit({ ...creds, xff });
    assert.equal(opened.status, 200);
    const sid = opened.sessionId;
    assert.ok(sid);

    // Same caller, same session-id — must NOT be a 403. (The SDK may return
    // 200 or 202 depending on the request; the only thing we're proving is
    // that the auth-binding check did NOT reject the request.)
    const reuse = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: mcpHeaders({ ...creds, xff, sessionId: sid! }),
        body: JSON.stringify({ jsonrpc: "2.0", id: 99, method: "ping" }),
    });

    assert.notEqual(reuse.status, 403, `same-caller reuse must not 403, got ${reuse.status}`);
});

test("malformed bearer returns 401, not 429 — auth still runs after rate-limit on streamable", async () => {
    // streamable's order is: auth → method check → rate-limit. Wrong bearer
    // shape must surface as 401 with www-authenticate, not as a rate-limit
    // refusal. (Use a fresh IP.)
    const res = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: {
            "content-type": "application/json",
            accept: "application/json, text/event-stream",
            authorization: "Bearer not-a-hex-key",
            "x-memwal-account-id": "0x" + "a".repeat(64),
            "x-forwarded-for": "192.0.2.60",
            // Origin is verified; the malformed bearer is what must be rejected.
            [INTERNAL_TOKEN_HEADER]: INTERNAL_TOKEN,
        },
        body: initializeBody(1),
    });

    assert.equal(res.status, 401);
    assert.ok(res.headers.get("www-authenticate"));
});

test("SSE message POST is bound to the principal that opened the session", async () => {
    const owner = fakeCreds();
    const attacker = fakeCreds();
    const opened = await openSse({ ...owner, xff: "192.0.2.70" });
    const url = `${baseUrl}/mcp/messages?sessionId=${opened.sessionId}`;
    const body = JSON.stringify({ jsonrpc: "2.0", id: 7, method: "ping" });

    try {
        const noAuth = await fetch(url, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                // Origin is verified; the absent bearer is what must be rejected.
                [INTERNAL_TOKEN_HEADER]: INTERNAL_TOKEN,
            },
            body,
        });
        assert.equal(noAuth.status, 401);
        assert.ok(noAuth.headers.get("www-authenticate"));

        const crossPrincipal = await fetch(url, {
            method: "POST",
            headers: mcpHeaders({ ...attacker, xff: "192.0.2.71" }),
            body,
        });
        assert.equal(crossPrincipal.status, 403);

        const samePrincipal = await fetch(url, {
            method: "POST",
            headers: mcpHeaders({ ...owner, xff: "192.0.2.70" }),
            body,
        });
        assert.equal(samePrincipal.status, 202);
    } finally {
        await opened.reader.cancel();
    }
});

test("unknown SSE session id remains 404", async () => {
    const creds = fakeCreds();
    const response = await fetch(
        `${baseUrl}/mcp/messages?sessionId=00000000-0000-4000-8000-000000000000`,
        {
            method: "POST",
            headers: mcpHeaders({ ...creds, xff: "192.0.2.72" }),
            body: JSON.stringify({ jsonrpc: "2.0", id: 8, method: "ping" }),
        }
    );
    assert.equal(response.status, 404);
});

test("official stdio bridge authenticates SSE message POSTs", async (t) => {
    const creds = fakeCreds();
    const home = mkdtempSync(join(tmpdir(), "memwal-mcp-auth-binding-"));
    const credentialsPath = join(home, ".memwal", "credentials.json");
    mkdirSync(dirname(credentialsPath), { recursive: true });
    writeFileSync(
        credentialsPath,
        JSON.stringify({
            accountId: creds.accountId,
            createdAt: new Date(0).toISOString(),
            delegateAddress: `0x${"1".repeat(64)}`,
            delegatePrivateKey: creds.bearer,
            delegatePublicKeyHex: "2".repeat(64),
            packageId: `0x${"3".repeat(64)}`,
            relayerUrl: baseUrl,
            version: 1,
            walletAddress: `0x${"4".repeat(64)}`,
        }),
        { mode: 0o600 },
    );

    const testDir = dirname(fileURLToPath(import.meta.url));
    const tsxBin = resolve(testDir, "../../node_modules/.bin/tsx");
    const bridgeEntry = resolve(testDir, "../../../../../packages/mcp/src/bin/memwal-mcp.ts");
    const child = spawn(tsxBin, [bridgeEntry, "--relayer", baseUrl, "--web-url", baseUrl], {
        env: { ...process.env, HOME: home, USERPROFILE: home },
        stdio: ["pipe", "pipe", "pipe"],
    });

    const messages: any[] = [];
    const listeners = new Set<(message: any) => void>();
    let stdoutBuffer = "";
    let stderrBuffer = "";
    child.stdout.on("data", (chunk) => {
        stdoutBuffer += chunk.toString();
        let newline: number;
        while ((newline = stdoutBuffer.indexOf("\n")) >= 0) {
            const line = stdoutBuffer.slice(0, newline);
            stdoutBuffer = stdoutBuffer.slice(newline + 1);
            if (!line.trim()) continue;
            try {
                const message = JSON.parse(line);
                messages.push(message);
                for (const listener of listeners) listener(message);
            } catch {
                // Notes and diagnostics belong on stderr, but ignore any
                // non-JSON stdout so the assertion below remains focused.
            }
        }
    });
    child.stderr.on("data", (chunk) => {
        stderrBuffer += chunk.toString();
    });

    const waitFor = (predicate: (message: any) => boolean, timeoutMs = 10_000): Promise<any> => {
        const existing = messages.find(predicate);
        if (existing) return Promise.resolve(existing);
        return new Promise((resolve, reject) => {
            const listener = (message: any) => {
                if (!predicate(message)) return;
                clearTimeout(timeout);
                listeners.delete(listener);
                resolve(message);
            };
            const timeout = setTimeout(() => {
                listeners.delete(listener);
                reject(new Error(`timed out waiting for bridge response\n${stderrBuffer}`));
            }, timeoutMs);
            listeners.add(listener);
        });
    };
    const send = (message: unknown) => {
        child.stdin.write(`${JSON.stringify(message)}\n`);
    };

    t.after(() => {
        child.kill("SIGKILL");
        rmSync(home, { recursive: true, force: true });
    });

    send({
        jsonrpc: "2.0",
        id: 901,
        method: "initialize",
        params: {
            capabilities: {},
            clientInfo: { name: "bridge-auth-test", version: "1.0.0" },
            protocolVersion: "2025-06-18",
        },
    });
    const initialized = await waitFor((message) => message.id === 901);
    assert(initialized.result, JSON.stringify(initialized));

    send({ jsonrpc: "2.0", method: "notifications/initialized" });

    // Wait for the upstream SSE BEFORE asking for tools. The bridge answers
    // tools/list from its coldstart path while the connection is still in
    // flight, and its local fallback advertises the same tool names as the
    // relayer — so a list requested too early cannot distinguish the two.
    const sse = await waitForApi((entry) => entry.path.includes("/mcp/sse"));
    assert.equal(sse.status, 200, `upstream SSE was rejected: ${JSON.stringify(apiLog)}`);

    send({ jsonrpc: "2.0", id: 902, method: "tools/list", params: {} });
    const tools = await waitFor((message) => message.id === 902);
    assert(Array.isArray(tools.result?.tools), JSON.stringify(tools));

    // Require the relayer-registered tools. These appear only when the proxy
    // stated a scope wide enough for `registerTools` to register them, so this
    // fails if the simulated proxy stops sending either internal header.
    const names = new Set(tools.result.tools.map((tool: { name?: string }) => tool.name));
    assert(
        ["memwal_recall", "memwal_health", "memwal_remember"].every((n) => names.has(n)),
        `bridge should receive the authenticated upstream tools/list response, got: ${[...names].join(", ")}`,
    );

    child.stdin.end();
});

test("GET /server-card and /mcp/server-card return 200 with server card and 304 on matching etag", async () => {
    for (const path of ["/server-card", "/mcp/server-card", "/.well-known/mcp/server-card.json"]) {
        const res = await fetch(`${baseUrl}${path}`);
        assert.equal(res.status, 200);
        assert.equal(
            res.headers.get("content-type"),
            "application/mcp-server-card+json; charset=utf-8"
        );
        assert.equal(res.headers.get("cache-control"), "public, max-age=300");
        const etag = res.headers.get("etag");
        assert(etag, "etag must be present");

        const data = await res.json() as Record<string, unknown>;
        assert.equal(data.name, "memwal");
        assert.equal(data.schemaVersion, "1.0");
        assert.equal(data.title, "Walrus Memory MCP Server");
        assert.equal(
            data.description,
            "Decentralized, SEAL-encrypted long-term memory for AI agents on Walrus and Sui."
        );
        assert.equal((data.endpoints as Record<string, string>).streamableHttp, "/api/mcp");
        assert.equal((data.endpoints as Record<string, string>).sse, "/api/mcp/sse");
        assert.equal((data.authentication as Record<string, unknown>).required, true);

        const tools = data.tools as Array<{ name: string; description: string }>;
        assert.equal(tools.length, 8);
        const expectedTools = [
            "memwal_remember",
            "memwal_remember_bulk",
            "memwal_recall",
            "memwal_analyze",
            "memwal_ask",
            "memwal_forget",
            "memwal_stats",
            "memwal_restore",
        ];
        for (let i = 0; i < expectedTools.length; i++) {
            assert.equal(tools[i].name, expectedTools[i]);
            assert(tools[i].description.length > 0);
        }

        const cachedRes = await fetch(`${baseUrl}${path}`, {
            headers: { "if-none-match": etag },
        });
        assert.equal(cachedRes.status, 304);
        assert.equal(cachedRes.headers.get("etag"), etag);
        assert.equal(cachedRes.headers.get("cache-control"), "public, max-age=300");
        const bodyText = await cachedRes.text();
        assert.equal(bodyText, "");
    }
});
