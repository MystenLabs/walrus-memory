import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { MemWalSession } from "../auth.js";
import { resolveAuth } from "../auth.js";
import { createMcpServer } from "../server.js";

// memwal_health reported status + version only. Nothing said WHICH relayer
// answered, so a config pointing at the wrong network looked perfectly healthy
// right up until the memories were missing.
//
// The value it reports must be a network identity. `relayerUrl` is not one:
// it is the address the sidecar dials, and the Rust parent fills it with
// loopback whenever an operator did not override it. Only an operator-supplied
// public origin reaches `publicRelayerUrl`, and only that is printed.

const PUBLIC_ORIGIN = "https://relayer.dev.memwal.ai";
const LOOPBACK = "http://127.0.0.1:8000";

const TOKEN = "test-sidecar-token-0123456789";
const DELEGATE_KEY = "a".repeat(64);
const ACCOUNT_ID = `0x${"b".repeat(64)}`;

function mcpHeaders(): Headers {
    return new Headers({
        authorization: `Bearer ${DELEGATE_KEY}`,
        "x-memwal-account-id": ACCOUNT_ID,
        "x-memwal-internal-sidecar-token": TOKEN,
        "x-memwal-internal-oauth-scope": "memwal:read",
    });
}

/** Stubbed relayer health so the tool call stays offline. */
const HEALTH_STUB = { health: async () => ({ status: "ok", version: "1.2.3" }) };

async function callHealth(t: TestContext, session: Partial<MemWalSession>): Promise<string> {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createMcpServer({
        oauthScope: "memwal:read",
        memwal: HEALTH_STUB,
        ...session,
    } as unknown as MemWalSession);
    const client = new Client({ name: "health-test", version: "1.0.0" });
    t.after(async () => {
        await client.close();
        await server.close();
    });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const res = (await client.callTool({ name: "memwal_health", arguments: {} })) as {
        content: { type: string; text: string }[];
    };
    return res.content.map((c) => c.text).join("\n");
}

/**
 * Health text for a session built the way a real request builds one — through
 * `resolveAuth`, not hand-assembled — with only the relayer round-trip stubbed.
 */
async function callHealthThroughResolveAuth(
    t: TestContext,
    serverUrl: string,
    publicRelayerUrl?: string
): Promise<string> {
    process.env.SIDECAR_AUTH_TOKEN = TOKEN;
    const { session } = await resolveAuth(mcpHeaders(), serverUrl, publicRelayerUrl);
    return callHealth(t, {
        ...session,
        memwal: HEALTH_STUB as unknown as MemWalSession["memwal"],
    });
}

test("memwal_health names the relayer origin the deployment published", async (t) => {
    const text = await callHealthThroughResolveAuth(t, LOOPBACK, PUBLIC_ORIGIN);
    assert.ok(text.includes(PUBLIC_ORIGIN), `public origin missing from health output:\n${text}`);
    // Existing contract must survive.
    assert.ok(text.includes("status=ok"));
    assert.ok(text.includes("version=1.2.3"));
});

test("memwal_health does not report the loopback address as a network", async (t) => {
    // The default deployment: the sidecar dials loopback and no operator
    // supplied a public origin. Printing `relayer=http://127.0.0.1:8000` here
    // is the "healthy on the wrong network" failure this tool exists to catch,
    // so health must stay silent about the relayer instead.
    const text = await callHealthThroughResolveAuth(t, LOOPBACK);
    assert.ok(text.includes("status=ok"), `health broke without a public origin:\n${text}`);
    assert.ok(
        !text.includes("relayer="),
        `health named a relayer it cannot vouch for:\n${text}`
    );
    assert.ok(!text.includes(LOOPBACK), `health leaked the loopback dial address:\n${text}`);
});

test("memwal_health still answers when the session carries no relayer URL", async (t) => {
    const text = await callHealth(t, { relayerUrl: undefined, publicRelayerUrl: undefined });
    assert.ok(text.includes("status=ok"), `health broke without a relayer URL:\n${text}`);
});
