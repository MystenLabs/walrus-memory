/**
 * Idempotency keys for `remember`, derived from content rather than random.
 *
 * Poll cadence is deliberately NOT tested here — WALM-623 (#902) owns the
 * backoff, including the immediate first attempt, and pins it in
 * test/polling-delay.test.mjs. Asserting it from two places would leave one
 * copy silently wrong the next time the cap moves.
 */
import assert from "node:assert/strict";
import test from "node:test";

import { MemWal } from "../dist/memwal.js";

const originalFetch = globalThis.fetch;

test.afterEach(() => {
    globalThis.fetch = originalFetch;
});

/** Stub relayer. `onStatus(pollIndex)` decides what each status poll returns. */
function stubRelayer({ onStatus, posted = [] }) {
    let polls = 0;
    globalThis.fetch = async (url, init = {}) => {
        const path = new URL(url).pathname;
        if (path === "/version") {
            return Response.json({
                apiVersion: "1.0.0",
                relayerVersion: "1.0.0",
                minSupportedSdk: { typescript: "0.0.4" },
            });
        }
        if (path === "/api/config") {
            return Response.json({ packageId: "0x1", network: "testnet" });
        }
        if (path === "/api/remember" && init.method === "POST") {
            posted.push({ body: JSON.parse(init.body), at: Date.now() });
            return Response.json({ job_id: "job-1", status: "pending" }, { status: 202 });
        }
        if (path === "/api/remember/job-1") {
            return Response.json(onStatus(polls++));
        }
        throw new Error(`unexpected request ${path}`);
    };
    return { posted, pollCount: () => polls };
}

function newClient() {
    const client = MemWal.create({
        key: new Uint8Array(32).fill(1),
        accountId: "0x1",
        serverUrl: "https://relayer.example",
    });
    client.buildSealSession = async () => "test-session";
    return client;
}

const DONE = {
    job_id: "job-1",
    status: "done",
    blob_id: "blob-1",
    owner: "0x1",
    namespace: "default",
};

test("the same fact reuses one idempotency key across client instances", async () => {
    const posted = [];
    stubRelayer({ onStatus: () => DONE, posted });

    // Two instances = what the MCP sidecar builds when the stdio bridge
    // reconnects a dropped SSE stream. A per-instance random key made the
    // replay look like a new write, so the relayer minted a second paid
    // Walrus blob for a write already in flight.
    await newClient().rememberAndWait("a durable fact");
    await newClient().rememberAndWait("a durable fact");

    assert.equal(posted.length, 2);
    assert.equal(posted[0].body.idempotency_key, posted[1].body.idempotency_key);
});

test("different text and different namespaces get different keys", async () => {
    const posted = [];
    stubRelayer({ onStatus: () => DONE, posted });

    const client = newClient();
    await client.rememberAndWait("fact one");
    await client.rememberAndWait("fact two");
    await client.rememberAndWait("fact one", "other-namespace");

    const keys = posted.map((p) => p.body.idempotency_key);
    assert.equal(new Set(keys).size, 3, "distinct writes must not collapse onto one job");
});

test("an explicit idempotency key still wins", async () => {
    const posted = [];
    stubRelayer({ onStatus: () => DONE, posted });

    await newClient().rememberAndWait("a fact", undefined, { idempotencyKey: "caller-owned" });

    assert.equal(posted[0].body.idempotency_key, "caller-owned");
    assert.equal("dedupe" in posted[0].body, false);
});

test("dedupe: true sends dedupe flag and derives a bucket-less content-hash key across 30-minute windows (#769)", async () => {
    const posted = [];
    stubRelayer({ onStatus: () => DONE, posted });

    const originalNow = Date.now;
    let fakeNow = 1_700_000_000_000;
    Date.now = () => fakeNow;
    try {
        await newClient().remember("User is allergic to peanuts", "health", { dedupe: true });
        // Advance 31 minutes past the 30-minute idempotency bucket boundary.
        fakeNow += 31 * 60 * 1000;
        await newClient().rememberAndWait("User is allergic to peanuts", "health", { dedupe: true });
        // Shorthand options in the namespace slot also works.
        fakeNow += 31 * 60 * 1000;
        await newClient().remember("User is allergic to peanuts", { dedupe: true });
    } finally {
        Date.now = originalNow;
    }

    assert.equal(posted.length, 3);
    assert.equal(posted[0].body.dedupe, true);
    assert.equal(posted[1].body.dedupe, true);
    assert.equal(posted[2].body.dedupe, true);
    assert.match(posted[0].body.idempotency_key, /^dedupe:[0-9a-f]{64}$/);
    assert.equal(
        posted[0].body.idempotency_key,
        posted[1].body.idempotency_key,
        "dedupe: true must reuse the same content-hash key across 30-minute bucket boundaries",
    );
    assert.notEqual(
        posted[0].body.idempotency_key,
        posted[2].body.idempotency_key,
        "different namespaces must produce distinct content-hash keys",
    );
});

test("default remember omits dedupe and rotates derived keys across 30-minute windows (#769)", async () => {
    const posted = [];
    stubRelayer({ onStatus: () => DONE, posted });

    const originalNow = Date.now;
    let fakeNow = 1_700_000_000_000;
    Date.now = () => fakeNow;
    try {
        await newClient().remember("User is allergic to peanuts", "health");
        fakeNow += 31 * 60 * 1000;
        await newClient().remember("User is allergic to peanuts", "health", { dedupe: false });
    } finally {
        Date.now = originalNow;
    }

    assert.equal(posted.length, 2);
    assert.equal("dedupe" in posted[0].body, false);
    assert.equal("dedupe" in posted[1].body, false);
    assert.match(posted[0].body.idempotency_key, /^r1-[0-9a-f]{64}$/);
    assert.match(posted[1].body.idempotency_key, /^r1-[0-9a-f]{64}$/);
    assert.notEqual(
        posted[0].body.idempotency_key,
        posted[1].body.idempotency_key,
        "without dedupe: true, calls in separate 30-minute buckets get distinct keys",
    );
});

