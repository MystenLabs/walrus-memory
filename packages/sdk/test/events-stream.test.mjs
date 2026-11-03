import assert from "node:assert/strict";
import test from "node:test";

import { MemWal } from "../dist/memwal.js";

const originalFetch = globalThis.fetch;

function createClient() {
    return MemWal.create({
        key: new Uint8Array(32).fill(7),
        accountId: "0x123456",
        serverUrl: "https://relayer.example",
    });
}

test("subscribeEvents parses SSE frames and passes signed headers", async (t) => {
    t.after(() => {
        globalThis.fetch = originalFetch;
    });

    let requestedUrl = "";
    let requestedHeaders = {};

    globalThis.fetch = async (url, init = {}) => {
        const u = new URL(url);
        if (u.pathname === "/version") {
            return Response.json({
                apiVersion: "1.0.0",
                relayerVersion: "1.0.0",
                minSupportedSdk: { typescript: "0.0.4" },
            });
        }
        if (u.pathname === "/api/events") {
            requestedUrl = url;
            requestedHeaders = init.headers ?? {};

            const stream = new ReadableStream({
                start(controller) {
                    controller.enqueue(
                        new TextEncoder().encode(
                            ": keepalive\n\n" +
                            "id: evt-1\nevent: memory.remember.accepted\ndata: {\"id\":\"evt-1\",\"type\":\"memory.remember.accepted\",\"owner\":\"0x1\",\"namespace\":\"default\",\"timestamp\":\"2026-11-03T00:00:00Z\",\"count\":1}\n\n" +
                            ": keepalive\n\n" +
                            "id: evt-2\nevent: memory.forget\ndata: {\"id\":\"evt-2\",\"type\":\"memory.forget\",\"owner\":\"0x1\",\"namespace\":\"default\",\"timestamp\":\"2026-11-03T00:00:01Z\",\"count\":3}\n\n"
                        )
                    );
                    controller.close();
                },
            });

            return new Response(stream, {
                status: 200,
                headers: { "Content-Type": "text/event-stream" },
            });
        }
        throw new Error(`Unexpected request to ${u.pathname}`);
    };

    const client = createClient();
    const events = [];

    for await (const evt of client.subscribeEvents({
        namespace: "work",
        types: ["memory.remember.accepted", "memory.forget"],
    })) {
        events.push(evt);
    }

    assert.equal(events.length, 2);
    assert.equal(events[0].id, "evt-1");
    assert.equal(events[0].type, "memory.remember.accepted");
    assert.equal(events[0].count, 1);
    assert.equal(events[1].id, "evt-2");
    assert.equal(events[1].type, "memory.forget");
    assert.equal(events[1].count, 3);

    const parsedUrl = new URL(requestedUrl);
    assert.equal(parsedUrl.pathname, "/api/events");
    assert.equal(parsedUrl.searchParams.get("namespace"), "work");
    assert.equal(
        parsedUrl.searchParams.get("types"),
        "memory.remember.accepted,memory.forget"
    );

    assert.equal(requestedHeaders["Accept"], "text/event-stream");
    assert.ok(requestedHeaders["x-public-key"]);
    assert.ok(requestedHeaders["x-signature"]);
    assert.ok(requestedHeaders["x-timestamp"]);
    assert.ok(requestedHeaders["x-nonce"]);
    assert.equal(requestedHeaders["x-account-id"], "0x123456");
});

test("subscribeEvents respects AbortSignal", async (t) => {
    t.after(() => {
        globalThis.fetch = originalFetch;
    });

    const ac = new AbortController();

    globalThis.fetch = async (url, init = {}) => {
        const u = new URL(url);
        if (u.pathname === "/version") {
            return Response.json({
                apiVersion: "1.0.0",
                relayerVersion: "1.0.0",
                minSupportedSdk: { typescript: "0.0.4" },
            });
        }
        if (u.pathname === "/api/events") {
            const stream = new ReadableStream({
                start(controller) {
                    controller.enqueue(
                        new TextEncoder().encode(
                            "id: evt-1\nevent: memory.remember.accepted\ndata: {\"id\":\"evt-1\",\"type\":\"memory.remember.accepted\",\"owner\":\"0x1\",\"namespace\":\"default\",\"timestamp\":\"2026-11-03T00:00:00Z\"}\n\n"
                        )
                    );
                    // Do not close; wait for abort
                },
            });

            return new Response(stream, {
                status: 200,
                headers: { "Content-Type": "text/event-stream" },
            });
        }
        throw new Error(`Unexpected request to ${u.pathname}`);
    };

    const client = createClient();
    const events = [];

    try {
        for await (const evt of client.subscribeEvents({ signal: ac.signal })) {
            events.push(evt);
            ac.abort();
        }
    } catch (err) {
        // AbortError expected when reading after abort
        assert.ok(err.name === "AbortError" || ac.signal.aborted);
    }

    assert.equal(events.length, 1);
    assert.equal(events[0].id, "evt-1");
});
