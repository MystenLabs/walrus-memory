import assert from "node:assert/strict";
import test from "node:test";

import { MemWal } from "../dist/memwal.js";

const originalFetch = globalThis.fetch;

test.afterEach(() => {
    globalThis.fetch = originalFetch;
});

/**
 * `fetch` has no timeout of its own, and the SDK used to pass a signal on
 * exactly one method (`recall`). Everything else — the accept POST, every job
 * status read, and the `/version` and `/config` handshake calls that run before
 * any of them — could stay pending for as long as the socket stayed open.
 *
 * A poll loop only checks its budget between polls, so that was not merely
 * untidy: one stalled read ran straight past `timeoutMs`, which is how a
 * `memwal_remember` documented as capping at 90s was seen still running after
 * 120s by an MCP client.
 */

/** Stands in for a stalled socket: never answers, but honours abort the way a
 * real `fetch` does — which is also what proves the signal reaches it. */
function hangUntilAborted(init = {}) {
    return new Promise((_, reject) => {
        const signal = init.signal;
        if (!signal) return; // no signal reaching fetch => hangs forever => test times out
        if (signal.aborted) return reject(abortError());
        signal.addEventListener("abort", () => reject(abortError()), { once: true });
    });
}

function abortError() {
    const err = new Error("This operation was aborted");
    err.name = "AbortError";
    return err;
}

/** Stub relayer whose handshake always answers; `onApi` decides the rest. */
function stubRelayer(onApi) {
    globalThis.fetch = async (url, init = {}) => {
        const path = new URL(url).pathname;
        if (path === "/version") {
            return Response.json({
                apiVersion: "1.0.0",
                relayerVersion: "1.0.0",
                minSupportedSdk: { typescript: "0.0.4" },
            });
        }
        if (path === "/config") {
            return Response.json({ packageId: "0x1", network: "testnet" });
        }
        return onApi(path, init, url);
    };
}

function clientWith(extra = {}) {
    const client = MemWal.create({
        key: new Uint8Array(32).fill(1),
        accountId: "0x1",
        serverUrl: "https://relayer.example",
        ...extra,
    });
    client.buildSealSession = async () => "test-session";
    return client;
}

test("a stalled accept is bounded instead of hanging forever", async () => {
    stubRelayer((path, init) =>
        path === "/api/remember" ? hangUntilAborted(init) : Promise.reject(new Error(path)),
    );

    const started = Date.now();
    await assert.rejects(
        clientWith({ requestTimeoutMs: 120 }).rememberAsync("a durable fact"),
        (err) => {
            assert.equal(err.name, "MemWalRequestTimeout");
            // 504 is load-bearing: `isTransientPollingStatus` treats it as
            // retryable, so a stalled poll inside a wait loop is retried
            // against the remaining budget rather than failing the whole wait.
            assert.equal(err.status, 504);
            assert.match(err.message, /POST \/api\/remember/);
            return true;
        },
    );
    assert.ok(Date.now() - started < 2_000, "should give up at the deadline, not hang");
});

test("a stalled handshake is bounded too", async () => {
    // `/version` runs before any memory call, so leaving it unbounded hangs
    // every method on the client rather than one request.
    globalThis.fetch = async (url, init = {}) => hangUntilAborted(init);

    await assert.rejects(
        clientWith({ requestTimeoutMs: 120 }).rememberAsync("a durable fact"),
        (err) => {
            assert.equal(err.name, "MemWalRequestTimeout");
            return true;
        },
    );
});

test("waitForRememberJob stays inside its budget when every poll stalls", async () => {
    stubRelayer((path, init) =>
        path.startsWith("/api/remember/") ? hangUntilAborted(init) : Promise.reject(new Error(path)),
    );

    const started = Date.now();
    await assert.rejects(
        clientWith({ requestTimeoutMs: 10_000 }).waitForRememberJob("job-1", {
            timeoutMs: 400,
            pollIntervalMs: 50,
        }),
        /timed out/,
    );
    // The budget is the bound now. Previously the loop only checked it between
    // polls, so a single stalled read outlived it by however long the socket
    // stayed open — here that would have been the 10s client deadline.
    assert.ok(
        Date.now() - started < 3_000,
        `wait overran its budget: ${Date.now() - started}ms`,
    );
});

test("an expired poll is retried rather than failing the whole wait", async () => {
    let call = 0;
    stubRelayer((path, init) => {
        if (!path.startsWith("/api/remember/")) return Promise.reject(new Error(path));
        // First poll stalls; the retry answers.
        if (call++ === 0) return hangUntilAborted(init);
        return Response.json({
            job_id: "job-1",
            status: "done",
            blob_id: "blob-1",
            owner: "0x1",
            namespace: "default",
        });
    });

    const result = await clientWith({ requestTimeoutMs: 100 }).waitForRememberJob("job-1", {
        timeoutMs: 5_000,
        pollIntervalMs: 20,
    });

    assert.equal(result.blob_id, "blob-1");
    assert.ok(call >= 2, "the stalled poll should have been retried, not fatal");
});

test("a transport failure that is not a deadline keeps its own identity", async () => {
    // The deadline path must not swallow real network errors — an operator
    // debugging DNS or TLS needs the original, not "timed out".
    stubRelayer(() => Promise.reject(new TypeError("fetch failed")));

    await assert.rejects(
        clientWith({ requestTimeoutMs: 5_000 }).rememberAsync("a durable fact"),
        (err) => {
            assert.notEqual(err.name, "MemWalRequestTimeout");
            assert.match(err.message, /fetch failed/);
            return true;
        },
    );
});

test("an unusable requestTimeoutMs falls back to the default rather than disabling the bound", async () => {
    // 0 / negative / NaN would mean "no deadline", which is the bug this
    // exists to prevent — a typo must not silently restore it.
    for (const bad of [0, -1, Number.NaN, undefined]) {
        const client = clientWith({ requestTimeoutMs: bad });
        assert.equal(client.requestTimeoutMs, 30_000, `bad value ${bad} disabled the bound`);
    }
    assert.equal(clientWith({ requestTimeoutMs: 1234 }).requestTimeoutMs, 1234);
});

test("a body that stalls after the headers is bounded too", { timeout: 10_000 }, async () => {
    stubRelayer((path, init) => {
        if (path !== "/api/remember") return Promise.reject(new Error(path));
        return Promise.resolve({
            ok: true,
            status: 202,
            headers: new Headers(),
            json: () => hangUntilAborted(init),
            text: () => hangUntilAborted(init),
        });
    });

    const started = Date.now();
    await assert.rejects(
        clientWith({ requestTimeoutMs: 120 }).rememberAsync("a durable fact"),
        (err) => {
            assert.equal(err.name, "MemWalRequestTimeout");
            assert.equal(err.status, 504);
            assert.match(err.message, /POST \/api\/remember/);
            return true;
        },
    );
    assert.ok(
        Date.now() - started < 2_000,
        "the deadline should still be armed while the body is read",
    );
});

test("a classified error survives a deadline that expires during its body read", async () => {
    const raw = JSON.stringify({ error: "Rate limit exceeded", retry_after_seconds: 60 });
    stubRelayer((path) => {
        if (path !== "/api/remember") return Promise.reject(new Error(path));
        return Promise.resolve({
            ok: false,
            status: 429,
            headers: new Headers({ "content-type": "application/json", "retry-after": "60" }),
            text: () => new Promise((resolve) => setTimeout(() => resolve(raw), 300)),
            json: () => new Promise((resolve) => setTimeout(() => resolve(JSON.parse(raw)), 300)),
        });
    });

    await assert.rejects(
        clientWith({ requestTimeoutMs: 120 }).rememberAsync("a durable fact"),
        (err) => {
            assert.equal(err.status, 429);
            assert.equal(err.retryAfterSeconds, 60);
            assert.equal(err.cause, raw);
            return true;
        },
    );
});

test("analyze() forwards options.signal and aborts in-flight POST /api/analyze when caller signal fires", async () => {
    let analyzeSignal = null;
    stubRelayer((path, init) => {
        if (path !== "/api/analyze") return Promise.reject(new Error(path));
        analyzeSignal = init.signal;
        return hangUntilAborted(init);
    });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error("caller-cancelled-analyze")), 40);
    const started = Date.now();
    try {
        await assert.rejects(
            clientWith().analyze("I prefer TypeScript for backend services", {
                namespace: "default",
                signal: controller.signal,
            }),
            /caller-cancelled-analyze|aborted/i,
        );
    } finally {
        clearTimeout(timer);
    }
    assert.ok(analyzeSignal?.aborted, "POST /api/analyze fetch signal must be aborted when caller signal fires");
    assert.ok(Date.now() - started < 2_000, "caller abort must not wait for the 120s analyze deadline");
});

