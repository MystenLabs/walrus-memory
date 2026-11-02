import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { MemWal } from "../dist/memwal.js";
import { fetchWithDeadline, isTimeoutError, DEFAULT_RECALL_TIMEOUT_MS } from "../dist/utils.js";

// The shipped deadline contract (WALM-648): name `MemWalRequestTimeout`, status
// 504 so `isTransientPollingStatus` retries one stalled poll, plus the `phase`
// WALM-598 adds so the stalled round-trip is named.
const isRequestTimeout = (err) =>
    err instanceof Error && err.name === "MemWalRequestTimeout" && typeof err.phase === "string";

// WALM-598 / GH #438.
//
// `recall()` used to arm a single 15s AbortController *before* calling
// `signedRequest`, which then awaited two unabortable, untimed preflights —
// `ensureCompatibleRelayer()` (`GET /version`, falling back to `GET /health`)
// and `buildSealSession()` (`GET /config` + a Sui RPC round-trip). A relayer
// whose `/health` p50 had drifted to ~9s therefore spent most of the caller's
// budget before `/api/recall` was even dispatched, and the resulting
// `AbortError` surfaced on the recall fetch even though recall was healthy.
//
// The budget now starts on the recall request itself; the preflights carry
// their own independent deadlines.

const originalFetch = globalThis.fetch;

test.afterEach(() => {
    globalThis.fetch = originalFetch;
});

/**
 * Resolve `factory()` after `ms`, or reject with an `AbortError` if the
 * caller's signal fires first — i.e. behave like a real `fetch`. Without the
 * signal handling these tests could not observe an abort at all.
 */
function delayed(ms, factory, signal) {
    return new Promise((resolve, reject) => {
        if (signal?.aborted) {
            reject(abortError());
            return;
        }
        const tid = setTimeout(() => resolve(factory()), ms);
        signal?.addEventListener(
            "abort",
            () => {
                clearTimeout(tid);
                reject(abortError());
            },
            { once: true },
        );
    });
}

function abortError() {
    return Object.assign(new Error("This operation was aborted"), { name: "AbortError" });
}

const VERSION_BODY = {
    apiVersion: "1.0.0",
    relayerVersion: "1.0.0",
    minSupportedSdk: { typescript: "0.0.4" },
};

/**
 * Route stub with per-path latency. `never` means "hang until aborted",
 * which is how a wedged preflight looks to the client.
 */
function stubServer({ versionDelayMs = 0, recallDelayMs = 0, hits = [] } = {}) {
    const seen = [];
    globalThis.fetch = async (url, init = {}) => {
        const path = new URL(url).pathname;
        seen.push(path);
        if (path === "/version") {
            if (versionDelayMs === "never") return delayed(1e9, () => null, init.signal);
            return delayed(versionDelayMs, () => Response.json(VERSION_BODY), init.signal);
        }
        if (path === "/api/recall" && init.method === "POST") {
            return delayed(
                recallDelayMs,
                () => Response.json({ results: hits, total: hits.length }),
                init.signal,
            );
        }
        throw new Error(`unexpected request ${path}`);
    };
    return seen;
}

function client(config = {}) {
    const c = MemWal.create({
        key: new Uint8Array(32).fill(1),
        accountId: "0x1",
        serverUrl: "https://relayer.example",
        ...config,
    });
    // Standard SEAL stub — building a real SessionKey needs @mysten/seal and
    // a live Sui RPC. `buildSealSession` is awaited inside `signedRequest`,
    // i.e. in the same preflight window as `/config`.
    c.buildSealSession = async () => "test-session";
    return c;
}

test("a slow /version preflight does not abort a healthy recall", async () => {
    // The regression, reproduced at test speed: the preflight takes longer
    // than the entire recall budget. Before WALM-598 the shared
    // AbortController had already fired by the time `/api/recall` was
    // dispatched, so this rejected with an unlabeled AbortError.
    const seen = stubServer({ versionDelayMs: 120, recallDelayMs: 0 });

    const result = await client({ recallTimeoutMs: 40 }).recall({ query: "food allergies" });

    assert.deepEqual(result.results, []);
    assert.deepEqual(seen, ["/version", "/api/recall"]);
});

test("a slow SEAL session build does not abort a healthy recall", async () => {
    // `buildSealSession()` is the other unabortable preflight inside the old
    // budget: on a cold cache it fetches /config, dynamic-imports @mysten/seal
    // and @mysten/sui, and calls SessionKey.create() against Sui RPC.
    stubServer({ recallDelayMs: 0 });

    const c = client({ recallTimeoutMs: 40 });
    c.buildSealSession = async () => {
        await new Promise((resolve) => setTimeout(resolve, 120));
        return "test-session";
    };

    const result = await c.recall({ query: "food allergies" });
    assert.deepEqual(result.results, []);
});

test("recall honours a per-call timeoutMs", async () => {
    stubServer({ recallDelayMs: 5_000 });

    await assert.rejects(
        client().recall({ query: "food allergies", timeoutMs: 30 }),
        (err) => {
            assert.ok(isRequestTimeout(err), `expected a MemWalRequestTimeout, got ${err?.name}`);
            assert.equal(err.timeoutMs, 30);
            return true;
        },
    );
});

test("recall honours a client-level recallTimeoutMs", async () => {
    stubServer({ recallDelayMs: 5_000 });

    await assert.rejects(client({ recallTimeoutMs: 30 }).recall({ query: "q" }), (err) => {
        assert.ok(isRequestTimeout(err));
        assert.equal(err.timeoutMs, 30);
        return true;
    });
});

test("a per-call timeoutMs overrides the client default", async () => {
    stubServer({ recallDelayMs: 5_000 });

    await assert.rejects(
        client({ recallTimeoutMs: 60_000 }).recall({ query: "q", timeoutMs: 25 }),
        (err) => {
            assert.equal(err.timeoutMs, 25);
            return true;
        },
    );
});

test("a recall timeout names the recall request as the phase", async () => {
    // The diagnostic that was missing: every stall in the chain used to
    // surface as an unlabeled AbortError on the recall fetch.
    stubServer({ recallDelayMs: 5_000 });

    await assert.rejects(client().recall({ query: "q", timeoutMs: 25 }), (err) => {
        assert.equal(err.phase, "POST /api/recall");
        assert.match(err.message, /timed out after 25ms during POST \/api\/recall/);
        return true;
    });
});

test("a preflight timeout names the preflight as the phase", async () => {
    // A wedged /version now fails on its own budget instead of hanging
    // forever (it carried no signal at all before) or being misreported as
    // a recall abort.
    stubServer({ versionDelayMs: "never" });

    await assert.rejects(
        client({ preflightTimeoutMs: 30, recallTimeoutMs: 5_000 }).recall({ query: "q" }),
        (err) => {
            assert.ok(isRequestTimeout(err));
            assert.equal(err.phase, "preflight GET /version");
            assert.equal(err.timeoutMs, 30);
            return true;
        },
    );
});

test("health() is bounded by the preflight budget", async () => {
    globalThis.fetch = async (url, init = {}) => {
        assert.equal(new URL(url).pathname, "/health");
        return delayed(1e9, () => null, init.signal);
    };

    await assert.rejects(client({ preflightTimeoutMs: 30 }).health(), (err) => {
        assert.ok(isRequestTimeout(err));
        assert.equal(err.phase, "GET /health");
        return true;
    });
});

test("the deadline covers the response body, not just the headers", async () => {
    // fetch() resolves at the headers. A server that answers promptly and then
    // trickles the body must still blow the budget the caller named, and blow
    // it as a phase-tagged TimeoutError rather than a bare AbortError.
    globalThis.fetch = async (_url, init = {}) =>
        new Response(
            new ReadableStream({
                start(controller) {
                    init.signal?.addEventListener(
                        "abort",
                        () => controller.error(abortError()),
                        { once: true },
                    );
                },
            }),
            { status: 200, headers: { "content-type": "application/json" } },
        );

    const res = await fetchWithDeadline(
        "https://relayer.test/api/recall",
        { method: "POST" },
        25,
        "POST /api/recall",
    );
    // `utils.fetchWithDeadline` is the standalone helper (used by manual.ts);
    // it raises utils' own phase-tagged `TimeoutError`, not the client's
    // `MemWalRequestTimeout`. Both carry `phase`/`timeoutMs`.
    await assert.rejects(res.json(), (err) => {
        assert.ok(isTimeoutError(err));
        assert.equal(err.phase, "POST /api/recall");
        assert.equal(err.timeoutMs, 25);
        return true;
    });
});

test("the timer survives the headers and is released by the body read", async () => {
    // Both halves of the fix in one assertion pair: the deadline must still be
    // armed when fetch() resolves (otherwise a trickled body is unbounded), and
    // it must be cleared once the body settles (otherwise every request leaks a
    // pending timer). Asserting only that json() returns would pass either way.
    const live = new Set();
    const realSetTimeout = globalThis.setTimeout;
    const realClearTimeout = globalThis.clearTimeout;
    globalThis.setTimeout = (...args) => {
        const id = realSetTimeout(...args);
        live.add(id);
        return id;
    };
    globalThis.clearTimeout = (id) => {
        live.delete(id);
        return realClearTimeout(id);
    };

    try {
        globalThis.fetch = async () => new Response(JSON.stringify({ ok: true }), { status: 200 });

        const res = await fetchWithDeadline(
            "https://relayer.test/version",
            { method: "GET" },
            5_000,
            "preflight GET /version",
        );
        assert.equal(live.size, 1, "the deadline must outlive the response headers");

        assert.deepEqual(await res.json(), { ok: true });
        assert.equal(live.size, 0, "reading the body must release the deadline");
    } finally {
        globalThis.setTimeout = realSetTimeout;
        globalThis.clearTimeout = realClearTimeout;
    }
});

test("the default recall budget is unchanged at 15s", async () => {
    assert.equal(DEFAULT_RECALL_TIMEOUT_MS, 15_000);
});

test("recall timeoutMs 0 does not send deadline_ms", async () => {
    let body = {};
    globalThis.fetch = async (url, init = {}) => {
        const path = new URL(url).pathname;
        if (path === "/version") return Response.json(VERSION_BODY);
        if (path === "/api/recall") {
            body = JSON.parse(init.body);
            return Response.json({ results: [], total: 0 });
        }
        throw new Error(path);
    };
    const result = await client().recall({ query: "x", timeoutMs: 0 });
    assert.deepEqual(result, { results: [], total: 0 });
    assert.equal(body.deadline_ms, undefined);
    const timeout = new Error("timed out");
    timeout.name = "MemWalRequestTimeout";
    assert.equal(isTimeoutError(timeout), true);
});

test("client recallTimeoutMs 0 does not send deadline_ms", async () => {
    let body = {};
    globalThis.fetch = async (url, init = {}) => {
        const path = new URL(url).pathname;
        if (path === "/version") return Response.json(VERSION_BODY);
        if (path === "/api/recall") {
            body = JSON.parse(init.body);
            return Response.json({ results: [], total: 0 });
        }
        throw new Error(path);
    };
    const result = await client({ recallTimeoutMs: 0 }).recall({ query: "x" });
    assert.deepEqual(result, { results: [], total: 0 });
    assert.equal(body.deadline_ms, undefined);
});

test("a short recall budget is sent whole instead of floored at 1", async () => {
    let body = {};
    globalThis.fetch = async (url, init = {}) => {
        const path = new URL(url).pathname;
        if (path === "/version") return Response.json(VERSION_BODY);
        if (path === "/api/recall") {
            body = JSON.parse(init.body);
            return Response.json({ results: [], total: 0 });
        }
        throw new Error(path);
    };
    await client().recall({ query: "x", timeoutMs: 400 });
    assert.equal(body.deadline_ms, 400);
});

test("a stalled SessionKey.create rejects within preflightTimeoutMs with classified MemWalRequestTimeout (#1367)", async () => {
    const seen = [];
    globalThis.fetch = async (url, init = {}) => {
        const path = new URL(url).pathname;
        seen.push(path);
        if (path === "/version") return Response.json(VERSION_BODY);
        if (path === "/config") {
            return Response.json({
                packageId: "0x123",
                network: "testnet",
                suiGrpcUrl: "http://127.0.0.1:9999",
                suiTransport: "grpc",
            });
        }
        if (path === "/api/recall") {
            return Response.json({ results: [], total: 0 });
        }
        throw new Error(path);
    };

    const c = MemWal.create({
        key: new Uint8Array(32).fill(1),
        accountId: "0x1",
        serverUrl: "https://relayer.example",
        preflightTimeoutMs: 35,
    });

    // Stalled Sui endpoint inside buildSealSessionInner
    const origBuildInner = c.buildSealSessionInner;
    c.buildSealSessionInner = async function () {
        await c.fetchServerConfig();
        const deadline = c.preflightTimeoutMs;
        return new Promise((_, reject) => {
            setTimeout(() => {
                const err = new Error(
                    `Walrus Memory request timed out after ${deadline}ms during preflight SessionKey.create. The relayer accepted the connection but did not answer in time.`,
                );
                err.name = "MemWalRequestTimeout";
                err.status = 504;
                err.phase = "preflight SessionKey.create";
                err.timeoutMs = deadline;
                reject(err);
            }, deadline);
        });
    };

    await assert.rejects(
        c.recall({ query: "allergies" }),
        (err) => {
            assert.ok(isRequestTimeout(err));
            assert.equal(err.phase, "preflight SessionKey.create");
            assert.equal(err.timeoutMs, 35);
            assert.equal(err.status, 504);
            return true;
        },
    );
    assert.deepEqual(seen, ["/version", "/config"]);
});

test("SessionKey.create timeout clears single-flight state and allows recovery (#1367)", async () => {
    let callCount = 0;
    const c = MemWal.create({
        key: new Uint8Array(32).fill(1),
        accountId: "0x1",
        serverUrl: "https://relayer.example",
        preflightTimeoutMs: 30,
    });

    globalThis.fetch = async (url) => {
        const path = new URL(url).pathname;
        if (path === "/version") return Response.json(VERSION_BODY);
        if (path === "/api/recall") return Response.json({ results: [{ id: "mem1" }], total: 1 });
        throw new Error(path);
    };

    c.buildSealSessionInner = async () => {
        callCount++;
        if (callCount === 1) {
            // First call stalls and times out
            await new Promise((r) => setTimeout(r, 40));
            const err = new Error(
                "Walrus Memory request timed out after 30ms during preflight SessionKey.create.",
            );
            err.name = "MemWalRequestTimeout";
            err.status = 504;
            err.phase = "preflight SessionKey.create";
            err.timeoutMs = 30;
            throw err;
        }
        return "healthy-session-token";
    };

    // First call rejects with timeout
    await assert.rejects(c.recall({ query: "first" }), (err) => {
        assert.ok(isRequestTimeout(err));
        assert.equal(err.phase, "preflight SessionKey.create");
        return true;
    });

    // Single-flight state must be cleared: second call succeeds
    const recovered = await c.recall({ query: "second" });
    assert.equal(recovered.total, 1);
    assert.equal(recovered.results[0].id, "mem1");
});

test("RecallOptions and MemWalConfig declare the timeout knobs", () => {
    // A .mjs test cannot catch a missing type; assert on the emitted .d.ts,
    // which is what a TypeScript consumer actually resolves.
    const dts = readFileSync(
        fileURLToPath(new URL("../dist/types.d.ts", import.meta.url)),
        "utf8",
    );

    assert.match(dts, /recallTimeoutMs\?: number;/);
    assert.match(dts, /preflightTimeoutMs\?: number;/);
});
