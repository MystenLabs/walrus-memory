/**
 * Live-relayer e2e for the JS SDK.
 *
 * Unauthenticated tests always run. Authenticated tests need
 * MEMWAL_PRIVATE_KEY + MEMWAL_ACCOUNT_ID and write into a per-run namespace
 * on the shared bench account.
 *
 * Keep this suite small. Every authenticated write is a full Walrus pipeline
 * against a rate-limited account; method-level coverage belongs in unit tests.
 * The authenticated path is one flow: remember → recall → namespace isolation.
 *
 *   pnpm --filter @mysten-incubation/memwal test:e2e
 *
 *   MEMWAL_PRIVATE_KEY=<hex> MEMWAL_ACCOUNT_ID=0x... \
 *     pnpm --filter @mysten-incubation/memwal test:e2e
 */

import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { describe, test } from "node:test";

import * as ed from "@noble/ed25519";

import {
    MemWal,
    MemWalCompatibilityError,
    MemWalRememberJobTimeoutError,
} from "../../dist/index.js";
import { bytesToHex, sha256hex } from "../../dist/utils.js";

const SERVER_URL = (process.env.MEMWAL_SERVER_URL ?? "https://relayer.dev.memwal.ai").replace(/\/$/, "");
const PRIVATE_KEY_HEX = process.env.MEMWAL_PRIVATE_KEY ?? "";
const ACCOUNT_ID = process.env.MEMWAL_ACCOUNT_ID ?? "";

function positiveIntEnv(name, fallback) {
    const raw = process.env[name];
    if (raw === undefined || raw === "") return fallback;
    const parsed = Number(raw);
    if (!Number.isFinite(parsed) || parsed <= 0) {
        throw new Error(`${name} must be a positive number of milliseconds, got '${raw}'`);
    }
    return parsed;
}

// A live write is embed → SEAL → Walrus → on-chain metadata (~44s on dev).
// 120s matches the SDK bulk pipeline budget.
const REMEMBER_TIMEOUT_MS = positiveIntEnv("MEMWAL_REMEMBER_TIMEOUT_MS", 120_000);

const E2E_NAMESPACE = `sdk-e2e-${randomUUID().replaceAll("-", "").slice(0, 8)}`;
const E2E_NAMESPACE_ALT = `${E2E_NAMESPACE}-alt`;

const HAS_KEY = Boolean(PRIVATE_KEY_HEX && ACCOUNT_ID);
const requiresKey = HAS_KEY ? false : "MEMWAL_PRIVATE_KEY and MEMWAL_ACCOUNT_ID not set";
const RUN_CONCURRENT_E2E = process.env.MEMWAL_E2E_CONCURRENT === "1";
const requiresConcurrentOptIn = !HAS_KEY
    ? "MEMWAL_PRIVATE_KEY and MEMWAL_ACCOUNT_ID not set"
    : RUN_CONCURRENT_E2E
      ? false
      : "MEMWAL_E2E_CONCURRENT=1 not set (opt-in 5x concurrent rememberAndWait load test)";

function client(namespace = E2E_NAMESPACE) {
    return MemWal.create({
        key: PRIVATE_KEY_HEX,
        accountId: ACCOUNT_ID,
        serverUrl: SERVER_URL,
        namespace,
    });
}

/**
 * Raw signed request without the SDK (auth-rejection cases).
 * Message format matches memwal.ts signedRequest():
 *   "{timestamp}.{method}.{path}.{body_sha256}.{nonce}.{account_id}"
 */
async function rawSignedRequest(method, path, body, privateKey, overrides = {}) {
    const bodyStr = JSON.stringify(body);
    const bodySha256 = await sha256hex(bodyStr);
    const timestamp = overrides.timestamp ?? Math.floor(Date.now() / 1000).toString();
    const nonce = randomUUID();
    const accountId = ACCOUNT_ID || "0x0";
    const message = `${timestamp}.${method}.${path}.${bodySha256}.${nonce}.${accountId}`;
    const signature = await ed.signAsync(new TextEncoder().encode(message), privateKey);
    const publicKeyHex = overrides.publicKeyHex ?? bytesToHex(await ed.getPublicKeyAsync(privateKey));

    return fetch(`${SERVER_URL}${path}`, {
        method,
        headers: {
            "Content-Type": "application/json",
            "x-public-key": publicKeyHex,
            "x-signature": bytesToHex(signature),
            "x-timestamp": timestamp,
            "x-nonce": nonce,
            "x-account-id": accountId,
        },
        body: bodyStr,
    });
}

const REJECTION_BODY = { text: "hello", namespace: "default" };

describe("health and compatibility", () => {
    test("health returns ok with a version string", async () => {
        const mw = MemWal.create({ key: "aa".repeat(32), accountId: "0x0", serverUrl: SERVER_URL });
        const result = await mw.health();
        assert.equal(result.status, "ok", `Expected 'ok', got '${result.status}'`);
        assert.equal(typeof result.version, "string");
    });

    test("compatibility contract accepts this SDK version", async () => {
        const mw = MemWal.create({ key: "aa".repeat(32), accountId: "0x0", serverUrl: SERVER_URL });
        const result = await mw.compatibility();
        assert.equal(typeof result.relayerVersion, "string");
        assert.equal(typeof result.apiVersion, "string");
        assert.equal(typeof result.minSupportedSdk.typescript, "string");
    });
});

describe("auth rejection", () => {
    test("unsigned request is rejected with 401", async () => {
        const res = await fetch(`${SERVER_URL}/api/remember`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(REJECTION_BODY),
        });
        assert.equal(res.status, 401, `Expected 401, got ${res.status}: ${await res.text()}`);
    });

    test("wrong signature is rejected with 401", async () => {
        const keyA = ed.utils.randomPrivateKey();
        const keyB = ed.utils.randomPrivateKey();
        const res = await rawSignedRequest("POST", "/api/remember", REJECTION_BODY, keyA, {
            publicKeyHex: bytesToHex(await ed.getPublicKeyAsync(keyB)),
        });
        assert.equal(res.status, 401, `Expected 401, got ${res.status}: ${await res.text()}`);
    });

    test("expired timestamp is rejected with 401", async () => {
        const key = ed.utils.randomPrivateKey();
        const tenMinutesAgo = String(Math.floor(Date.now() / 1000) - 600);
        const res = await rawSignedRequest("POST", "/api/remember", REJECTION_BODY, key, {
            timestamp: tenMinutesAgo,
        });
        assert.equal(res.status, 401, `Expected 401, got ${res.status}: ${await res.text()}`);
    });

    test("future timestamp is rejected with 401", async () => {
        const key = ed.utils.randomPrivateKey();
        const tenMinutesAhead = String(Math.floor(Date.now() / 1000) + 600);
        const res = await rawSignedRequest("POST", "/api/remember", REJECTION_BODY, key, {
            timestamp: tenMinutesAhead,
        });
        assert.equal(res.status, 401, `Expected 401, got ${res.status}: ${await res.text()}`);
    });

    test("SDK surfaces an unregistered key as an auth error", async (t) => {
        const mw = MemWal.create({
            key: "bb".repeat(32),
            accountId: "0x0",
            serverUrl: SERVER_URL,
        });
        try {
            await mw.remember("hello");
            assert.fail("Expected remember() with an unregistered key to throw");
        } catch (err) {
            if (err instanceof MemWalCompatibilityError) {
                t.skip("live relayer does not expose compatibility metadata yet");
                return;
            }
            const status = err.status ?? 0;
            assert.ok(
                status === 401 || status === 403 || /\b40[13]\b/.test(String(err.message)),
                `Expected a 401/403 auth rejection, got: ${err.message}`,
            );
        }
    });
});

describe("authenticated", { skip: requiresKey, concurrency: 1 }, () => {
    test("embed returns a vector", async () => {
        const result = await client().embed("hello world");
        assert.ok(Array.isArray(result.vector));
        assert.ok(result.vector.length > 0);
        assert.equal(typeof result.vector[0], "number");
    });

    test("remember accepts a job", async () => {
        const mw = client();
        const result = await mw.remember("Integration test: the sky is blue");
        assert.equal(typeof result.job_id, "string");
        assert.ok(result.job_id.length > 0);
        assert.ok(["pending", "running"].includes(result.status), `unexpected status: ${result.status}`);

        const status = await mw.getRememberStatus(result.job_id);
        assert.equal(status.job_id, result.job_id);
        assert.ok(
            ["pending", "running", "uploaded", "done", "failed"].includes(status.status),
            `unexpected job status: ${status.status}`,
        );
    });

    test("analyze extracts facts", async () => {
        const result = await client().analyze("I love hiking and my favorite food is pho.");
        assert.ok(Array.isArray(result.facts));
        assert.ok(result.fact_count >= 0);
        assert.ok(result.owner.startsWith("0x"));
        for (const fact of result.facts) {
            assert.equal(typeof fact.text, "string");
        }
    });

    test("full flow: remember, recall, namespace isolation", async () => {
        const unique = randomUUID().replaceAll("-", "").slice(0, 8);
        const text = `SDK e2e test ${unique}: quantum entanglement in photonics`;
        const mw = client();

        const memory = await mw.rememberAndWait(text, undefined, { timeoutMs: REMEMBER_TIMEOUT_MS });
        assert.equal(memory.namespace, E2E_NAMESPACE);
        assert.ok(memory.id.length > 0);
        assert.ok(memory.blob_id.length > 0);
        assert.ok(memory.owner.startsWith("0x"));

        const recalled = await mw.recall({
            query: `quantum photonics ${unique}`,
            limit: 5,
        });
        assert.ok(recalled.total >= 1, `Expected >= 1 result, got ${recalled.total}`);
        assert.ok(recalled.results.length <= 5);
        assert.ok(
            recalled.results.some((entry) => entry.text.includes(unique)),
            `Expected unique marker '${unique}' in recalled texts: ${JSON.stringify(recalled.results.map((entry) => entry.text))}`,
        );
        for (const entry of recalled.results) {
            assert.equal(typeof entry.text, "string");
            assert.equal(typeof entry.blob_id, "string");
            assert.equal(typeof entry.distance, "number");
        }

        const isolated = await mw.recall({
            query: `quantum photonics ${unique}`,
            limit: 5,
            namespace: E2E_NAMESPACE_ALT,
        });
        assert.ok(
            !isolated.results.some((entry) => entry.text.includes(unique)),
            `Namespace ${E2E_NAMESPACE_ALT} must not see the marker '${unique}'`,
        );

        const restored = await mw.restore(E2E_NAMESPACE);
        assert.equal(restored.namespace, E2E_NAMESPACE);
        assert.ok(Number.isInteger(restored.restored) && restored.restored >= 0);
        assert.ok(Number.isInteger(restored.skipped) && restored.skipped >= 0);
        assert.ok(Number.isInteger(restored.total) && restored.total >= 0);
        assert.equal(typeof restored.truncated, "boolean");
        assert.ok(restored.owner.startsWith("0x"));
    });

    test("recall maxDistance drops distant hits and keeps close ones", async () => {
        const namespace = `${E2E_NAMESPACE}-cutoff`;
        const mw = client(namespace);
        const unique = randomUUID().replaceAll("-", "").slice(0, 8);

        const written = await mw.rememberBulkAndWait(
            [
                { text: `SDK e2e cutoff ${unique}: my mother takes lisinopril for blood pressure` },
                { text: `SDK e2e cutoff ${unique}: the pharmacy is on 5th street next to the bakery` },
            ],
            { timeoutMs: REMEMBER_TIMEOUT_MS },
        );
        assert.equal(written.succeeded, 2, `expected 2 writes, got ${JSON.stringify(written)}`);

        const query = "What medication does my mother take?";

        // No cutoff: both hits come back, however distant.
        const all = await mw.recall({ query, limit: 5 });
        assert.equal(all.results.length, 2);
        const [near, far] = [...all.results].sort((a, b) => a.distance - b.distance);
        assert.ok(near.text.includes("lisinopril"), `closest hit should be the medication: ${near.text}`);
        assert.ok(far.distance > near.distance, "the two hits must be at different distances");

        // Cutoff between the two: only the close hit survives. `total` stays
        // the relayer page size, so a filtered page is not `total: 0`.
        const cutoff = (near.distance + far.distance) / 2;
        const filtered = await mw.recall({ query, limit: 5, maxDistance: cutoff });
        assert.deepEqual(filtered.results.map((r) => r.blob_id), [near.blob_id]);
        assert.equal(filtered.total, all.total);

        // Cutoff at the closest distance: `>=` drops it too, but the page
        // was not empty.
        const none = await mw.recall({ query, limit: 5, maxDistance: near.distance });
        assert.deepEqual(none.results, []);
        assert.equal(none.total, all.total);
    });

    test("listMemories counts a fresh namespace exactly", async () => {
        const namespace = `${E2E_NAMESPACE}-list`;
        const mw = client(namespace);
        const unique = randomUUID().replaceAll("-", "").slice(0, 8);

        const written = await mw.rememberBulkAndWait(
            ["alpha", "beta", "gamma"].map((word) => ({ text: `SDK e2e list ${unique}: ${word}` })),
            { timeoutMs: REMEMBER_TIMEOUT_MS },
        );
        assert.equal(written.succeeded, 3, `expected 3 writes, got ${JSON.stringify(written)}`);
        const blobIds = new Set(written.results.map((r) => r.blob_id));

        // Walk every page, filtered to this namespace.
        const listed = [];
        let cursor;
        let more = true;
        while (more) {
            const page = await mw.listMemories({ cursor, namespace, limit: 100 });
            for (const m of page.memories) {
                assert.equal(m.namespace_id, namespace);
                assert.equal(typeof m.memory_id, "string");
                assert.equal(typeof m.blob_id, "string");
                assert.equal(typeof m.size, "number");
                assert.ok(!Number.isNaN(Date.parse(m.updated_at)));
            }
            listed.push(...page.memories);
            assert.ok(Array.isArray(page.deleted));
            assert.equal(typeof page.must_resync, "boolean");
            cursor = page.next_cursor ?? undefined;
            more = page.has_more;
        }

        assert.equal(listed.length, 3);
        assert.deepEqual(new Set(listed.map((m) => m.blob_id)), blobIds);

        // Cross-check against the namespace rollup.
        const namespaces = [];
        cursor = undefined;
        more = true;
        while (more) {
            const page = await mw.listNamespaces({ cursor });
            namespaces.push(...page.namespaces);
            cursor = page.next_cursor ?? undefined;
            more = page.has_more;
        }
        const summary = namespaces.find((ns) => ns.name === namespace);
        assert.ok(summary, `listNamespaces must include ${namespace}`);
        assert.equal(summary.memory_count, 3);
    });

    test(
        "5x concurrent rememberAndWait smoke test recording completion or MemWalRememberJobTimeoutError (Refs #1130)",
        { skip: requiresConcurrentOptIn },
        async () => {
            const namespace = `${E2E_NAMESPACE}-concurrent5`;
            const mw = client(namespace);
            const unique = randomUUID().replaceAll("-", "").slice(0, 8);
            const timeoutMs = positiveIntEnv("MEMWAL_CONCURRENT_TIMEOUT_MS", 90_000);

            let outcomes = [];
            try {
                outcomes = await Promise.allSettled(
                    [1, 2, 3, 4, 5].map((i) =>
                        mw.rememberAndWait(
                            `SDK e2e concurrent #${i} (${unique}): parallel remember load verification`,
                            undefined,
                            { timeoutMs },
                        ),
                    ),
                );

                assert.equal(outcomes.length, 5);
                for (const outcome of outcomes) {
                    if (outcome.status === "fulfilled") {
                        const memory = outcome.value;
                        assert.equal(memory.namespace, namespace);
                        assert.ok(memory.id.length > 0);
                        assert.ok(memory.blob_id.length > 0);
                        assert.ok(memory.owner.startsWith("0x"));
                    } else {
                        const err = outcome.reason;
                        assert.ok(
                            err instanceof MemWalRememberJobTimeoutError,
                            `expected MemWalRememberJobTimeoutError on timeout, got ${err?.name}: ${err?.message}`,
                        );
                        assert.equal(err.status, 504);
                        assert.equal(typeof err.jobId, "string");
                        assert.ok(err.jobId.length > 0);
                        assert.ok(
                            ["pending", "running", "uploaded"].includes(err.lastStatus ?? ""),
                            `expected active lastStatus on timeout, got ${err.lastStatus}`,
                        );
                    }
                }
            } finally {
                // Best-effort cleanup of the isolated test namespace on the shared bench account.
                // Wait for any timed-out jobs to settle so their late completion does not leak into the namespace.
                try {
                    const timedOutJobIds = outcomes
                        .filter((o) => o.status === "rejected" && o.reason?.jobId)
                        .map((o) => o.reason.jobId);
                    if (timedOutJobIds.length > 0) {
                        await Promise.allSettled(
                            timedOutJobIds.map(async (jobId) => {
                                for (let poll = 0; poll < 10; poll += 1) {
                                    try {
                                        const st = await mw.getRememberStatus(jobId);
                                        if (st?.status === "done" || st?.status === "failed") break;
                                    } catch {
                                        // Ignore polling errors
                                    }
                                    await new Promise((r) => setTimeout(r, 1_000));
                                }
                            }),
                        );
                    }
                    await mw.signedRequest(
                        "POST",
                        "/api/forget",
                        { namespace },
                        [200],
                        { includeDelegateKey: false },
                    );
                } catch {
                    // Ignore cleanup errors if rate-limited.
                }
            }
        },
    );
});
