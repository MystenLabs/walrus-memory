import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import type { SealClient } from "@mysten/seal";
import {
    createSealSessionClientCache,
    delegateKeyCacheKey,
    sessionCacheKeyFromExportedSession,
    SEAL_LEGACY_KEY_CACHE_TTL_MS,
    type SealSessionCacheKey,
} from "../sidecar/seal-session-cache.js";

function fakeClient(id: number): SealClient {
    return { testClientId: id } as unknown as SealClient;
}

function cacheKey(fingerprint: string, expiresAt: number): SealSessionCacheKey {
    return { fingerprint, expiresAt };
}

function deferred<T>() {
    let resolve!: (value: T) => void;
    let reject!: (reason: unknown) => void;
    const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
    return { promise, resolve, reject };
}

test("an exported session key is fingerprinted from the exact header bytes and bounded by its own TTL", () => {
    const header = Buffer.from("exported-session").toString("base64");
    const key = sessionCacheKeyFromExportedSession(header, {
        creationTimeMs: 1_000,
        ttlMin: 5,
    });

    assert.ok(key);
    assert.equal(key.fingerprint, createHash("sha256").update(header).digest("hex"));
    assert.equal(key.expiresAt, 1_000 + 5 * 60_000);
    assert.notEqual(
        sessionCacheKeyFromExportedSession(header, { creationTimeMs: 1_000, ttlMin: 5 })!.fingerprint,
        sessionCacheKeyFromExportedSession(`${header} `, { creationTimeMs: 1_000, ttlMin: 5 })!.fingerprint,
    );
});

test("a session without a usable expiry is not cacheable", () => {
    const header = Buffer.from("exported-session").toString("base64");
    for (const exported of [
        {},
        { creationTimeMs: 1_000 },
        { ttlMin: 5 },
        { creationTimeMs: 1_000, ttlMin: 0 },
        { creationTimeMs: 1_000, ttlMin: -1 },
        { creationTimeMs: Number.NaN, ttlMin: 5 },
        { creationTimeMs: 1_000, ttlMin: Number.POSITIVE_INFINITY },
    ]) {
        assert.equal(sessionCacheKeyFromExportedSession(header, exported), undefined);
    }
});

test("a legacy delegate key is fingerprinted without retaining the key and gets a five-minute deadline", () => {
    const now = 12_345;
    const first = delegateKeyCacheKey("suiprivkey1abc", now);
    const second = delegateKeyCacheKey("suiprivkey1abc", now + 1_000);
    const other = delegateKeyCacheKey("suiprivkey1xyz", now);

    assert.equal(first.fingerprint, second.fingerprint);
    assert.notEqual(first.fingerprint, other.fingerprint);
    assert.equal(first.expiresAt, now + SEAL_LEGACY_KEY_CACHE_TTL_MS);
    assert.ok(!first.fingerprint.includes("suiprivkey1abc"));
});

test("the same credential reuses one client and one factory call", async () => {
    let creates = 0;
    const cache = createSealSessionClientCache(async () => fakeClient(++creates), { now: () => 0 });
    const key = cacheKey("session-a", 10_000);

    const first = await cache.get(key);
    const second = await cache.get(key);
    assert.equal(first, second);
    assert.equal(creates, 1);
    assert.equal(cache.size(), 1);
});

test("different credentials never share a client", async () => {
    let creates = 0;
    const cache = createSealSessionClientCache(async () => fakeClient(++creates), { now: () => 0 });

    const a = await cache.get(cacheKey("session-a", 10_000));
    const b = await cache.get(cacheKey("session-b", 10_000));
    assert.notEqual(a, b);
    assert.equal(creates, 2);
    assert.equal(cache.size(), 2);
});

test("concurrent requests for one credential single-flight the client creation", async () => {
    const create = deferred<SealClient>();
    let creates = 0;
    const cache = createSealSessionClientCache(() => {
        creates++;
        return create.promise;
    }, { now: () => 0 });
    const key = cacheKey("session-a", 10_000);

    const pending = Array.from({ length: 8 }, () => cache.get(key));
    await Promise.resolve();
    assert.equal(creates, 1);
    const client = fakeClient(1);
    create.resolve(client);
    const clients = await Promise.all(pending);
    assert.ok(clients.every(candidate => candidate === client));
});

test("an entry stops being reused at its own deadline", async () => {
    let now = 0;
    let creates = 0;
    const cache = createSealSessionClientCache(async () => fakeClient(++creates), {
        now: () => now,
    });
    const key = cacheKey("session-a", 100);

    const first = await cache.get(key);
    now = 99;
    assert.equal(await cache.get(key), first);
    assert.equal(creates, 1);

    now = 100;
    const second = await cache.get(key);
    assert.notEqual(second, first);
    assert.equal(creates, 2);
});

test("the cache's own maximum TTL clamps a longer credential lifetime", async () => {
    let now = 0;
    let creates = 0;
    const cache = createSealSessionClientCache(async () => fakeClient(++creates), {
        maxTtlMs: 50,
        now: () => now,
    });
    const key = cacheKey("session-a", 1_000_000);

    const first = await cache.get(key);
    now = 49;
    assert.equal(await cache.get(key), first);
    now = 50;
    assert.notEqual(await cache.get(key), first);
    assert.equal(creates, 2);
});

test("the cache evicts the least recently used credential once it is full", async () => {
    let now = 0;
    let creates = 0;
    const cache = createSealSessionClientCache(async () => fakeClient(++creates), {
        maxEntries: 2,
        now: () => now,
    });
    const a = cacheKey("session-a", 1_000);
    const b = cacheKey("session-b", 1_000);
    const c = cacheKey("session-c", 1_000);

    const clientA = await cache.get(a);
    now = 1;
    const clientB = await cache.get(b);
    now = 2;
    assert.equal(await cache.get(a), clientA, "touching A makes B the LRU");
    now = 3;
    const clientC = await cache.get(c);

    assert.equal(cache.size(), 2);
    assert.notEqual(clientC, clientA);
    now = 4;
    const replacedB = await cache.get(b);
    assert.notEqual(replacedB, clientB, "B was evicted and recreated");
    assert.equal(creates, 4);
});

test("a credential already at its deadline is not retained", async () => {
    let creates = 0;
    const cache = createSealSessionClientCache(async () => fakeClient(++creates), {
        now: () => 100,
    });
    await cache.get(cacheKey("session-expired", 100));
    assert.equal(creates, 1);
    assert.equal(cache.size(), 0);
});

test("a failed client creation is not cached", async () => {
    let attempts = 0;
    const cache = createSealSessionClientCache(async () => {
        attempts++;
        if (attempts === 1) throw new Error("metadata unavailable");
        return fakeClient(attempts);
    }, { now: () => 0 });
    const key = cacheKey("session-a", 10_000);

    await assert.rejects(cache.get(key), /metadata unavailable/);
    assert.equal(cache.size(), 0);
    const recovered = await cache.get(key);
    assert.equal((recovered as unknown as { testClientId: number }).testClientId, 2);
    assert.equal(attempts, 2);
});

test("reset drops every entry and isolates in-flight creations", async () => {
    const create = deferred<SealClient>();
    const cache = createSealSessionClientCache(() => create.promise, { now: () => 0 });
    const pending = cache.get(cacheKey("session-a", 10_000));
    await Promise.resolve();

    cache.reset();
    assert.equal(cache.size(), 0);
    create.resolve(fakeClient(1));
    await pending;

    assert.equal(cache.size(), 0, "an in-flight entry must not resurrect after reset");
});
