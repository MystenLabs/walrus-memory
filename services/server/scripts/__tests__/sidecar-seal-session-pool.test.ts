import test from "node:test";
import assert from "node:assert/strict";
import type { SealClient, SessionKey } from "@mysten/seal";
import {
    assertSealSessionClientLive,
    clearCachedInitialSharedVersionsForTests,
    createSealSessionPool,
    getCachedInitialSharedVersion,
    hasSealSessionApprovedKeys,
    readSealAuthorizationVersions,
    type SessionClientInput,
} from "../sidecar/seal-session-pool.js";

const input = (changes: Partial<SessionClientInput> = {}): SessionClientInput => ({
    header: "opaque-session-A", expiresAt: 10_000,
    scope: ["testnet", "package", "policy", "account", "registry", "committee"], ids: ["id"], ...changes,
});
const args = { ids: ["id"], threshold: 1, txBytes: Uint8Array.of(1), sessionKey: {} as SessionKey };

function fixture(options: Parameters<typeof createSealSessionPool>[2] = {}) {
    let time = 0;
    let state = "account-v1/registry-v1";
    let failState = false;
    let reads = 0;
    let creates = 0;
    let fetches = 0;
    const pool = createSealSessionPool(async () => {
        creates++;
        return {
            async fetchKeys() { fetches++; },
            async decrypt() { return Uint8Array.of(42); },
        } as unknown as SealClient;
    }, async () => {
        reads++;
        if (failState) throw new Error("RPC unavailable");
        return state;
    }, { now: () => time, ...options });
    return { pool, setTime: (value: number) => { time = value; },
        setState: (value: string) => { state = value; }, fail: () => { failState = true; },
        counts: () => ({ reads, creates, fetches }) };
}

test("same session/state reuses a client but reads live state on every hit", async () => {
    const f = fixture();
    const a = await f.pool.get(input());
    const b = await f.pool.get(input());
    assert.equal(a, b);
    assert.deepEqual(f.counts(), { reads: 2, creates: 1, fetches: 0 });
    assert.equal(f.pool.stats().hit, 1);
});

test("sessions and each security scope dimension are isolated", async () => {
    const f = fixture();
    const clients = [await f.pool.get(input())];
    clients.push(await f.pool.get(input({ header: "opaque-session-B" })));
    for (let i = 0; i < 6; i++) {
        const scope = [...input().scope]; scope[i] += "-other";
        clients.push(await f.pool.get(input({ scope })));
    }
    assert.equal(new Set(clients).size, 8);
});

for (const change of ["account-revoked-v2/registry-v1", "account-v1/registry-upgraded-v2"]) {
    test(`state change ${change} cannot reuse already approved keys`, async () => {
        const f = fixture();
        const approved = await f.pool.get(input());
        await approved.fetchKeys(args);
        f.setState(change);
        const changed = await f.pool.get(input());
        assert.notEqual(changed, approved);
        await changed.fetchKeys(args);
        assert.equal(f.counts().fetches, 2, "new SDK must perform policy authorization again");
    });
}

test("RPC failure never falls back to a warm authorization", async () => {
    const f = fixture();
    await f.pool.get(input());
    f.fail();
    await assert.rejects(f.pool.get(input()), /RPC unavailable/);
    assert.equal(f.counts().creates, 1);
});

test("five-minute cache lease rotates without rejecting a valid longer SDK session", async () => {
    const f = fixture({ idleMs: 600_000 });
    const longer = input({ expiresAt: 600_000 });
    const a = await f.pool.get(longer);
    f.setTime(299_999);
    assert.equal(await f.pool.get(longer), a);
    f.setTime(300_000);
    const b = await f.pool.get(longer);
    assert.notEqual(b, a, "five-minute lease must not slide on cache hits");
    await b.fetchKeys(args);
    f.setTime(600_000);
    await assert.rejects(b.fetchKeys(args), /expired/);
    f.pool.reset();
});

test("absolute expiry blocks even retained client references and in-flight results", async () => {
    const f = fixture();
    const client = await f.pool.get(input({ expiresAt: 10 }));
    f.setTime(10);
    await assert.rejects(f.pool.get(input({ expiresAt: 10 })), /expired/);
    await assert.rejects(client.fetchKeys(args), /expired/);
    await assert.rejects(client.decrypt({} as any), /expired/);
    assert.equal(f.pool.stats().entries, 0);
});

test("expiry during asynchronous key retrieval cannot return a usable cached result", async () => {
    let time = 0;
    let finish!: () => void;
    const gate = new Promise<void>(resolve => { finish = resolve; });
    const pool = createSealSessionPool(async () => ({ fetchKeys: () => gate, decrypt: async () => new Uint8Array() } as any),
        async () => "v1", { now: () => time });
    const client = await pool.get(input({ expiresAt: 10 }));
    const pending = client.fetchKeys(args);
    time = 10; finish();
    await assert.rejects(pending, /expired/);
    assert.equal(pool.stats().entries, 0);
});

test("concurrent cold requests coalesce both client creation and actual SDK fetchKeys", async () => {
    let creates = 0, fetches = 0;
    let finish!: () => void;
    const gate = new Promise<void>(resolve => { finish = resolve; });
    const pool = createSealSessionPool(async () => {
        creates++;
        return { fetchKeys: async () => { fetches++; await gate; }, decrypt: async () => new Uint8Array() } as any;
    }, async () => "v1", { now: () => 0 });
    const clients = await Promise.all(Array.from({ length: 12 }, () => pool.get(input())));
    assert.equal(creates, 1);
    const requests = clients.map(client => client.fetchKeys(args));
    await Promise.resolve();
    assert.equal(fetches, 1);
    finish(); await Promise.all(requests);
    assert.equal(pool.stats().keyJoin, 11);
});

test("failed creation and failed key retrieval are evicted; a later request recovers", async () => {
    let creates = 0;
    const pool = createSealSessionPool(async () => {
        creates++;
        if (creates === 1) throw new Error("creation failed");
        const fail = creates === 2;
        return { fetchKeys: async () => { if (fail) throw new Error("keys denied"); }, decrypt: async () => new Uint8Array() } as any;
    }, async () => "v1", { now: () => 0 });
    await assert.rejects(pool.get(input()), /creation failed/);
    await assert.rejects((await pool.get(input())).fetchKeys(args), /keys denied/);
    await (await pool.get(input())).fetchKeys(args);
    assert.equal(creates, 3);
});

test("idle expiry, LRU and per-client identity budget keep retained state bounded", async () => {
    const f = fixture({ maxEntries: 2, maxIds: 2, idleMs: 100 });
    const a = await f.pool.get(input());
    await f.pool.get(input({ header: "B" }));
    await f.pool.get(input());
    await f.pool.get(input({ header: "C" }));
    assert.equal(f.pool.stats().entries, 2);
    assert.equal(await f.pool.get(input()), a, "recent entry survives LRU");
    assert.equal(f.pool.stats().lru, 1);
    const rotated = await f.pool.get(input({ ids: ["second", "third"] }));
    assert.notEqual(rotated, a);
    assert.equal(f.pool.stats().capacity, 1);
    await assert.rejects(rotated.fetchKeys(args), /Unreserved/);
    f.setTime(100);
    assert.equal(f.pool.stats().entries, 0);
    await f.pool.get(input()); f.pool.reset();
    assert.equal(f.pool.stats().entries, 0);
});

test("authorization state reader requires current versions and digests of both objects", async () => {
    const seen: string[] = [];
    const reader = { getObject: async ({ objectId }: { objectId: string }) => {
        seen.push(objectId); return { object: { version: "7", digest: `digest-${objectId}` } };
    } };
    assert.deepEqual(JSON.parse(await readSealAuthorizationVersions(reader, "account", "registry")),
        [["account", "7", "digest-account"], ["registry", "7", "digest-registry"]]);
    assert.deepEqual(seen.sort(), ["account", "registry"]);
    for (const object of [null, {}, { version: "1" }, { version: "garbage", digest: "x" }]) {
        await assert.rejects(readSealAuthorizationVersions({ getObject: async () => ({ object }) }, "a", "r"), /Cannot verify/);
    }
});

test("readSealAuthorizationVersions batches getObjects, caches initialSharedVersion, and never shares an already-started read", async () => {
    clearCachedInitialSharedVersionsForTests();
    let batchCalls = 0;
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const acc = `0x${"3".repeat(64)}`;
    const reg = `0x${"9".repeat(64)}`;

    const batchedReader = {
        getObject: async () => {
            throw new Error("getObjects should be preferred when available");
        },
        getObjects: async ({ objectIds }: { objectIds: string[] }) => {
            const callNumber = ++batchCalls;
            if (callNumber === 1) await gate;
            return {
                objects: objectIds.map((_id, idx) => ({
                    version: String(10 + callNumber + idx),
                    digest: `d-${callNumber}-${idx}`,
                    owner: { $kind: "Shared", Shared: { initialSharedVersion: String(100 + idx) } },
                })),
            };
        },
    };

    const firstLookup = readSealAuthorizationVersions(batchedReader, acc, reg);
    await Promise.resolve();
    const secondLookup = readSealAuthorizationVersions(batchedReader, acc, reg);
    release();
    const [firstState, secondState] = await Promise.all([firstLookup, secondLookup]);
    assert.equal(batchCalls, 2, "each lookup must issue its own BatchGetObjects read after arrival");
    assert.notEqual(firstState, secondState);
    assert.equal(getCachedInitialSharedVersion(acc), "100");
    assert.equal(getCachedInitialSharedVersion(reg), "101");
});

test("revoke between auth snapshot and concurrent lookup never reuses pre-revocation warm session", async () => {
    clearCachedInitialSharedVersionsForTests();
    const acc = `0x${"3".repeat(64)}`;
    const reg = `0x${"9".repeat(64)}`;
    let accountVersion = 1;
    const registryVersion = 10;
    let pauseNextAfterSnapshot = false;
    let releaseInFlight!: () => void;
    const inFlightGate = new Promise<void>((r) => { releaseInFlight = r; });
    let snapshotEntered!: () => void;
    const snapshotReady = new Promise<void>((r) => { snapshotEntered = r; });
    let creates = 0;
    let fetches = 0;

    const batchedReader = {
        getObject: async () => {
            throw new Error("getObjects should be preferred");
        },
        getObjects: async () => {
            // Fullnode snapshots on-chain state at RPC receipt time (t1).
            const snapAcc = accountVersion;
            const snapReg = registryVersion;
            if (pauseNextAfterSnapshot) {
                pauseNextAfterSnapshot = false;
                snapshotEntered();
                await inFlightGate;
            }
            return {
                objects: [
                    {
                        version: String(snapAcc),
                        digest: `acc-digest-v${snapAcc}`,
                        owner: { $kind: "Shared", Shared: { initialSharedVersion: "200" } },
                    },
                    {
                        version: String(snapReg),
                        digest: `reg-digest-v${snapReg}`,
                        owner: { $kind: "Shared", Shared: { initialSharedVersion: "201" } },
                    },
                ],
            };
        },
    };

    const pool = createSealSessionPool(
        async () => {
            creates += 1;
            return {
                async fetchKeys() { fetches += 1; },
                async decrypt() { return Uint8Array.of(7); },
            } as unknown as SealClient;
        },
        (scope) => readSealAuthorizationVersions(batchedReader, scope[3], scope[4]),
        { now: () => 0 },
    );

    const sessionScope = ["testnet", "package", "policy", acc, reg, "committee"];
    const warmClient = await pool.get(input({ scope: sessionScope }));
    await warmClient.fetchKeys(args);
    assert.equal(creates, 1);
    assert.equal(fetches, 1);
    assert.equal(hasSealSessionApprovedKeys(warmClient, ["id"], 1), true);

    // Lookup A arrives before revocation and snapshots v1 on the fullnode (t1),
    // while its network response remains in flight.
    pauseNextAfterSnapshot = true;
    const lookupA = pool.get(input({ scope: sessionScope }));
    await snapshotReady;

    // Owner revokes delegate on-chain at t2 > t1, bumping MemWalAccount to v2.
    accountVersion = 2;

    // Lookup B arrives at t3 > t2 while Lookup A's RPC response is still returning.
    const lookupB = pool.get(input({ scope: sessionScope }));
    releaseInFlight();

    const [clientA, clientB] = await Promise.all([lookupA, lookupB]);
    assert.equal(clientA, warmClient, "pre-revocation lookup may use the v1 snapshot taken after it started");
    assert.notEqual(
        clientB,
        warmClient,
        "post-revocation lookup must never join Lookup A's older v1 snapshot",
    );
    assert.equal(
        hasSealSessionApprovedKeys(clientB, ["id"], 1),
        false,
        "post-revocation client must have zero approved keys and force fresh policy evaluation",
    );
    await clientB.fetchKeys(args);
    assert.equal(creates, 2);
    assert.equal(fetches, 2, "post-revocation lookup must re-evaluate key-server policy");
});

test("hasSealSessionApprovedKeys tracks approved thresholds per identity and enforces liveness", async () => {
    const f = fixture();
    const client = await f.pool.get(input({ ids: ["id-1", "id-2"] }));
    assert.equal(hasSealSessionApprovedKeys(client, ["id-1"], 2), false);

    await client.fetchKeys({ ...args, ids: ["id-1"], threshold: 2 });
    assert.equal(hasSealSessionApprovedKeys(client, ["id-1"], 2), true);
    assert.equal(hasSealSessionApprovedKeys(client, ["id-1"], 3), false);
    assert.equal(hasSealSessionApprovedKeys(client, ["id-1", "id-2"], 2), false);

    f.setTime(10_000);
    assert.throws(() => assertSealSessionClientLive(client), /expired/);
    assert.throws(() => hasSealSessionApprovedKeys(client, ["id-1"], 2), /expired/);
});
