import test from "node:test";
import assert from "node:assert/strict";
import { SealClient, type SessionKey } from "@mysten/seal";
import { bcs } from "@mysten/sui/bcs";
import { fromBase64, fromHex } from "@mysten/sui/utils";
import { createSealDecryptClientFactory } from "../sidecar/seal-metadata.js";

type KeyServers = Awaited<ReturnType<SealClient["getKeyServers"]>>;
const SERVER_ID = `0x${"22".repeat(32)}`;
const PACKAGE_ID = `0x${"11".repeat(32)}`;

function metadata(revision = 1): KeyServers {
    return new Map([[SERVER_ID, {
        objectId: SERVER_ID,
        name: `server-${revision}`,
        url: `https://seal-${revision}.invalid`,
        keyType: 0,
        pk: Uint8Array.of(revision, 2, 3),
        serverType: "Independent",
    }]]);
}

function deferred<T>() {
    let resolve!: (value: T) => void;
    let reject!: (reason: unknown) => void;
    const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
    return { promise, resolve, reject };
}

function fakeClient(getKeyServers: () => Promise<KeyServers>): SealClient {
    return { getKeyServers } as SealClient;
}

test("concurrent cold requests share one verified metadata load and each get a fresh client", async () => {
    const load = deferred<KeyServers>();
    const verificationModes: boolean[] = [];
    let metadataReads = 0;
    let now = 0;
    const factory = createSealDecryptClientFactory(({ verifyKeyServers }) => {
        verificationModes.push(verifyKeyServers);
        return fakeClient(async () => {
            metadataReads++;
            assert.equal(verifyKeyServers, true, "only the verifier may read metadata");
            return load.promise;
        });
    }, { now: () => now });

    const requests = Array.from({ length: 12 }, () => factory.create());
    await Promise.resolve();
    assert.equal(metadataReads, 1);
    load.resolve(metadata());
    const clients = await Promise.all(requests);
    assert.equal(new Set(clients).size, 12);
    assert.deepEqual(verificationModes, [true, ...Array(12).fill(false)]);

    now = 5 * 60 * 1000 - 1;
    const warm = await factory.create();
    assert.ok(clients.every(client => client !== warm));
    for (const client of [...clients, warm]) {
        assert.equal((await client.getKeyServers()).get(SERVER_ID)!.name, "server-1");
    }
    assert.equal(metadataReads, 1, "warm clients make zero metadata reads");
    now++;
    await factory.create();
    assert.equal(metadataReads, 2, "the default trust window is exactly five minutes");
    assert.equal(verificationModes.filter(Boolean).length, 2);
});

test("TTL starts after successful verification and refresh picks up rotated metadata", async () => {
    let now = 0;
    let revision = 1;
    let verificationCount = 0;
    const firstLoad = deferred<KeyServers>();
    const factory = createSealDecryptClientFactory(({ verifyKeyServers }) => {
        return fakeClient(async () => {
            assert.equal(verifyKeyServers, true);
            verificationCount++;
            return verificationCount === 1 ? firstLoad.promise : metadata(revision);
        });
    }, { metadataTtlMs: 100, now: () => now });

    const pending = factory.create();
    await Promise.resolve();
    now = 80;
    firstLoad.resolve(metadata());
    const oldClient = await pending;
    revision = 2;
    now = 179;
    assert.equal((await (await factory.create()).getKeyServers()).get(SERVER_ID)!.name, "server-1");
    assert.equal(verificationCount, 1);

    now = 180;
    const rotated = (await (await factory.create()).getKeyServers()).get(SERVER_ID)!;
    assert.equal(verificationCount, 2, "refresh must verify again");
    assert.equal(rotated.url, "https://seal-2.invalid");
    assert.deepEqual(rotated.pk, Uint8Array.of(2, 2, 3));
    assert.equal((await oldClient.getKeyServers()).get(SERVER_ID)!.name, "server-1");
});

for (const failure of ["metadata RPC unavailable", "invalid proof of possession"]) {
    test(`${failure} is not cached and expired metadata is never a fallback`, async () => {
        let now = 0;
        let shouldFail = true;
        let metadataReads = 0;
        let requestClients = 0;
        const factory = createSealDecryptClientFactory(({ verifyKeyServers }) => {
            if (!verifyKeyServers) requestClients++;
            return fakeClient(async () => {
                metadataReads++;
                if (shouldFail) throw new Error(failure);
                return metadata(metadataReads);
            });
        }, { metadataTtlMs: 100, now: () => now });

        const cold = await Promise.allSettled([factory.create(), factory.create()]);
        assert.ok(cold.every(result => result.status === "rejected"));
        assert.equal(metadataReads, 1, "concurrent callers share the failed load");
        assert.equal(requestClients, 0);
        shouldFail = false;
        assert.equal((await (await factory.create()).getKeyServers()).get(SERVER_ID)!.name, "server-2");

        now = 100;
        shouldFail = true;
        await assert.rejects(factory.create(), { message: failure });
        assert.equal(requestClients, 1, "expiry failure cannot return a stale request client");
        shouldFail = false;
        assert.equal((await (await factory.create()).getKeyServers()).get(SERVER_ID)!.name, "server-4");
        assert.equal(metadataReads, 4, "the request after a failure retries verification immediately");
    });
}

test("loader and request mutations cannot poison shared metadata", async () => {
    const loaded = metadata();
    const loaderServer = loaded.get(SERVER_ID)!;
    const factory = createSealDecryptClientFactory(() => fakeClient(async () => loaded));
    const first = await factory.create();

    loaderServer.name = "poisoned loader";
    loaderServer.pk.fill(99);
    loaded.clear();
    const a = await first.getKeyServers();
    const b = await first.getKeyServers();
    assert.notEqual(a, b);
    assert.notEqual(a.get(SERVER_ID), b.get(SERVER_ID));
    assert.notEqual(a.get(SERVER_ID)!.pk, b.get(SERVER_ID)!.pk);
    a.get(SERVER_ID)!.name = "poisoned request";
    a.get(SERVER_ID)!.url = "https://attacker.invalid";
    a.get(SERVER_ID)!.pk.fill(88);
    a.delete(SERVER_ID);
    a.set("unexpected", { ...loaderServer });

    for (const servers of [b, await first.getKeyServers(), await (await factory.create()).getKeyServers()]) {
        assert.deepEqual(servers, metadata());
    }
});

test("reset isolates a completed old generation from the replacement snapshot", async () => {
    const oldLoad = deferred<KeyServers>();
    let loads = 0;
    const factory = createSealDecryptClientFactory(() => fakeClient(async () => {
        loads++;
        return loads === 1 ? oldLoad.promise : metadata(2);
    }));
    const oldRequest = factory.create();
    await Promise.resolve();
    factory.reset();
    const replacement = await factory.create();
    oldLoad.resolve(metadata(1));
    await oldRequest;
    assert.deepEqual(await replacement.getKeyServers(), metadata(2));
    assert.deepEqual(await (await factory.create()).getKeyServers(), metadata(2));
    assert.equal(loads, 2);
});

test("a rejected pre-reset load cannot clear a replacement that is still in flight", async () => {
    const oldLoad = deferred<KeyServers>();
    const replacementLoad = deferred<KeyServers>();
    let loads = 0;
    const factory = createSealDecryptClientFactory(() => fakeClient(async () => {
        loads++;
        return loads === 1 ? oldLoad.promise : replacementLoad.promise;
    }));
    const oldRequest = factory.create();
    const oldRejected = assert.rejects(oldRequest, /old load failed/);
    await Promise.resolve();
    factory.reset();
    const replacement = factory.create();
    await Promise.resolve();
    oldLoad.reject(new Error("old load failed"));
    await oldRejected;
    const concurrent = factory.create();
    await Promise.resolve();
    assert.equal(loads, 2, "the new request must join the replacement load");
    replacementLoad.resolve(metadata(2));
    const clients = await Promise.all([replacement, concurrent]);
    assert.notEqual(clients[0], clients[1]);
    assert.deepEqual(await clients[0].getKeyServers(), metadata(2));
});

// Fixed offline BLS fixtures: server secret = 7, ephemeral secret = 1,
// ElGamal randomness = 1, and identity PACKAGE_ID || aabb. The PoP signs
// SUI-SEAL-IBE-BLS12381-POP-00 || pk || SERVER_ID. No test imports SDK internals.
const PUBLIC_KEY = "jQJz9r8x7TfDuNaAg+w9jiC18swXD6JLm1vjWzTtAT+akh8crRZE1L2xRnQkcjTIBJzR27LSw1geVMCIE1/vNlBaaCPWG4WUN7/Hm2FwMNyLQOMrrR+oW5wPNor20408";
const POP = "hh2p6OLoLoWRGwV1OIBtkcE7oF5uYHZPqE6BPeXvQ9aKbdU5UJubSDEKmQFRBLNc";
const ENCRYPTED_KEY = [
    "l/HTpzGX15QmlWOMT6msD8NojE+XdLkFoU46PxcbrFhsVeg/+Xoa7/s68ArbIsa7",
    "kB+jTmJCA4K4HzxJ0CCO6RQ89jqnAzsCd/t6DPo3DbBs797/xF2ZfbmjjXvXT4qr",
];
const VERIFICATION_KEY = "k+ArYFJxn2B9rNOgiCdPZVlr0NCZILYatdphu9x/UEkzTPESE5RdV+WsfQVdBCt+AkqisvCPCpEmCAUnLcUQUcbketT6QDsCtFELZHrj0XcLrAMmqAW779SAVsjBIb24";

test("actual Seal SDK saves metadata reads while every request fetches and authorizes its own keys", async t => {
    const parentBytes = bcs.struct("KeyServer", {
        id: bcs.Address,
        firstVersion: bcs.u64(),
        lastVersion: bcs.u64(),
    }).serialize({ id: SERVER_ID, firstVersion: 1, lastVersion: 1 }).toBytes();
    const serverBytes = bcs.struct("KeyServerV1", {
        name: bcs.string(),
        url: bcs.string(),
        keyType: bcs.u8(),
        pk: bcs.byteVector(),
    }).serialize({ name: "offline server", url: "https://seal.invalid", keyType: 0, pk: fromBase64(PUBLIC_KEY) }).toBytes();
    const counts = { object: 0, dynamicField: 0, pop: 0, fetchKey: 0, certificate: 0, signedRequest: 0 };
    const resetCounts = () => { for (const key of Object.keys(counts)) counts[key as keyof typeof counts] = 0; };
    const suiClient = {
        core: {
            async getObject({ objectId }: { objectId: string }) {
                if (objectId === PACKAGE_ID) return { object: { version: "1" } };
                assert.equal(objectId, SERVER_ID);
                counts.object++;
                return { object: { content: parentBytes } };
            },
            async getDynamicField({ parentId }: { parentId: string }) {
                assert.equal(parentId, SERVER_ID);
                counts.dynamicField++;
                return { dynamicField: { value: { bcs: serverBytes } } };
            },
        },
    } as unknown as ConstructorParameters<typeof SealClient>[0]["suiClient"];
    const makeClient = ({ verifyKeyServers }: { verifyKeyServers: boolean }) => new SealClient({
        suiClient,
        serverConfigs: [{ objectId: SERVER_ID, weight: 1 }],
        verifyKeyServers,
    });
    let rejectProof = false;
    t.mock.method(globalThis, "fetch", async (input: string | URL | Request, init?: RequestInit) => {
        const url = String(input);
        if (url === `https://seal.invalid/v1/service?service_id=${SERVER_ID}`) {
            counts.pop++;
            return Response.json({ service_id: rejectProof ? "wrong-service" : SERVER_ID, pop: POP }, {
                headers: { "X-KeyServer-Version": "0.4.1" },
            });
        }
        assert.equal(url, "https://seal.invalid/v1/fetch_key", "unexpected network request");
        assert.equal(init?.method, "POST");
        const body = JSON.parse(String(init.body));
        assert.match(body.request_signature, /^allowed-/);
        assert.equal(body.certificate.label, body.request_signature.slice("allowed-".length));
        assert.equal(body.ptb, "AgM=");
        counts.fetchKey++;
        return Response.json({ decryption_keys: [{
            id: Array.from(fromHex(`${PACKAGE_ID}aabb`)),
            encrypted_key: ENCRYPTED_KEY,
        }] }, { headers: { "X-KeyServer-Version": "0.4.1" } });
    });
    function session(label: string, allowed = true): SessionKey {
        return {
            getPackageId: () => PACKAGE_ID,
            async getCertificate() {
                counts.certificate++;
                if (!allowed) throw new Error("SessionKey authorization denied");
                return { label };
            },
            async createRequestParams() {
                counts.signedRequest++;
                const encKey = new Uint8Array(32);
                encKey[31] = 1;
                return {
                    requestSignature: `allowed-${label}`,
                    encKey,
                    encKeyPk: fromBase64(ENCRYPTED_KEY[0]),
                    encVerificationKey: fromBase64(VERIFICATION_KEY),
                };
            },
        } as unknown as SessionKey;
    }
    const plaintext = new TextEncoder().encode("metadata can be shared; authorization cannot");
    const encrypted = await makeClient({ verifyKeyServers: true }).encrypt({
        packageId: PACKAGE_ID, id: "aabb", threshold: 1, data: plaintext,
    });
    const decrypt = (client: SealClient, key: SessionKey) => client.decrypt({
        data: encrypted.encryptedObject, sessionKey: key, txBytes: Uint8Array.of(1, 2, 3),
    });

    // The prior path verifies once, then repeats Sui metadata reads in each
    // fresh decrypt client even though those clients disable PoP verification.
    resetCounts();
    await makeClient({ verifyKeyServers: true }).getKeyServers();
    for (let i = 0; i < 3; i++) {
        assert.deepEqual(await decrypt(makeClient({ verifyKeyServers: false }), session(`baseline-${i}`)), plaintext);
    }
    assert.deepEqual(counts, { object: 4, dynamicField: 4, pop: 1, fetchKey: 3, certificate: 3, signedRequest: 3 });

    // This control demonstrates why globally sharing the SDK client is unsafe:
    // its cached derived key lets a subsequent denied SessionKey decrypt.
    resetCounts();
    const sharedClient = makeClient({ verifyKeyServers: true });
    await decrypt(sharedClient, session("shared-first"));
    assert.deepEqual(await decrypt(sharedClient, session("denied", false)), plaintext);
    assert.equal(counts.certificate, 1);
    assert.equal(counts.fetchKey, 1);

    resetCounts();
    const factory = createSealDecryptClientFactory(makeClient);
    for (let i = 0; i < 3; i++) {
        assert.deepEqual(await decrypt(await factory.create(), session(`factory-${i}`)), plaintext);
    }
    assert.deepEqual(counts, { object: 1, dynamicField: 1, pop: 1, fetchKey: 3, certificate: 3, signedRequest: 3 });
    await assert.rejects(decrypt(await factory.create(), session("denied", false)), /SessionKey authorization denied/);
    assert.equal(counts.certificate, 4, "the second principal must authorize despite warm metadata");
    assert.equal(counts.fetchKey, 3, "a denied certificate stops the request before key fetch");

    // Exercise an actual SDK PoP rejection as well as the unit failure cases.
    factory.reset();
    rejectProof = true;
    await assert.rejects(factory.create(), /not valid/);
    rejectProof = false;
    await factory.create();
    assert.equal(counts.object, 3);
    assert.equal(counts.dynamicField, 3);
    assert.equal(counts.pop, 3, "failed verification is retried by the next request");
});
