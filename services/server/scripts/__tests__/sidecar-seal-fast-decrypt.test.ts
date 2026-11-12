import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { EncryptedObject, type SealClient, type SessionKey } from "@mysten/seal";
import {
    combineSharesGF256,
    decryptBonehFranklinItem,
    decryptBonehFranklinSlice,
    FallbackShareSubsetError,
} from "../sidecar/seal-decrypt-crypto.mjs";
import {
    decryptBatchSealItems,
    decryptSingleSealItem,
    stopSealDecryptPool,
} from "../sidecar/seal-decrypt-pool.js";

const sealEntryUrl = import.meta.resolve("@mysten/seal");
const sealRequire = createRequire(sealEntryUrl);
const [
    { bls12_381 },
    { bytesToNumberBE },
    { fromHex, toHex },
    { encrypt: sealEncryptRaw },
    { decrypt: sealDecryptRaw },
    { AesGcm256, Hmac256Ctr },
    { split: sealShamirSplit, combine: sealShamirCombine },
] = await Promise.all([
    import(pathToFileURL(sealRequire.resolve("@noble/curves/bls12-381.js")).href),
    import(pathToFileURL(sealRequire.resolve("@noble/curves/utils.js")).href),
    import(pathToFileURL(sealRequire.resolve("@mysten/bcs")).href),
    import(new URL("./encrypt.mjs", sealEntryUrl).href),
    import(new URL("./decrypt.mjs", sealEntryUrl).href),
    import(new URL("./dem.mjs", sealEntryUrl).href),
    import(new URL("./shamir.mjs", sealEntryUrl).href),
]);

const PKG = `0x${"ab".repeat(32)}`;
const SERVER_IDS = [
    `0x${"11".repeat(32)}`,
    `0x${"22".repeat(32)}`,
    `0x${"33".repeat(32)}`,
];
const DST = Buffer.from("SUI-SEAL-IBE-BLS12381-00", "utf8");

function makeCommittee(weights: number[]) {
    const masterScalars = weights.map(() => {
        const skBytes = bls12_381.utils.randomSecretKey();
        return bytesToNumberBE(skBytes) % bls12_381.fields.Fr.ORDER;
    });
    const weightedKeyServers: Array<{
        objectId: string;
        name: string;
        url: string;
        keyType: number;
        pk: Uint8Array;
        serverType: string;
    }> = [];
    const serverWeights = new Map<string, number>();
    let totalWeight = 0;

    weights.forEach((weight, idx) => {
        const objectId = SERVER_IDS[idx];
        const pk = bls12_381.G2.Point.BASE.multiply(masterScalars[idx]).toBytes();
        serverWeights.set(objectId, weight);
        totalWeight += weight;
        for (let w = 0; w < weight; w++) {
            weightedKeyServers.push({
                objectId,
                name: `ks-${idx}`,
                url: `https://ks-${idx}.example`,
                keyType: 0,
                pk,
                serverType: "Independent",
            });
        }
    });

    function deriveUserSecretKeys(innerIdHex: string) {
        const pkgBytes = fromHex(PKG.slice(2));
        const idBytes = fromHex(innerIdHex);
        const fullIdBytes = new Uint8Array(pkgBytes.length + idBytes.length);
        fullIdBytes.set(pkgBytes, 0);
        fullIdBytes.set(idBytes, pkgBytes.length);
        const fullIdHex = toHex(fullIdBytes);

        const dstInput = new Uint8Array(DST.length + fullIdBytes.length);
        dstInput.set(DST, 0);
        dstInput.set(fullIdBytes, DST.length);
        const hPoint = bls12_381.G1.Point.fromAffine(bls12_381.G1.hashToCurve(dstInput).toAffine());

        const sdkKeys = new Map<string, any>();
        const fastKeys = new Map<string, Uint8Array>();

        weights.forEach((_, idx) => {
            const objectId = SERVER_IDS[idx];
            const uskPoint = hPoint.multiply(masterScalars[idx]);
            const uskBytes = uskPoint.toBytes();
            fastKeys.set(objectId, uskBytes);
            sdkKeys.set(`${fullIdHex}:${objectId}`, {
                point: uskPoint,
                pairing(other: { point: any }) {
                    const elem = bls12_381.pairing(uskPoint, other.point);
                    return {
                        toBytes() {
                            const raw = bls12_381.fields.Fp12.toBytes(elem);
                            const out = new Uint8Array(576);
                            const perm = [0, 3, 1, 4, 2, 5];
                            for (let i = 0; i < 6; i++) {
                                out.set(raw.subarray(perm[i] * 96, (perm[i] + 1) * 96), i * 96);
                            }
                            return out;
                        },
                    };
                },
            });
        });

        return { fullIdHex, sdkKeys, fastKeys };
    }

    async function encryptPayload(
        innerIdHex: string,
        plaintext: Uint8Array,
        threshold: number,
        dem: "aes" | "hmac" = "aes",
        aad: Uint8Array = new Uint8Array(0),
    ): Promise<Uint8Array> {
        const encryptionInput = dem === "aes" ? new AesGcm256(plaintext, aad) : new Hmac256Ctr(plaintext, aad);
        const { encryptedObject } = await sealEncryptRaw({
            keyServers: weightedKeyServers,
            kemType: 0,
            threshold,
            packageId: PKG,
            id: innerIdHex,
            encryptionInput,
        });
        return encryptedObject;
    }

    return { serverWeights, totalWeight, deriveUserSecretKeys, encryptPayload };
}

test.after(async () => {
    await stopSealDecryptPool();
});

test("fast Boneh-Franklin decrypt matches @mysten/seal byte-for-byte across AES-GCM, HMAC-CTR, subsets, and weighted committees", async () => {
    for (const weights of [[1, 1, 1], [2, 1]]) {
        const committee = makeCommittee(weights);
        const innerId = "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff";
        const { sdkKeys, fastKeys } = committee.deriveUserSecretKeys(innerId);

        for (const dem of ["aes", "hmac"] as const) {
            for (const size of [0, 1, 31, 32, 33, 1024, 16_384]) {
                const plaintext = Buffer.alloc(size, (size % 251) + 1);
                const aad = size % 2 === 0 ? new Uint8Array(0) : Buffer.from("memwal-aad");
                const encryptedData = await committee.encryptPayload(innerId, plaintext, 2, dem, aad);
                const parsed = EncryptedObject.parse(encryptedData);

                const expected = await sealDecryptRaw({
                    encryptedObject: parsed,
                    keys: sdkKeys,
                    checkLEEncoding: false,
                });

                // Test full 3-key map (threshold slicing to 2 pairings) and exact 2-key subsets.
                const subsets: Array<Map<string, Uint8Array>> = [fastKeys];
                if (weights.length === 3) {
                    subsets.push(
                        new Map([[SERVER_IDS[0], fastKeys.get(SERVER_IDS[0])!], [SERVER_IDS[1], fastKeys.get(SERVER_IDS[1])!]]),
                        new Map([[SERVER_IDS[0], fastKeys.get(SERVER_IDS[0])!], [SERVER_IDS[2], fastKeys.get(SERVER_IDS[2])!]]),
                        new Map([[SERVER_IDS[1], fastKeys.get(SERVER_IDS[1])!], [SERVER_IDS[2], fastKeys.get(SERVER_IDS[2])!]]),
                    );
                }

                for (const subset of subsets) {
                    const actual = decryptBonehFranklinItem({
                        encryptedData,
                        derivedKeysByObjectId: subset,
                        serverWeights: committee.serverWeights,
                        totalServerWeight: committee.totalWeight,
                    });
                    assert.deepEqual(Buffer.from(actual), Buffer.from(expected));
                    assert.deepEqual(Buffer.from(actual), plaintext);
                }
            }
        }
    }
});

test("fast decrypt rejects tampered ciphertext, tampered MAC, insufficient shares, and triggers subset fallback when needed", async () => {
    const committee = makeCommittee([1, 1, 1]);
    const innerId = "deadbeef01020304";
    const { fastKeys } = committee.deriveUserSecretKeys(innerId);
    const plaintext = Buffer.from("sensitive memory payload");

    const aesEncrypted = await committee.encryptPayload(innerId, plaintext, 2, "aes");
    const parsedAes = EncryptedObject.parse(new Uint8Array(aesEncrypted));
    parsedAes.ciphertext.Aes256Gcm.blob[0] ^= 0xff;
    const tamperedAesBytes = EncryptedObject.serialize(parsedAes).toBytes();
    assert.throws(
        () =>
            decryptBonehFranklinItem({
                encryptedData: tamperedAesBytes,
                derivedKeysByObjectId: fastKeys,
                serverWeights: committee.serverWeights,
                totalServerWeight: committee.totalWeight,
            }),
        /Decryption failed/,
    );

    const hmacEncrypted = await committee.encryptPayload(innerId, plaintext, 2, "hmac");
    const parsedHmac = EncryptedObject.parse(new Uint8Array(hmacEncrypted));
    parsedHmac.ciphertext.Hmac256Ctr.mac[0] ^= 0xff;
    const tamperedHmacBytes = EncryptedObject.serialize(parsedHmac).toBytes();
    assert.throws(
        () =>
            decryptBonehFranklinItem({
                encryptedData: tamperedHmacBytes,
                derivedKeysByObjectId: fastKeys,
                serverWeights: committee.totalWeight ? committee.serverWeights : undefined,
                totalServerWeight: committee.totalWeight,
            }),
        /Invalid MAC/,
    );

    // Only 1 share when threshold is 2 -> Not enough shares.
    const singleKey = new Map([[SERVER_IDS[0], fastKeys.get(SERVER_IDS[0])!]]);
    assert.throws(
        () =>
            decryptBonehFranklinItem({
                encryptedData: aesEncrypted,
                derivedKeysByObjectId: singleKey,
            }),
        /Not enough shares/,
    );

    // Corrupt share 0 while 3 keys are present -> raises FallbackShareSubsetError so coordinator can fall back.
    const parsedCorruptShare0 = EncryptedObject.parse(new Uint8Array(aesEncrypted));
    parsedCorruptShare0.encryptedShares.BonehFranklinBLS12381.encryptedShares[0][0] ^= 0xff;
    const corruptShare0Bytes = EncryptedObject.serialize(parsedCorruptShare0).toBytes();
    assert.throws(
        () =>
            decryptBonehFranklinItem({
                encryptedData: corruptShare0Bytes,
                derivedKeysByObjectId: fastKeys,
            }),
        FallbackShareSubsetError,
    );

    // Slice zeroes ephemeral key buffers in finally.
    const disposableKey = new Uint8Array(fastKeys.get(SERVER_IDS[0])!);
    const disposableKey2 = new Uint8Array(fastKeys.get(SERVER_IDS[1])!);
    const sliceOut = decryptBonehFranklinSlice({
        items: [{ index: 0, encryptedData: aesEncrypted, fullId: innerId }],
        derivedKeysById: [[innerId, [[SERVER_IDS[0], disposableKey], [SERVER_IDS[1], disposableKey2]]]],
    });
    assert.equal(sliceOut.results.length, 1);
    assert.equal(Buffer.from(sliceOut.results[0].decryptedData, "base64").toString("utf8"), "sensitive memory payload");
    assert.ok(disposableKey.every((b) => b === 0), "ephemeral derived key buffer must be zeroized");
    assert.ok(disposableKey2.every((b) => b === 0), "ephemeral derived key buffer 2 must be zeroized");
});

test("stateless worker_threads decrypt pool decrypts 25 items in parallel, preserves order, and enforces session expiry", async () => {
    const committee = makeCommittee([1, 1, 1]);
    const innerId = "cafebabe00112233";
    const { fastKeys } = committee.deriveUserSecretKeys(innerId);

    const items = await Promise.all(
        Array.from({ length: 25 }, async (_, index) => {
            const encryptedData = await committee.encryptPayload(
                innerId,
                Buffer.from(`memory-item-${index}-${"payload-".repeat(20)}`),
                2,
                index % 2 === 0 ? "aes" : "hmac",
            );
            return { index, encryptedData, fullId: innerId };
        }),
    );

    const mockSealClient = {
        async getDerivedKeys() {
            return new Map(
                Array.from(fastKeys, ([objId, bytes]) => [
                    objId,
                    { toString: () => toHex(bytes) },
                ]),
            );
        },
        async decrypt() {
            throw new Error("worker fast-path should handle all valid Boneh-Franklin items without fallback");
        },
    } as unknown as SealClient;

    let getTxBytesCalls = 0;
    const out = await decryptBatchSealItems({
        sealClient: mockSealClient,
        parsedItems: items,
        uniqueIds: [innerId],
        sessionKey: {} as SessionKey,
        getTxBytes: async () => {
            getTxBytesCalls += 1;
            return Uint8Array.of(1);
        },
    });

    assert.equal(out.errors.length, 0);
    assert.equal(out.results.length, 25);
    assert.equal(getTxBytesCalls, 1);
    for (let i = 0; i < 25; i++) {
        assert.equal(out.results[i].index, i);
        assert.equal(
            Buffer.from(out.results[i].decryptedData, "base64").toString("utf8"),
            `memory-item-${i}-${"payload-".repeat(20)}`,
        );
    }

    // Expired session during or after worker execution must reject before returning plaintext.
    let checks = 0;
        await assert.rejects(
        () =>
            decryptBatchSealItems({
                sealClient: mockSealClient,
                parsedItems: items.slice(0, 4),
                uniqueIds: [innerId],
                sessionKey: {} as SessionKey,
                getTxBytes: async () => Uint8Array.of(1),
                assertLive: () => {
                    checks += 1;
                    if (checks >= 2) throw new Error("SEAL session expired");
                },
            }),
        /SEAL session expired/,
    );
});

test("threshold=1 single-server MPC committee ciphertexts and GF(256) denom=1 subsets match @mysten/seal without fallback", async () => {
    const committee = makeCommittee([1]);
    const innerId = "686098f1439237fff9f36b99c7329683c22979d2005c2465cb891acb012a7595";
    const { sdkKeys, fastKeys } = committee.deriveUserSecretKeys(innerId);

    const mockSealClient = {
        async getDerivedKeys() {
            return new Map(
                Array.from(fastKeys, ([objId, bytes]) => [
                    objId,
                    { toString: () => toHex(bytes) },
                ]),
            );
        },
        async decrypt() {
            throw new Error("fast Boneh-Franklin path must decrypt threshold=1 committee items without fallback");
        },
    } as unknown as SealClient;

    for (const dem of ["aes", "hmac"] as const) {
        const plaintext = Buffer.from(`mainnet-committee-${dem}-payload`);
        const encryptedData = await committee.encryptPayload(innerId, plaintext, 1, dem);
        const parsed = EncryptedObject.parse(encryptedData);
        assert.equal(parsed.threshold, 1);

        const expected = await sealDecryptRaw({
            encryptedObject: parsed,
            keys: sdkKeys,
            checkLEEncoding: false,
        });
        const actualDirect = decryptBonehFranklinItem({
            encryptedData,
            parsedObject: parsed,
            derivedKeysByObjectId: fastKeys,
            serverWeights: committee.serverWeights,
            totalServerWeight: committee.totalWeight,
        });
        assert.deepEqual(Buffer.from(actualDirect), Buffer.from(expected));
        assert.deepEqual(Buffer.from(actualDirect), plaintext);

        const actualSingle = await decryptSingleSealItem({
            sealClient: mockSealClient,
            encryptedData,
            parsedObject: parsed,
            fullId: `${PKG}${innerId}`,
            sessionKey: {} as SessionKey,
            getTxBytes: async () => Uint8Array.of(1),
        });
        assert.deepEqual(Buffer.from(actualSingle), plaintext);

        const actualBatch = await decryptBatchSealItems({
            sealClient: mockSealClient,
            parsedItems: [{ index: 0, encryptedData, parsedObject: parsed, fullId: innerId }],
            uniqueIds: [innerId],
            sessionKey: {} as SessionKey,
            getTxBytes: async () => Uint8Array.of(1),
        });
        assert.equal(actualBatch.errors.length, 0);
        assert.deepEqual(Buffer.from(actualBatch.results[0].decryptedData, "base64"), plaintext);
    }

    // Verify Shamir GF(256) interpolation across threshold = 1, 2, 3, 5 AND k=2 subsets
    // where x_0 * (x_0 ^ x_1) === 1 in GF(256) (for example x_0 = 2, x_1 = 140 since 2 * 142 = 1 in Rijndael GF(2^8)).
    const secret = Uint8Array.from({ length: 32 }, (_, i) => (i * 37 + 13) & 0xff);
    for (const threshold of [1, 2, 3, 5]) {
        const allShares = sealShamirSplit(secret, threshold, 10);
        const subset = allShares.slice(0, threshold);
        assert.deepEqual(Buffer.from(combineSharesGF256(subset)), Buffer.from(sealShamirCombine(subset)));
        assert.deepEqual(Buffer.from(combineSharesGF256(subset)), Buffer.from(secret));
    }
    const all150 = sealShamirSplit(secret, 2, 150);
    // Test every index pair (2, idx) up to 150 to hit denom === 1 in GF(2^8) during k=2 interpolation.
    for (let idx = 1; idx <= 150; idx++) {
        if (idx === 2) continue;
        const pair = [all150[1], all150[idx - 1]];
        assert.deepEqual(Buffer.from(combineSharesGF256(pair)), Buffer.from(secret));
    }
});

test("session expiry during batch fallback or single-item post-check rejects instead of leaking fast-path plaintext", async () => {
    const committee = makeCommittee([1, 1, 1]);
    const innerId = "feedface01020304";
    const { fastKeys } = committee.deriveUserSecretKeys(innerId);

    const validCiphertext = await committee.encryptPayload(
        innerId,
        Buffer.from("secret-fast-path-memory"),
        2,
        "aes",
    );
    // Corrupt share 0 while 3 derived keys are available so item 1 raises FallbackShareSubsetError
    // and enters the per-item sealClient.decrypt fallback loop after item 0 already decrypted.
    const fallbackParsed = EncryptedObject.parse(new Uint8Array(validCiphertext));
    fallbackParsed.encryptedShares.BonehFranklinBLS12381.encryptedShares[0][0] ^= 0xff;
    const fallbackCiphertext = EncryptedObject.serialize(fallbackParsed).toBytes();

    const mixedItems = [
        { index: 0, encryptedData: validCiphertext, fullId: innerId, threshold: 2 },
        { index: 1, encryptedData: fallbackCiphertext, fullId: innerId, threshold: 2 },
    ];

    // Case 1: session expires while sealClient.decrypt succeeds on fallback item 1.
    let expired1 = false;
    const mockClient1 = {
        async getDerivedKeys() {
            return new Map(
                Array.from(fastKeys, ([objId, bytes]) => [objId, { toString: () => toHex(bytes) }]),
            );
        },
        async decrypt() {
            expired1 = true;
            return Buffer.from("fallback-plaintext");
        },
    } as unknown as SealClient;

    await assert.rejects(
        () =>
            decryptBatchSealItems({
                sealClient: mockClient1,
                parsedItems: mixedItems,
                uniqueIds: [innerId],
                sessionKey: {} as SessionKey,
                getTxBytes: async () => Uint8Array.of(1),
                assertLive: () => {
                    if (expired1) throw new Error("SEAL session expired");
                },
            }),
        /SEAL session expired/,
        "session expiry after fallback decrypt must reject the entire batch without returning item 0",
    );

    // Case 2: fallback item 1 throws a normal decrypt failure AFTER session expiry.
    let expired2 = false;
    const mockClient2 = {
        async getDerivedKeys() {
            return new Map(
                Array.from(fastKeys, ([objId, bytes]) => [objId, { toString: () => toHex(bytes) }]),
            );
        },
        async decrypt() {
            expired2 = true;
            throw new Error("corrupt fallback ciphertext");
        },
    } as unknown as SealClient;

    await assert.rejects(
        () =>
            decryptBatchSealItems({
                sealClient: mockClient2,
                parsedItems: mixedItems,
                uniqueIds: [innerId],
                sessionKey: {} as SessionKey,
                getTxBytes: async () => Uint8Array.of(1),
                assertLive: () => {
                    if (expired2) throw new Error("SEAL session expired");
                },
            }),
        /SEAL session expired/,
        "session expiry coinciding with fallback cipher error must reject the entire batch",
    );

    // Case 3: fallback sealClient.decrypt itself throws ExpiredSessionKeyError.
    const mockClient3 = {
        async getDerivedKeys() {
            return new Map(
                Array.from(fastKeys, ([objId, bytes]) => [objId, { toString: () => toHex(bytes) }]),
            );
        },
        async decrypt() {
            const err = new Error("Session key has expired");
            err.name = "ExpiredSessionKeyError";
            throw err;
        },
    } as unknown as SealClient;

    await assert.rejects(
        () =>
            decryptBatchSealItems({
                sealClient: mockClient3,
                parsedItems: mixedItems,
                uniqueIds: [innerId],
                sessionKey: {} as SessionKey,
                getTxBytes: async () => Uint8Array.of(1),
            }),
        /Session key has expired/,
        "ExpiredSessionKeyError from SDK fallback must propagate instead of becoming per-item DECRYPT_FAILED",
    );

    // Case 4: decryptSingleSealItem expiring right after fast-path decrypt must NOT fall through to sealClient.decrypt.
    let singleChecks = 0;
    let fallbackDecryptCalls = 0;
    const mockSingleClient = {
        async getDerivedKeys() {
            return new Map(
                Array.from(fastKeys, ([objId, bytes]) => [objId, { toString: () => toHex(bytes) }]),
            );
        },
        async decrypt() {
            fallbackDecryptCalls += 1;
            return Buffer.from("should-not-run");
        },
    } as unknown as SealClient;

    await assert.rejects(
        () =>
            decryptSingleSealItem({
                sealClient: mockSingleClient,
                encryptedData: validCiphertext,
                parsedObject: EncryptedObject.parse(validCiphertext),
                fullId: innerId,
                sessionKey: {} as SessionKey,
                getTxBytes: async () => Uint8Array.of(1),
                assertLive: () => {
                    singleChecks += 1;
                    if (singleChecks >= 3) throw new Error("SEAL session expired");
                },
            }),
        /SEAL session expired/,
    );
    assert.equal(fallbackDecryptCalls, 0, "post-decrypt session expiry must not enter fallback sealClient.decrypt");
});
