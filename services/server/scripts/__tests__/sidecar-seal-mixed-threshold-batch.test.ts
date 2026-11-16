import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import type { Server } from "node:http";
import { pathToFileURL } from "node:url";
import { bcs } from "@mysten/sui/bcs";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { fromBase64, fromHex, toBase64, toHex } from "@mysten/sui/utils";
import { SealClient, SessionKey } from "@mysten/seal";

const sealEntryUrl = import.meta.resolve("@mysten/seal");
const sealRequire = createRequire(sealEntryUrl);
const { bls12_381 } = await import(pathToFileURL(sealRequire.resolve("@noble/curves/bls12-381.js")).href);

const PACKAGE_ID = `0x${"ab".repeat(32)}`;
const POLICY_PKG_ID = `0x${"cd".repeat(32)}`;
const ACCOUNT_ID = `0x${"33".repeat(32)}`;
const REGISTRY_ID = `0x${"99".repeat(32)}`;
const SERVER_IDS = [
    `0x${"11".repeat(32)}`,
    `0x${"22".repeat(32)}`,
    `0x${"44".repeat(32)}`,
];

const POP_DST = Buffer.from("SUI-SEAL-IBE-BLS12381-POP-00", "utf8");
const IBE_DST = Buffer.from("SUI-SEAL-IBE-BLS12381-00", "utf8");

// Configure a genuine 3-server committee (weight 1 each) with SEAL_THRESHOLD=2 before loading sidecar modules.
process.env.SERVER_SUI_PRIVATE_KEYS = new Ed25519Keypair().getSecretKey();
process.env.SUI_NETWORK = "testnet";
process.env.SUI_GRPC_URL = "https://seal-mixed-threshold.testnet.example";
process.env.WALRUS_PACKAGE_ID = `0x${"aa".repeat(32)}`;
process.env.MEMWAL_SEAL_POLICY_PACKAGE_ID = POLICY_PKG_ID;
process.env.SEAL_SERVER_CONFIGS = JSON.stringify(
    SERVER_IDS.map((objectId) => ({ objectId, weight: 1 })),
);
process.env.SEAL_THRESHOLD = "2";
process.env.SEAL_KEY_SERVER_TIMEOUT_MS = "2000";

const express = (await import("express")).default;
const { suiClient, resetSealKeyServerTrustForTests } = await import("../sidecar/clients.js");
const { parseSealDecryptBatchItems, registerSealRoutes } = await import("../sidecar/routes/seal.js");
const { buildSealApproveTx } = await import("../sidecar/seal-ptb.js");
const { decryptBatchSealItems, stopSealDecryptPool } = await import("../sidecar/seal-decrypt-pool.js");

const KeyServerStruct = bcs.struct("KeyServer", {
    id: bcs.Address,
    firstVersion: bcs.u64(),
    lastVersion: bcs.u64(),
});
const KeyServerV1Struct = bcs.struct("KeyServerV1", {
    name: bcs.string(),
    url: bcs.string(),
    keyType: bcs.u8(),
    pk: bcs.byteVector(),
});

interface MockKeyServerFixture {
    objectId: string;
    url: string;
    scalar: bigint;
    secretKeyBytes: Uint8Array;
    pkBytes: Uint8Array;
    popBase64: string;
    parentBytes: Uint8Array;
    v1Bytes: Uint8Array;
}

function buildKeyServerFixtures(): MockKeyServerFixture[] {
    return SERVER_IDS.map((objectId, idx) => {
        const scalar = BigInt(11 + idx * 7);
        const secretKeyBytes = new Uint8Array(32);
        secretKeyBytes[31] = Number(scalar);
        const pkBytes = bls12_381.G2.Point.BASE.multiply(scalar).toBytes();
        const objectIdBytes = fromHex(objectId);
        const popMsg = new Uint8Array(POP_DST.length + pkBytes.length + objectIdBytes.length);
        popMsg.set(POP_DST, 0);
        popMsg.set(pkBytes, POP_DST.length);
        popMsg.set(objectIdBytes, POP_DST.length + pkBytes.length);
        const popSig = bls12_381.shortSignatures.sign(
            bls12_381.shortSignatures.hash(popMsg),
            secretKeyBytes,
        );
        const popSigBytes = popSig instanceof Uint8Array ? popSig : popSig.toBytes();
        const url = `https://seal-ks-${idx}.invalid`;
        return {
            objectId,
            url,
            scalar,
            secretKeyBytes,
            pkBytes,
            popBase64: toBase64(popSigBytes),
            parentBytes: KeyServerStruct.serialize({
                id: objectId,
                firstVersion: 1,
                lastVersion: 1,
            }).toBytes(),
            v1Bytes: KeyServerV1Struct.serialize({
                name: `ks-${idx}`,
                url,
                keyType: 0,
                pk: pkBytes,
            }).toBytes(),
        };
    });
}

function elgamalEncryptDerivedKey(scalar: bigint, fullIdHex: string, encKeyPkBase64: string): [string, string] {
    const fullIdBytes = fromHex(fullIdHex);
    const dstInput = new Uint8Array(IBE_DST.length + fullIdBytes.length);
    dstInput.set(IBE_DST, 0);
    dstInput.set(fullIdBytes, IBE_DST.length);
    const hPoint = bls12_381.G1.Point.fromAffine(bls12_381.G1.hashToCurve(dstInput).toAffine());
    const uskPoint = hPoint.multiply(scalar);
    const encKeyPkPoint = bls12_381.G1.Point.fromBytes(fromBase64(encKeyPkBase64));
    // ElGamal randomness r = 1: c0 = G1 * 1, c1 = usk + encKeyPk * 1.
    const c0 = bls12_381.G1.Point.BASE.toBytes();
    const c1 = uskPoint.add(encKeyPkPoint).toBytes();
    return [toBase64(c0), toBase64(c1)];
}

test.after(async () => {
    await stopSealDecryptPool();
});

test("/seal/decrypt-batch preserves threshold-2 items when a threshold-3 key fetch fails during partial key-server outage", async (t) => {
    resetSealKeyServerTrustForTests();
    const fixtures = buildKeyServerFixtures();
    const byId = new Map(fixtures.map((f) => [f.objectId, f]));
    const byUrl = new Map(fixtures.map((f) => [f.url, f]));

    const idThreshold2 = "1111111111111111111111111111111111111111111111111111111111111111";
    const idThreshold3 = "2222222222222222222222222222222222222222222222222222222222222222";
    const idShared = "3333333333333333333333333333333333333333333333333333333333333333";
    const allKnownFullIds = [idThreshold2, idThreshold3, idShared].map(
        (inner) => `${PACKAGE_ID.slice(2)}${inner}`,
    );

    // Mock only external Sui object/metadata reads and key-server HTTP endpoints.
    t.mock.method(suiClient.core, "getObject", async ({ objectId }: { objectId: string }) => {
        if (objectId === PACKAGE_ID) {
            return { object: { version: "1", digest: "pkg-digest" } } as any;
        }
        const server = byId.get(objectId);
        assert.ok(server, `unexpected core.getObject(${objectId})`);
        return { object: { content: server.parentBytes } } as any;
    });
    t.mock.method(suiClient.core, "getDynamicField", async ({ parentId }: { parentId: string }) => {
        const server = byId.get(parentId);
        assert.ok(server, `unexpected core.getDynamicField(${parentId})`);
        return { dynamicField: { value: { bcs: server.v1Bytes } } } as any;
    });
    t.mock.method(suiClient, "getObjects", async ({ objectIds }: { objectIds: string[] }) => {
        return {
            objects: objectIds.map((id, idx) => ({
                objectId: id,
                version: "10",
                digest: `digest-${idx}`,
                owner: { $kind: "Shared", Shared: { initialSharedVersion: String(100 + idx) } },
            })),
        } as any;
    });

    let unavailableServerUrl: string | null = fixtures[2].url;
    let unavailableStatus = 503;
    const realFetch = globalThis.fetch;
    t.mock.method(globalThis, "fetch", async (input: string | URL | Request, init?: RequestInit) => {
        const urlStr = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
        if (urlStr.startsWith("http://127.0.0.1:")) {
            return realFetch(input as any, init);
        }
        const parsedUrl = new URL(urlStr);
        const origin = parsedUrl.origin;
        const server = byUrl.get(origin);
        assert.ok(server, `unexpected external fetch URL ${urlStr}`);

        if (parsedUrl.pathname === "/v1/service") {
            return Response.json(
                { service_id: server.objectId, pop: server.popBase64 },
                { headers: { "X-KeyServer-Version": "0.4.1" } },
            );
        }

        assert.equal(parsedUrl.pathname, "/v1/fetch_key");
        if (unavailableServerUrl === origin) {
            return new Response(
                JSON.stringify({ error: "Key server unavailable" }),
                {
                    status: unavailableStatus,
                    headers: {
                        "Content-Type": "application/json",
                        "X-KeyServer-Version": "0.4.1",
                    },
                },
            );
        }

        const body = JSON.parse(String(init?.body ?? "{}"));
        return Response.json(
            {
                decryption_keys: allKnownFullIds.map((fullIdHex) => ({
                    id: Array.from(fromHex(fullIdHex)),
                    encrypted_key: elgamalEncryptDerivedKey(server.scalar, fullIdHex, body.enc_key),
                })),
            },
            { headers: { "X-KeyServer-Version": "0.4.1" } },
        );
    });

    // Encrypt genuine SDK ciphertexts with thresholds 2 and 3 against the 3-server committee.
    const sdkEncryptClient = new SealClient({
        suiClient: suiClient as any,
        serverConfigs: SERVER_IDS.map((objectId) => ({ objectId, weight: 1 })),
        verifyKeyServers: true,
    });
    const encDistinct2 = await sdkEncryptClient.encrypt({
        packageId: PACKAGE_ID,
        id: idThreshold2,
        threshold: 2,
        data: new TextEncoder().encode("route-distinct-threshold-2"),
    });
    const encDistinct3 = await sdkEncryptClient.encrypt({
        packageId: PACKAGE_ID,
        id: idThreshold3,
        threshold: 3,
        data: new TextEncoder().encode("route-distinct-threshold-3"),
    });
    const encShared2 = await sdkEncryptClient.encrypt({
        packageId: PACKAGE_ID,
        id: idShared,
        threshold: 2,
        data: new TextEncoder().encode("route-shared-threshold-2"),
    });
    const encShared3 = await sdkEncryptClient.encrypt({
        packageId: PACKAGE_ID,
        id: idShared,
        threshold: 3,
        data: new TextEncoder().encode("route-shared-threshold-3"),
    });

    const items = [
        Buffer.from(encDistinct2.encryptedObject).toString("base64"),
        Buffer.from(encDistinct3.encryptedObject).toString("base64"),
        Buffer.from(encShared2.encryptedObject).toString("base64"),
        Buffer.from(encShared3.encryptedObject).toString("base64"),
    ];

    const signer = new Ed25519Keypair();
    const session = await SessionKey.create({
        address: signer.getPublicKey().toSuiAddress(),
        packageId: PACKAGE_ID,
        ttlMin: 5,
        signer,
        suiClient: suiClient as any,
    });
    await session.getCertificate();
    const exportedSessionHeader = Buffer.from(JSON.stringify({ ...session.export() })).toString("base64");

    const app = express();
    registerSealRoutes(app, {
        enableMigrationSealRoute: false,
        enableLegacySealAbi: true,
        sealPolicyPackageId: POLICY_PKG_ID,
    });
    const server: Server = await new Promise((resolve) => {
        const s = app.listen(0, "127.0.0.1", () => resolve(s));
    });

    try {
        const addr = server.address();
        const port = typeof addr === "object" && addr ? addr.port : 0;
        const baseUrl = `http://127.0.0.1:${port}`;

        // 1. x-seal-session path with 1 of 3 key servers unavailable (403 non-retryable and 503 retryable).
        for (const modeledStatus of [403, 503]) {
            resetSealKeyServerTrustForTests();
            unavailableServerUrl = fixtures[2].url;
            unavailableStatus = modeledStatus;

            const resp = await realFetch(`${baseUrl}/seal/decrypt-batch`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "x-seal-session": exportedSessionHeader,
                },
                body: JSON.stringify({
                    items,
                    packageId: PACKAGE_ID,
                    policyPackageId: POLICY_PKG_ID,
                    registryId: REGISTRY_ID,
                    accountId: ACCOUNT_ID,
                    sealAbi: "v1-new",
                }),
            });
            assert.equal(resp.status, 200);
            const body = (await resp.json()) as {
                results: Array<{ index: number; decryptedData: string }>;
                errors: Array<{ index: number; code: string; error: string }>;
            };

            assert.deepEqual(
                body.results.map((r) => ({
                    index: r.index,
                    text: Buffer.from(r.decryptedData, "base64").toString("utf8"),
                })),
                [
                    { index: 0, text: "route-distinct-threshold-2" },
                    { index: 2, text: "route-shared-threshold-2" },
                ],
                `status=${modeledStatus}: threshold-2 items must decrypt when 2 of 3 servers succeed`,
            );
            assert.deepEqual(
                body.errors.map((e) => e.index),
                [1, 3],
                `status=${modeledStatus}: only threshold-3 items may fail`,
            );
            for (const err of body.errors) {
                assert.match(err.error, /fetch_keys failed:/);
            }
        }

        // 2. Legacy x-delegate-key path (request-local SealClient) under the same partial outage.
        unavailableServerUrl = fixtures[2].url;
        unavailableStatus = 403;
        const delegateResp = await realFetch(`${baseUrl}/seal/decrypt-batch`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "x-delegate-key": signer.getSecretKey(),
            },
            body: JSON.stringify({
                items: items.slice(0, 2),
                packageId: PACKAGE_ID,
                policyPackageId: POLICY_PKG_ID,
                registryId: REGISTRY_ID,
                accountId: ACCOUNT_ID,
                sealAbi: "v1-new",
            }),
        });
        assert.equal(delegateResp.status, 200);
        const delegateBody = (await delegateResp.json()) as {
            results: Array<{ index: number; decryptedData: string }>;
            errors: Array<{ index: number; code: string; error: string }>;
        };
        assert.deepEqual(
            delegateBody.results.map((r) => ({
                index: r.index,
                text: Buffer.from(r.decryptedData, "base64").toString("utf8"),
            })),
            [{ index: 0, text: "route-distinct-threshold-2" }],
        );
        assert.deepEqual(delegateBody.errors.map((e) => e.index), [1]);

        // 3. Direct decryptBatchSealItems call with a genuine SDK SealClient under the same partial outage.
        const directClient = new SealClient({
            suiClient: suiClient as any,
            serverConfigs: SERVER_IDS.map((objectId) => ({ objectId, weight: 1 })),
            verifyKeyServers: true,
            timeout: 2_000,
        });
        const { parsedItems } = parseSealDecryptBatchItems(items, PACKAGE_ID);
        const directTx = buildSealApproveTx(
            POLICY_PKG_ID,
            REGISTRY_ID,
            ACCOUNT_ID,
            [...new Set(parsedItems.map((p) => p.fullId))],
            { registryInitialSharedVersion: "101", accountInitialSharedVersion: "100" },
        );
        const directTxBytes = await directTx.build({ onlyTransactionKind: true });
        const directOut = await decryptBatchSealItems({
            sealClient: directClient,
            parsedItems,
            uniqueIds: [...new Set(parsedItems.map((p) => p.fullId))],
            sessionKey: session,
            getTxBytes: async () => directTxBytes,
        });
        assert.deepEqual(
            directOut.results.map((r) => ({
                index: r.index,
                text: Buffer.from(r.decryptedData, "base64").toString("utf8"),
            })),
            [
                { index: 0, text: "route-distinct-threshold-2" },
                { index: 2, text: "route-shared-threshold-2" },
            ],
        );
        assert.deepEqual(directOut.errors.map((e) => e.index), [1, 3]);

        // 4. When all 3 key servers are available, both threshold-2 and threshold-3 items decrypt cleanly.
        unavailableServerUrl = null;
        const healthyResp = await realFetch(`${baseUrl}/seal/decrypt-batch`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "x-seal-session": exportedSessionHeader,
            },
            body: JSON.stringify({
                items,
                packageId: PACKAGE_ID,
                policyPackageId: POLICY_PKG_ID,
                registryId: REGISTRY_ID,
                accountId: ACCOUNT_ID,
                sealAbi: "v1-new",
            }),
        });
        assert.equal(healthyResp.status, 200);
        const healthyBody = (await healthyResp.json()) as {
            results: Array<{ index: number; decryptedData: string }>;
            errors: Array<{ index: number; code: string; error: string }>;
        };
        assert.deepEqual(healthyBody.errors, []);
        assert.deepEqual(
            healthyBody.results.map((r) => ({
                index: r.index,
                text: Buffer.from(r.decryptedData, "base64").toString("utf8"),
            })),
            [
                { index: 0, text: "route-distinct-threshold-2" },
                { index: 1, text: "route-distinct-threshold-3" },
                { index: 2, text: "route-shared-threshold-2" },
                { index: 3, text: "route-shared-threshold-3" },
            ],
        );
    } finally {
        await new Promise<void>((resolve) => server.close(() => resolve()));
    }
});
