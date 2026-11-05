import test from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";

// Minimal env so importing the shared clients/config does not throw. The seal
// routes reject a bad sealAbi at the validate phase, before any Sui/SEAL client
// is touched, so no real network config or credential is needed here.
const { Ed25519Keypair } = await import("@mysten/sui/keypairs/ed25519");
const { EncryptedObject } = await import("@mysten/seal");
process.env.SERVER_SUI_PRIVATE_KEYS = new Ed25519Keypair().getSecretKey();
process.env.SUI_NETWORK = "testnet";
process.env.SUI_GRPC_URL = "https://seal-routes.testnet.example";
process.env.WALRUS_PACKAGE_ID = `0x${"a".repeat(64)}`;
process.env.SIDECAR_ENABLE_LEGACY_SEED_ROUTE = "true";

const express = (await import("express")).default;
const { Transaction } = await import("@mysten/sui/transactions");
const { createSealClient } = await import("../sidecar/clients.js");
const { appendSealPersistenceFence, InvalidSealPersistenceFenceError, parseSealPersistenceFence } = await import(
    "../sidecar/blob-metadata.js"
);
const {
    parseSealDecryptBatchItems,
    registerSealRoutes,
    retryTransientSealDecryptRpc,
    sealEncryptCommitteeFailure,
} = await import("../sidecar/routes/seal.js");
const { SEAL_COMMITTEE_IDENTITY } = await import("../sidecar/config.js");

const ROUTE_POLICY = {
    enableMigrationSealRoute: true,
    enableLegacySealAbi: true,
    sealPolicyPackageId: `0x${"2".repeat(64)}`,
};

function listen(policy = ROUTE_POLICY): Promise<{ server: Server; baseUrl: string }> {
    const app = express();
    registerSealRoutes(app, policy);
    return new Promise((resolve) => {
        const server = app.listen(0, "127.0.0.1", () => {
            const addr = server.address();
            const port = typeof addr === "object" && addr ? addr.port : 0;
            resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
        });
    });
}

async function post(baseUrl: string, path: string, body: unknown, headers: Record<string, string> = {}) {
    const res = await fetch(`${baseUrl}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...headers },
        body: JSON.stringify(body),
    });
    return {
        status: res.status,
        body: (await res.json().catch(() => ({}))) as { error?: string },
    };
}

// A ciphertext-shaped payload is enough: validation runs before any parsing.
const DATA = Buffer.from("ciphertext").toString("base64");
const PKG = `0x${"2".repeat(64)}`;
const POLICY_PKG = `0x${"5".repeat(64)}`;
const OTHER_PKG = `0x${"4".repeat(64)}`;
const ACC = `0x${"3".repeat(64)}`;
const REG = `0x${"9".repeat(64)}`;
const PERSISTENCE_POLICY = { allowLegacySealAbi: false, policyPackageId: POLICY_PKG };

function ciphertext(packageId: string): string {
    return Buffer.from(
        EncryptedObject.serialize({
            version: 0,
            packageId,
            id: "aabb",
            services: [[ACC, 1]],
            threshold: 1,
            encryptedShares: {
                BonehFranklinBLS12381: {
                    nonce: new Uint8Array(96),
                    encryptedShares: [new Uint8Array(32)],
                    encryptedRandomness: new Uint8Array(32),
                },
            },
            ciphertext: { Plain: {} },
        }).toBytes()
    ).toString("base64");
}

function sessionHeader(packageId: string): string {
    const owner = new Ed25519Keypair();
    return Buffer.from(
        JSON.stringify({
            address: owner.getPublicKey().toSuiAddress(),
            packageId,
            creationTimeMs: Date.now(),
            ttlMin: 5,
            sessionKey: new Ed25519Keypair().getSecretKey(),
        })
    ).toString("base64");
}

test("decrypt callers can use isolated SealClient caches", () => {
    assert.notEqual(createSealClient(), createSealClient());
});

test("v1-new persistence fence is derived from the ciphertext identity", () => {
    const fence = parseSealPersistenceFence(
        {
            sealAbi: "v1-new",
            accountId: ACC,
            registryId: REG,
            policyPackageId: POLICY_PKG,
            data: ciphertext(PKG),
        },
        PKG,
        PERSISTENCE_POLICY
    );
    assert.deepEqual(fence, {
        sealAbi: "v1-new",
        accountId: ACC,
        registryId: REG,
        policyPackageId: POLICY_PKG,
        idBytes: [0xaa, 0xbb],
    });

    const tx = new Transaction();
    appendSealPersistenceFence(tx, fence);
    const command = (tx.getData().commands[0] as any).MoveCall;
    assert.equal(command.package, POLICY_PKG);
    assert.equal(command.module, "account");
    assert.equal(command.function, "seal_encrypt_fence");
    assert.equal(command.arguments.length, 3);
});

test("persistence fence only permits the legacy ABI when the sidecar opts in", () => {
    assert.throws(() => parseSealPersistenceFence({ sealAbi: "v1" }, undefined, PERSISTENCE_POLICY), /disabled/);
    assert.deepEqual(
        parseSealPersistenceFence({ sealAbi: "v1" }, undefined, {
            ...PERSISTENCE_POLICY,
            allowLegacySealAbi: true,
        }),
        {
            sealAbi: "v1",
        }
    );
    assert.throws(() => parseSealPersistenceFence({}, PKG, PERSISTENCE_POLICY), InvalidSealPersistenceFenceError);
    assert.throws(
        () =>
            parseSealPersistenceFence(
                {
                    sealAbi: "v1-new",
                    accountId: ACC,
                    registryId: REG,
                    policyPackageId: POLICY_PKG,
                    data: ciphertext(OTHER_PKG),
                },
                PKG,
                PERSISTENCE_POLICY
            ),
        /Ciphertext packageId does not match packageId/
    );
    assert.throws(
        () =>
            parseSealPersistenceFence(
                {
                    sealAbi: "v1-new",
                    accountId: ACC,
                    policyPackageId: POLICY_PKG,
                    data: ciphertext(PKG),
                },
                PKG,
                PERSISTENCE_POLICY
            ),
        /registryId/
    );
});

test("persistence fence rejects a request-controlled policy package", () => {
    assert.throws(
        () =>
            parseSealPersistenceFence(
                {
                    sealAbi: "v1-new",
                    accountId: ACC,
                    registryId: REG,
                    policyPackageId: OTHER_PKG,
                    data: ciphertext(PKG),
                },
                PKG,
                PERSISTENCE_POLICY
            ),
        /configured SEAL policy package/
    );
});

async function withServer(fn: (baseUrl: string) => Promise<void>) {
    const { server, baseUrl } = await listen();
    try {
        await fn(baseUrl);
    } finally {
        server.close();
    }
}

test("/seal/decrypt 400s on an unknown sealAbi", async () => {
    await withServer(async (baseUrl) => {
        const r = await post(baseUrl, "/seal/decrypt", {
            data: DATA,
            packageId: PKG,
            accountId: ACC,
            sealAbi: "v2",
        });
        assert.equal(r.status, 400);
        assert.match(r.body.error!, /sealAbi/);
    });
});

test("the opt-in legacy seed encrypt route is registered", async () => {
    await withServer(async (baseUrl) => {
        const r = await post(baseUrl, "/e2e/legacy/seal/encrypt", {});
        assert.equal(r.status, 400);
        assert.match(r.body.error!, /Missing required fields/);
    });
});

test("/seal/encrypt enforces the pinned committee before RPC work", async () => {
    const missing = sealEncryptCommitteeFailure(
        undefined,
        true,
        SEAL_COMMITTEE_IDENTITY
    );
    assert.equal(missing?.status, 400);

    const mismatch = sealEncryptCommitteeFailure(
        { ...SEAL_COMMITTEE_IDENTITY, threshold: SEAL_COMMITTEE_IDENTITY.threshold + 1 },
        true,
        SEAL_COMMITTEE_IDENTITY
    );
    assert.equal(mismatch?.status, 409);
    assert.equal(mismatch?.body.code, "SEAL_COMMITTEE_MISMATCH");

    assert.equal(
        sealEncryptCommitteeFailure(
            SEAL_COMMITTEE_IDENTITY,
            true,
            SEAL_COMMITTEE_IDENTITY
        ),
        null
    );
});

test("the migration encrypt route is absent unless the sidecar opts in", async () => {
    const { server, baseUrl } = await listen({ ...ROUTE_POLICY, enableMigrationSealRoute: false });
    try {
        const r = await post(baseUrl, "/migration/seal/encrypt", {});
        assert.equal(r.status, 404);
    } finally {
        server.close();
    }
});

test("/seal/decrypt 400s when sealAbi=v1-new omits registryId", async () => {
    await withServer(async (baseUrl) => {
        const r = await post(baseUrl, "/seal/decrypt", {
            data: DATA,
            packageId: PKG,
            accountId: ACC,
            sealAbi: "v1-new",
        });
        assert.equal(r.status, 400);
        assert.match(r.body.error!, /registryId/);
    });
});

test("/seal/decrypt rejects malformed account and registry IDs during validation", async () => {
    await withServer(async (baseUrl) => {
        const badAccount = await post(baseUrl, "/seal/decrypt", {
            data: DATA,
            packageId: PKG,
            accountId: "not-an-object-id",
            sealAbi: "v1",
        });
        assert.equal(badAccount.status, 400);
        assert.match(badAccount.body.error!, /accountId format/);

        const badRegistry = await post(baseUrl, "/seal/decrypt-batch", {
            items: [DATA],
            packageId: PKG,
            policyPackageId: ROUTE_POLICY.sealPolicyPackageId,
            accountId: ACC,
            registryId: `0x${"1".repeat(65)}`,
            sealAbi: "v1-new",
        });
        assert.equal(badRegistry.status, 400);
        assert.match(badRegistry.body.error!, /registryId format/);
    });
});

test("/seal/decrypt 400s on an invalid policyPackageId", async () => {
    await withServer(async (baseUrl) => {
        const r = await post(baseUrl, "/seal/decrypt", {
            data: DATA,
            packageId: PKG,
            policyPackageId: "not-an-address",
            accountId: ACC,
            sealAbi: "v1",
        });
        assert.equal(r.status, 400);
        assert.match(r.body.error!, /policyPackageId/);
    });
});

test("/seal/decrypt rejects ciphertext from another immutable package", async () => {
    await withServer(async (baseUrl) => {
        const r = await post(
            baseUrl,
            "/seal/decrypt",
            {
                data: ciphertext(OTHER_PKG),
                packageId: PKG,
                accountId: ACC,
                sealAbi: "v1",
            },
            { "x-seal-session": sessionHeader(PKG) }
        );
        assert.equal(r.status, 400);
        assert.match(r.body.error!, /Ciphertext packageId/);
    });
});

test("/seal/decrypt rejects a SessionKey from another immutable package", async () => {
    await withServer(async (baseUrl) => {
        const r = await post(
            baseUrl,
            "/seal/decrypt",
            {
                data: ciphertext(PKG),
                packageId: PKG,
                accountId: ACC,
                sealAbi: "v1",
            },
            { "x-seal-session": sessionHeader(OTHER_PKG) }
        );
        assert.equal(r.status, 400);
        assert.match(r.body.error!, /SessionKey packageId/);
    });
});

test("batch parsing quarantines a foreign package and preserves the valid subset", () => {
    const parsed = parseSealDecryptBatchItems([ciphertext(PKG), ciphertext(OTHER_PKG)], PKG);
    assert.deepEqual(
        parsed.parsedItems.map((item: { index: number }) => item.index),
        [0]
    );
    assert.equal(parsed.errors.length, 1);
    assert.equal(parsed.errors[0].index, 1);
    assert.equal(parsed.errors[0].code, "CORRUPT_CIPHERTEXT");
    assert.match(parsed.errors[0].error, /Ciphertext packageId/);
});

test("/seal/decrypt-batch reports a foreign immutable package per item", async () => {
    await withServer(async (baseUrl) => {
        const r = await post(
            baseUrl,
            "/seal/decrypt-batch",
            {
                items: [ciphertext(OTHER_PKG)],
                packageId: PKG,
                accountId: ACC,
                sealAbi: "v1",
            },
            { "x-seal-session": sessionHeader(PKG) }
        );
        assert.equal(r.status, 200);
        assert.deepEqual((r.body as any).results, []);
        assert.equal((r.body as any).errors[0].code, "CORRUPT_CIPHERTEXT");
    });
});

test("/seal/decrypt-batch rejects a foreign SessionKey request-wide", async () => {
    await withServer(async (baseUrl) => {
        const r = await post(
            baseUrl,
            "/seal/decrypt-batch",
            {
                items: [ciphertext(PKG)],
                packageId: PKG,
                accountId: ACC,
                sealAbi: "v1",
            },
            { "x-seal-session": sessionHeader(OTHER_PKG) }
        );
        assert.equal(r.status, 400);
        assert.match(r.body.error!, /SessionKey packageId/);
    });
});

test("/seal/decrypt-batch 400s when sealAbi=v1 carries a registryId", async () => {
    await withServer(async (baseUrl) => {
        const r = await post(baseUrl, "/seal/decrypt-batch", {
            items: [DATA],
            packageId: PKG,
            accountId: ACC,
            sealAbi: "v1",
            registryId: REG,
        });
        assert.equal(r.status, 400);
        assert.match(r.body.error!, /not valid/);
    });
});

test("retryTransientSealDecryptRpc retries transient key-server errors once and skips permanent errors", async () => {
    let transientCalls = 0;
    const sleeps: number[] = [];
    const recovered = await retryTransientSealDecryptRpc(
        async () => {
            transientCalls += 1;
            if (transientCalls === 1) {
                throw new TypeError("fetch failed");
            }
            return "keys-ready";
        },
        async (ms: number) => {
            sleeps.push(ms);
        },
    );
    assert.equal(recovered, "keys-ready");
    assert.equal(transientCalls, 2);
    assert.deepEqual(sleeps, [250]);

    let permanentCalls = 0;
    await assert.rejects(
        () =>
            retryTransientSealDecryptRpc(
                async () => {
                    permanentCalls += 1;
                    const err = new Error("NoAccessError: user does not have access");
                    err.name = "NoAccessError";
                    throw err;
                },
                async () => {},
            ),
        /NoAccessError/,
    );
    assert.equal(permanentCalls, 1);
});
