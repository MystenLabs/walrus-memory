import assert from "node:assert/strict";
import test from "node:test";

import { MemWal } from "../dist/memwal.js";
import { MemWalManual } from "../dist/manual.js";

test("a request in flight when destroy() lands is rejected, not signed with a zeroed key", async () => {
    const originalFetch = globalThis.fetch;
    let releaseVersion;
    const versionGate = new Promise((resolve) => {
        releaseVersion = resolve;
    });

    globalThis.fetch = async (url) => {
        const path = new URL(url).pathname;
        if (path === "/version") {
            await versionGate;
            return Response.json({
                apiVersion: "1.0.0",
                relayerVersion: "1.0.0",
                minSupportedSdk: { typescript: "0.0.4" },
            });
        }
        throw new Error(`a wiped client still signed and sent ${path}`);
    };

    try {
        const client = MemWal.create({
            key: new Uint8Array(32).fill(1),
            accountId: "0x1",
            serverUrl: "https://relayer.example",
        });
        client.buildSealSession = async () => "test-session";

        const pending = client.recall({ query: "anything" });
        await new Promise((resolve) => setImmediate(resolve));
        client.destroy();
        releaseVersion();

        await assert.rejects(pending, /Walrus Memory client was destroyed/);
    } finally {
        globalThis.fetch = originalFetch;
    }
});

test("MemWal.destroy() clones caller Uint8Array key so caller buffer remains intact and reusable (#973)", async () => {
    const callerKey = new Uint8Array(32);
    for (let i = 0; i < 32; i++) callerKey[i] = i + 1;
    const expectedSnapshot = new Uint8Array(callerKey);

    const first = MemWal.create({
        key: callerKey,
        accountId: "0x1",
        serverUrl: "https://relayer.example",
    });
    const firstPubKey = await first.getPublicKeyHex();
    first.destroy();

    assert.deepEqual(
        callerKey,
        expectedSnapshot,
        "MemWal.destroy() must not zero-fill the caller's Uint8Array buffer",
    );
    assert.ok(
        first.privateKey.every((b) => b === 0),
        "MemWal.destroy() must zero-fill the internal privateKey copy",
    );

    // Mutating callerKey after create() also must not affect an active client
    const second = MemWal.create({
        key: callerKey,
        accountId: "0x1",
        serverUrl: "https://relayer.example",
    });
    const secondPubKey = await second.getPublicKeyHex();
    assert.equal(secondPubKey, firstPubKey);
    second.destroy();
});

test("MemWalManual.destroy() clones caller Uint8Array key and leaves caller buffer intact (#973)", () => {
    const callerKey = new Uint8Array(32).fill(0x42);
    const expectedSnapshot = new Uint8Array(callerKey);

    const manual = MemWalManual.create({
        key: callerKey,
        suiPrivateKey: "suiprivkey1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5f0f2e",
        embeddingApiKey: "sk-test-secret",
        packageId: "0x1",
        accountId: "0x2",
        registryId: "0x3",
        serverUrl: "https://relayer.example",
    });

    manual.destroy();

    assert.deepEqual(
        callerKey,
        expectedSnapshot,
        "MemWalManual.destroy() must not zero-fill the caller's Uint8Array buffer",
    );
    assert.ok(
        manual.delegatePrivateKey.every((b) => b === 0),
        "MemWalManual.destroy() must zero-fill the internal delegatePrivateKey copy",
    );
});

test("MemWalManual.destroy() scrubs retained credentials and cached clients and rejects subsequent calls (#977)", async () => {
    const callerConfig = {
        key: "11".repeat(32),
        suiPrivateKey: "suiprivkey1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5f0f2e",
        embeddingApiKey: "sk-live-secret-api-key",
        packageId: "0x1",
        accountId: "0x2",
        registryId: "0x3",
        serverUrl: "https://relayer.example",
        sealServerConfigs: [
            {
                objectId: "0x145540d931f182fef76467dd8074c9839aea126852d90d18e1556fcbbd1208b6",
                weight: 1,
                apiKeyName: "x-api-key",
                apiKey: "seal-secret-token",
            },
        ],
    };

    const manual = MemWalManual.create(callerConfig);
    // Prime delegate public key and simulate initialized lazy clients
    await manual.getDelegatePublicKey();
    const fakeKeypairSecret = new Uint8Array(32).fill(9);
    manual._keypair = { keypair: { secretKey: fakeKeypairSecret } };
    manual._suiClient = { fake: true };
    manual._sealClient = { fake: true };

    manual.destroy();

    // Internal delegate keys and keypair secret buffer are wiped
    assert.ok(manual.delegatePrivateKey.every((b) => b === 0));
    assert.equal(manual.delegatePublicKey, null);
    assert.ok(fakeKeypairSecret.every((b) => b === 0));

    // Lazily cached clients and signers are released
    assert.equal(manual._keypair, null);
    assert.equal(manual._suiClient, null);
    assert.equal(manual._sealClient, null);
    assert.equal(manual.walletSigner, null);

    // Secrets are no longer reachable from manual.config
    assert.equal(manual.config.suiPrivateKey, undefined);
    assert.equal(manual.config.embeddingApiKey, undefined);
    assert.equal(manual.config.key, undefined);
    assert.equal(manual.config.sealServerConfigs?.[0]?.apiKey, undefined);
    assert.equal(manual.config.sealServerConfigs?.[0]?.apiKeyName, undefined);

    // Caller's input config object was not mutated
    assert.equal(
        callerConfig.suiPrivateKey,
        "suiprivkey1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5f0f2e",
    );
    assert.equal(callerConfig.embeddingApiKey, "sk-live-secret-api-key");
    assert.equal(callerConfig.sealServerConfigs[0].apiKey, "seal-secret-token");

    // Subsequent operations fail immediately without touching the network
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
        throw new Error(`destroyed MemWalManual unexpectedly fetched ${url}`);
    };
    try {
        await assert.rejects(() => manual.restore("default"), /Walrus Memory client was destroyed/);
        await assert.rejects(() => manual.rememberManual("hello"), /Walrus Memory client was destroyed/);
        await assert.rejects(() => manual.recallManual("hello"), /Walrus Memory client was destroyed/);
        await assert.rejects(() => manual.buildSealSession(), /Walrus Memory client was destroyed/);
        await assert.rejects(() => manual.compatibility(), /Walrus Memory client was destroyed/);
    } finally {
        globalThis.fetch = originalFetch;
    }
});

test("MemWalManual request in flight when destroy() lands is rejected, not signed with a zeroed key (#977)", async () => {
    const originalFetch = globalThis.fetch;
    let releaseVersion;
    const versionGate = new Promise((resolve) => {
        releaseVersion = resolve;
    });

    globalThis.fetch = async (url) => {
        const path = new URL(url).pathname;
        if (path === "/version") {
            await versionGate;
            return Response.json({
                apiVersion: "1.0.0",
                relayerVersion: "1.0.0",
                minSupportedSdk: { typescript: "0.0.4" },
            });
        }
        throw new Error(`a wiped MemWalManual client still signed and sent ${path}`);
    };

    try {
        const manual = MemWalManual.create({
            key: new Uint8Array(32).fill(7),
            suiPrivateKey: "suiprivkey1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5f0f2e",
            embeddingApiKey: "sk-test-secret",
            packageId: "0x1",
            accountId: "0x2",
            registryId: "0x3",
            serverUrl: "https://relayer.example",
        });
        manual.buildSealSession = async () => "test-session";

        const pending = manual.restore("default");
        await new Promise((resolve) => setImmediate(resolve));
        manual.destroy();
        releaseVersion();

        await assert.rejects(pending, /Walrus Memory client was destroyed/);
    } finally {
        globalThis.fetch = originalFetch;
    }
});
