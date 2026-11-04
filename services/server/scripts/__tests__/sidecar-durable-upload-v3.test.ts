import test from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction, TransactionDataBuilder } from "@mysten/sui/transactions";

const writer = new Ed25519Keypair();
process.env.SERVER_SUI_PRIVATE_KEYS = writer.getSecretKey();
process.env.SUI_NETWORK = "testnet";
process.env.WALRUS_PACKAGE_ID = `0x${"a".repeat(64)}`;
process.env.WALRUS_DIRECT_UPLOAD = "true";
delete process.env.ENOKI_API_KEY;
process.env.DURABLE_ENOKI_REGISTER_ENABLED = "false";

const { getWalrusClient, suiClient } = await import("../sidecar/clients.js");
const { DURABLE_UPLOAD_PROTOCOL_VERSION } = await import("../sidecar/config.js");
const { registerWalrusUploadJournalRoute, resetUploadStepFlightsForTests } =
    await import("../sidecar/routes/walrus-upload-journal.js");

async function preparedRegisterForWriter(keypair: Ed25519Keypair) {
    const transaction = new Transaction();
    transaction.setSender(keypair.toSuiAddress());
    transaction.setGasOwner(keypair.toSuiAddress());
    transaction.setGasBudget(1_000n);
    transaction.setGasPrice(1n);
    transaction.setGasPayment([]);
    transaction.setExpiration({
        ValidDuring: {
            minEpoch: "1",
            maxEpoch: "2",
            minTimestamp: null,
            maxTimestamp: null,
            chain: "69WiPg3DAQiwdxfncX6wYQ2siKwAe6L9BZthQea3JNMD",
            nonce: 1,
        },
    });
    const walType = `0x${"2".repeat(64)}::wal::WAL`;
    const withdrawal = transaction.withdrawal({
        amount: 1n,
        type: walType,
    });
    const wal = transaction.moveCall({
        target: "0x2::coin::redeem_funds",
        typeArguments: [walType],
        arguments: [withdrawal],
    });
    transaction.moveCall({
        target: "0x2::coin::destroy_zero",
        typeArguments: [walType],
        arguments: [wal],
    });
    const bytes = await transaction.build({ client: suiClient });
    const signed = await keypair.signTransaction(bytes);
    return {
        transactionBytes: signed.bytes,
        signature: signed.signature,
        digest: TransactionDataBuilder.getDigestFromBytes(bytes),
    };
}

test("stale encoded resume with new ciphertext returns 409 on reconcile and 503 NO_SIDE_EFFECT on execute", async (t) => {
    resetUploadStepFlightsForTests();
    t.after(resetUploadStepFlightsForTests);

    t.mock.method(getWalrusClient(), "getBlobType", async () => `${process.env.WALRUS_PACKAGE_ID}::blob::Blob`);
    t.mock.method(suiClient.ledgerService, "getServiceInfo", async () => ({
        response: { chainId: "69WiPg3DAQiwdxfncX6wYQ2siKwAe6L9BZthQea3JNMD" },
    }));
    t.mock.method(suiClient.core, "getCurrentSystemState", async () => ({
        systemState: { epoch: "1" },
    }));
    t.mock.method(suiClient.core, "resolveTransactionPlugin", () => (
        async (data: { gasData: { budget?: bigint; price?: bigint } }, _options: unknown, next: () => Promise<void>) => {
            data.gasData.budget = 10_000_000n;
            data.gasData.price = 1n;
            await next();
        }
    ));

    let encodeCalls = 0;
    t.mock.method(getWalrusClient(), "writeBlobFlow", ({ resume }: any = {}) => ({
        encode: async () => {
            encodeCalls += 1;
            if (resume?.step === "encoded" && resume?.blobId !== "new-ciphertext-blob-id") {
                throw new Error(`Resume blobId mismatch: expected ${resume.blobId}, got new-ciphertext-blob-id. The blob content may have changed.`);
            }
            return {
                step: "encoded",
                blobId: "new-ciphertext-blob-id",
                rootHash: "new-root",
                unencodedSize: 14,
            };
        },
        register: () => new Transaction(),
    }));

    t.mock.method(suiClient, "getTransaction", async () => {
        throw Object.assign(new Error("transaction not found"), { code: "NOT_FOUND" });
    });

    const app = express();
    registerWalrusUploadJournalRoute(app);
    const server = app.listen(0, "127.0.0.1");
    await new Promise<void>((resolve) => server.once("listening", resolve));
    t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
    const address = server.address();
    assert.ok(address && typeof address !== "string");

    const preparedRegister = await preparedRegisterForWriter(writer);
    const staleEncoded = {
        step: "encoded",
        blobId: "stale-blob-id",
        rootHash: "stale-root",
        unencodedSize: 10,
    };

    const nativeFetch = globalThis.fetch;
    const postStep = async (reconcileOnly: boolean, mayHaveBeenSubmitted?: boolean) => {
        const response = await nativeFetch(`http://127.0.0.1:${address.port}/walrus/upload-step-v3`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                data: Buffer.from("new-ciphertext").toString("base64"),
                keyIndex: 0,
                walletAddress: writer.toSuiAddress(),
                jobId: "stale-encoded-test",
                epochs: 1,
                uploadProtocolVersion: DURABLE_UPLOAD_PROTOCOL_VERSION,
                resumeStep: staleEncoded,
                registerTransaction: preparedRegister,
                reconcileOnly,
                indexAttempts: 1,
                ...(mayHaveBeenSubmitted !== undefined ? { mayHaveBeenSubmitted } : {}),
            }),
        });
        return { status: response.status, body: await response.json() };
    };

    // 1. Reconcile-only call with mayHaveBeenSubmitted = false:
    // Must return 409 PREPARED_REGISTER_NOT_ON_CHAIN without acquiring slots or calling encodeFlow.
    const reconcileResult = await postStep(true, false);
    assert.equal(reconcileResult.status, 409, JSON.stringify(reconcileResult.body));
    assert.equal(reconcileResult.body.code, "PREPARED_REGISTER_NOT_ON_CHAIN");
    assert.equal(reconcileResult.body.digest, preparedRegister.digest);
    assert.equal(encodeCalls, 0, "encodeFlow must not be called during reconcile-only prepared check");

    // 2. Follow-up execute call (reconcileOnly = false):
    // encodeFlow runs, detects blobId mismatch, and returns 503 NO_SIDE_EFFECT.
    const executeResult = await postStep(false);
    assert.equal(executeResult.status, 503, JSON.stringify(executeResult.body));
    assert.equal(executeResult.body.code, "NO_SIDE_EFFECT");
    assert.match(executeResult.body.error, /Resume blobId mismatch/);
    assert.equal(encodeCalls, 1, "encodeFlow should be called once on the execute path");
});
