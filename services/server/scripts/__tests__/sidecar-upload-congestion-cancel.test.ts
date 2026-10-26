import test from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";

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

test("a finalized congestion cancel rebuilds the register with a new digest", async (t) => {
    resetUploadStepFlightsForTests();
    t.after(resetUploadStepFlightsForTests);
    const encoded = { step: "encoded", blobId: "cancel-blob", rootHash: "root", unencodedSize: 4 };
    t.mock.method(getWalrusClient(), "getBlobType", async () => `${process.env.WALRUS_PACKAGE_ID}::blob::Blob`);
    t.mock.method(suiClient.ledgerService, "getServiceInfo", async () => ({
        response: { chainId: "69WiPg3DAQiwdxfncX6wYQ2siKwAe6L9BZthQea3JNMD" },
    }));
    t.mock.method(suiClient.core, "getCurrentSystemState", async () => ({
        systemState: { epoch: "10" },
    }));
    // The gRPC client resolves a direct-signed build by simulating it against
    // the live network. The bytes and expiration are already complete here.
    t.mock.method(suiClient.core, "resolveTransactionPlugin", () => (
        async (data: { gasData: { budget?: bigint; price?: bigint } }, _options: unknown, next: () => Promise<void>) => {
            data.gasData.budget = 10_000_000n;
            data.gasData.price = 1n;
            await next();
        }
    ));
    t.mock.method(getWalrusClient(), "writeBlobFlow", () => ({
        encode: async () => encoded,
        register: () => {
            const tx = new Transaction();
            const walType = `0x${"c".repeat(64)}::wal::WAL`;
            const wal = tx.moveCall({
                target: "0x2::coin::redeem_funds", typeArguments: [walType],
                arguments: [tx.withdrawal({ amount: 1n, type: walType })],
            });
            tx.moveCall({ target: "0x2::coin::destroy_zero", typeArguments: [walType], arguments: [wal] });
            return tx;
        },
    }));
    const finalized = new Map<string, unknown>();
    t.mock.method(suiClient, "getTransaction", async ({ digest }: { digest: string }) => {
        const result = finalized.get(digest);
        if (result) return result;
        throw Object.assign(new Error("transaction not found"), { code: "NOT_FOUND" });
    });

    const app = express();
    registerWalrusUploadJournalRoute(app);
    const server = app.listen(0, "127.0.0.1");
    await new Promise<void>((resolve) => server.once("listening", resolve));
    t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const base = {
        data: Buffer.from("test").toString("base64"), keyIndex: 0,
        jobId: "congestion-cancel", epochs: 1, uploadProtocolVersion: DURABLE_UPLOAD_PROTOCOL_VERSION,
    };
    const nativeFetch = globalThis.fetch;
    const request = async (registerTransaction?: unknown, resumeStep: unknown = encoded) => {
        const response = await nativeFetch(`http://127.0.0.1:${address.port}/walrus/upload-step-v3`, {
            method: "POST", headers: { "content-type": "application/json" },
            body: JSON.stringify({ ...base, resumeStep, registerTransaction }),
        });
        return { status: response.status, body: await response.json() };
    };

    const prepared = await request();
    assert.equal(prepared.status, 200, JSON.stringify(prepared.body));
    const firstDigest = prepared.body.registerTransaction.digest;
    assert.equal(typeof firstDigest, "string");

    finalized.set(firstDigest, {
        $kind: "FailedTransaction",
        FailedTransaction: {
            digest: firstDigest,
            status: { success: false, error: { $kind: "CongestedObjects", message: "congested" } },
        },
    });
    const rejected = await request(prepared.body.registerTransaction);
    assert.equal(rejected.status, 503);
    assert.equal(rejected.body.code, "CONGESTION_CANCELLED_TRANSACTION");
    assert.match(rejected.body.error, /shared-object congestion/);

    // Rust names the dead digest on the encoded checkpoint before rebuilding.
    const rebuilt = await request(undefined, { ...encoded, registerRebuild: firstDigest });
    assert.equal(rebuilt.status, 200);
    assert.notEqual(
        rebuilt.body.registerTransaction.digest,
        firstDigest,
        "the rebuild must not sign the cancelled bytes again",
    );
});
