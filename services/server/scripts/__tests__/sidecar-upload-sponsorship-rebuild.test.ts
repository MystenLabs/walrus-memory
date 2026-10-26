import test from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction, TransactionDataBuilder } from "@mysten/sui/transactions";

const writer = new Ed25519Keypair();
const sponsor = new Ed25519Keypair();
process.env.SERVER_SUI_PRIVATE_KEYS = writer.getSecretKey();
process.env.SUI_NETWORK = "testnet";
process.env.WALRUS_PACKAGE_ID = `0x${"a".repeat(64)}`;
process.env.WALRUS_DIRECT_UPLOAD = "true";
process.env.ENOKI_API_KEY = "mock-enoki-key";
process.env.DURABLE_ENOKI_REGISTER_ENABLED = "true";
process.env.ENOKI_TRANSIENT_MAX_ATTEMPTS = "2";
process.env.ENOKI_TRANSIENT_BASE_DELAY_MS = "100";

const { getWalrusClient, suiClient } = await import("../sidecar/clients.js");
const { DURABLE_UPLOAD_PROTOCOL_VERSION, ENOKI_API_BASE_URL } = await import("../sidecar/config.js");
const { registerWalrusUploadJournalRoute, resetUploadStepFlightsForTests } =
    await import("../sidecar/routes/walrus-upload-journal.js");

test("Enoki 500 then 404 rebuilds sponsorship through the HTTP route without replaying the stale prepare", async (t) => {
    resetUploadStepFlightsForTests();
    t.after(resetUploadStepFlightsForTests);
    const encoded = { step: "encoded", blobId: "test-blob", rootHash: "test-root", unencodedSize: 4 };
    const blobObjectId = `0x${"b".repeat(64)}`;
    const finalized = new Map<string, unknown>();
    const sponsorships: { digest: string; handle: string }[] = [];
    const executeCalls: string[] = [];
    let absentLookups = 0;
    t.mock.method(getWalrusClient(), "getBlobType", async () => `${process.env.WALRUS_PACKAGE_ID}::blob::Blob`);
    t.mock.method(suiClient.ledgerService, "getServiceInfo", async () => ({
        response: { chainId: "69WiPg3DAQiwdxfncX6wYQ2siKwAe6L9BZthQea3JNMD" },
    }));
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
    t.mock.method(suiClient, "getTransaction", async ({ digest }: { digest: string }) => {
        if (finalized.has(digest)) return finalized.get(digest);
        absentLookups += 1;
        throw Object.assign(new Error("transaction not found"), { code: "NOT_FOUND" });
    });
    t.mock.method(suiClient, "getObject", async () => ({
        object: { json: { blob_id: encoded.blobId, size: "4", deletable: true } },
    }));
    const nativeFetch = globalThis.fetch;
    t.mock.method(globalThis, "fetch", async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
        const url = String(input);
        assert.ok(url.startsWith(ENOKI_API_BASE_URL), `unexpected external request: ${url}`);
        const payload = JSON.parse(String(init?.body));
        if (url.endsWith("/transaction-blocks/sponsor")) {
            const tx = Transaction.fromKind(payload.transactionBlockKindBytes);
            tx.setSender(payload.sender);
            tx.setGasOwner(sponsor.toSuiAddress());
            tx.setGasBudget(10_000_000n);
            tx.setGasPrice(1n);
            tx.setGasPayment([{
                objectId: `0x${"d".repeat(64)}`, version: String(sponsorships.length + 1),
                digest: "11111111111111111111111111111111",
            }]);
            const bytes = await tx.build();
            const entry = { digest: TransactionDataBuilder.getDigestFromBytes(bytes), handle: `handle-${sponsorships.length}` };
            sponsorships.push(entry);
            return Response.json({ data: { bytes: Buffer.from(bytes).toString("base64"), digest: entry.handle } });
        }
        executeCalls.push(payload.digest);
        if (payload.digest === "handle-0") {
            const first = executeCalls.length === 1;
            return Response.json({ errors: [{
                code: first ? "gas_station_error" : "not_found",
                message: first ? "Failed to execute transaction" : "Sponsored transaction not found",
            }] }, { status: first ? 500 : 404 });
        }
        const entry = sponsorships.find(({ handle }) => handle === payload.digest);
        assert.ok(entry, "execution must use a prepared sponsorship");
        finalized.set(entry.digest, {
            $kind: "Transaction", Transaction: {
                digest: entry.digest, status: { success: true },
                effects: { changedObjects: [{ idOperation: "Created", objectId: blobObjectId }] },
                objectTypes: { [blobObjectId]: `${process.env.WALRUS_PACKAGE_ID}::blob::Blob` },
            },
        });
        return Response.json({ data: { digest: entry.digest } });
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
        jobId: "sponsorship-rebuild", epochs: 1, uploadProtocolVersion: DURABLE_UPLOAD_PROTOCOL_VERSION,
        resumeStep: encoded,
    };
    const request = async (registerTransaction?: unknown) => {
        const response = await nativeFetch(`http://127.0.0.1:${address.port}/walrus/upload-step-v3`, {
            method: "POST", headers: { "content-type": "application/json" },
            body: JSON.stringify({ ...base, registerTransaction }),
        });
        return { status: response.status, body: await response.json() };
    };
    const prepared = await request();
    assert.equal(prepared.status, 200);
    const replay = await request();
    assert.deepEqual(replay.body, prepared.body, "a lost prepare response must replay exact signed bytes");
    assert.equal(sponsorships.length, 1);
    const rejected = await request(prepared.body.registerTransaction);
    assert.equal(rejected.status, 503);
    assert.equal(rejected.body.code, "NO_SIDE_EFFECT");
    assert.match(rejected.body.error, /not found and is not on chain/);
    assert.equal(absentLookups, 9, "rebuild must wait for the pre-execute probe and all eight reconciliation probes");

    const replacement = await request();
    assert.equal(replacement.status, 200);
    assert.equal(sponsorships.length, 2, "reset must request a fresh sponsorship immediately");
    assert.notEqual(replacement.body.registerTransaction.digest, prepared.body.registerTransaction.digest);
    const registered = await request(replacement.body.registerTransaction);
    assert.equal(registered.status, 200);
    assert.equal(registered.body.step.step, "registered");
    assert.equal(registered.body.step.blobObjectId, blobObjectId);
    assert.deepEqual((await request(replacement.body.registerTransaction)).body, registered.body);
    assert.deepEqual(executeCalls, ["handle-0", "handle-0", "handle-1"], "completed registration must not execute twice");
});
