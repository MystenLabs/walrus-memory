import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Inputs, Transaction, TransactionDataBuilder } from "@mysten/sui/transactions";
import {
    assertCompletionBlobObject,
    assertCompletionBlobResponse,
    blobIdFromRaw,
    blobIdMatchesRequested,
    blobObjectMatchesRegistration,
    chainBlobIdFromRaw,
    filterTrustedBlobCandidates,
    findBlobCreationSender,
    getCachedBlobCreationTimestamp,
    isSourceCapped,
    isWalrusBlobObjectType,
    isVerifiedNonexistentSource,
    ownerMatchesRecipient,
    readBlobObject,
    strictWalrusEpoch,
    trustedBlobCandidate,
} from "../sidecar/routes/walrus-query.js";
import { assertSuccessfulMetadataTransfer, extractBlobObjectId } from "../sidecar/blob-metadata.js";
import {
    ENOKI_FALLBACK_TO_DIRECT_SIGN,
    parseDurableWalrusEpochs,
    SUI_TYPE,
    WALRUS_PACKAGE_ID,
} from "../sidecar/config.js";
import {
    addressBalanceExpiration,
    assertAddressBalanceRegisterTransaction,
    assertSponsoredRegisterTransactionKind,
    createdBlobObjectIdFromTransaction,
    durableRegisterDirectSigningAllowed,
    executePreparedRegisterTransaction,
    readUploadBlobObject,
    waitForCertifiedStep,
    certifiedStep,
    type PreparedRegisterTransaction,
    validatePreparedRegisterTransaction,
} from "../sidecar/routes/walrus-upload-journal.js";
import { classifyDurableSideEffectError, NoSideEffectError } from "../sidecar/retry/rpc.js";
import { uploadWalrusBlobWithEffectsRetry } from "../sidecar/routes/walrus-upload.js";
import { metadataReceiptAlreadyApplied } from "../sidecar/routes/walrus-metadata.js";
import { sidecarMetrics } from "../sidecar/state.js";
import {
    ADDRESS_BALANCE_WALLET_FALLBACK_POLICY,
    DURABLE_WALLET_FALLBACK_POLICY,
} from "../sidecar/wallet.js";
import { enforceAddressBalanceCoinIntents } from "../sidecar/address-balance.js";

async function preparedRegisterFixture(funding: "addressBalance" | "coin" | "mixedLegacy" = "addressBalance"): Promise<{
    signer: Ed25519Keypair;
    prepared: PreparedRegisterTransaction;
}> {
    const signer = new Ed25519Keypair();
    const transaction = new Transaction();
    transaction.setSender(signer.toSuiAddress());
    transaction.setGasOwner(signer.toSuiAddress());
    transaction.setGasBudget(1_000n);
    transaction.setGasPrice(1n);
    if (funding !== "coin") {
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
        if (funding === "addressBalance") {
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
        } else {
            transaction.transferObjects(
                [
                    transaction.objectRef({
                    objectId: `0x${"2".repeat(64)}`,
                    version: "1",
                    digest: "11111111111111111111111111111111",
                    }),
                ],
                signer.toSuiAddress()
            );
        }
    } else {
        transaction.setGasPayment([
            {
            objectId: `0x${"1".repeat(64)}`,
            version: "1",
            digest: "11111111111111111111111111111111",
            },
        ]);
    }
    const bytes = await transaction.build();
    const signed = await signer.signTransaction(bytes);
    return {
        signer,
        prepared: {
            transactionBytes: signed.bytes,
            signature: signed.signature,
            digest: TransactionDataBuilder.getDigestFromBytes(bytes),
        },
    };
}

test("durable submissions direct-sign only when sponsorship is unconfigured", () => {
    assert.deepEqual(DURABLE_WALLET_FALLBACK_POLICY, {
        directSignIfUnconfigured: true,
        directSignAfterSponsorFailure: false,
        gasMode: "addressBalance",
    });
});

test("legacy uploads preserve fallback behavior while using address balances", () => {
    assert.deepEqual(ADDRESS_BALANCE_WALLET_FALLBACK_POLICY, {
        directSignIfUnconfigured: ENOKI_FALLBACK_TO_DIRECT_SIGN,
        directSignAfterSponsorFailure: ENOKI_FALLBACK_TO_DIRECT_SIGN,
        gasMode: "addressBalance",
    });
});

test("durable register sponsorship uses an explicit two-phase rollout gate", () => {
    assert.equal(durableRegisterDirectSigningAllowed(false, false), true);
    assert.equal(durableRegisterDirectSigningAllowed(true, false), true);
    assert.equal(durableRegisterDirectSigningAllowed(true, true), false);
});

test("sponsored registration keeps WAL on the sender while assigning gas to the sponsor", async () => {
    const signer = new Ed25519Keypair();
    const sponsor = new Ed25519Keypair();
    const walType = `0x${"2".repeat(64)}::wal::WAL`;
    const transaction = new Transaction();
    transaction.setSender(signer.toSuiAddress());
    transaction.setGasOwner(sponsor.toSuiAddress());
    transaction.setGasBudget(10_000_000n);
    transaction.setGasPrice(1n);
    transaction.setGasPayment([{
        objectId: `0x${"1".repeat(64)}`,
        version: "1",
        digest: "11111111111111111111111111111111",
    }]);
    const withdrawal = transaction.withdrawal({ amount: 1n, type: walType });
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
    const bytes = await transaction.build();
    const signed = await signer.signTransaction(bytes);
    const digest = TransactionDataBuilder.getDigestFromBytes(bytes);
    const sponsorDigest = `sponsor-${digest}`;
    const prepared: PreparedRegisterTransaction = {
        transactionBytes: signed.bytes,
        signature: signed.signature,
        digest,
        sponsorDigest,
    };

    const validated = await validatePreparedRegisterTransaction(prepared, signer.toSuiAddress());
    assert.equal(validated.sponsorDigest, sponsorDigest);
    const expectedKind = TransactionDataBuilder.fromBytes(bytes).build({ onlyTransactionKind: true });
    assert.doesNotThrow(() => assertSponsoredRegisterTransactionKind(
        TransactionDataBuilder.fromBytes(bytes),
        expectedKind,
    ));
    const tamperedKind = expectedKind.slice();
    tamperedKind[tamperedKind.length - 1] ^= 1;
    assert.throws(
        () => assertSponsoredRegisterTransactionKind(
            TransactionDataBuilder.fromBytes(bytes),
            tamperedKind,
        ),
        /kind differs/,
    );

    let submitted = false;
    let directExecutions = 0;
    const finalized = { Transaction: { digest } };
    const client = {
        async getTransaction() {
            if (!submitted) throw Object.assign(new Error("not found"), { code: "NOT_FOUND" });
            return finalized;
        },
        async executeTransaction() {
            directExecutions += 1;
            throw new Error("sponsored journal must not execute directly");
        },
    };
    const result = await executePreparedRegisterTransaction(
        validated,
        client,
        () => {},
        async () => 1n,
        false,
        async (executedSponsorDigest, signature) => {
            assert.equal(executedSponsorDigest, sponsorDigest);
            assert.equal(signature, signed.signature);
            submitted = true;
            return { digest };
        },
    );
    assert.equal(result, finalized);
    assert.equal(directExecutions, 0);

    submitted = false;
    await assert.rejects(
        executePreparedRegisterTransaction(
            validated,
            client,
            () => {},
            async () => 1n,
            false,
            async () => {
                throw new Error('Enoki API error (400): {"errors":[{"code":"expired"}]}');
            },
            1,
        ),
        (error: unknown) => error instanceof NoSideEffectError && /rebuild sponsorship/.test(error.message),
    );

    await assert.rejects(
        executePreparedRegisterTransaction(
            validated,
            client,
            () => {},
            async () => 1n,
            false,
            async () => {
                throw new Error('Enoki API error (404): {"errors":[{"code":"not_found","message":"Sponsored transaction not found"}]}');
            },
            1,
        ),
        (error: unknown) => error instanceof NoSideEffectError
            && /not found and is not on chain; rebuild sponsorship/.test(error.message)
            && classifyDurableSideEffectError(error, true, true)?.code === "NO_SIDE_EFFECT",
    );

    await assert.rejects(
        executePreparedRegisterTransaction(
            validated,
            client,
            () => {},
            async () => 1n,
            true,
            async () => {
                throw new Error('Enoki API error (404): {"errors":[{"code":"not_found","message":"Sponsored transaction not found"}]}');
            },
            1,
        ),
        (error: unknown) => error instanceof Error
            && (error as { code?: string }).code === "UNAVAILABLE"
            && /ambiguous/.test(error.message),
    );

    let lookups = 0;
    const retryClient = {
        async getTransaction() {
            lookups += 1;
            // 1 = pre-execute probe. 2 = first expired-path miss. 3 = hit.
            // A helper that only looks up once would stop after #2 and fail.
            if (lookups < 3) throw Object.assign(new Error("not found"), { code: "NOT_FOUND" });
            return finalized;
        },
        async executeTransaction() {
            throw new Error("sponsored journal must not execute directly");
        },
    };
    const recovered = await executePreparedRegisterTransaction(
        validated,
        retryClient,
        () => {},
        async () => 1n,
        false,
        async () => {
            throw new Error('Enoki API error (400): {"errors":[{"code":"expired"}]}');
        },
        2,
    );
    assert.equal(recovered, finalized);
    assert.equal(lookups, 3);

    await assert.rejects(
        executePreparedRegisterTransaction(
            validated,
            client,
            () => {},
            async () => 1n,
            true,
            async () => {
                throw new Error('Enoki API error (400): {"errors":[{"code":"expired"}]}');
            },
            1,
        ),
        (error: unknown) => error instanceof Error
            && (error as { code?: string }).code === "UNAVAILABLE"
            && /ambiguous/.test(error.message),
    );
});

test("prepared registration rejects tampered digest, signature, and wallet", async () => {
    const { signer, prepared } = await preparedRegisterFixture();
    await assert.doesNotReject(validatePreparedRegisterTransaction(prepared, signer.toSuiAddress()));
    await assert.rejects(
        validatePreparedRegisterTransaction(
            { ...prepared, digest: `x${prepared.digest.slice(1)}` },
            signer.toSuiAddress()
        ),
        /digest mismatch/
    );

    const otherSigner = new Ed25519Keypair();
    const bytes = new Uint8Array(Buffer.from(prepared.transactionBytes, "base64"));
    const otherSignature = await otherSigner.signTransaction(bytes);
    await assert.rejects(
        validatePreparedRegisterTransaction(
            { ...prepared, signature: otherSignature.signature },
            signer.toSuiAddress()
        ),
        /provided address/
    );
    await assert.rejects(
        validatePreparedRegisterTransaction(prepared, otherSigner.toSuiAddress()),
        /sender does not match the journaled wallet/
    );
});

test("new registrations require address balances while legacy signed journals remain replayable", async () => {
    const { signer, prepared } = await preparedRegisterFixture("coin");
    const validated = await validatePreparedRegisterTransaction(prepared, signer.toSuiAddress());
    assert.equal(validated.maxEpoch, undefined);
    assert.throws(
        () => assertAddressBalanceRegisterTransaction(TransactionDataBuilder.fromBytes(validated.bytes)),
        /must pay gas from the address balance/
    );

    const mixed = await preparedRegisterFixture("mixedLegacy");
    const validatedMixed = await validatePreparedRegisterTransaction(mixed.prepared, mixed.signer.toSuiAddress());
    assert.equal(validatedMixed.maxEpoch, 2n);
    assert.throws(
        () => assertAddressBalanceRegisterTransaction(TransactionDataBuilder.fromBytes(validatedMixed.bytes)),
        /resolved WAL from an owned coin/
    );
});

test("the pinned Sui SDK resolves WAL payment and relay SUI tip from address balances", async () => {
    const signer = new Ed25519Keypair();
    const walType = `0x${"2".repeat(64)}::wal::WAL`;
    const transaction = new Transaction();
    transaction.setSender(signer.toSuiAddress());
    transaction.setGasOwner(signer.toSuiAddress());
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
    const wal = transaction.coin({
        type: walType,
        balance: 1n,
        useGasCoin: false,
    });
    const relayTip = transaction.coin({ type: SUI_TYPE, balance: 1n });
    transaction.moveCall({
        target: "0x2::coin::destroy_zero",
        typeArguments: [walType],
        arguments: [wal],
    });
    transaction.transferObjects([relayTip], signer.toSuiAddress());

    const client = {
        core: {
            async getBalance({ coinType }: { coinType: string }) {
                return {
                    balance: {
                        coinType,
                        balance: "10",
                        addressBalance: "10",
                        coinBalance: "0",
                    },
                };
            },
            async listCoins() {
                return { objects: [], cursor: null, hasNextPage: false };
            },
        },
    };
    await transaction.prepareForSerialization({ client: client as never });

    const resolved = TransactionDataBuilder.restore(transaction.getData() as never);
    assert.equal(assertAddressBalanceRegisterTransaction(resolved), 2n);
    const withdrawals = resolved.inputs.filter((input) => input.$kind === "FundsWithdrawal");
    assert.equal(withdrawals.length, 2, "WAL payment and relay SUI tip both use address balances");
});

test("address-balance uploads fail instead of falling back to owned coins", async () => {
    const signer = new Ed25519Keypair();
    const walType = `0x${"2".repeat(64)}::wal::WAL`;
    const transaction = new Transaction();
    transaction.setSender(signer.toSuiAddress());
    transaction.coin({ type: walType, balance: 1n, useGasCoin: false });
    enforceAddressBalanceCoinIntents(transaction);

    let balanceCalls = 0;
    const client = {
        core: {
            async getBalance() {
                balanceCalls += 1;
                return {
                    balance: {
                        balance: "1",
                        addressBalance: balanceCalls === 1 ? "1" : "0",
                        coinBalance: balanceCalls === 1 ? "0" : "1",
                    },
                };
            },
            async listCoins() {
                return {
                    objects: [{
                        objectId: `0x${"1".repeat(64)}`,
                        version: "1",
                        digest: "11111111111111111111111111111111",
                        balance: "1",
                        coinType: walType,
                    }],
                    cursor: null,
                    hasNextPage: false,
                };
            },
            async getObjects({ objectIds }: { objectIds: string[] }) {
                return {
                    objects: objectIds.map((objectId) => ({
                        objectId,
                        type: `0x2::coin::Coin<${walType}>`,
                    })),
                };
            },
        },
    };
    await assert.rejects(
        transaction.prepareForSerialization({ client: client as never }),
        /Address-balance upload resolved owned coin objects/,
    );
    await assert.rejects(
        transaction.prepareForSerialization({ client: client as never }),
        /Address-balance upload resolved owned coin objects/,
    );
});

test("address-balance enforcement permits newly resolved non-coin objects", async () => {
    const signer = new Ed25519Keypair();
    const walType = `0x${"2".repeat(64)}::wal::WAL`;
    const objectId = `0x${"6".repeat(64)}`;
    const transaction = new Transaction();
    transaction.setSender(signer.toSuiAddress());
    transaction.coin({ type: walType, balance: 1n, useGasCoin: false });
    enforceAddressBalanceCoinIntents(transaction);
    transaction.addSerializationPlugin(async (transactionData, _options, next) => {
        transactionData.addInput("object", Inputs.ObjectRef({
            objectId,
            version: "1",
            digest: "33333333333333333333333333333333",
        }));
        await next();
    });

    const client = {
        core: {
            async getBalance() {
                return {
                    balance: {
                        balance: "1",
                        addressBalance: "1",
                        coinBalance: "0",
                    },
                };
            },
            async listCoins() {
                return { objects: [], cursor: null, hasNextPage: false };
            },
            async getObjects() {
                return {
                    objects: [{
                        objectId,
                        type: `${WALRUS_PACKAGE_ID}::blob::Blob`,
                    }],
                };
            },
        },
    };

    await assert.doesNotReject(
        transaction.prepareForSerialization({ client: client as never }),
    );
});

test("address-balance uploads reject owned gas resolved during build", async () => {
    const signer = new Ed25519Keypair();
    const gasObjectId = `0x${"4".repeat(64)}`;
    const transaction = new Transaction();
    transaction.setSender(signer.toSuiAddress());
    transaction.setGasBudget(1n);
    transaction.setGasPrice(1n);
    transaction.transferObjects(
        [transaction.objectRef({
            objectId: `0x${"5".repeat(64)}`,
            version: "1",
            digest: "11111111111111111111111111111111",
        })],
        signer.toSuiAddress(),
    );
    enforceAddressBalanceCoinIntents(transaction);

    const client = {
        core: {
            resolveTransactionPlugin() {
                return async (
                    transactionData: TransactionDataBuilder,
                    _options: unknown,
                    next: () => Promise<void>,
                ) => {
                    transactionData.gasData.payment = [{
                        objectId: gasObjectId,
                        version: "1",
                        digest: "22222222222222222222222222222222",
                    }];
                    await next();
                };
            },
        },
    };

    await assert.rejects(
        transaction.build({ client: client as never }),
        /Address-balance upload resolved gas from an owned coin/,
    );
});

test("address-balance enforcement preserves async object inputs across rebuilds", async () => {
    const signer = new Ed25519Keypair();
    const objectId = `0x${"3".repeat(64)}`;
    const transaction = new Transaction();
    transaction.setSender(signer.toSuiAddress());
    transaction.add(async (tx) => {
        await Promise.resolve();
        tx.transferObjects(
            [tx.objectRef({
                objectId,
                version: "1",
                digest: "11111111111111111111111111111111",
            })],
            signer.toSuiAddress(),
        );
    });
    enforceAddressBalanceCoinIntents(transaction);

    await assert.doesNotReject(transaction.build({ onlyTransactionKind: true }));
    await assert.doesNotReject(transaction.build({ onlyTransactionKind: true }));
});

test("migration source status trusts only verified nonexistent blobs", () => {
    assert.equal(isVerifiedNonexistentSource({ type: "nonexistent" }), true);
    assert.equal(isVerifiedNonexistentSource({ type: "invalid" }), false);
    assert.equal(isVerifiedNonexistentSource({ type: "permanent" }), false);
    assert.equal(isVerifiedNonexistentSource({ type: "deletable" }), false);
    assert.equal(isVerifiedNonexistentSource({ type: "unknown" }), false);
});

test("prepared registration queries the digest before replaying the same signed bytes", async () => {
    const { signer, prepared } = await preparedRegisterFixture();
    const validated = await validatePreparedRegisterTransaction(prepared, signer.toSuiAddress());
    const finalized = {
        $kind: "Transaction",
        Transaction: { digest: prepared.digest },
    };
    let storedResult: unknown;
    let executeCalls = 0;
    const client = {
        async getTransaction({ digest }: { digest: string }) {
            assert.equal(digest, prepared.digest);
            if (!storedResult) {
                throw Object.assign(new Error("transaction not found"), {
                    code: "NOT_FOUND",
                });
            }
            return storedResult;
        },
        async executeTransaction({ transaction, signatures }: { transaction: Uint8Array; signatures: string[] }) {
            executeCalls += 1;
            assert.deepEqual(transaction, validated.bytes);
            assert.deepEqual(signatures, [prepared.signature]);
            storedResult = finalized;
            return storedResult;
        },
    };

    const submittedBefore = sidecarMetrics.walletSubmittedTotal;
    const currentEpoch = async () => 1n;
    assert.equal(await executePreparedRegisterTransaction(validated, client, () => {}, currentEpoch), finalized);
    assert.equal(sidecarMetrics.walletSubmittedTotal, submittedBefore + 1);
    assert.equal(await executePreparedRegisterTransaction(validated, client, () => {}, currentEpoch), finalized);
    assert.equal(
        sidecarMetrics.walletSubmittedTotal,
        submittedBefore + 1,
        "querying an already-finalized digest is not a new wallet submission"
    );
    assert.equal(executeCalls, 1);
    storedResult = {
        $kind: "Transaction",
        Transaction: { digest: "wrong-digest" },
    };
    await assert.rejects(
        executePreparedRegisterTransaction(validated, client, () => {}, currentEpoch),
        /response digest mismatch/
    );
});

test("an expired prepared registration absent from chain is safe to rebuild", async () => {
    const { signer, prepared } = await preparedRegisterFixture();
    const validated = await validatePreparedRegisterTransaction(prepared, signer.toSuiAddress());
    assert.ok(validated.maxEpoch !== undefined);
    const expiredEpoch = validated.maxEpoch + 1n;
    let executeCalls = 0;
    const client = {
        async getTransaction() {
            throw Object.assign(new Error("transaction not found"), {
                code: "NOT_FOUND",
            });
        },
        async executeTransaction() {
            executeCalls += 1;
            throw new Error("must not execute an expired transaction");
        },
    };

    await assert.rejects(
        executePreparedRegisterTransaction(
            validated,
            client,
            () => {},
            async () => expiredEpoch
        ),
        NoSideEffectError
    );
    const ambiguous = await executePreparedRegisterTransaction(
        validated,
        client,
        () => {},
        async () => expiredEpoch,
        true
    ).then(
        () => null,
        (error) => error
    );
    assert.match(ambiguous?.message, /expired .* but remains ambiguous/);
    assert.deepEqual(classifyDurableSideEffectError(ambiguous, true, true), {
        code: "SHARED_SERVICE_UNAVAILABLE",
    });
    assert.equal(executeCalls, 0);
});

test("a newly created Blob missing from an RPC replica remains replayable", async () => {
    const objectId = `0x${"2".repeat(64)}`;
    await assert.rejects(
        readBlobObject(
            objectId,
            { json: true },
            {
            async getObject() {
                throw new Error(`Object ${objectId} not found`);
            },
            }
        ),
        (error: unknown) => {
            assert.deepEqual(classifyDurableSideEffectError(error, true, true), {
                code: "SHARED_SERVICE_UNAVAILABLE",
            });
            return true;
        }
    );

    await assert.rejects(
        readBlobObject(
            objectId,
            { json: true },
            {
            async getObject() {
                throw new Error(`Object 0x${"3".repeat(64)} not found`);
            },
            }
        ),
        (error: unknown) => {
            assert.deepEqual(classifyDurableSideEffectError(error, true, true), {
                code: "DURABLE_SIDE_EFFECT_VERIFY_FAILED",
            });
            return true;
        }
    );
});

test("upload journal retries a newly created Blob on a stale RPC replica", async () => {
    const objectId = `0x${"2".repeat(64)}`;
    const expected = { object: { objectId } };
    let calls = 0;

    const result = await readUploadBlobObject(
        objectId,
        { json: true },
        {
        async getObject() {
            calls += 1;
            if (calls === 1) throw new Error(`Object ${objectId} not found`);
            return expected as never;
        },
        }
    );

    assert.equal(calls, 2);
    assert.equal(result, expected);
});

test("waitForCertifiedStep retries when blob object has certified_epoch null due to replica lag", async () => {
    const objectId = `0x${"3".repeat(64)}`;
    const oneLe = Buffer.from(new Uint8Array([1, ...new Array(31).fill(0)]));
    const blobId = oneLe.toString("base64url");
    let calls = 0;

    const mockClient = {
        async getObject() {
            calls += 1;
            return {
                object: {
                    json: {
                        blob_id: "1",
                        id: objectId,
                        registered_epoch: 40,
                        // First 2 calls simulate replica lag (certified_epoch is null)
                        certified_epoch: calls >= 3 ? 40 : null,
                    },
                },
            } as never;
        },
    };

    const result = await waitForCertifiedStep(blobId, objectId, 5, 10, mockClient);
    assert.ok(result);
    assert.equal(result.step, "certified");
    assert.equal(result.blobId, blobId);
    assert.equal(result.blobObjectId, objectId);
    assert.equal(result.blobObject.certified_epoch, 40);
    assert.equal(calls, 3);
});

test("waitForCertifiedStep returns null if certified_epoch remains null after maxAttempts", async () => {
    const objectId = `0x${"4".repeat(64)}`;
    const oneLe = Buffer.from(new Uint8Array([1, ...new Array(31).fill(0)]));
    const blobId = oneLe.toString("base64url");
    let calls = 0;

    const mockClient = {
        async getObject() {
            calls += 1;
            return {
                object: {
                    json: {
                        blob_id: "1",
                        id: objectId,
                        registered_epoch: 40,
                        certified_epoch: null,
                    },
                },
            } as never;
        },
    };

    const result = await waitForCertifiedStep(blobId, objectId, 3, 10, mockClient);
    assert.equal(result, null);
    assert.equal(calls, 3);
});

test("metadata ownership is adopted only during reconciliation", () => {
    const owner = `0x${"1".repeat(64)}`;
    const currentOwner = { AddressOwner: owner };
    assert.equal(metadataReceiptAlreadyApplied(true, currentOwner, owner), true);
    assert.equal(metadataReceiptAlreadyApplied(false, currentOwner, owner), false);
});

test("blobIdFromRaw converts on-chain U256 decimal to little-endian base64url", () => {
    // 1 → 32-byte LE array [1, 0, ..., 0] → "AQAA...". Walrus blob IDs are
    // unpadded base64url of the 32-byte little-endian representation.
    const oneLe = Buffer.from(new Uint8Array([1, ...new Array(31).fill(0)]));
    assert.equal(blobIdFromRaw("1".padStart(21, "0")), oneLe.toString("base64url"));
});

test("blobIdFromRaw passes through already-encoded ids and rejects empties", () => {
    assert.equal(blobIdFromRaw("AbCd_efg"), "AbCd_efg");
    // Short decimal strings (≤20 chars) are not treated as U256.
    assert.equal(blobIdFromRaw("12345"), "12345");
    assert.equal(blobIdFromRaw(null), null);
    assert.equal(blobIdFromRaw(undefined), null);
    assert.equal(blobIdFromRaw(""), null);
});

test("chainBlobIdFromRaw converts every decimal U256 representation", () => {
    const oneLe = Buffer.from(new Uint8Array([1, ...new Array(31).fill(0)]));
    assert.equal(chainBlobIdFromRaw("1"), oneLe.toString("base64url"));
    assert.equal(chainBlobIdFromRaw("already-encoded"), "already-encoded");
});

test("source lease epochs accept only u32 numbers", () => {
    assert.equal(strictWalrusEpoch(0, "epoch"), 0);
    assert.equal(strictWalrusEpoch(0xffff_ffff, "epoch"), 0xffff_ffff);
    for (const invalid of [-1, 1.5, 0x1_0000_0000, "460", null, undefined]) {
        assert.throws(() => strictWalrusEpoch(invalid, "epoch"), /epoch must be a u32/);
    }
});

test("isSourceCapped flags only when the raw candidate fetch proved more than cap exist (WALM-319)", () => {
    // The call site now probes with `cap + 1` and slices back down to `cap`,
    // so `fetchedCount` here is the probe fetch's raw count compared against
    // the real (non-probe) cap. Exactly `cap` fetched means discovery
    // completed within the cap — not capped. Only strictly more than `cap`
    // proves the source had more candidates than the cap allowed (Henry's
    // review on PR #538: exact-cap results must not read as truncated).
    assert.equal(isSourceCapped(3, 5), false, "fewer fetched than cap: not capped");
    assert.equal(isSourceCapped(5, 5), false, "fetched exactly cap: discovery completed, not capped");
    assert.equal(isSourceCapped(6, 5), true, "fetched more than cap (probe proved more exist): capped");
    assert.equal(isSourceCapped(0, 5), false, "nothing fetched: not capped");
    assert.equal(isSourceCapped(5, Infinity), false, "unbounded cap can never be hit");
});

test("registration reconciliation requires matching size and deletability", () => {
    assert.equal(blobObjectMatchesRegistration({ rawSize: "42", deletable: true }, 42), true);
    assert.equal(blobObjectMatchesRegistration({ rawSize: 41, deletable: true }, 42), false);
    assert.equal(blobObjectMatchesRegistration({ rawSize: 42, deletable: false }, 42), false);
});

test("durable upload epochs require 15 on mainnet and allow 1 through 15 elsewhere", () => {
    assert.equal(parseDurableWalrusEpochs(1, "testnet"), 1);
    assert.equal(parseDurableWalrusEpochs(14, "testnet"), 14);
    assert.equal(parseDurableWalrusEpochs(15, "mainnet"), 15);
    assert.equal(parseDurableWalrusEpochs(1, "mainnet"), null);
    assert.equal(parseDurableWalrusEpochs(14, "mainnet"), null);
    for (const invalid of [0, 16, -1, 1.5, "3", null, undefined, Number.NaN]) {
        assert.equal(parseDurableWalrusEpochs(invalid, "testnet"), null);
    }
});

test("blobIdMatchesRequested filters migration IDs before metadata lookup", () => {
    const requested = new Set(["wanted", "also-wanted"]);
    assert.equal(blobIdMatchesRequested("wanted", requested), true);
    assert.equal(blobIdMatchesRequested("other", requested), false);
    assert.equal(blobIdMatchesRequested(null, requested), false);
    assert.equal(blobIdMatchesRequested("anything", undefined), true);
});

test("ownerMatchesRecipient handles string and object owner encodings", () => {
    assert.equal(ownerMatchesRecipient("0xa", "0xa"), true);
    assert.equal(ownerMatchesRecipient({ AddressOwner: "0xa" }, "0xa"), true);
    assert.equal(ownerMatchesRecipient({ ObjectOwner: "0xa" }, "0xa"), true);
    assert.equal(ownerMatchesRecipient({ AddressOwner: "0xb" }, "0xa"), false);
    assert.equal(ownerMatchesRecipient(null, "0xa"), false);
    assert.equal(ownerMatchesRecipient(42, "0xa"), false);
});

test("blob provenance uses the archival creation transaction, not the latest transfer", async () => {
    const objectId = `0x${"1".repeat(64)}`;
    const trusted = `0x${"2".repeat(64)}`;
    const attacker = `0x${"3".repeat(64)}`;
    const createdTimestamp = "2026-09-30T07:23:16.416Z";
    const client = {
        async getCreationTransaction() {
            return "create-tx";
        },
        async getTransaction(digest: string) {
            assert.equal(digest, "create-tx");
            return {
                status: { success: true },
                transaction: { sender: trusted },
                effects: {
                    timestamp: createdTimestamp,
                    changedObjects: [{ objectId, idOperation: "Created" }],
                },
            };
        },
    };

    assert.equal(await findBlobCreationSender({ objectId, previousTransaction: "attacker-transfer-tx" }, client), trusted);
    assert.equal(getCachedBlobCreationTimestamp(objectId), createdTimestamp);
    assert.deepEqual(
        await trustedBlobCandidate(
            { objectId, owner: { AddressOwner: attacker }, previousTransaction: "transfer-tx" },
            attacker,
            new Set([trusted]),
            client
        ),
        { trusted: true, reason: "trusted", uploader: trusted }
    );
});

test("blob provenance excludes external creators and fails closed on incomplete history", async () => {
    const objectId = `0x${"1".repeat(64)}`;
    const recipient = `0x${"2".repeat(64)}`;
    const attacker = `0x${"3".repeat(64)}`;
    const creationClient = {
        async getTransaction() {
            return {
                status: { success: true },
                transaction: { sender: attacker },
                effects: { changedObjects: [{ objectId, idOperation: "Created" }] },
            };
        },
        async getCreationTransaction() {
            return "create-tx";
        },
    };
    const blob = { objectId, owner: { AddressOwner: recipient }, previousTransaction: "create-tx" };
    assert.deepEqual(await trustedBlobCandidate(blob, recipient, new Set([recipient]), creationClient), {
        trusted: false,
        reason: "provenance",
        uploader: attacker,
    });
    const unavailableClient = { ...creationClient, getCreationTransaction: async () => null };
    assert.equal(await findBlobCreationSender(blob, unavailableClient), null);
    assert.deepEqual(await trustedBlobCandidate(blob, recipient, new Set([attacker]), unavailableClient), {
        trusted: false,
        reason: "provenance",
        uploader: null,
    });
    assert.deepEqual(await trustedBlobCandidate({ ...blob, owner: { AddressOwner: attacker } }, recipient, new Set(), creationClient), {
        trusted: false,
        reason: "owner",
        uploader: null,
    });
});

test("provenance transport failures fail the query instead of silently dropping blobs", async () => {
    const recipient = `0x${"2".repeat(64)}`;
    const blob = {
        objectId: `0x${"1".repeat(64)}`,
        owner: { AddressOwner: recipient },
        previousTransaction: "create-tx",
    };
    await assert.rejects(
        filterTrustedBlobCandidates([blob], recipient, "test-request", async () => {
            throw new Error("archive timeout");
        }),
        /unable to verify creation provenance.*archive timeout/
    );
});

test("ownerMatchesRecipient compares canonicalized addresses, not exact strings", () => {
    const lower = `0x${"ab".repeat(32)}`;
    const upper = `0x${"AB".repeat(32)}`;
    // gRPC returns lowercase; a mixed-case journaled owner must still match.
    assert.equal(ownerMatchesRecipient(lower, upper), true);
    assert.equal(ownerMatchesRecipient({ AddressOwner: lower }, upper), true);
    assert.equal(ownerMatchesRecipient({ ObjectOwner: upper }, lower), true);
    // Zero-padding differences are canonicalized too.
    assert.equal(ownerMatchesRecipient("0x00a", "0xA"), true);
    // Distinct addresses still never match.
    assert.equal(ownerMatchesRecipient(lower, `0x${"cd".repeat(32)}`), false);
});

test("metadata reconciliation adopts a lowercase chain owner for a mixed-case journal", () => {
    const lower = `0x${"ab".repeat(32)}`;
    const upper = `0x${"AB".repeat(32)}`;
    assert.equal(metadataReceiptAlreadyApplied(true, { AddressOwner: lower }, upper), true);
});

test("isWalrusBlobObjectType normalizes 0x-padded package addresses", () => {
    const blobType = "0xfdc88f7d::blob::Blob";
    assert.equal(isWalrusBlobObjectType("0xfdc88f7d::blob::Blob", blobType), true);
    assert.equal(isWalrusBlobObjectType("0x000fdc88f7d::blob::Blob", blobType), true);
    assert.equal(isWalrusBlobObjectType("0xFDC88F7D::blob::Blob", blobType), true);
    assert.equal(isWalrusBlobObjectType("0xother::blob::Blob", blobType), false);
    assert.equal(isWalrusBlobObjectType("0xfdc88f7d::storage::Blob", blobType), false);
    assert.equal(isWalrusBlobObjectType(undefined, blobType), false);
});

test("completion requires the current destination Blob object and an unexpired lease", () => {
    const blobId = chainBlobIdFromRaw("7")!;
    const objectId = `0x${"1".repeat(64)}`;
    const owner = `0x${"2".repeat(64)}`;
    const object = {
        objectType: `${WALRUS_PACKAGE_ID}::blob::Blob`,
        owner: { AddressOwner: owner },
        json: {
            blob_id: "7",
            size: 42,
            deletable: true,
            certified_epoch: 1,
            storage: { end_epoch: 10 },
        },
    };
    const expected = { objectId, owner, size: 42, blobId };

    assert.equal(assertCompletionBlobObject(object, expected, 9), 10);
    assert.equal(assertCompletionBlobResponse({ object }, expected, 9), 10);
    assert.throws(() => assertCompletionBlobResponse(object, expected, 9), /missing from the gRPC response/);
    assert.throws(
        () => assertCompletionBlobObject(object, { ...expected, blobId: chainBlobIdFromRaw("8")! }, 9),
        /does not contain/
    );
    assert.throws(() => assertCompletionBlobObject(object, expected, 10), /expired/);
});

test("extractBlobObjectId prefers the SDK certified-step field", () => {
    assert.equal(extractBlobObjectId({ blobObjectId: "0xtop" }), "0xtop");
    assert.equal(extractBlobObjectId({ blobObject: { id: "0xnested" } }), "0xnested");
    assert.equal(extractBlobObjectId({}), null);
});

test("metadata transfer accepts only a successful Sui transaction", () => {
    assert.doesNotThrow(() =>
        assertSuccessfulMetadataTransfer(
            {
        $kind: "Transaction",
        Transaction: { status: { success: true, error: null } },
            },
            "success-digest"
        )
    );
    assert.throws(
        () =>
            assertSuccessfulMetadataTransfer(
                {
            $kind: "FailedTransaction",
                    FailedTransaction: {
                        status: { success: false, error: {} },
                    },
                },
                "failed-digest"
            ),
        /failed-digest was not successful/
    );
});

test("journaled upload resumes the registered deletable object", async () => {
    let options: unknown;
    const flow = {
        upload: async (value: unknown) => {
            options = value;
            return { step: "uploaded" };
        },
    };
    await uploadWalrusBlobWithEffectsRetry(
        flow,
        "register-digest",
        { traceId: "trace", jobId: "job", keyIndex: 0 },
        true
    );
    assert.deepEqual(options, { digest: "register-digest", deletable: true });
});

test("normal registration checkpoints the exact Blob from transaction effects", () => {
    assert.equal(
        createdBlobObjectIdFromTransaction({
        $kind: "Transaction",
        Transaction: {
            status: { success: true, error: null },
            objectTypes: {
                "0xblob": `${WALRUS_PACKAGE_ID}::blob::Blob`,
                "0xmetadata": "0x2::dynamic_field::Field",
            },
            effects: {
                changedObjects: [
                    { objectId: "0xblob", idOperation: "Created" },
                    { objectId: "0xmetadata", idOperation: "Created" },
                ],
            },
        },
        }),
        "0xblob"
    );
    assert.throws(() =>
        createdBlobObjectIdFromTransaction({
        $kind: "FailedTransaction",
        FailedTransaction: { status: { success: false, error: {} } },
        })
    );
});

test("a rejected register expiration names the bound that broke the guard", () => {
    // The guard rejects on three conditions joined by `||`. When every upload
    // job on testnet hit this (2026-09-17) the logged sentence named the
    // invariant but not the value, so the relayer logs could not say which
    // condition fired. The message has to carry the shape it saw.
    const signer = new Ed25519Keypair();
    const transaction = new Transaction();
    transaction.setSender(signer.toSuiAddress());
    transaction.setGasOwner(signer.toSuiAddress());
    transaction.setGasBudget(1_000n);
    transaction.setGasPrice(1n);
    transaction.setGasPayment([]);
    transaction.setExpiration({
        ValidDuring: {
            minEpoch: "1",
            maxEpoch: "2",
            minTimestamp: "5",
            maxTimestamp: null,
            chain: "69WiPg3DAQiwdxfncX6wYQ2siKwAe6L9BZthQea3JNMD",
            nonce: 1,
        },
    });

    const resolved = TransactionDataBuilder.restore(transaction.getData() as never);
    assert.throws(
        () => assertAddressBalanceRegisterTransaction(resolved),
        (error: Error) => {
            assert.match(error.message, /must use a ValidDuring address-balance expiration/);
            assert.match(error.message, /expiration=ValidDuring/);
            assert.match(error.message, /minTimestamp="5"/);
            assert.match(error.message, /maxTimestamp=null/);
            return true;
        },
    );
});


/** Build a register the way `prepareRegisterTransaction` does: gas from the
 * address balance, a WAL withdrawal, and the expiration the production path now
 * applies. Every other register fixture in this file hand-sets `ValidDuring`,
 * which is exactly why the direct-signed path could reject every write in
 * production while the suite stayed green. */
async function directSignedRegister(
    rebuild = "",
    signer = new Ed25519Keypair(),
): Promise<TransactionDataBuilder> {
    const transaction = new Transaction();
    transaction.setSender(signer.toSuiAddress());
    transaction.setGasOwner(signer.toSuiAddress());
    transaction.setGasBudget(1_000n);
    transaction.setGasPrice(1n);
    transaction.setGasPayment([]);
    const walType = `0x${"2".repeat(64)}::wal::WAL`;
    const withdrawal = transaction.withdrawal({ amount: 1n, type: walType });
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
    transaction.setExpiration(
        addressBalanceExpiration(
            7n,
            await transaction.build({ onlyTransactionKind: true }),
            rebuild,
        ),
    );
    return TransactionDataBuilder.fromBytes(await transaction.build());
}

test("the expiration prepareRegisterTransaction applies is the one the guard demands", async () => {
    // The positive half of the dev outage: `flow.register()` hands back a
    // transaction with no expiration, and the guard one line later requires a
    // ValidDuring window, so every direct-signed register failed its own
    // assertion and no blob was certified. A register carrying what
    // addressBalanceExpiration builds passes, and reports the epoch the journal
    // then uses as its expiry guard.
    assert.equal(assertAddressBalanceRegisterTransaction(await directSignedRegister()), 7n);
});

test("a register whose expiration is not ValidDuring is rejected", async () => {
    // The `$kind` arm of the guard, which the timestamp case above does not
    // reach. Built with the real expiration first: a withdrawal cannot be
    // resolved offline without one, which is its own evidence that the window
    // is not optional here.
    const data = await directSignedRegister();
    data.expiration = { $kind: "Epoch", Epoch: "7" } as typeof data.expiration;
    assert.throws(
        () => assertAddressBalanceRegisterTransaction(data),
        /must use a ValidDuring address-balance expiration/,
    );
});

test("the address-balance nonce is derived from the transaction, not drawn at random", () => {
    const kind = new Uint8Array([1, 2, 3]);
    const otherKind = new Uint8Array([1, 2, 4]);

    // Re-preparing the same register must rebuild byte-identical, or the
    // journal stops being idempotent and a replay pays for a second blob.
    assert.equal(
        addressBalanceExpiration(9n, kind).ValidDuring.nonce,
        addressBalanceExpiration(9n, kind).ValidDuring.nonce,
    );
    // Two different registers must still reserve under different nonces.
    assert.notEqual(
        addressBalanceExpiration(9n, kind).ValidDuring.nonce,
        addressBalanceExpiration(9n, otherKind).ValidDuring.nonce,
    );

    const { minEpoch, maxEpoch, minTimestamp, maxTimestamp } =
        addressBalanceExpiration(9n, kind).ValidDuring;
    assert.equal(minEpoch, "9");
    assert.equal(maxEpoch, "9");
    assert.equal(minTimestamp, null);
    assert.equal(maxTimestamp, null);
});

test("a congestion rebuild is not the same nonce or the same bytes", async () => {
    const kind = new Uint8Array([1, 2, 3]);
    const firstNonce = addressBalanceExpiration(9n, kind).ValidDuring.nonce;
    // An empty salt is the first attempt. It must stay the hash of the kind.
    assert.equal(firstNonce, addressBalanceExpiration(9n, kind, "").ValidDuring.nonce);
    assert.notEqual(
        firstNonce,
        addressBalanceExpiration(9n, kind, "cancelled-digest").ValidDuring.nonce,
    );

    const signer = new Ed25519Keypair();
    const first = await directSignedRegister("", signer);
    const second = await directSignedRegister("cancelled-digest", signer);
    const firstKind = first.build({ onlyTransactionKind: true });
    const secondKind = second.build({ onlyTransactionKind: true });
    assert.ok(Buffer.from(firstKind).equals(Buffer.from(secondKind)));
    const nonce = (data: TransactionDataBuilder) => (
        data.expiration?.$kind === "ValidDuring" ? data.expiration.ValidDuring.nonce : undefined
    );
    assert.equal(nonce(first), addressBalanceExpiration(7n, firstKind).ValidDuring.nonce);
    assert.equal(
        nonce(second),
        addressBalanceExpiration(7n, secondKind, "cancelled-digest").ValidDuring.nonce,
    );
    assert.notEqual(nonce(first), nonce(second));
    assert.equal(Buffer.from(first.build()).equals(Buffer.from(second.build())), false);
});

test("lease and verify reads use the shared Walrus client max age", () => {
    // A 1s override reset the client on every expiry-sweep owner. Each reset
    // re-parsed system state synchronously and the main thread stopped
    // accepting /health. The default is WALRUS_CLIENT_MAX_AGE_MS.
    const src = readFileSync(new URL("../sidecar/routes/walrus-query.ts", import.meta.url), "utf8");
    const calls = [...src.matchAll(/refreshWalrusClientIfStale\(([^)]*)\)/g)].map((match) =>
        match[1].trim(),
    );
    assert.ok(calls.length >= 2);
    for (const arg of calls) {
        assert.equal(arg, "");
    }
});
