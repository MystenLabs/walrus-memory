import test from "node:test";
import assert from "node:assert/strict";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";
import {
    classifyDurableSideEffectError,
    CongestionCancelledTransaction,
    FinalizedTransactionFailure,
    isRetryableRpcError,
    isRetryableSharedInfraError,
} from "../sidecar/retry/rpc.js";
import { sealKeyFetchErrorCode } from "../sidecar/routes/seal.js";
import { assertFinalizedTransactionSuccess } from "../sidecar/wallet.js";
import { executeDirectSignedTransaction, isMoveAbortBalanceSplit } from "../sidecar/enoki.js";

test("shared-service failures preserve pre-submit and ambiguous state", () => {
    const unavailable = Object.assign(new Error("RPC unavailable"), { code: "UNAVAILABLE" });

    assert.deepEqual(classifyDurableSideEffectError(unavailable, true, false), {
        code: "NO_SIDE_EFFECT",
        causeCode: "SHARED_SERVICE_UNAVAILABLE",
    });
    assert.deepEqual(classifyDurableSideEffectError(unavailable, true, true), {
        code: "SHARED_SERVICE_UNAVAILABLE",
    });
    assert.deepEqual(classifyDurableSideEffectError(unavailable, false, false), {
        code: "SHARED_SERVICE_UNAVAILABLE",
    });
});

test("non-shared failures retain the existing no-side-effect contract", () => {
    const deterministic = new Error("invalid object");
    assert.deepEqual(classifyDurableSideEffectError(deterministic, true, false), {
        code: "NO_SIDE_EFFECT",
    });
    assert.equal(classifyDurableSideEffectError(deterministic, false, false), null);
});

test("retry matching does not confuse generate with a rate limit", () => {
    assert.equal(isRetryableRpcError(new Error("failed to generate transaction")), false);
    assert.equal(isRetryableRpcError(new Error("rate limit exceeded")), true);
});

test("retry matching covers downstream HTTP outages, timeouts, and Node connection failures", () => {
    for (const message of [
        "HTTP 408",
        "HTTP 429",
        "HTTP 500",
        "HTTP 502",
        "HTTP 599",
        "request timed out",
    ]) {
        assert.equal(isRetryableRpcError(new Error(message)), true);
    }
    assert.equal(isRetryableRpcError(new Error("HTTP 400")), false);
    assert.equal(isRetryableRpcError(Object.assign(new Error("request failed"), { status: 500 })), true);
    assert.equal(isRetryableRpcError(Object.assign(new Error("request failed"), { status: 400 })), false);
    for (const code of ["ECONNREFUSED", "ECONNRESET", "EAI_AGAIN", "ETIMEDOUT"]) {
        assert.equal(
            isRetryableRpcError(Object.assign(new Error("fetch failed"), { cause: { code } })),
            true,
        );
    }
});

test("durable classification never treats bare digits in deterministic failures as outages", () => {
    const moveAbort = new Error(
        "MoveAbort(MoveLocation { module: 0x2::example }, 503) in command 0: abort code: 503",
    );
    // The strict shared-infra classifier ignores free-text 3-digit codes...
    assert.equal(isRetryableSharedInfraError(moveAbort), false);
    // ...so a deterministic on-chain failure after a durable started-marker
    // is quarantined without clearing the exact-replay journal.
    assert.deepEqual(classifyDurableSideEffectError(moveAbort, true, true), {
        code: "DURABLE_SIDE_EFFECT_VERIFY_FAILED",
    });
    assert.deepEqual(classifyDurableSideEffectError(moveAbort, true, false), {
        code: "NO_SIDE_EFFECT",
    });
    // The legacy bounded-retry classifier still matches "HTTP 503"-style text.
    assert.equal(isRetryableRpcError(moveAbort), true);

    // A structured HTTP 503 remains a shared-infra outage on both paths.
    const structured503 = Object.assign(new Error("Service Unavailable"), { status: 503 });
    assert.equal(isRetryableSharedInfraError(structured503), true);
    assert.deepEqual(classifyDurableSideEffectError(structured503, true, true), {
        code: "SHARED_SERVICE_UNAVAILABLE",
    });

    // Specific phrase matches stay retryable on the strict path too.
    assert.equal(isRetryableSharedInfraError(new Error("rate limit exceeded")), true);
    assert.equal(isRetryableSharedInfraError(new Error("request timed out")), true);
    assert.equal(isRetryableSharedInfraError(new Error("service temporarily unavailable")), true);
});

test("a finalized failed transaction clears ambiguity but consumes the data budget", () => {
    const failure = new FinalizedTransactionFailure("transaction failed on chain");
    assert.deepEqual(classifyDurableSideEffectError(failure, true, true), {
        code: "NO_SIDE_EFFECT",
    });
});

test("only a congestion cancel asks for a new transaction", () => {
    const cancelled = new CongestionCancelledTransaction("congested");
    assert.deepEqual(classifyDurableSideEffectError(cancelled, true, true), {
        code: "CONGESTION_CANCELLED_TRANSACTION",
    });

    assert.throws(
        () => assertFinalizedTransactionSuccess({
            $kind: "FailedTransaction",
            FailedTransaction: {
                status: {
                    success: false,
                    error: { $kind: "CongestedObjects", message: "congested" },
                },
            },
        }, "register"),
        (err: unknown) => err instanceof CongestionCancelledTransaction,
    );
    assert.throws(
        () => assertFinalizedTransactionSuccess({
            $kind: "FailedTransaction",
            FailedTransaction: {
                status: {
                    success: false,
                    error: { $kind: "MoveAbort", message: "abort" },
                },
            },
        }, "register"),
        (err: unknown) => err instanceof FinalizedTransactionFailure
            && !(err instanceof CongestionCancelledTransaction),
        "a deterministic abort must keep replaying the same digest",
    );
});

test("a landed price abort keeps the failure class and carries the MoveAbort text", () => {
    const abort = "MoveAbort in 3rd command, abort code: 2, in '0x2::balance::split' (instruction 10)";
    assert.throws(
        () => assertFinalizedTransactionSuccess({
            $kind: "FailedTransaction",
            FailedTransaction: {
                status: {
                    success: false,
                    error: { $kind: "MoveAbort", message: abort },
                },
            },
        }, "registration transaction"),
        (err: Error) => {
            assert.ok(err instanceof FinalizedTransactionFailure);
            assert.equal(err.message, `registration transaction was not successful: ${abort}`);
            assert.equal(isMoveAbortBalanceSplit(err.message), true);
            assert.deepEqual(classifyDurableSideEffectError(err, true, true), {
                code: "NO_SIDE_EFFECT",
            });
            return true;
        },
    );
    assert.throws(
        () => assertFinalizedTransactionSuccess({
            $kind: "FailedTransaction",
            FailedTransaction: { status: { success: false, error: abort } },
        }, "registration transaction"),
        (err: Error) => {
            assert.equal(err.message, `registration transaction was not successful: ${abort}`);
            return true;
        },
    );
    for (const error of [{}, null]) {
        assert.throws(
            () => assertFinalizedTransactionSuccess({
                $kind: "FailedTransaction",
                FailedTransaction: { status: { success: false, error } },
            }, "registration transaction"),
            (err: Error) => {
                assert.equal(err.message, "registration transaction was not successful");
                return true;
            },
        );
    }
});

test("a landed certify or metadata abort does not carry MoveAbort text", () => {
    const abort = "MoveAbort in 3rd command, abort code: 2, in '0x2::balance::split' (instruction 10)";
    const failed = {
        $kind: "FailedTransaction",
        FailedTransaction: {
            status: {
                success: false,
                error: { $kind: "MoveAbort", message: abort },
            },
        },
    };
    for (const label of [
        "certification transaction 0xabc",
        "metadata transfer transaction 0xabc",
    ]) {
        assert.throws(
            () => assertFinalizedTransactionSuccess(failed, label),
            (err: Error) => {
                assert.ok(err instanceof FinalizedTransactionFailure);
                assert.equal(err.message, `${label} was not successful`);
                assert.equal(isMoveAbortBalanceSplit(err.message), false);
                return true;
            },
        );
    }
});

test("an unexpected finalization response remains ambiguous", () => {
    assert.throws(
        () => assertFinalizedTransactionSuccess({ Transaction: { digest: "0xcommitted" } }, "upload"),
        (err: unknown) => {
            assert.equal(err instanceof FinalizedTransactionFailure, false);
            assert.match(String(err), /unexpected finalization result/);
            return true;
        },
    );
});

test("direct signing marks submission only after transaction build and signing", async () => {
    const signer = new Ed25519Keypair();
    const buildFailure = new Transaction();
    buildFailure.addSerializationPlugin(async () => {
        throw new Error("InsufficientGas");
    });
    let submissionStarted = false;
    let executeCalls = 0;
    const client = {
        async executeTransaction() {
            executeCalls += 1;
            return { Transaction: { digest: "must-not-execute" } };
        },
    };

    await assert.rejects(
        executeDirectSignedTransaction(
            buildFailure,
            signer,
            () => {
                submissionStarted = true;
            },
            client as never,
        ),
        /InsufficientGas/,
    );
    assert.equal(submissionStarted, false);
    assert.equal(executeCalls, 0);

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
    const callOrder: string[] = [];
    const successClient = {
        async executeTransaction() {
            callOrder.push("execute");
            return { Transaction: { digest: "submitted-digest" } };
        },
    };
    assert.equal(
        await executeDirectSignedTransaction(
            transaction,
            signer,
            () => callOrder.push("started"),
            successClient as never,
        ),
        "submitted-digest",
    );
    assert.deepEqual(callOrder, ["started", "execute"]);
});

test("Seal key-fetch errors preserve budget only for identified outages", () => {
    assert.equal(
        sealKeyFetchErrorCode(Object.assign(new Error("fetch failed"), {
            cause: { code: "ECONNRESET" },
        })),
        "SHARED_SERVICE_UNAVAILABLE",
    );
    assert.equal(
        sealKeyFetchErrorCode(new Error("access denied by key server policy")),
        "KEY_FETCH_FAILED",
    );
});

// bench-w7-pr1055-204e580-100-20261001: one remember failed before any paid
// work on a bare gRPC "fetch failed" from the Seal account read.
test("Seal encrypt-side RPC retries a dropped connection and stops on a real error", async () => {
    const { retryTransientSealRpc } = await import("../sidecar/routes/seal.js");
    const noWait = async () => {};
    let calls = 0;
    const value = await retryTransientSealRpc(async () => {
        calls += 1;
        if (calls < 3) throw Object.assign(new Error("fetch failed"), { name: "RpcError" });
        return "account";
    }, noWait);
    assert.equal(value, "account");
    assert.equal(calls, 3);

    let permanentCalls = 0;
    await assert.rejects(
        retryTransientSealRpc(async () => {
            permanentCalls += 1;
            throw new Error("object 0x1 is not a MemWalAccount");
        }, noWait),
        /not a MemWalAccount/,
    );
    assert.equal(permanentCalls, 1);

    let droppedCalls = 0;
    await assert.rejects(
        retryTransientSealRpc(async () => {
            droppedCalls += 1;
            throw new Error("fetch failed");
        }, noWait),
        /fetch failed/,
    );
    assert.equal(droppedCalls, 4);
});
