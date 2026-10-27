import test from "node:test";
import assert from "node:assert/strict";
import { assertFinalizedTransactionSuccess } from "../sidecar/wallet.js";
import { classifyDurableSideEffectError } from "../sidecar/retry/rpc.js";

const {
    beginOrJoinUploadStepFlight,
    resetUploadStepFlightsForTests,
    settleUploadStepFlight,
    uploadStepFlightKey,
} = await import("../sidecar/routes/walrus-upload-journal.js");

test("a dropped upload retries the same step instead of starting another", async () => {
    resetUploadStepFlightsForTests();
    const key = uploadStepFlightKey("job-1", "encoded", "blob-1", "digest-1");
    const leader = beginOrJoinUploadStepFlight(key);
    const follower = beginOrJoinUploadStepFlight(key);
    assert.equal(leader.leader, true);
    assert.equal(follower.leader, false);
    let calls = 0;
    const body = { step: { step: "registered", blobId: "blob-1" } };
    const done = (async () => {
        calls += 1;
        await new Promise((resolve) => setTimeout(resolve, 20));
        settleUploadStepFlight(key, leader.flight, { status: 200, body });
        return body;
    })();
    const followed = await follower.flight.promise;
    await done;
    assert.equal(calls, 1);
    assert.equal(followed.status, 200);
    assert.deepEqual(followed.body, body);
    resetUploadStepFlightsForTests();
});

test("a landed price abort evicts only its rejected preparation and execution", () => {
    resetUploadStepFlightsForTests();
    const prepare = uploadStepFlightKey("job-1", "encoded", "blob-1", undefined);
    const execute = uploadStepFlightKey("job-1", "encoded", "blob-1", "digest-1", "sponsor-1");
    const certify = uploadStepFlightKey("job-1", "uploaded", "blob-1", undefined);
    const other = uploadStepFlightKey("job-2", "encoded", "blob-2", undefined);
    const prepared = beginOrJoinUploadStepFlight(prepare);
    settleUploadStepFlight(prepare, prepared.flight, {
        status: 200,
        body: { registerTransaction: { digest: "digest-1", sponsorDigest: "sponsor-1" } },
    });
    const executing = beginOrJoinUploadStepFlight(execute);
    const certifying = beginOrJoinUploadStepFlight(certify);
    const unrelated = beginOrJoinUploadStepFlight(other);
    let failure: unknown;
    try {
        assertFinalizedTransactionSuccess({
            $kind: "FailedTransaction",
            FailedTransaction: {
                status: {
                    success: false,
                    error: { $kind: "MoveAbort", message: "MoveAbort in 0x2::balance::split" },
                },
            },
        }, "registration transaction");
    } catch (error) {
        failure = error;
    }
    const classified = classifyDurableSideEffectError(failure, true, true);
    assert.deepEqual(classified, { code: "NO_SIDE_EFFECT" });
    settleUploadStepFlight(execute, executing.flight, { status: 503, body: classified }, {
        key: prepare, digest: "digest-1", sponsorDigest: "sponsor-1",
    });
    assert.equal(beginOrJoinUploadStepFlight(prepare).leader, true);
    assert.equal(beginOrJoinUploadStepFlight(execute).leader, true);
    assert.equal(beginOrJoinUploadStepFlight(certify).flight, certifying.flight);
    assert.equal(beginOrJoinUploadStepFlight(other).flight, unrelated.flight);
    resetUploadStepFlightsForTests();
});

test("a different checkpoint is a different step", () => {
    assert.notEqual(
        uploadStepFlightKey("job-1", "encoded", "blob-1", undefined),
        uploadStepFlightKey("job-1", "registered", "blob-1", undefined),
    );
    assert.notEqual(
        uploadStepFlightKey("job-1", "encoded", "blob-1", "digest", "old-handle"),
        uploadStepFlightKey("job-1", "encoded", "blob-1", "digest", "new-handle"),
        "a replacement sponsorship with the same signed bytes must not join the rejected handle",
    );
});

for (const code of ["NO_SIDE_EFFECT", "INVALID_PREPARED_REGISTER_TRANSACTION"]) {
    test(`${code} evicts the rejected preparation and wakes existing followers`, async () => {
        resetUploadStepFlightsForTests();
        const key = uploadStepFlightKey("job-1", "encoded", "blob-1", undefined);
        const prepared = beginOrJoinUploadStepFlight(key);
        settleUploadStepFlight(key, prepared.flight, {
            status: 200, body: { registerTransaction: { digest: "old-digest" } },
        });
        assert.equal(beginOrJoinUploadStepFlight(key).leader, false, "dropped prepare responses stay cached");

        const executeKey = uploadStepFlightKey("job-1", "encoded", "blob-1", "old-digest");
        const executing = beginOrJoinUploadStepFlight(executeKey);
        const follower = beginOrJoinUploadStepFlight(executeKey);
        settleUploadStepFlight(executeKey, executing.flight, { status: 503, body: { code } }, {
            key, digest: "old-digest",
        });
        assert.equal((await follower.flight.promise).status, 503);
        assert.equal(beginOrJoinUploadStepFlight(key).leader, true, "reprepare must bypass the stale success");
        assert.equal(beginOrJoinUploadStepFlight(executeKey).leader, true, "a replacement handle may have the same Sui digest");
        resetUploadStepFlightsForTests();
    });
}

test("a rejected old digest cannot evict a newer or in-flight preparation", () => {
    for (const settled of [true, false]) {
        resetUploadStepFlightsForTests();
        const key = uploadStepFlightKey("job-1", "encoded", "blob-1", undefined);
        const newer = beginOrJoinUploadStepFlight(key);
        if (settled) settleUploadStepFlight(key, newer.flight, {
            status: 200, body: { registerTransaction: { digest: "new-digest" } },
        });
        const executeKey = uploadStepFlightKey("job-1", "encoded", "blob-1", "old-digest");
        const executing = beginOrJoinUploadStepFlight(executeKey);
        settleUploadStepFlight(executeKey, executing.flight, {
            status: 503, body: { code: "NO_SIDE_EFFECT" },
        }, { key, digest: "old-digest" });
        assert.equal(beginOrJoinUploadStepFlight(key).flight, newer.flight);
    }
    resetUploadStepFlightsForTests();
});

test("a rejected sponsorship cannot evict a newer handle for the same Sui digest", () => {
    resetUploadStepFlightsForTests();
    const key = uploadStepFlightKey("job-1", "encoded", "blob-1", undefined);
    const newer = beginOrJoinUploadStepFlight(key);
    settleUploadStepFlight(key, newer.flight, {
        status: 200, body: { registerTransaction: { digest: "digest", sponsorDigest: "new-handle" } },
    });
    const executeKey = uploadStepFlightKey("job-1", "encoded", "blob-1", "digest", "old-handle");
    const executing = beginOrJoinUploadStepFlight(executeKey);
    settleUploadStepFlight(executeKey, executing.flight, {
        status: 503, body: { code: "NO_SIDE_EFFECT" },
    }, { key, digest: "digest", sponsorDigest: "old-handle" });
    assert.equal(beginOrJoinUploadStepFlight(key).flight, newer.flight);
    resetUploadStepFlightsForTests();
});

for (const result of [
    { status: 503, body: { code: "SHARED_SERVICE_UNAVAILABLE" } },
    { status: 422, body: { code: "DURABLE_SIDE_EFFECT_VERIFY_FAILED" } },
    { status: 200, body: { step: { step: "registered" } } },
]) {
    test(`a ${result.body.code ?? "completed registration"} result preserves replay caches`, () => {
        resetUploadStepFlightsForTests();
        const key = uploadStepFlightKey("job-1", "encoded", "blob-1", undefined);
        const prepared = beginOrJoinUploadStepFlight(key);
        settleUploadStepFlight(key, prepared.flight, {
            status: 200, body: { registerTransaction: { digest: "digest" } },
        });
        const executeKey = uploadStepFlightKey("job-1", "encoded", "blob-1", "digest");
        const executing = beginOrJoinUploadStepFlight(executeKey);
        settleUploadStepFlight(executeKey, executing.flight, result, { key, digest: "digest" });
        assert.equal(beginOrJoinUploadStepFlight(key).flight, prepared.flight);
        assert.equal(beginOrJoinUploadStepFlight(executeKey).flight, executing.flight);
        resetUploadStepFlightsForTests();
    });
}
