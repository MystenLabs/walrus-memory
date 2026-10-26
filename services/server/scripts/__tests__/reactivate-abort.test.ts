import assert from "node:assert/strict";
import test from "node:test";
import { reactivateRejectionCode } from "../sidecar/enoki.js";

const ALREADY_ACTIVE =
    "Enoki API error (400): {\"errors\":[{\"message\":\"Transaction resolution failed: MoveAbort in 1st command, abort code: 11, in '0x0a625e2db2af6f591a4c80a3d8551ddf11656089cc3a20c5e9e7f8fb75b9265c::account::reactivate_account' (instruction 57)\",\"data\":{\"executionError\":{\"MoveAbort\":{\"abortCode\":\"11\",\"location\":{\"functionName\":\"reactivate_account\"}}}}}]}";

test("reactivate abort 11 is already active", () => {
    assert.equal(reactivateRejectionCode(ALREADY_ACTIVE), "account_already_active");
});

test("reactivate abort 20 is still locked", () => {
    assert.equal(
        reactivateRejectionCode(
            "MoveAbort in 1st command, abort code: 20, in '0xabc::account::reactivate_account'",
        ),
        "account_quarantined",
    );
});

test("an already-active abort in another module stays unclassified", () => {
    assert.equal(
        reactivateRejectionCode(
            "MoveAbort in 1st command, abort code: 11, in '0x2::balance::split'",
        ),
        null,
    );
});

test("a different reactivate abort stays unclassified", () => {
    assert.equal(
        reactivateRejectionCode(
            "MoveAbort in 1st command, abort code: 3, in '0xabc::account::reactivate_account'",
        ),
        null,
    );
});
