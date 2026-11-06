import assert from "node:assert/strict";
import test from "node:test";
import { addDelegateKeyRejectionCode, reactivateRejectionCode } from "../sidecar/enoki.js";

const ALREADY_ACTIVE =
    "Enoki API error (400): {\"errors\":[{\"message\":\"Transaction resolution failed: MoveAbort in 1st command, abort code: 11, in '0x0a625e2db2af6f591a4c80a3d8551ddf11656089cc3a20c5e9e7f8fb75b9265c::account::reactivate_account' (instruction 57)\",\"data\":{\"executionError\":{\"MoveAbort\":{\"abortCode\":\"11\",\"location\":{\"functionName\":\"reactivate_account\"}}}}}]}";

const TOO_MANY_DELEGATE_KEYS_JSON =
    "Enoki API error (400): {\"errors\":[{\"message\":\"Transaction resolution failed: MoveAbort in 1st command, abort code: 2, in '0x0a625e2db2af6f591a4c80a3d8551ddf11656089cc3a20c5e9e7f8fb75b9265c::account::add_delegate_key' (instruction 42)\",\"data\":{\"executionError\":{\"MoveAbort\":{\"abortCode\":\"2\",\"location\":{\"functionName\":\"add_delegate_key\"}}}}}]}";

const TOO_MANY_DELEGATE_KEYS_DRY_RUN =
    'Enoki API error (400): {"errors":[{"code":"dry_run_failed","message":"Dry run failed, could not automatically determine a budget: MoveAbort(MoveLocation { module: ModuleId { address: 0a625e2db2af6f591a4c80a3d8551ddf11656089cc3a20c5e9e7f8fb75b9265c, name: Identifier(\\"account\\") }, function: 2, instruction: 42, function_name: Some(\\"add_delegate_key\\") }, 2) in command 0"}]}';

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

test("add_delegate_key abort 2 is classified as max_delegate_keys across Enoki shapes", () => {
    assert.equal(addDelegateKeyRejectionCode(TOO_MANY_DELEGATE_KEYS_JSON), "max_delegate_keys");
    assert.equal(addDelegateKeyRejectionCode(TOO_MANY_DELEGATE_KEYS_DRY_RUN), "max_delegate_keys");
});

test("add_delegate_key non-limit aborts and foreign abort code 2 stay unclassified", () => {
    assert.equal(
        addDelegateKeyRejectionCode(
            "MoveAbort in 1st command, abort code: 0, in '0xabc::account::add_delegate_key'",
        ),
        null,
    );
    assert.equal(
        addDelegateKeyRejectionCode(
            "MoveAbort in 1st command, abort code: 4, in '0xabc::account::add_delegate_key'",
        ),
        null,
    );
    assert.equal(
        addDelegateKeyRejectionCode(
            "MoveAbort in 3rd command, abort code: 2, in '0x2::balance::split'",
        ),
        null,
    );
});
