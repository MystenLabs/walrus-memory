import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
    isMoveAbortBalanceSplit,
    isMoveAbortWalDestroyZero,
    refreshWalrusClientOnStaleWalPrice,
} from "../sidecar/enoki.js";

// Production format reference (issue #351): the Walrus register PTB pre-funds an
// exact WAL payment from the client's cached storage price, then asserts the
// coin is empty via `0x2::coin::destroy_zero`. When the on-chain price drops
// between the cached read and execution, the contract deducts less WAL and the
// leftover trips `destroy_zero` with ENonZero (abort code 0). Enoki surfaces it
// during its budget dry-run as a 400 dry_run_failed.

const PROD_DESTROY_ZERO_ERROR =
    'Enoki API error (400): {"errors":[{"code":"dry_run_failed","message":"Dry run failed, ' +
    "could not automatically determine a budget: MoveAbort(MoveLocation { module: ModuleId { " +
    "address: 0000000000000000000000000000000000000000000000000000000000000002, name: " +
    'Identifier(\\"balance\\") }, function: 9, instruction: 8, function_name: ' +
    'Some(\\"destroy_zero\\") }, 0) in command 2"}]}';

test("matches the verbatim prod destroy_zero abort", () => {
    assert.equal(isMoveAbortWalDestroyZero(PROD_DESTROY_ZERO_ERROR), true);
});

test("matches the compact MoveLocation shape", () => {
    assert.equal(
        isMoveAbortWalDestroyZero(
            "MoveAbort(MoveLocation { module: coin, function_name: Some(\"destroy_zero\") }, 0) in command 9",
        ),
        true,
    );
});

test("is case-insensitive on both anchors", () => {
    assert.equal(isMoveAbortWalDestroyZero("moveabort ... destroy_zero"), true);
});

test("bare destroy_zero without MoveAbort context is rejected", () => {
    // Guards against unrelated log lines that merely mention the function.
    assert.equal(isMoveAbortWalDestroyZero("calling coin::destroy_zero"), false);
});

test("balance::split abort does not match the destroy_zero detector", () => {
    // The two detectors stay disjoint so one abort refreshes the client once.
    const balanceSplit =
        "MoveAbort(MoveLocation { module: balance, function_name: Some(\"split\") }, 2) in command 1";
    assert.equal(isMoveAbortWalDestroyZero(balanceSplit), false);
    assert.equal(isMoveAbortBalanceSplit(balanceSplit), true);
});

test("the destroy_zero abort is NOT matched by the balance-split detector", () => {
    // The prod message contains the `balance` module name but no `split`, so the
    // existing isMoveAbortBalanceSplit stays false — this is exactly the gap the
    // new detector closes.
    assert.equal(isMoveAbortBalanceSplit(PROD_DESTROY_ZERO_ERROR), false);
});

test("unrelated errors do not match", () => {
    assert.equal(isMoveAbortWalDestroyZero("connection refused"), false);
    assert.equal(isMoveAbortWalDestroyZero("HTTP 500 from upload relay"), false);
    assert.equal(isMoveAbortWalDestroyZero(""), false);
});

// Job 2b1cf6b0, Enoki budget dry-run, 2026-10-05. The shape is the gRPC
// abort text, not the older MoveLocation rendering above.
const CAREERACE_DESTROY_ZERO =
    "Enoki API error (400): {\"errors\":[{\"code\":\"dry_run_failed\",\"message\":\"Dry run failed, could not automatically determine a budget: MoveAbort in 4th command, abort code: 0, in '0x0000000000000000000000000000000000000000000000000000000000000002::balance::destroy_zero' (instruction 8)\",\"data\":{\"executionError\":{\"$kind\":\"MoveAbort\",\"message\":\"MoveAbort in 4th command, abort code: 0, in '0x0000000000000000000000000000000000000000000000000000000000000002::balance::destroy_zero' (instruction 8)\",\"command\":3,\"MoveAbort\":{\"abortCode\":\"0\",\"location\":{\"package\":\"0x0000000000000000000000000000000000000000000000000000000000000002\",\"module\":\"balance\",\"function\":9,\"instruction\":8,\"functionName\":\"destroy_zero\"}}}}}]}";

test("matches the careerace budget dry-run abort", () => {
    assert.equal(isMoveAbortWalDestroyZero(CAREERACE_DESTROY_ZERO), true);
    assert.equal(isMoveAbortBalanceSplit(CAREERACE_DESTROY_ZERO), false);
});

// Job faa81809, Enoki sponsor dry-run, 2026-10-15. Cached storage price was
// below the live price, so reserve_space's balance::split aborted ENotEnough
// in the 3rd command (index 2).
const PROD_PRICE_UP_BALANCE_SPLIT =
    "Enoki API error (400): {\"errors\":[{\"code\":\"transaction_build_failed\",\"message\":\"Transaction resolution failed: MoveAbort in 3rd command, abort code: 2, in '0x0000000000000000000000000000000000000000000000000000000000000002::balance::split' (instruction 10)\",\"data\":{\"executionError\":{\"$kind\":\"MoveAbort\",\"command\":2,\"MoveAbort\":{\"abortCode\":\"2\",\"location\":{\"module\":\"balance\",\"functionName\":\"split\"}}}}}]}";

function refreshedReasons(run: () => void): string[] {
    const warnings: string[] = [];
    const warn = console.warn;
    console.warn = (message?: unknown) => {
        warnings.push(String(message));
    };
    try {
        run();
    } finally {
        console.warn = warn;
    }
    return warnings.filter((line) => line.includes("[walrus/client] refreshed"));
}

test("a stale-price abort refreshes the Walrus client and other errors do not", () => {
    assert.deepEqual(
        refreshedReasons(() => {
            refreshWalrusClientOnStaleWalPrice(CAREERACE_DESTROY_ZERO);
            refreshWalrusClientOnStaleWalPrice("Object 0x" + "ab".repeat(32) + " not found");
            refreshWalrusClientOnStaleWalPrice("Sponsored transaction has expired");
        }),
        ["[walrus/client] refreshed reason=walrus_wal_payment_destroy_zero"],
    );
});

test("a price-up balance::split refreshes the client once", () => {
    assert.equal(isMoveAbortBalanceSplit(PROD_PRICE_UP_BALANCE_SPLIT), true);
    assert.equal(isMoveAbortWalDestroyZero(PROD_PRICE_UP_BALANCE_SPLIT), false);
    let refreshed = false;
    assert.deepEqual(
        refreshedReasons(() => {
            refreshed = refreshWalrusClientOnStaleWalPrice(PROD_PRICE_UP_BALANCE_SPLIT);
        }),
        ["[walrus/client] refreshed reason=walrus_wal_payment_balance_split"],
    );
    assert.equal(refreshed, true);
    assert.equal(refreshWalrusClientOnStaleWalPrice("Sponsored transaction has expired"), false);
});

test("both upload routes drop the cached price on this abort", () => {
    const journal = readFileSync(new URL("../sidecar/routes/walrus-upload-journal.ts", import.meta.url), "utf8");
    const legacy = readFileSync(new URL("../sidecar/routes/walrus-upload.ts", import.meta.url), "utf8");
    assert.match(journal, /refreshWalrusClientOnStaleWalPrice\(message\)/);
    assert.match(
        journal,
        /if \(refreshWalrusClientOnStaleWalPrice\(message\)\) \{\s*dropUploadStepFlightsForCheckpoint\(flightKey\);/,
    );
    assert.match(legacy, /refreshWalrusClientOnStaleWalPrice\(message\)/);
    assert.doesNotMatch(legacy, /register_sponsor_balance_split/);
    assert.doesNotMatch(legacy, /dropUploadStepFlightsForCheckpoint/);
});
