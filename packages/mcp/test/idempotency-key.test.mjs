import assert from "node:assert/strict";
import test from "node:test";

import { applyIdempotencyKey } from "../dist/bridge.js";

test("applyIdempotencyKey injects a UUID into memwal_remember_bulk", () => {
    const msg = {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
            name: "memwal_remember_bulk",
            arguments: {
                facts: ["fact 1", "fact 2"],
            },
        },
    };

    const updated = applyIdempotencyKey(msg);
    assert.equal(typeof updated.params.arguments._idempotency_key, "string");
    assert.match(
        updated.params.arguments._idempotency_key,
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
        "expected a v4 UUID"
    );
    // In-place mutation — same reference.
    assert.equal(msg.params.arguments._idempotency_key, updated.params.arguments._idempotency_key);
});

test("applyIdempotencyKey preserves existing key (no overwrite on replay)", () => {
    const existingKey = "aaaaaaaa-bbbb-4ccc-9ddd-eeeeeeeeeeee";
    const msg = {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: {
            name: "memwal_remember_bulk",
            arguments: {
                facts: ["fact 1"],
                _idempotency_key: existingKey,
            },
        },
    };

    applyIdempotencyKey(msg);
    assert.equal(msg.params.arguments._idempotency_key, existingKey);
});

test("applyIdempotencyKey does not inject for memwal_remember (already has content-derived key)", () => {
    const msg = {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: {
            name: "memwal_remember",
            arguments: { text: "I love coffee" },
        },
    };

    applyIdempotencyKey(msg);
    assert.equal(msg.params.arguments._idempotency_key, undefined);
});

test("applyIdempotencyKey does not inject for unrelated tools", () => {
    for (const name of ["memwal_recall", "memwal_analyze", "memwal_login", "memwal_health"]) {
        const msg = {
            jsonrpc: "2.0",
            id: 4,
            method: "tools/call",
            params: { name, arguments: {} },
        };

        applyIdempotencyKey(msg);
        assert.equal(
            msg.params.arguments._idempotency_key,
            undefined,
            `should not inject key for ${name}`
        );
    }
});

test("applyIdempotencyKey does not inject for non-tools/call messages", () => {
    const msg = {
        jsonrpc: "2.0",
        id: 5,
        method: "tools/list",
        params: {},
    };

    const updated = applyIdempotencyKey(msg);
    assert.equal(updated.params._idempotency_key, undefined);
});

test("applyIdempotencyKey creates arguments object if missing", () => {
    const msg = {
        jsonrpc: "2.0",
        id: 6,
        method: "tools/call",
        params: {
            name: "memwal_remember_bulk",
        },
    };

    applyIdempotencyKey(msg);
    assert.equal(typeof msg.params.arguments._idempotency_key, "string");
});
