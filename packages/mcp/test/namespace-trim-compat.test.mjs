import assert from "node:assert/strict";
import test from "node:test";

import {
    normalizeNamespaceValue,
    normalizeToolNamespace,
} from "../dist/bridge.js";

test("normalizeNamespaceValue trims whitespace and preserves mixed case", () => {
    assert.equal(normalizeNamespaceValue("  MyTeam_2026  "), "MyTeam_2026");
    assert.equal(normalizeNamespaceValue("MyTeam_2026"), "MyTeam_2026");
    assert.equal(normalizeNamespaceValue("\t ProjectScope \t"), "ProjectScope");
});

test("normalizeNamespaceValue returns undefined for empty or whitespace-only inputs", () => {
    assert.equal(normalizeNamespaceValue(undefined), undefined);
    assert.equal(normalizeNamespaceValue(null), undefined);
    assert.equal(normalizeNamespaceValue(123), undefined);
    assert.equal(normalizeNamespaceValue(""), undefined);
    assert.equal(normalizeNamespaceValue("   "), undefined);
    assert.equal(normalizeNamespaceValue("\t   \t"), undefined);
});

test("normalizeNamespaceValue rejects control characters and excessive length", () => {
    assert.throws(
        () => normalizeNamespaceValue("bad\nnamespace"),
        /Namespace cannot contain control characters/
    );
    assert.throws(
        () => normalizeNamespaceValue("bad\rnamespace"),
        /Namespace cannot contain control characters/
    );
    assert.throws(
        () => normalizeNamespaceValue("bad\0namespace"),
        /Namespace cannot contain control characters/
    );
    assert.throws(
        () => normalizeNamespaceValue("\n"),
        /Namespace cannot contain control characters/
    );
    assert.throws(
        () => normalizeNamespaceValue("\r\n"),
        /Namespace cannot contain control characters/
    );

    const longNamespace = "x".repeat(256);
    assert.throws(
        () => normalizeNamespaceValue(longNamespace),
        /Namespace cannot exceed 255 bytes/
    );

    const valid255 = "x".repeat(255);
    assert.equal(normalizeNamespaceValue(valid255), valid255);
});

test("normalizeToolNamespace trims surrounding whitespace on write tools and preserves exact legacy namespaces on read/restore tools", () => {
    const writeTools = [
        "memwal_remember",
        "memwal_remember_bulk",
        "memwal_analyze",
        "memwal_forget",
    ];

    for (const tool of writeTools) {
        const msg = {
            jsonrpc: "2.0",
            id: 10,
            method: "tools/call",
            params: {
                name: tool,
                arguments: {
                    namespace: " work ",
                },
            },
        };

        const updated = normalizeToolNamespace(msg, "default-ns");
        assert.equal(
            updated.params.arguments.namespace,
            "work",
            `expected trimmed namespace for write tool ${tool}`
        );
    }

    const readTools = [
        "memwal_recall",
        "memwal_restore",
        "memwal_ask",
        "memwal_stats",
    ];

    for (const tool of readTools) {
        const paddedMsg = {
            jsonrpc: "2.0",
            id: 20,
            method: "tools/call",
            params: {
                name: tool,
                arguments: {
                    namespace: " work ",
                },
            },
        };
        const trimmedMsg = {
            jsonrpc: "2.0",
            id: 21,
            method: "tools/call",
            params: {
                name: tool,
                arguments: {
                    namespace: "work",
                },
            },
        };

        const updatedPadded = normalizeToolNamespace(paddedMsg, "default-ns");
        const updatedTrimmed = normalizeToolNamespace(trimmedMsg, "default-ns");
        assert.equal(
            updatedPadded.params.arguments.namespace,
            " work ",
            `expected exact legacy namespace preserved for read tool ${tool}`
        );
        assert.equal(
            updatedTrimmed.params.arguments.namespace,
            "work",
            `expected canonical namespace preserved for read tool ${tool}`
        );
        assert.notEqual(
            updatedPadded.params.arguments.namespace,
            updatedTrimmed.params.arguments.namespace,
            `expected " work " and "work" to remain distinct on ${tool}`
        );
    }
});

test("normalizeToolNamespace preserves mixed-case namespaces verbatim", () => {
    const msg = {
        jsonrpc: "2.0",
        id: 11,
        method: "tools/call",
        params: {
            name: "memwal_remember",
            arguments: {
                text: "Remember this setting",
                namespace: "  MyTeam_2026  ",
            },
        },
    };

    const updated = normalizeToolNamespace(msg);
    assert.equal(updated.params.arguments.namespace, "MyTeam_2026");
});

test("normalizeToolNamespace falls back to configured default on whitespace-only namespace", () => {
    const msg = {
        jsonrpc: "2.0",
        id: 12,
        method: "tools/call",
        params: {
            name: "memwal_remember",
            arguments: {
                text: "Remember this setting",
                namespace: "   ",
            },
        },
    };

    const updated = normalizeToolNamespace(msg, "  ProjectDefault  ");
    assert.equal(updated.params.arguments.namespace, "ProjectDefault");
});

test("normalizeToolNamespace deletes whitespace-only namespace when no default is configured", () => {
    const msg = {
        jsonrpc: "2.0",
        id: 13,
        method: "tools/call",
        params: {
            name: "memwal_remember",
            arguments: {
                text: "Remember this setting",
                namespace: "   ",
            },
        },
    };

    const updated = normalizeToolNamespace(msg, undefined);
    assert.equal("namespace" in updated.params.arguments, false);
});

test("normalizeToolNamespace rejects control characters on tool calls", () => {
    const msg = {
        jsonrpc: "2.0",
        id: 14,
        method: "tools/call",
        params: {
            name: "memwal_remember",
            arguments: {
                text: "Remember this setting",
                namespace: "bad\nnamespace",
            },
        },
    };

    assert.throws(
        () => normalizeToolNamespace(msg),
        /Namespace cannot contain control characters/
    );
});

test("normalizeToolNamespace rejects explicit blank restore namespace even when default is configured", () => {
    const msg = {
        jsonrpc: "2.0",
        id: 15,
        method: "tools/call",
        params: {
            name: "memwal_restore",
            arguments: {
                namespace: "   ",
                limit: 10,
            },
        },
    };

    assert.throws(
        () => normalizeToolNamespace(msg, "work"),
        /Namespace cannot be empty/
    );
});
