/**
 * Cross-layer write-path validation & secret-pattern parity tests (#435).
 *
 * Verifies that:
 * 1. `validateRemember` in `@mysten-incubation/memwal` and `sanitizeFact` in
 *    the MCP bridge (`services/server/scripts/mcp/tools/redaction.ts`) agree on
 *    every secret kind and every legitimate MemWal identifier.
 * 2. `MemWal` and `MemWalMock` reject unopted-out secrets and >1 MiB inputs
 *    client-side before signing or opening a socket, and honour
 *    `{ allowSecrets: true }`, `{ skipValidation: true }`, and `{ dryRun: true }`.
 */
import assert from "node:assert/strict";
import test from "node:test";

import {
    MemWal,
    MemWalMock,
    MemWalValidationError,
    MAX_REMEMBER_TEXT_BYTES,
    validateRemember,
} from "../dist/index.js";
import { sanitizeFact } from "../../../services/server/scripts/mcp/tools/redaction.ts";

const TEST_KEY = "01".repeat(32);
const TEST_ACCOUNT_ID = "0x" + "22".repeat(32);

const REPRO_SUIPRIVKEY =
    "suiprivkey1qzfake0000000000000000000000000000000000000000000000000000";
const VALID_SUIPRIVKEY =
    "suiprivkey1qqtac0q7an7dcq2vp6axts0c0zt6hw7jznar94qp3ayxdx6axlzpxcetm48";
const DELEGATE_SEED =
    "4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b";

const SECRET_CORPUS = [
    {
        label: "bare suiprivkey1 repro (#435)",
        text: REPRO_SUIPRIVKEY,
        expectedKind: "vendor-api-key",
    },
    {
        label: "embedded suiprivkey1 repro (#435)",
        text: `My Sui wallet key is ${REPRO_SUIPRIVKEY} on testnet`,
        expectedKind: "vendor-api-key",
    },
    {
        label: "valid bech32 suiprivkey1",
        text: `Deploy testnet contract with ${VALID_SUIPRIVKEY}`,
        expectedKind: "vendor-api-key",
    },
    {
        label: "Anthropic API key",
        text: "CI uses sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789 for builds",
        expectedKind: "vendor-api-key",
    },
    {
        label: "GitHub PAT",
        text: "Release token is ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        expectedKind: "vendor-api-key",
    },
    {
        label: "AWS access key ID",
        text: "Bucket uses AKIAIOSFODNN7EXAMPLE in staging",
        expectedKind: "vendor-api-key",
    },
    {
        label: "URL with embedded userinfo",
        text: "Staging DB is postgres://admin:hunter2@db.internal:5432/app",
        expectedKind: "url-credentials",
    },
    {
        label: "PEM private key block",
        text: "Key:\n-----BEGIN OPENSSH PRIVATE KEY-----\nMIIEowIBAAKCAQEAx7Vk9mJ0ZwQ3\n-----END OPENSSH PRIVATE KEY-----",
        expectedKind: "private-key-block",
    },
    {
        label: "JWT",
        text: "Session token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        expectedKind: "jwt",
    },
    {
        label: "credential assignment",
        text: "Local env has POSTGRES_PASSWORD=hunter2 for local tests",
        expectedKind: "credential-assignment",
    },
    {
        label: "authorization header",
        text: "Call with Authorization: Bearer abc123xyz789 on staging",
        expectedKind: "auth-header",
    },
    {
        label: "labelled BIP-39 seed phrase",
        text: "My wallet recovery phrase is abandon ability able about above absent absorb abstract absurd abuse access accident",
        expectedKind: "seed-phrase",
    },
    {
        label: "delegatePrivateKey JSON assignment",
        text: `Setup notes: "delegatePrivateKey": "${DELEGATE_SEED}" on laptop`,
        expectedKind: "credential-assignment",
    },
    {
        label: "labelled delegate private key hex",
        text: `Setup notes: my delegate private key is ${DELEGATE_SEED} on laptop`,
        expectedKind: "labelled-key-material",
    },
    {
        label: "labelled sui.keystore base64 key",
        text: "From sui.keystore: AD7xQ9mKp2vN8rT4wY1bC5dF0gH3jL6nP9qS2uV5xZ8= for localnet",
        expectedKind: "labelled-key-material",
    },
    {
        label: "high-entropy secret blob",
        text: "Signing blob QWxhZGRpbjpvcGVuIHNlc2FtZQBcdefGHIjklMNOpqrSTUvwxYZ0123456789abcDEF0123 in vault",
        expectedKind: "high-entropy-secret",
    },
];

const CLEAN_CORPUS = [
    "I always use pnpm, and TypeScript strict mode on every project.",
    "My account id is 0x7f3a9c2e5b8d1f4a6c9e2b5d8f1a4c7e0b3d6f9a2c5e8b1d4f7a0c3e6b9d2f5a",
    "The blob landed as blob_id=Xj9vKq2mP7nR4tW8yB1cE5gH0dF3sA6uZ2xN8qL4kM7",
    "Pin the build to commit 4f2b8c1e9d7a3f5b6c0e2d4a8b1f3c5e7d9a0b2c",
    "My Sui package id is 0xe80f2feec1c139616a86c9f71210152e2a7ca552b20841f2e192f99f75864437",
    "Our dashboard is at https://app.example.com:8443?owner=alice@corp.com and we deploy Fridays",
    "My password manager is 1Password and I rotate keys every quarter.",
];

test("SDK validateRemember and MCP sanitizeFact agree across the secret corpus (#435)", () => {
    for (const { label, text, expectedKind } of SECRET_CORPUS) {
        const sdkResult = validateRemember(text);
        const mcpResult = sanitizeFact(text);

        assert.equal(sdkResult.valid, false, `SDK accepted secret (${label}): ${text}`);
        assert.equal(mcpResult.changed, true, `MCP missed secret (${label}): ${text}`);
        assert.ok(
            sdkResult.kinds.includes(expectedKind),
            `SDK kinds ${sdkResult.kinds} missing ${expectedKind} (${label})`,
        );
        assert.ok(
            mcpResult.kinds.includes(expectedKind),
            `MCP kinds ${mcpResult.kinds} missing ${expectedKind} (${label})`,
        );
        assert.deepEqual(
            sdkResult.kinds,
            mcpResult.kinds,
            `SDK and MCP kinds diverged on ${label}`,
        );
        assert.ok(
            sdkResult.issues.some(
                (i) => i.code === "secret_pattern_detected" && i.kind === expectedKind,
            ),
        );
    }
});

test("SDK validateRemember and MCP sanitizeFact agree across the clean corpus (#435)", () => {
    for (const text of CLEAN_CORPUS) {
        const sdkResult = validateRemember(text);
        const mcpResult = sanitizeFact(text);

        assert.equal(sdkResult.valid, true, `SDK rejected clean text: ${text}`);
        assert.deepEqual(sdkResult.issues, []);
        assert.deepEqual(sdkResult.kinds, []);
        assert.equal(sdkResult.sanitizedText, text);

        assert.equal(mcpResult.changed, false, `MCP altered clean text: ${text}`);
        assert.deepEqual(mcpResult.kinds, []);
        assert.equal(mcpResult.text, text);
    }
});

test("validateRemember reports empty_text and text_too_long offline", () => {
    for (const blank of ["", "   ", "\u200B\uFEFF"]) {
        const res = validateRemember(blank);
        assert.equal(res.valid, false);
        assert.ok(res.issues.some((i) => i.code === "empty_text"));
    }

    const oversized = "a".repeat(MAX_REMEMBER_TEXT_BYTES + 1);
    const overRes = validateRemember(oversized);
    assert.equal(overRes.valid, false);
    assert.equal(overRes.byteLength, MAX_REMEMBER_TEXT_BYTES + 1);
    assert.ok(overRes.issues.some((i) => i.code === "text_too_long"));
});

test("MemWal and MemWalMock reject secrets and >1 MiB inputs before any network call, and support allowSecrets + dryRun", async () => {
    let fetchCalls = 0;
    const origFetch = globalThis.fetch;
    globalThis.fetch = async () => {
        fetchCalls += 1;
        return new Response(JSON.stringify({ job_id: "job-1", status: "pending" }), {
            status: 202,
            headers: { "content-type": "application/json" },
        });
    };

    try {
        const client = MemWal.create({
            key: TEST_KEY,
            accountId: TEST_ACCOUNT_ID,
            serverUrl: "https://relayer.example.com",
        });
        const mock = MemWalMock.create();

        // 1. Secret rejected before signing or network call.
        for (const target of [client, mock]) {
            await assert.rejects(
                () => target.remember(REPRO_SUIPRIVKEY),
                (err) => {
                    assert.ok(err instanceof MemWalValidationError);
                    assert.equal(err.code, "secret_pattern_detected");
                    assert.ok(err.kinds.includes("vendor-api-key"));
                    return true;
                },
            );
            await assert.rejects(
                () =>
                    target.rememberBulk([
                        { text: "User prefers pnpm" },
                        { text: `Key is ${REPRO_SUIPRIVKEY}` },
                    ]),
                (err) => {
                    assert.ok(err instanceof MemWalValidationError);
                    assert.equal(err.code, "secret_pattern_detected");
                    return true;
                },
            );
        }
        assert.equal(fetchCalls, 0, "rejected secret must not trigger any HTTP request");

        // 2. Oversized text (>1 MiB) rejected before signing or network call.
        const oversized = "x".repeat(MAX_REMEMBER_TEXT_BYTES + 10);
        for (const target of [client, mock]) {
            await assert.rejects(
                () => target.remember(oversized),
                (err) => {
                    assert.ok(err instanceof MemWalValidationError);
                    assert.equal(err.code, "text_too_long");
                    return true;
                },
            );
        }
        assert.equal(fetchCalls, 0, "oversized input must not trigger any HTTP request");

        // 3. dryRun validates locally and returns without network calls.
        const drySingle = await client.remember("User prefers dark mode", { dryRun: true });
        assert.deepEqual(drySingle, { job_id: "dry-run", status: "dry_run" });
        const dryBulk = await client.rememberBulk(
            [{ text: "Fact one" }, { text: "Fact two" }],
            { dryRun: true },
        );
        assert.equal(dryBulk.status, "dry_run");
        assert.equal(dryBulk.total, 2);
        assert.equal(fetchCalls, 0, "dryRun must not trigger any HTTP request");

        // 4. allowSecrets / skipValidation permits intentional storage in MemWalMock.
        const allowed = await mock.remember(`Test fixture key ${REPRO_SUIPRIVKEY}`, {
            allowSecrets: true,
        });
        assert.equal(allowed.status, "done");

        const skipped = await mock.remember(`Test fixture key ${VALID_SUIPRIVKEY}`, {
            skipValidation: true,
        });
        assert.equal(skipped.status, "done");
    } finally {
        globalThis.fetch = origFetch;
    }
});
