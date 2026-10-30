import assert from "node:assert/strict";
import test from "node:test";

import { MemWal, MemWalMock } from "../dist/index.js";
import { MemWalManual } from "../dist/manual-entry.js";

const OWNER = "0xowner0000000000000000000000000000000000000000000000000000000001";
const originalFetch = globalThis.fetch;

function createClient(namespace = "default-ns") {
    return MemWal.create({
        key: new Uint8Array(32).fill(1),
        accountId: "0x1",
        serverUrl: "https://relayer.example",
        namespace,
    });
}

function createManualClient(namespace = "default-manual-ns") {
    return MemWalManual.create({
        key: new Uint8Array(32).fill(2),
        suiPrivateKey: "suiprivkey1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq55956v",
        embeddingApiKey: "sk-test",
        packageId: "0x1",
        accountId: "0x2",
        registryId: "0x3",
        serverUrl: "https://relayer.example",
        namespace,
    });
}

function stubForgetRelayer(forgetResponseOrHandler) {
    const calls = [];
    globalThis.fetch = async (url, init = {}) => {
        const u = new URL(url);
        const bodyText = typeof init.body === "string" ? init.body : undefined;
        calls.push({
            path: u.pathname,
            method: init.method ?? "GET",
            headers: init.headers ?? {},
            body: bodyText ? JSON.parse(bodyText) : undefined,
        });

        if (u.pathname === "/version") {
            return Response.json({
                apiVersion: "1.0.0",
                relayerVersion: "1.0.0",
                minSupportedSdk: { typescript: "0.0.4" },
            });
        }
        if (u.pathname === "/api/forget") {
            const payload =
                typeof forgetResponseOrHandler === "function"
                    ? forgetResponseOrHandler(calls.at(-1))
                    : forgetResponseOrHandler;
            return Response.json(payload);
        }
        throw new Error(`unexpected request: ${init.method ?? "GET"} ${u.pathname}`);
    };
    return calls;
}

test.afterEach(() => {
    globalThis.fetch = originalFetch;
});

test("MemWal.forget defaults to the client namespace and does not send x-seal-session (#1043)", async () => {
    const calls = stubForgetRelayer({
        deleted: 3,
        namespace: "default-ns",
        owner: OWNER,
    });
    const memwal = createClient("default-ns");
    memwal.buildSealSession = async () => {
        throw new Error("forget must not build a SEAL session");
    };

    const result = await memwal.forget();

    assert.deepEqual(result, {
        deleted: 3,
        namespace: "default-ns",
        owner: OWNER,
    });
    const forgetCall = calls.find((c) => c.path === "/api/forget");
    assert.ok(forgetCall, "expected POST /api/forget call");
    assert.equal(forgetCall.method, "POST");
    assert.deepEqual(forgetCall.body, { namespace: "default-ns" });
    assert.equal("x-seal-session" in forgetCall.headers, false);
    assert.equal(forgetCall.headers["x-account-id"], "0x1");
});

test("MemWal.forget('custom') and MemWal.forgetNamespace('custom') forward the target namespace (#1043)", async () => {
    const calls = stubForgetRelayer((call) => ({
        deleted: 5,
        namespace: call.body.namespace,
        owner: OWNER,
    }));
    const memwal = createClient("default-ns");

    const direct = await memwal.forget("custom-a");
    const alias = await memwal.forgetNamespace("custom-b");
    const aliasDefault = await memwal.forgetNamespace();

    assert.deepEqual(direct, {
        deleted: 5,
        namespace: "custom-a",
        owner: OWNER,
    });
    assert.deepEqual(alias, {
        deleted: 5,
        namespace: "custom-b",
        owner: OWNER,
    });
    assert.deepEqual(aliasDefault, {
        deleted: 5,
        namespace: "default-ns",
        owner: OWNER,
    });

    const forgetCalls = calls.filter((c) => c.path === "/api/forget");
    assert.deepEqual(
        forgetCalls.map((c) => c.body),
        [
            { namespace: "custom-a" },
            { namespace: "custom-b" },
            { namespace: "default-ns" },
        ],
    );
});

test("MemWalManual.forget and MemWalManual.forgetNamespace call POST /api/forget without x-seal-session (#1043)", async () => {
    const calls = stubForgetRelayer((call) => ({
        deleted: 2,
        namespace: call.body.namespace,
        owner: OWNER,
    }));
    const manual = createManualClient("manual-default");
    manual.buildSealSession = async () => {
        throw new Error("MemWalManual.forget must not build a SEAL session");
    };

    const defaultRes = await manual.forget();
    const customRes = await manual.forget("manual-custom");
    const aliasRes = await manual.forgetNamespace("manual-alias");

    assert.deepEqual(defaultRes, {
        deleted: 2,
        namespace: "manual-default",
        owner: OWNER,
    });
    assert.deepEqual(customRes, {
        deleted: 2,
        namespace: "manual-custom",
        owner: OWNER,
    });
    assert.deepEqual(aliasRes, {
        deleted: 2,
        namespace: "manual-alias",
        owner: OWNER,
    });

    const forgetCalls = calls.filter((c) => c.path === "/api/forget");
    assert.equal(forgetCalls.length, 3);
    for (const call of forgetCalls) {
        assert.equal(call.method, "POST");
        assert.equal("x-seal-session" in call.headers, false);
        assert.equal(call.headers["x-account-id"], "0x2");
    }
});

test("forget and forgetNamespace reject empty or whitespace-only namespaces before any HTTP request (#1043)", async () => {
    let fetchCount = 0;
    globalThis.fetch = async () => {
        fetchCount += 1;
        throw new Error("network must not be called when namespace is invalid");
    };

    const memwal = createClient("default-ns");
    const manual = createManualClient("default-manual-ns");
    const mock = MemWalMock.create({ namespace: "default-mock-ns" });

    for (const invalid of ["", "   ", "\t\n"]) {
        await assert.rejects(() => memwal.forget(invalid), {
            message: /namespace cannot be empty/,
        });
        await assert.rejects(() => memwal.forgetNamespace(invalid), {
            message: /namespace cannot be empty/,
        });
        await assert.rejects(() => manual.forget(invalid), {
            message: /namespace cannot be empty/,
        });
        await assert.rejects(() => manual.forgetNamespace(invalid), {
            message: /namespace cannot be empty/,
        });
        assert.throws(() => mock.forgetNamespace(invalid), {
            message: /namespace cannot be empty/,
        });
    }

    for (const nonString of [123, null, {}, []]) {
        await assert.rejects(() => memwal.forget(nonString), {
            message: /namespace cannot be empty/,
        });
        await assert.rejects(() => manual.forget(nonString), {
            message: /namespace cannot be empty/,
        });
        assert.throws(() => mock.forgetNamespace(nonString), {
            message: /namespace cannot be empty/,
        });
    }

    assert.equal(fetchCount, 0);
});

test("forget rejects malformed POST /api/forget responses on MemWal and MemWalManual (#1043)", async () => {
    const malformedBodies = [
        { body: null, match: /POST \/api\/forget response is missing deleted, namespace, and owner fields/ },
        { body: [], match: /POST \/api\/forget response is missing deleted, namespace, and owner fields/ },
        { body: { namespace: "ns", owner: OWNER }, match: /missing a valid deleted count/ },
        { body: { deleted: -1, namespace: "ns", owner: OWNER }, match: /missing a valid deleted count/ },
        { body: { deleted: 1.5, namespace: "ns", owner: OWNER }, match: /missing a valid deleted count/ },
        { body: { deleted: "2", namespace: "ns", owner: OWNER }, match: /missing a valid deleted count/ },
        { body: { deleted: 2, owner: OWNER }, match: /missing a valid namespace/ },
        { body: { deleted: 2, namespace: "", owner: OWNER }, match: /missing a valid namespace/ },
        { body: { deleted: 2, namespace: "ns" }, match: /missing a valid owner/ },
        { body: { deleted: 2, namespace: "ns", owner: "" }, match: /missing a valid owner/ },
    ];

    for (const { body, match } of malformedBodies) {
        stubForgetRelayer(body);
        const memwal = createClient("ns");
        const manual = createManualClient("ns");

        await assert.rejects(() => memwal.forget("ns"), { message: match });
        await assert.rejects(() => manual.forget("ns"), { message: match });
    }
});

test("forget and forgetNamespace reject after destroy() without making network calls (#1043)", async () => {
    let fetchCount = 0;
    globalThis.fetch = async () => {
        fetchCount += 1;
        throw new Error("destroyed client must not call fetch");
    };

    const memwal = createClient("ns");
    const manual = createManualClient("ns");
    memwal.destroy();
    manual.destroy();

    await assert.rejects(() => memwal.forget(), { message: /destroyed/i });
    await assert.rejects(() => memwal.forgetNamespace("ns"), { message: /destroyed/i });
    await assert.rejects(() => manual.forget(), { message: /destroyed/i });
    await assert.rejects(() => manual.forgetNamespace("ns"), { message: /destroyed/i });
    assert.equal(fetchCount, 0);
});
