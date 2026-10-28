import assert from "node:assert/strict";
import test from "node:test";

import { MemWalMock } from "../dist/index.js";

test("MemWalMock remembers and recalls deterministically without network access", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => {
        throw new Error("MemWalMock must not access the network");
    };
    try {
        const mock = MemWalMock.create({
            namespace: "user-a",
            owner: "test-owner",
        });
        const coffee = await mock.rememberAndWait(
            "I prefer coffee in the morning"
        );
        const tea = await mock.rememberAndWait("I drink tea at night");

        assert.equal(coffee.id, "mock-job-000001");
        assert.equal(coffee.job_id, "mock-job-000001");
        assert.equal(coffee.namespace, "user-a");
        assert.equal(tea.blob_id, "mock-blob-000002");

        const recalled = await mock.recall({
            query: "morning coffee",
            limit: 2,
        });
        assert.deepEqual(
            recalled.results.map((memory) => memory.text),
            ["I prefer coffee in the morning", "I drink tea at night"]
        );
        assert.equal(recalled.results[0].distance, 0);
        assert.equal(recalled.results[1].distance, 1);
    } finally {
        globalThis.fetch = originalFetch;
    }
});

test("MemWalMock isolates namespaces and honors maxDistance", async () => {
    const mock = MemWalMock.create({ namespace: "default" });
    await mock.rememberAndWait("Alice likes ramen", "user-a");
    await mock.rememberAndWait("Bob likes tacos", "user-b");

    const alice = await mock.recall({
        query: "likes",
        namespace: "user-a",
        maxDistance: 0.5,
    });
    const bob = await mock.recall({ query: "likes", namespace: "user-b" });
    const empty = await mock.recall({ query: "likes", namespace: "default" });

    assert.deepEqual(
        alice.results.map((memory) => memory.text),
        ["Alice likes ramen"]
    );
    assert.deepEqual(
        bob.results.map((memory) => memory.text),
        ["Bob likes tacos"]
    );
    assert.equal(empty.total, 0);
    const dropped = await mock.recall({
        query: "likes",
        namespace: "user-a",
        maxDistance: 0,
    });
    assert.equal(dropped.results.length, 0);
    assert.equal(dropped.total, 1);
});

test("MemWalMock matches production recall overloads and topK precedence", async () => {
    const mock = MemWalMock.create();
    await mock.rememberAndWait("shared first", "options");
    await mock.rememberAndWait("shared second", "options");

    const optionsStyle = await mock.recall("shared", {
        namespace: "options",
        limit: 2,
    });
    const objectStyle = await mock.recall({
        query: "shared",
        namespace: "options",
        limit: 1,
        topK: 2,
    });

    assert.deepEqual(
        optionsStyle.results.map((memory) => memory.text),
        ["shared first", "shared second"]
    );
    assert.equal(objectStyle.results.length, 2);
});

test("MemWalMock throws when positional recall gets a namespace string as the second arg", async () => {
    const mock = MemWalMock.create();
    await mock.rememberAndWait("food allergies", "profile");

    await assert.rejects(() => mock.recall("food allergies", "profile"), {
        name: "TypeError",
        message: /not a string/,
    });

    const positional = await mock.recall("food allergies", 5, "profile");
    const optionsStyle = await mock.recall("food allergies", {
        namespace: "profile",
    });
    const objectStyle = await mock.recall({
        query: "food allergies",
        namespace: "profile",
    });
    const defaultNs = await mock.recall({ query: "food allergies" });

    assert.deepEqual(
        positional.results.map((memory) => memory.text),
        ["food allergies"]
    );
    assert.equal(optionsStyle.total, 1);
    assert.equal(objectStyle.total, 1);
    assert.equal(defaultNs.total, 0);
});

test("MemWalMock matches production token-budget behavior", async () => {
    const mock = MemWalMock.create({
        initialMemories: [
            { text: "a".repeat(40) },
            { text: "a".repeat(40) },
        ],
    });

    assert.equal(mock.countTokens("a".repeat(8)), 2);

    const unbudgeted = await mock.recall({ query: "a", limit: 2 });
    assert.equal(unbudgeted.results.length, 2);
    assert.equal("meta" in unbudgeted, false);

    const budgeted = await mock.recall({
        query: "a",
        limit: 2,
        maxTokens: 10,
    });
    assert.equal(budgeted.results.length, 1);
    assert.equal(budgeted.total, 2);
    assert.deepEqual(budgeted.meta, {
        tokenEstimate: 10,
        truncated: true,
    });
});

test("MemWalMock tokenization does not depend on the host locale", async () => {
    const originalLocaleLowerCase = String.prototype.toLocaleLowerCase;
    String.prototype.toLocaleLowerCase = () => {
        throw new Error("locale-dependent lowercase must not be used");
    };
    try {
        const mock = MemWalMock.create();
        await mock.rememberAndWait("I LIKE COFFEE");
        const recalled = await mock.recall({ query: "i like coffee" });

        assert.equal(recalled.results[0].distance, 0);
        assert.equal((await mock.embed("I LIKE COFFEE")).vector.length, 16);
    } finally {
        String.prototype.toLocaleLowerCase = originalLocaleLowerCase;
    }
});

test("MemWalMock supports job, bulk, analyze, forget, and clear flows", async () => {
    const mock = MemWalMock.create();
    const accepted = await mock.remember("single fact");
    assert.deepEqual(await mock.getRememberStatus(accepted.job_id), {
        job_id: "mock-job-000001",
        status: "done",
        owner: "mock-owner",
        namespace: "default",
        blob_id: "mock-blob-000001",
    });

    const bulk = await mock.rememberBulkAndWait([
        { text: "bulk one", namespace: "one" },
        { text: "bulk two", namespace: "two" },
    ]);
    assert.equal(bulk.succeeded, 2);
    assert.equal(bulk.failed, 0);

    const analyzed = await mock.analyzeAndWait(
        "durable analyzed fact",
        "analysis"
    );
    assert.equal(analyzed.facts[0].text, "durable analyzed fact");
    assert.equal(analyzed.results[0].namespace, "analysis");

    assert.equal(mock.forget("mock-blob-000001"), true);
    assert.equal(mock.forget("missing"), false);
    assert.equal(mock.clear("one"), 1);
    assert.equal(
        (await mock.recall({ query: "bulk", namespace: "one" })).total,
        0
    );
});

test("MemWalMock provides deterministic embeddings and seed data", async () => {
    const first = MemWalMock.create({
        initialMemories: [
            { text: "seed memory", namespace: "seed", blobId: "seed-blob" },
        ],
    });
    const second = MemWalMock.create();

    assert.deepEqual(
        await first.embed("same text"),
        await second.embed("same text")
    );
    const recalled = await first.recall({ query: "seed", namespace: "seed" });
    assert.equal(recalled.results[0].blob_id, "seed-blob");
    assert.equal((await first.health()).status, "ok");
    assert.equal((await first.compatibility()).featureFlags.offlineMock, true);
});

test("MemWalMock.listNamespaces aggregates seeded memories by namespace", async () => {
    const mock = MemWalMock.create({
        initialMemories: [
            { text: "one", namespace: "work" },
            { text: "two", namespace: "work" },
            { text: "three", namespace: "home" },
        ],
    });

    const page = await mock.listNamespaces();
    const byName = Object.fromEntries(page.namespaces.map((n) => [n.name, n]));

    assert.deepEqual(Object.keys(byName).sort(), ["home", "work"]);
    assert.equal(byName.work.memory_count, 2);
    assert.equal(byName.home.memory_count, 1);
    assert.equal(page.has_more, false);
});

test("MemWalMock.listNamespaces reports has_more when limit truncates the page", async () => {
    const mock = MemWalMock.create({
        initialMemories: [
            { text: "a", namespace: "alpha" },
            { text: "b", namespace: "bravo" },
            { text: "c", namespace: "charlie" },
        ],
    });

    const page = await mock.listNamespaces({ limit: 2 });

    assert.equal(page.namespaces.length, 2);
    assert.equal(page.has_more, true, "has_more is the pagination signal, not page length");
    assert.ok(page.next_cursor, "a truncated page must hand back a cursor");
});

test("MemWalMock.listNamespaces reports the relayer's current snapshot_version", async () => {
    // Verified against relayer.dev.memwal.ai on 2026-08-28: the live read API
    // returns snapshot_version 2. A double that disagrees with the server on a
    // wire-format version is a trap for anyone testing version-gated logic.
    const page = await MemWalMock.create().listNamespaces();
    assert.equal(page.snapshot_version, 2);
});

test("MemWalMock namespace cursors use the relayer wire format and reset after a walk", async () => {
    const mock = MemWalMock.create({ initialMemories: [
        { text: "a", namespace: "旅行" },
        { text: "b", namespace: "work" },
    ] });
    const first = await mock.listNamespaces({ limit: 1 });
    assert.match(first.next_cursor, /^[A-Za-z0-9_-]+$/);
    const cursor = JSON.parse(Buffer.from(first.next_cursor, "base64url").toString("utf8"));
    assert.equal(cursor.namespace, "旅行");
    assert.equal(cursor.updated_at, first.namespaces[0].updated_at);
    assert.ok(cursor.snapshot_at);
    const last = await mock.listNamespaces({ cursor: first.next_cursor });
    assert.deepEqual(last.namespaces.map(ns => ns.name), ["work"]);
    assert.equal(last.has_more, false);
    assert.equal(JSON.parse(Buffer.from(last.next_cursor, "base64url")).snapshot_at, null);
    const empty = await mock.listNamespaces({ cursor: last.next_cursor });
    assert.deepEqual(empty.namespaces, []);
    assert.equal(empty.next_cursor, last.next_cursor);
});

test("MemWalMock namespace walks defer new writes until the next poll", async () => {
    const mock = MemWalMock.create({ initialMemories: [
        { text: "a", namespace: "alpha" },
        { text: "b", namespace: "bravo" },
    ] });
    const first = await mock.listNamespaces({ limit: 1 });
    await mock.remember("new", "bravo");
    const last = await mock.listNamespaces({ cursor: first.next_cursor });
    assert.deepEqual(last.namespaces, []);
    assert.equal(last.has_more, false);
    const poll = await mock.listNamespaces({ cursor: last.next_cursor });
    assert.deepEqual(poll.namespaces.map(ns => ns.name), ["bravo"]);
    assert.equal(poll.namespaces[0].memory_count, 2);
});

test("MemWalMock.listNamespaces rejects a non-positive limit instead of paging forever", async () => {
    const mock = MemWalMock.create();
    await mock.remember("User likes coffee", "ns-a");
    await mock.remember("User likes tea", "ns-b");
    await mock.remember("User likes water", "ns-c");

    await assert.rejects(
        () => mock.listNamespaces({ limit: 0 }),
        /limit must be positive/,
    );
    await assert.rejects(
        () => mock.listNamespaces({ limit: -1 }),
        /limit must be positive/,
    );
    await assert.rejects(
        () => mock.listNamespaces({ limit: 1.5 }),
        /limit must be positive/,
    );

    const page = await mock.listNamespaces({ limit: 1 });
    assert.equal(page.namespaces.length, 1);
    assert.equal(page.has_more, true);
    assert.ok(page.next_cursor);

    // The documented walk still finishes, and a rejected limit did not drop a namespace.
    let cursor;
    let more = true;
    const seen = [];
    let iters = 0;
    while (more && iters < 10) {
        const next = await mock.listNamespaces({ cursor, limit: 1 });
        if (next.has_more) assert.ok(next.next_cursor);
        seen.push(...next.namespaces.map((ns) => ns.name));
        cursor = next.next_cursor ?? undefined;
        more = next.has_more;
        iters += 1;
    }
    assert.equal(more, false);
    assert.equal(iters, 3);
    assert.deepEqual(seen, ["ns-a", "ns-b", "ns-c"]);
});

test("MemWalMock.rememberBulkAsync rejects an empty or non-array batch", async () => {
    const mock = MemWalMock.create();
    const message = "rememberBulkAsync: items must be a non-empty array";
    await assert.rejects(() => mock.rememberBulkAsync([]), {
        name: "Error",
        message,
    });
    await assert.rejects(() => mock.rememberBulkAsync("nope"), {
        name: "Error",
        message,
    });
    await assert.rejects(() => mock.rememberBulk(null), {
        name: "Error",
        message,
    });
    await assert.rejects(() => mock.rememberBulk([]), {
        name: "Error",
        message,
    });
});

test("MemWalMock collapses a repeated idempotency key onto the original job", async () => {
    const mock = MemWalMock.create();
    const first = await mock.rememberAsync("dedupe me", "ns", {
        idempotencyKey: "key-123",
    });
    const second = await mock.rememberAsync("dedupe me", "ns", {
        idempotencyKey: "key-123",
    });
    assert.equal(first.job_id, second.job_id);
    assert.equal(
        (await mock.recall({ query: "dedupe", namespace: "ns", limit: 10 })).total,
        1,
    );

    await assert.rejects(
        () => mock.rememberAsync("other text", "ns", { idempotencyKey: "key-123" }),
        /different content/,
    );
    assert.equal(
        (await mock.recall({ query: "other", namespace: "ns", maxDistance: 0.5 })).total,
        1,
    );
    // WALM-781: Idempotency keys are scoped per namespace.
    // The same key used in another namespace must succeed and not collide.
    const otherNs = await mock.rememberAsync("dedupe me", "other-ns", {
        idempotencyKey: "key-123",
    });
    assert.notEqual(first.job_id, otherNs.job_id);
    assert.equal(
        (await mock.recall({ query: "dedupe", namespace: "other-ns", maxDistance: 0.5 })).total,
        1,
    );

    // Retrying with the same key in other-ns collapses.
    const otherNsRetry = await mock.rememberAsync("dedupe me", "other-ns", {
        idempotencyKey: "key-123",
    });
    assert.equal(otherNs.job_id, otherNsRetry.job_id);

    // Reusing the key with different content in other-ns rejects.
    await assert.rejects(
        () => mock.rememberAsync("different content text", "other-ns", { idempotencyKey: "key-123" }),
        /different content/,
    );

    const viaRemember = await mock.remember("via remember", "ns", {
        idempotencyKey: "remember-key",
    });
    const viaRememberAgain = await mock.remember("via remember", "ns", {
        idempotencyKey: "remember-key",
    });
    assert.equal(viaRemember.job_id, viaRememberAgain.job_id);

    const maxKey = "k".repeat(255);
    const atMax = await mock.rememberAsync("boundary", "ns", { idempotencyKey: maxKey });
    const atMaxAgain = await mock.rememberAsync("boundary", "ns", { idempotencyKey: maxKey });
    assert.equal(atMax.job_id, atMaxAgain.job_id);
    // "é" is two UTF-8 bytes. 128 of them are 256 bytes even though the string is shorter than 255.
    await assert.rejects(
        () => mock.rememberAsync("accent", "ns", { idempotencyKey: "é".repeat(128) }),
        /maximum length/,
    );
    await mock.rememberAsync("accent", "ns", { idempotencyKey: "é".repeat(127) });
    await assert.rejects(
        () => mock.rememberAsync("dedupe me", "ns", { idempotencyKey: "" }),
        /cannot be empty/,
    );
    await assert.rejects(
        () =>
            mock.rememberAsync("dedupe me", "ns", {
                idempotencyKey: "k".repeat(256),
            }),
        /maximum length/,
    );

    const written = await mock.rememberAndWait("again", "ns", {
        idempotencyKey: "key-again",
    });
    assert.equal(mock.forget(written.blob_id), true);
    const rewritten = await mock.rememberAndWait("again", "ns", {
        idempotencyKey: "key-again",
    });
    assert.notEqual(rewritten.job_id, written.job_id);
    const after = await mock.recall({
        query: "again",
        namespace: "ns",
        maxDistance: 0.5,
    });
    assert.equal(after.results.length, 1);
    assert.ok(after.total > after.results.length);
    assert.equal(after.results[0].blob_id, rewritten.blob_id);

    const cleared = MemWalMock.create();
    await cleared.rememberAsync("kept", "ns", { idempotencyKey: "clear-key" });
    assert.equal(cleared.clear("ns"), 1);
    const afterClear = await cleared.rememberAsync("kept", "ns", {
        idempotencyKey: "clear-key",
    });
    const kept = await cleared.recall({ query: "kept", namespace: "ns", maxDistance: 0.5 });
    assert.equal(kept.total, 1);
    assert.equal(kept.results[0].blob_id, `mock-blob-${afterClear.job_id.slice(-6)}`);
});

test("MemWalMock.recall sort recent returns the newest match and keeps relevance ties", async () => {
    const mock = MemWalMock.create();
    await mock.rememberAndWait("project release version one");
    await mock.rememberAndWait("project release version two");

    const recent = await mock.recall({
        query: "project release",
        sort: "recent",
        limit: 1,
    });
    assert.equal(recent.results[0].text, "project release version two");

    const relevance = await mock.recall({
        query: "project release",
        sort: "relevance",
        limit: 1,
    });
    assert.equal(relevance.results[0].text, "project release version one");

    const omitted = await mock.recall({ query: "project release", limit: 1 });
    assert.equal(omitted.results[0].text, "project release version one");

    // A newer, worse match inside the window wins. A distance tie-break would keep the older one.
    await mock.rememberAndWait("project notes");
    const recentWorse = await mock.recall({
        query: "project release",
        sort: "recent",
        limit: 2,
    });
    assert.deepEqual(
        recentWorse.results.map((memory) => memory.text),
        ["project notes", "project release version two"],
    );
    const relevanceWorse = await mock.recall({
        query: "project release",
        sort: "relevance",
        limit: 1,
    });
    assert.equal(relevanceWorse.results[0].text, "project release version one");
});

test("MemWalMock.recall sort recent stays inside the semantic candidate window", async () => {
    const mock = MemWalMock.create();
    for (let i = 1; i <= 6; i++) {
        await mock.rememberAndWait(`alpha fact ${i}`);
    }
    // Equal overlap, so semantic order is insertion order. limit 1 → window 5.
    const recent = await mock.recall({ query: "alpha", sort: "recent", limit: 1 });
    assert.equal(recent.results[0].text, "alpha fact 5");

    // topK wins over limit, so the window is 5, not 10 * 5.
    const byTopK = await mock.recall({
        query: "alpha",
        sort: "recent",
        limit: 10,
        topK: 1,
    });
    assert.equal(byTopK.results[0].text, "alpha fact 5");
});

test("MemWalMock.recall sort recent caps the window at 50 and never below limit", async () => {
    const capped = MemWalMock.create();
    for (let i = 1; i <= 51; i++) {
        await capped.rememberAndWait(`alpha fact ${i}`);
    }
    // limit 11 → window min(55, 50) = 50. Newest of those 50 ties comes first.
    const atCap = await capped.recall({ query: "alpha", sort: "recent", limit: 11 });
    assert.equal(atCap.results[0].text, "alpha fact 50");
    assert.equal(atCap.results.length, 11);
    assert.equal(atCap.results.at(-1).text, "alpha fact 40");

    const uncapped = MemWalMock.create();
    for (let i = 1; i <= 60; i++) {
        await uncapped.rememberAndWait(`alpha fact ${i}`);
    }
    // limit 60 is above the 50 ceiling, so the window grows and the newest row stays in it.
    const wide = await uncapped.recall({ query: "alpha", sort: "recent", limit: 60 });
    assert.equal(wide.results[0].text, "alpha fact 60");
    assert.equal(wide.results.length, 60);
    assert.equal(wide.results.at(-1).text, "alpha fact 1");
});

test("MemWalMock.recall sort recent filters namespace and still applies the token budget", async () => {
    const mock = MemWalMock.create();
    await mock.rememberAndWait("alpha one", "kept");
    await mock.rememberAndWait("alpha two", "kept");
    await mock.rememberAndWait("alpha elsewhere", "other");

    const result = await mock.recall({
        query: "alpha",
        namespace: "kept",
        sort: "recent",
        limit: 2,
        maxTokens: 3,
    });

    assert.deepEqual(
        result.results.map((memory) => memory.text),
        ["alpha two"],
    );
    assert.equal(result.meta.truncated, true);
});

test("MemWalMock.recall uses a positional namespace when the options object omits one", async () => {
    const mock = MemWalMock.create({ namespace: "default" });
    await mock.rememberAndWait("profile fact", "profile");
    await mock.rememberAndWait("default fact", "default");

    const positional = await mock.recall("fact", { limit: 5 }, "profile");
    assert.deepEqual(
        positional.results.map((memory) => memory.text),
        ["profile fact"],
    );

    const explicit = await mock.recall(
        "fact",
        { limit: 5, namespace: "default" },
        "profile",
    );
    assert.deepEqual(
        explicit.results.map((memory) => memory.text),
        ["default fact"],
    );

    const options = { limit: 5 };
    await mock.recall("fact", options, "profile");
    assert.deepEqual(options, { limit: 5 });
});

test("MemWalMock.remember rejects zero-width text instead of storing it", async () => {
    const mock = MemWalMock.create();
    await assert.rejects(() => mock.remember("\u200B"), /text cannot be empty/);
    await assert.rejects(() => mock.remember("\uFEFF"), /text cannot be empty/);
    const stored = await mock.remember("hello\u200Bworld");
    assert.equal(typeof stored.job_id, "string");
});

test("MemWalMock.remember with dedupe: true collapses identical text per namespace and rewrites after forget/clear (#769)", async () => {
    const mock = MemWalMock.create();

    const first = await mock.rememberAndWait("User is allergic to peanuts", "health", {
        dedupe: true,
    });
    const second = await mock.rememberAndWait("User is allergic to peanuts", "health", {
        dedupe: true,
    });
    assert.equal(second.id, first.id);
    assert.equal(second.blob_id, first.blob_id);

    const recalledHealth = await mock.recall({ query: "peanuts", namespace: "health" });
    assert.equal(recalledHealth.results.length, 1);

    // Same text in a different namespace is stored separately.
    const otherNs = await mock.rememberAndWait("User is allergic to peanuts", "work", {
        dedupe: true,
    });
    assert.notEqual(otherNs.blob_id, first.blob_id);

    // Default remember (without dedupe: true) still writes a second copy.
    const withoutDedupe = await mock.rememberAndWait("User is allergic to peanuts", "health");
    assert.notEqual(withoutDedupe.blob_id, first.blob_id);
    assert.equal((await mock.recall({ query: "peanuts", namespace: "health" })).results.length, 2);

    // Forgetting the deduped blob in "health" allows dedupe: true to write fresh
    // even while the non-dedupe copy remains live, matching the relayer's
    // dedupe:<sha256> job lookup.
    assert.equal(mock.forget(first.blob_id), true);
    const rewritten = await mock.rememberAndWait("User is allergic to peanuts", "health", {
        dedupe: true,
    });
    assert.notEqual(rewritten.blob_id, first.blob_id);
    assert.notEqual(rewritten.blob_id, withoutDedupe.blob_id);
    assert.equal((await mock.recall({ query: "peanuts", namespace: "health" })).results.length, 2);

    // Clearing the namespace also allows a fresh dedupe write, including shorthand options.
    assert.equal(mock.clear("default"), 0);
    const defFirst = await mock.remember("Default fact", { dedupe: true });
    const defSecond = await mock.remember("Default fact", { dedupe: true });
    assert.equal(defSecond.job_id, defFirst.job_id);
    assert.equal(mock.clear("default"), 1);
    const defAfterClear = await mock.remember("Default fact", { dedupe: true });
    assert.notEqual(defAfterClear.job_id, defFirst.job_id);
});

test("MemWalMock.remember with dedupe: true does not collapse onto a prior normal write (#769)", async () => {
    const mock = MemWalMock.create({
        initialMemories: [{ text: "Seeded fact", namespace: "ns", blobId: "seed-blob" }],
    });

    // Opting into dedupe after a seeded or normal (non-dedupe) write creates a
    // new dedupe-keyed job, matching the relayer where normal writes use an r1-*
    // key and dedupe: true looks up dedupe:<sha256>.
    const afterSeed = await mock.rememberAndWait("Seeded fact", "ns", { dedupe: true });
    assert.notEqual(afterSeed.blob_id, "seed-blob");
    const afterSeedRepeat = await mock.rememberAndWait("Seeded fact", "ns", { dedupe: true });
    assert.equal(afterSeedRepeat.id, afterSeed.id);
    assert.equal(afterSeedRepeat.blob_id, afterSeed.blob_id);

    const normalWrite = await mock.rememberAndWait("User prefers dark mode", "ns");
    const firstDedupe = await mock.rememberAndWait("User prefers dark mode", "ns", {
        dedupe: true,
    });
    assert.notEqual(firstDedupe.id, normalWrite.id);
    assert.notEqual(firstDedupe.blob_id, normalWrite.blob_id);

    const secondDedupe = await mock.rememberAndWait("User prefers dark mode", "ns", {
        dedupe: true,
    });
    assert.equal(secondDedupe.id, firstDedupe.id);
    assert.equal(secondDedupe.blob_id, firstDedupe.blob_id);
});


