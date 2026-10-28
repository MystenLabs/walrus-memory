/**
 * No credential reaches the SDK from any write tool (WALM-642).
 *
 * The ticket was reproduced exactly here: a preference plus a fake password URL
 * sent through the real MCP server, with the SDK mocked, and `remember`,
 * `remember_bulk` and `analyze` all passed the full text through unchanged.
 * These tests are that repro, inverted — the mock now records everything the
 * handler forwards, and every assertion is about what the SDK was *given*, not
 * about what the tool said afterwards. A handler that redacted its reply but
 * still forwarded the secret would pass a message-only test and fail these.
 *
 * Walrus storage is append-only and immutable, which is why the check has to be
 * in front of the write: there is no delete to fall back on.
 *
 * The wait budget is zeroed so each tool returns at accept. That is the shortest
 * path through each handler and it exercises the same pre-forward screen; the
 * bounded-wait branch is covered by the `*-fast-return` files.
 */
process.env.MEMWAL_MCP_REMEMBER_WAIT_MS = "0";

import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { MemWalSession } from "../auth.js";

const { createMcpServer } = await import("../server.js");

/** Everything the handlers handed to the SDK, in call order. */
interface Forwarded {
    remember: string[];
    bulk: string[][];
    analyze: string[];
}

function sessionWith(forwarded: Forwarded): MemWalSession {
    return {
        oauthScope: "memwal:read memwal:write",
        namespace: "default",
        memwal: {
            async rememberAsync(text: string) {
                forwarded.remember.push(text);
                return { job_id: "job-1", status: "running" };
            },
            async rememberBulkAsync(items: Array<{ text: string }>) {
                forwarded.bulk.push(items.map((i) => i.text));
                return {
                    job_ids: items.map((_, i) => `bulk-job-${i + 1}`),
                    total: items.length,
                    status: "accepted",
                };
            },
            async analyze(text: string) {
                forwarded.analyze.push(text);
                // Echo the passage back as one extracted fact, so a leak that
                // slipped through would also show up in the reply.
                return {
                    job_ids: ["analyze-job-1"],
                    facts: [{ text }],
                    fact_count: 1,
                    status: "accepted",
                    owner: "0xowner",
                };
            },
        },
    } as unknown as MemWalSession;
}

async function clientFor(session: MemWalSession, t: TestContext): Promise<Client> {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createMcpServer(session);
    const client = new Client({ name: "write-path-redaction-test", version: "1.0.0" });
    t.after(async () => {
        await client.close();
        await server.close();
    });
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    return client;
}

function textOf(result: unknown): string {
    return (result as { content: Array<{ text: string }> }).content
        .map((c) => c.text)
        .join("\n");
}

/** Everything the session was ever handed, flattened, plus the tool's reply. */
function allForwarded(forwarded: Forwarded): string {
    return [
        ...forwarded.remember,
        ...forwarded.bulk.flat(),
        ...forwarded.analyze,
    ].join("\n");
}

const PASSWORD = "hunter2";
const MIXED =
    "I prefer dark mode in every editor, and the staging db is " +
    `postgres://admin:${PASSWORD}@db.internal:5432/app`;
const PREFERENCE = "I prefer dark mode in every editor";

// ── the reproduction, on all three write paths ──────────────────────────────

test("memwal_remember keeps the preference and never forwards the password", async (t) => {
    const forwarded: Forwarded = { remember: [], bulk: [], analyze: [] };
    const client = await clientFor(sessionWith(forwarded), t);
    const result = await client.callTool({
        name: "memwal_remember",
        arguments: { text: MIXED },
    });

    assert.equal(forwarded.remember.length, 1, "the write must still happen");
    const sent = forwarded.remember[0];
    assert.ok(!sent.includes(PASSWORD), "the password was forwarded to the SDK");
    assert.ok(!sent.includes("admin:"), "the userinfo was forwarded to the SDK");
    // The point of redacting rather than dropping: the fact survives.
    assert.ok(sent.includes(PREFERENCE), "the preference was lost with the credential");
    assert.ok(sent.includes("db.internal:5432/app"), "the host was lost too");

    const text = textOf(result);
    assert.ok(!text.includes(PASSWORD), "the reply echoed the password back");
    assert.match(text, /url-credentials/);
    assert.match(text, /credential span\(s\) were removed/);
});

test("memwal_remember_bulk screens every entry, and one bad entry does not sink the batch", async (t) => {
    const forwarded: Forwarded = { remember: [], bulk: [], analyze: [] };
    const client = await clientFor(sessionWith(forwarded), t);
    const result = await client.callTool({
        name: "memwal_remember_bulk",
        arguments: {
            facts: [
                "I always use pnpm",
                MIXED,
                "sk-abcdefghijklmnopqrstuvwxyz0123",
                "Deploy on Thursdays",
            ],
        },
    });

    assert.equal(forwarded.bulk.length, 1);
    const sent = forwarded.bulk[0];
    const joined = sent.join("\n");
    assert.ok(!joined.includes(PASSWORD), "a password reached the SDK");
    assert.ok(!joined.includes("sk-abcdefghijklmnopqrstuvwxyz0123"), "a key reached the SDK");

    // Three survive: the two clean facts, plus the redacted mixed one. The
    // bare key had no fact around it, so it is dropped rather than stored as
    // an empty placeholder.
    assert.equal(sent.length, 3);
    assert.ok(sent.includes("I always use pnpm"), "a clean fact was altered or dropped");
    assert.ok(sent.includes("Deploy on Thursdays"), "a clean fact was altered or dropped");
    assert.ok(sent.some((s) => s.includes(PREFERENCE)));

    const text = textOf(result);
    assert.ok(!text.includes(PASSWORD));
    assert.match(text, /NOT SAVED \(1\)/);
    assert.match(text, /#3/, "the dropped entry must be identified by position");
});

test("memwal_analyze strips the passage before the extractor ever sees it", async (t) => {
    const forwarded: Forwarded = { remember: [], bulk: [], analyze: [] };
    const client = await clientFor(sessionWith(forwarded), t);
    const result = await client.callTool({
        name: "memwal_analyze",
        arguments: {
            text:
                `${MIXED}\nAlso, my GitHub token is ghp_abcdefghijklmnopqrstuvwxyz0123456789 ` +
                "and I review PRs on Fridays.",
        },
    });

    assert.equal(forwarded.analyze.length, 1);
    const sent = forwarded.analyze[0];
    assert.ok(!sent.includes(PASSWORD), "the password reached the extractor LLM");
    assert.ok(
        !sent.includes("ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
        "the GitHub token reached the extractor LLM",
    );
    assert.ok(sent.includes(PREFERENCE));
    assert.ok(sent.includes("review PRs on Fridays"));

    const text = textOf(result);
    assert.ok(!text.includes(PASSWORD));
    assert.match(text, /credential span\(s\) were removed/);
});

test("the delegate private key never reaches the SDK from any write path", async (t) => {
    // The one secret that matters most for this product: the Ed25519 seed in
    // ~/.memwal/credentials.json, which grants read AND write to the user's
    // memories until the delegate is revoked. It is pure lowercase hex, so it
    // is invisible to the entropy rule by design — the label beside it is what
    // catches it. A user pasting their credentials file into chat is the
    // realistic way this arrives.
    const SEED = "4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b";
    const pasted =
        `I set up a second laptop today. From credentials.json: ` +
        `"delegatePrivateKey": "${SEED}", and I use the work namespace there.`;

    const forwarded: Forwarded = { remember: [], bulk: [], analyze: [] };
    const client = await clientFor(sessionWith(forwarded), t);

    for (const [name, args] of [
        ["memwal_remember", { text: pasted }],
        ["memwal_remember_bulk", { facts: [pasted] }],
        ["memwal_analyze", { text: pasted }],
    ] as Array<[string, Record<string, unknown>]>) {
        const result = await client.callTool({ name, arguments: args });
        assert.ok(
            !textOf(result).includes(SEED),
            `${name} echoed the delegate key back in its reply`,
        );
    }

    const sent = allForwarded(forwarded);
    assert.ok(sent.length > 0, "the writes must still happen");
    assert.ok(!sent.includes(SEED), "the delegate private key reached the SDK");
    // Redacted, not dropped: the fact around it survives on every path.
    assert.equal(forwarded.remember.length, 1);
    assert.equal(forwarded.bulk.length, 1);
    assert.equal(forwarded.analyze.length, 1);
    for (const text of [forwarded.remember[0], forwarded.bulk[0][0], forwarded.analyze[0]]) {
        assert.ok(text.includes("second laptop"), "the fact was lost with the key");
        assert.ok(text.includes("work namespace"), "the fact was lost with the key");
    }
});

test("an unlabelled hex identifier still reaches the SDK unchanged", async (t) => {
    // The other half of the label gate, asserted at the handler boundary: a
    // 64-hex string nobody called a key is a digest, an object id or a blob id
    // — the facts this product exists to remember.
    const forwarded: Forwarded = { remember: [], bulk: [], analyze: [] };
    const client = await clientFor(sessionWith(forwarded), t);
    const fact =
        "My Sui package id is 0xe80f2feec1c139616a86c9f71210152e2a7ca552b20841f2e192f99f75864437 " +
        "and the release digest is 4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b";

    const result = await client.callTool({
        name: "memwal_remember",
        arguments: { text: fact },
    });
    assert.deepEqual(forwarded.remember, [fact]);
    assert.doesNotMatch(textOf(result), /redacted|NOT SAVED/i);
});

// ── the rules that are not about credentials ────────────────────────────────

test("an explicit do-not-save is honoured on every write path", async (t) => {
    const forwarded: Forwarded = { remember: [], bulk: [], analyze: [] };
    const client = await clientFor(sessionWith(forwarded), t);
    const text = "My bank PIN is 4821 — don't save this.";

    for (const [name, args] of [
        ["memwal_remember", { text }],
        ["memwal_remember_bulk", { facts: [text] }],
        ["memwal_analyze", { text }],
    ] as Array<[string, Record<string, unknown>]>) {
        const result = await client.callTool({ name, arguments: args });
        assert.match(
            textOf(result),
            /NOT SAVED|Nothing was saved/,
            `${name} did not say it withheld the text`,
        );
    }

    assert.deepEqual(forwarded.remember, []);
    assert.deepEqual(forwarded.bulk, []);
    assert.deepEqual(forwarded.analyze, []);
    assert.ok(!allForwarded(forwarded).includes("4821"));
});

test("pasted third-party content is not saved as a user fact", async (t) => {
    const forwarded: Forwarded = { remember: [], bulk: [], analyze: [] };
    const client = await clientFor(sessionWith(forwarded), t);
    const pasted = "```\nERROR 500 from the vendor API\n  at handler (index.js:42)\n```";

    const remembered = await client.callTool({
        name: "memwal_remember",
        arguments: { text: pasted },
    });
    assert.match(textOf(remembered), /pasted third-party content/);

    const analyzed = await client.callTool({
        name: "memwal_analyze",
        arguments: { text: pasted },
    });
    assert.match(textOf(analyzed), /pasted third-party content/);

    assert.deepEqual(forwarded.remember, []);
    assert.deepEqual(forwarded.analyze, []);
});

// ── the ordinary case, which must be untouched ──────────────────────────────

test("a plain preference is forwarded byte-for-byte, with no note attached", async (t) => {
    const forwarded: Forwarded = { remember: [], bulk: [], analyze: [] };
    const client = await clientFor(sessionWith(forwarded), t);
    const clean = "I always use pnpm, TypeScript strict mode, and deploy on Thursdays.";

    const remembered = await client.callTool({
        name: "memwal_remember",
        arguments: { text: clean },
    });
    assert.deepEqual(forwarded.remember, [clean]);
    assert.doesNotMatch(textOf(remembered), /redacted|NOT SAVED/i);

    await client.callTool({
        name: "memwal_remember_bulk",
        arguments: { facts: [clean, "My coffee order is a matcha oat latte"] },
    });
    assert.deepEqual(forwarded.bulk, [
        [clean, "My coffee order is a matcha oat latte"],
    ]);

    await client.callTool({ name: "memwal_analyze", arguments: { text: clean } });
    assert.deepEqual(forwarded.analyze, [clean]);
});

test("the idempotency key is derived from what is actually written", async (t) => {
    // Keyed on the original, a retry of a redacted fact would derive a key for
    // text that was never sent — and the accept-timeout message promises a
    // retry is safe.
    const seen: string[] = [];
    const session = {
        oauthScope: "memwal:read memwal:write",
        namespace: "default",
        memwal: {
            async rememberAsync(text: string, _ns: unknown, opts: { idempotencyKey: string }) {
                seen.push(`${text}::${opts.idempotencyKey}`);
                return { job_id: "job-1", status: "running" };
            },
        },
    } as unknown as MemWalSession;

    const client = await clientFor(session, t);
    await client.callTool({ name: "memwal_remember", arguments: { text: MIXED } });
    await client.callTool({ name: "memwal_remember", arguments: { text: MIXED } });

    assert.equal(seen.length, 2);
    assert.equal(seen[0], seen[1], "the same fact must derive the same key twice");
    assert.ok(!seen[0].includes(PASSWORD));
});

/* ───────────────────────────────────────────────────────────────────────────
 * Review findings on the WALM-642 branch, asserted where it counts: at what
 * the SDK was handed.
 * ------------------------------------------------------------------------ */

test("splitting a secret across bulk entries does not reach the SDK", async (t) => {
    // Every label-gated rule searched a window inside ONE string, so the label
    // in one entry and its value in the next walked past all of them — with
    // MemWal's own delegate private key, the worst thing this product can leak.
    // An agent that paraphrases a user across two entries is enough; nothing
    // here needs malice.
    const SEED = "4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b";
    const forwarded: Forwarded = { remember: [], bulk: [], analyze: [] };
    const client = await clientFor(sessionWith(forwarded), t);

    const result = await client.callTool({
        name: "memwal_remember_bulk",
        arguments: {
            facts: [
                "I set up a second laptop today",
                "my delegate private key for the mainnet account",
                SEED,
                "and I use the work namespace there",
            ],
        },
    });

    assert.equal(forwarded.bulk.length, 1, "the other facts must still be written");
    assert.ok(
        !forwarded.bulk[0].join("\n").includes(SEED),
        "the delegate private key reached the SDK from a split batch",
    );
    assert.ok(!textOf(result).includes(SEED), "the reply echoed the delegate key back");
    // The facts either side are still saved: this is a scalpel, not a batch
    // refusal.
    assert.ok(forwarded.bulk[0].some((f) => f.includes("second laptop")));
    assert.ok(forwarded.bulk[0].some((f) => f.includes("work namespace")));
});

test("a bulk batch of plain identifiers is still forwarded byte-for-byte", async (t) => {
    // The cross-entry screen only fires when a credential label is somewhere in
    // the batch. Without one, nothing about the batch path may differ from the
    // single-fact path.
    const forwarded: Forwarded = { remember: [], bulk: [], analyze: [] };
    const client = await clientFor(sessionWith(forwarded), t);
    const facts = [
        "My Sui package id is 0xe80f2feec1c139616a86c9f71210152e2a7ca552b20841f2e192f99f75864437",
        "The release digest is 4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b",
        "I always use pnpm",
    ];
    const result = await client.callTool({
        name: "memwal_remember_bulk",
        arguments: { facts },
    });
    assert.deepEqual(forwarded.bulk, [facts]);
    assert.doesNotMatch(textOf(result), /redacted|NOT SAVED/i);
});

test("one do-not-save line does not discard a whole transcript", async (t) => {
    // `NO_SAVE_DIRECTIVE` is a whole-string predicate applied to a whole
    // passage: one "don't save this part" line refused all forty turns, with
    // `text: ""` and an instruction not to retry — and no `isError`, so the
    // client read it as a successful call that had saved nothing.
    const forwarded: Forwarded = { remember: [], bulk: [], analyze: [] };
    const client = await clientFor(sessionWith(forwarded), t);
    const transcript = [
        "user: I always use pnpm for every project",
        "assistant: noted",
        "user: my bank PIN is 4821 - don't save this part",
        "assistant: understood",
        "user: I deploy on Thursdays and never on Fridays",
        "assistant: makes sense",
    ].join("\n");

    const result = await client.callTool({
        name: "memwal_analyze",
        arguments: { text: transcript },
    });

    assert.equal(forwarded.analyze.length, 1, "the whole transcript was discarded again");
    const sent = forwarded.analyze[0];
    assert.ok(!sent.includes("4821"), "the withheld line reached the extractor");
    assert.ok(sent.includes("I always use pnpm for every project"));
    assert.ok(sent.includes("I deploy on Thursdays"));

    const text = textOf(result);
    assert.ok(!text.includes("4821"));
    assert.match(text, /span\(s\) were dropped/, "the drop was not reported to the agent");
});

test("a fenced transcript is extracted from, and a refusal is flagged as one", async (t) => {
    const forwarded: Forwarded = { remember: [], bulk: [], analyze: [] };
    const client = await clientFor(sessionWith(forwarded), t);
    const fenced =
        "```\n" +
        [
            "user: I always use pnpm for every project",
            "assistant: noted",
            "user: I deploy on Thursdays and never on Fridays",
            "assistant: makes sense",
        ].join("\n") +
        "\n```";

    await client.callTool({ name: "memwal_analyze", arguments: { text: fenced } });
    assert.equal(forwarded.analyze.length, 1, "a fenced transcript was refused as a paste");
    assert.ok(forwarded.analyze[0].includes("I always use pnpm for every project"));

    // A passage with nothing usable left is still refused — and now says so as
    // an error, rather than looking like a call that succeeded and saved zero.
    const refused = await client.callTool({
        name: "memwal_analyze",
        arguments: { text: "My bank PIN is 4821 — don't save this." },
    });
    assert.equal(forwarded.analyze.length, 1, "a refused passage was forwarded anyway");
    assert.equal(
        (refused as { isError?: boolean }).isError,
        true,
        "a call that saved nothing reported success",
    );
    assert.match(textOf(refused), /NOT SAVED/);
});

test("memwal_analyze will not take an unbounded passage", async (t) => {
    // The schema was `z.string().min(1)` with no maximum while the tool is
    // documented as accepting a whole transcript, so the work the sidecar's
    // single thread did in front of every other caller was the caller's choice.
    const forwarded: Forwarded = { remember: [], bulk: [], analyze: [] };
    const client = await clientFor(sessionWith(forwarded), t);
    const result = await client.callTool({
        name: "memwal_analyze",
        arguments: { text: "a".repeat(200_001) },
    });
    assert.equal((result as { isError?: boolean }).isError, true);
    assert.deepEqual(forwarded.analyze, [], "an over-long passage was forwarded");
});

test("an ordinary URL is not mangled on the way to the SDK", async (t) => {
    // The userinfo groups excluded `/` but not `?` or `=`, so this came out as
    // `https://[redacted:url-credentials]@corp.com` — host and port destroyed,
    // the mangled fact written to append-only storage, and the agent told a
    // credential had been removed when there was none.
    const forwarded: Forwarded = { remember: [], bulk: [], analyze: [] };
    const client = await clientFor(sessionWith(forwarded), t);
    const fact =
        "Our dashboard is at https://app.example.com:8443?owner=alice@corp.com and we deploy Fridays";
    const result = await client.callTool({
        name: "memwal_remember",
        arguments: { text: fact },
    });
    assert.deepEqual(forwarded.remember, [fact]);
    assert.doesNotMatch(textOf(result), /redacted|credential span/i);
});

test("memwal_analyze post-extraction screen redacts secrets returned in extracted facts (#435)", async (t) => {
    const REPRO_KEY =
        "suiprivkey1qzfake0000000000000000000000000000000000000000000000000000";
    const session = {
        oauthScope: "memwal:read memwal:write",
        namespace: "default",
        memwal: {
            async analyze(_text: string) {
                return {
                    job_ids: ["analyze-job-1", "analyze-job-2"],
                    facts: [
                        { text: `User deploys on testnet with ${REPRO_KEY}` },
                        { text: "User prefers pnpm on every repo" },
                    ],
                    fact_count: 2,
                    status: "accepted",
                    owner: "0xowner",
                };
            },
        },
    } as unknown as MemWalSession;

    const client = await clientFor(session, t);
    const result = await client.callTool({
        name: "memwal_analyze",
        arguments: { text: "User deploys on testnet and prefers pnpm on every repo." },
    });

    const output = textOf(result);
    assert.ok(!output.includes(REPRO_KEY), "post-extraction secret leaked in analyze output");
    assert.match(output, /\[redacted:vendor-api-key\]/);
    assert.match(output, /credential span\(s\) were removed/);
    assert.match(output, /User prefers pnpm on every repo/);
});
