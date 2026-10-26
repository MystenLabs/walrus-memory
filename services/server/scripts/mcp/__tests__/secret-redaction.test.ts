/**
 * Unit coverage for the credential redactor (WALM-642).
 *
 * The write-path tests next door prove the three tools call this. These prove
 * what it does, and — just as important — what it leaves alone: Walrus storage
 * is append-only, so a false negative is permanent, but a false positive
 * silently destroys the fact the user asked to keep. Both directions are pinned
 * here.
 */
import assert from "node:assert/strict";
import test from "node:test";

import {
    sanitizeFact,
    sanitizeFactBatch,
    sanitizePassage,
    redactionNotice,
    refusalNotice,
    droppedSpanNotice,
    type RedactionKind,
} from "../tools/redaction.js";

/** Assert a secret is gone, the surrounding fact survived, and the kind is named. */
function assertRedacted(
    input: string,
    secret: string,
    kind: RedactionKind,
    keeps: string[],
): string {
    const out = sanitizeFact(input);
    assert.equal(out.refusal, undefined, `unexpectedly refused: ${input}`);
    assert.ok(out.changed, `nothing was redacted in: ${input}`);
    assert.ok(
        !out.text.includes(secret),
        `the secret survived redaction (kind=${kind})`,
    );
    assert.ok(out.kinds.includes(kind), `expected kind ${kind}, got ${out.kinds}`);
    for (const keep of keeps) {
        assert.ok(out.text.includes(keep), `lost "${keep}" from: ${input}`);
    }
    return out.text;
}

// ── the shapes that must never reach storage ────────────────────────────────

test("a connection string keeps its host and loses its credentials", () => {
    // The WALM-642 repro, almost verbatim: a preference stated next to a URL
    // carrying a password.
    const text = assertRedacted(
        "I prefer dark mode, and the staging db is postgres://admin:hunter2@db.internal:5432/app",
        "hunter2",
        "url-credentials",
        ["I prefer dark mode", "db.internal:5432/app", "postgres://"],
    );
    assert.ok(!text.includes("admin:hunter2"));
});

test("vendor-prefixed API keys are recognised without any context", () => {
    const cases: Array<[string, string]> = [
        ["sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789", "sk-ant"],
        ["sk-abcdefghijklmnopqrstuvwxyz0123", "openai"],
        ["ghp_abcdefghijklmnopqrstuvwxyz0123456789", "github"],
        ["github_pat_11ABCDEFG0abcdefghijklmnop", "github fine-grained"],
        ["AKIAIOSFODNN7EXAMPLE", "aws"],
        ["xoxb-1234567890-abcdefghij", "slack"],
        ["glpat-abcdefghij0123456789", "gitlab"],
    ];
    for (const [secret, label] of cases) {
        assertRedacted(
            `My deploy notes: the CI runner uses ${secret} for pushes`,
            secret,
            "vendor-api-key",
            ["My deploy notes", "CI runner"],
        );
        assert.ok(label);
    }
});

test("a PEM private key is removed whole, terminated or not", () => {
    const body = "MIIEowIBAAKCAQEAx7Vk9mJ0ZwQ3\nabcdefghijklmnopqrstuvwxyz0123456789\n";
    const closed =
        `Deploy key for the box:\n-----BEGIN RSA PRIVATE KEY-----\n${body}-----END RSA PRIVATE KEY-----\nIt lives in 1Password.`;
    const out = assertRedacted(closed, body.trim(), "private-key-block", ["Deploy key"]);
    assert.ok(!out.includes("BEGIN RSA PRIVATE KEY"));

    // A paste that was cut off has no END line. The body must still go.
    const truncated = `Deploy key for the box:\n-----BEGIN OPENSSH PRIVATE KEY-----\n${body}`;
    const cut = sanitizeFact(truncated);
    assert.ok(!cut.text.includes("MIIEowIBAAKCAQEAx7Vk9mJ0ZwQ3"));
    assert.ok(cut.kinds.includes("private-key-block"));
});

test("a JWT is removed", () => {
    const jwt =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    assertRedacted(
        `Our session tokens look like ${jwt} and expire hourly`,
        jwt,
        "jwt",
        ["Our session tokens", "expire hourly"],
    );
});

test("credential assignments lose the value and keep the key name", () => {
    for (const [line, secret] of [
        ["password=hunter2", "hunter2"],
        ["api_key: abc123def456", "abc123def456"],
        ['token = "t0ps3cr3t-value"', "t0ps3cr3t-value"],
        ["client_secret:swordfish99", "swordfish99"],
    ] as Array<[string, string]>) {
        const out = assertRedacted(
            `My local override file has ${line} and I never commit it`,
            secret,
            "credential-assignment",
            ["local override file", "never commit it"],
        );
        assert.ok(/redacted:credential-assignment/.test(out));
    }
});

test("authorization and cookie headers are removed", () => {
    assertRedacted(
        "To call the API: Authorization: Bearer abc123xyz789 — then GET /v1/me",
        "abc123xyz789",
        "auth-header",
        ["To call the API", "/v1/me"],
    );
    assertRedacted(
        "The dashboard needs Cookie: session=9f8e7d6c5b4a3 to load my profile",
        "9f8e7d6c5b4a3",
        "auth-header",
        ["The dashboard needs", "to load my profile"],
    );
});

test("a labelled seed phrase is removed", () => {
    const words =
        "abandon ability able about above absent absorb abstract absurd abuse access accident";
    assertRedacted(
        `My wallet recovery phrase is ${words} and the wallet is on Sui mainnet`,
        words,
        "seed-phrase",
        ["My wallet", "Sui mainnet"],
    );
});

test("MemWal's own delegate private key is removed, in every shape it arrives in", () => {
    // The 64-hex Ed25519 seed from ~/.memwal/credentials.json. auth.ts marks it
    // "NEVER log this": whoever holds it can read and write the user's memories
    // until the delegate is revoked. It is pure lowercase hex, so the entropy
    // rule deliberately does not see it — the LABEL is what catches it.
    const SEED = "4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b";

    // A pasted line from the file, the file itself, prose, and the label after
    // the value. Each keeps a fact around it so the refusal path is not what is
    // being measured here.
    for (const text of [
        `Notes from setup: delegatePrivateKey ${SEED} was written on this laptop`,
        `Notes from setup: "delegatePrivateKey": "${SEED}" is in the file`,
        `Notes from setup: my delegate private key is ${SEED} on this laptop`,
        `Notes from setup: ${SEED} is my private key for this laptop`,
        `Notes from setup: secret_key = ${SEED} on this laptop`,
        `Notes from setup: the signing key 0x${SEED} lives on this laptop`,
    ]) {
        const out = sanitizeFact(text);
        assert.equal(out.refusal, undefined, `unexpectedly refused: ${text}`);
        assert.ok(!out.text.includes(SEED), `the delegate key survived: ${text}`);
        assert.ok(out.text.includes("Notes from setup"), `lost the fact: ${text}`);
    }
});

test("an UNLABELLED hex run is still left alone — that is what the label gate buys", () => {
    // The regression this design protects. Same 64 hex characters as the test
    // above; the only difference is that nothing calls them a key.
    const HEX = "4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b";
    for (const fact of [
        `The release digest is ${HEX} and I verified it`,
        `Pin the deployment to 0x${HEX}`,
        // "credentials.json" is a phrase MemWal prose uses constantly, and it
        // sits within a window of the SHA here. It is excluded from the label
        // list precisely so this sentence keeps its commit id.
        "My creds live in ~/.memwal/credentials.json and the fix landed in 4f2b8c1e9d7a3f5b6c0e2d4a8b1f3c5e7d9a0b2c",
        // Documented in auth.ts as "Safe to display" — the public half must not
        // be swept up with the private one.
        `My delegatePublicKeyHex is ${HEX}`,
    ]) {
        const out = sanitizeFact(fact);
        assert.equal(out.text, fact, `redacted an unlabelled hex run: ${fact}`);
        assert.equal(out.changed, false);
    }
});

test("a seed phrase is caught however the label is spelled", () => {
    const WORDS =
        "abandon ability able about above absent absorb abstract absurd abuse access accident";
    for (const text of [
        `Wallet notes: my recovery phrase is ${WORDS} for the mainnet wallet`,
        `Wallet notes: seed_phrase: ${WORDS} for the mainnet wallet`,
        `Wallet notes: "mnemonic": "${WORDS}" for the mainnet wallet`,
        `Wallet notes: seedPhrase=${WORDS} for the mainnet wallet`,
    ]) {
        const out = sanitizeFact(text);
        assert.equal(out.refusal, undefined, `unexpectedly refused: ${text}`);
        assert.ok(!out.text.includes(WORDS), `the mnemonic survived: ${text}`);
        assert.ok(out.text.includes("Wallet notes"), `lost the fact: ${text}`);
    }

    // Still true, and still documented: a bare word run with no label at all is
    // indistinguishable from a sentence, so it is left to the model rules.
    const bare = sanitizeFact(`I wrote down ${WORDS} yesterday`);
    assert.equal(bare.changed, false);
});

test("a long mixed-case base64 blob is removed", () => {
    const blob =
        "QWxhZGRpbjpvcGVuIHNlc2FtZQBcdefGHIjklMNOpqrSTUvwxYZ0123456789abcDEF0123";
    assertRedacted(
        `The signing material is ${blob} which I keep in the vault`,
        blob,
        "high-entropy-secret",
        ["The signing material", "keep in the vault"],
    );
});

// ── the shapes that must survive untouched ──────────────────────────────────

test("a plain preference passes through byte-for-byte", () => {
    // The single most important assertion in this file: the ordinary case must
    // be indistinguishable from having no redactor at all.
    for (const fact of [
        "I always use pnpm, and TypeScript strict mode on every project.",
        "Tui luôn dùng pnpm và order cafe là matcha oat latte.",
        "Deploy to staging on Thursdays, never on Friday afternoons.",
        "My password manager is 1Password and I rotate keys every quarter.",
        "The API key for that service is stored in Vault, not in the repo.",
    ]) {
        const out = sanitizeFact(fact);
        assert.equal(out.text, fact, `changed a clean fact: ${fact}`);
        assert.equal(out.changed, false);
        assert.equal(out.count, 0);
        assert.deepEqual(out.kinds, []);
        assert.equal(out.refusal, undefined);
    }
});

test("the identifiers MemWal itself stores are not mistaken for secrets", () => {
    // A generic entropy rule would eat every one of these, which is why there
    // isn't one. See the trade-off note at the top of redaction.ts.
    for (const fact of [
        "My account id is 0x7f3a9c2e5b8d1f4a6c9e2b5d8f1a4c7e0b3d6f9a2c5e8b1d4f7a0c3e6b9d2f5a",
        "The blob landed as blob_id=Xj9vKq2mP7nR4tW8yB1cE5gH0dF3sA6uZ2xN8qL4kM7",
        "Pin the build to commit 4f2b8c1e9d7a3f5b6c0e2d4a8b1f3c5e7d9a0b2c",
        "The sha256 of the release tarball is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "My Sui package id is 0xe80f2feec1c139616a86c9f71210152e2a7ca552b20841f2e192f99f75864437",
        "The migration artifact hashes to 9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b",
    ]) {
        const out = sanitizeFact(fact);
        assert.equal(out.text, fact, `redacted a legitimate identifier: ${fact}`);
        assert.equal(out.changed, false);
    }
});

// ── refusals ────────────────────────────────────────────────────────────────

test("an explicit do-not-save is honoured", () => {
    for (const text of [
        "My bank PIN is 4821 — don't save this.",
        "Do not remember this: I'm interviewing elsewhere.",
        "Off the record, I'm leaving the team in March.",
        "Please don't store that anywhere.",
    ]) {
        const out = sanitizeFact(text);
        assert.equal(out.refusal, "no-save-directive", `not refused: ${text}`);
        assert.equal(out.text, "");
    }
});

test("an ordinary preference about not saving things is NOT a do-not-save", () => {
    // The demonstrative ("this"/"that"/"it") is what separates the two, and
    // without it the directive check would eat real preferences.
    for (const text of [
        "I don't save screenshots to the Desktop, they go to ~/Pictures.",
        "Never store build artifacts in the repo — use the cache.",
        "Don't keep logs longer than 30 days on staging.",
    ]) {
        const out = sanitizeFact(text);
        assert.equal(out.refusal, undefined, `wrongly refused: ${text}`);
        assert.equal(out.text, text);
    }
});

test("pasted third-party content is not saved as a fact about the user", () => {
    const fenced = "```\nERROR 500 from vendor api\n  at handler (index.js:42)\n```";
    assert.equal(sanitizeFact(fenced).refusal, "pasted-content");

    const quotedBlock = "> their PM said the deadline slips\n> and the scope is unchanged";
    assert.equal(sanitizeFact(quotedBlock).refusal, "pasted-content");

    const longQuote = `"${"the vendor's release note says the same thing again and again. ".repeat(5)}"`;
    assert.ok(longQuote.length >= 200);
    assert.equal(sanitizeFact(longQuote).refusal, "pasted-content");
});

test("a short quoted fact is still saved — an agent quotes the user routinely", () => {
    const quoted = '"I always use pnpm"';
    const out = sanitizeFact(quoted);
    assert.equal(out.refusal, undefined);
    assert.equal(out.text, quoted);
});

test("a text that is nothing but a secret is refused, not stored as a placeholder", () => {
    const out = sanitizeFact("sk-abcdefghijklmnopqrstuvwxyz0123");
    assert.equal(out.refusal, "credential-only");
    assert.equal(out.text, "");
    assert.ok(out.kinds.includes("vendor-api-key"));
});

// ── what the caller is told ─────────────────────────────────────────────────

test("the notices name the kind and never the value", () => {
    const secret = "hunter2";
    const out = sanitizeFact(`db is postgres://admin:${secret}@db.internal/app for staging`);
    const notice = redactionNotice(out.kinds, out.count);
    assert.match(notice, /url-credentials/);
    assert.match(notice, /do not re-send/i);
    assert.ok(!notice.includes(secret), "the notice must not echo the secret");

    const refusal = refusalNotice("credential-only");
    assert.match(refusal, /NOT SAVED/);
    assert.match(refusal, /Do not retry this text/);
});

test("nothing removed means nothing said", () => {
    assert.equal(redactionNotice([], 0), "");
});

/* ───────────────────────────────────────────────────────────────────────────
 * Review findings on the WALM-642 branch. Each of these leaked, verbatim,
 * through `sanitizeFact` before the fix beside it.
 * ------------------------------------------------------------------------ */

// ── finding 3: the credential-assignment gate missed whole spellings ────────

test("SCREAMING_SNAKE and quoted-JSON credential names are assignments too", () => {
    // `_` is a word character, so `\b` never fired between `_` and the
    // keyword, and `_` is not `[a-z]` so the camelCase lookbehind did not
    // either. That left the spelling credentials actually arrive in — a pasted
    // env file or shell export — completely unguarded.
    for (const [text, secret] of [
        ["POSTGRES_PASSWORD=hunter2", "hunter2"],
        [
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        ],
        ["DB_PASSWORD=hunter2SuperSecret", "hunter2SuperSecret"],
        ["X_AUTH_TOKEN: abcd1234", "abcd1234"],
        ["SESSION_SECRET=abcd1234efgh5678", "abcd1234efgh5678"],
        ["my_api_key=abcd1234efgh5678", "abcd1234efgh5678"],
    ] as Array<[string, string]>) {
        const out = sanitizeFact(text);
        assert.ok(out.changed, `not redacted at all: ${text}`);
        assert.ok(!out.text.includes(secret), `the secret survived: ${text}`);
    }

    // A JSON object puts a closing quote between the key and the colon, which
    // the old separator group demanded come immediately after the keyword.
    const json = sanitizeFact(
        'Save my config: {"username": "alice", "password": "hunter2-prod-9xQ"} for staging',
    );
    assert.equal(json.refusal, undefined);
    assert.ok(!json.text.includes("hunter2-prod-9xQ"), "the JSON password survived");
    assert.ok(json.text.includes("alice"), "the username is not a credential");
    assert.ok(json.text.includes("for staging"), "the fact was lost with the password");
});

test("widening the gate did not widen it onto ordinary prose", () => {
    // The lookbehind now admits `_`, `-` and digits. These are the sentences
    // that must not start matching because of it.
    for (const fact of [
        "My password manager is 1Password and I rotate keys every quarter.",
        "The API key for that service is stored in Vault, not in the repo.",
        "My creds live in ~/.memwal/credentials.json and the fix landed in 4f2b8c1e9a7d6f5c4b3a29180716253443219876",
        "We renamed the secret_store module to vault_client last sprint.",
        "Token bucket rate limiting is what the relayer uses.",
    ]) {
        const out = sanitizeFact(fact);
        assert.equal(out.text, fact, `changed a clean fact: ${fact}`);
        assert.equal(out.changed, false);
    }
});

// ── finding 5: the label rule only ever looked at hex ───────────────────────

test("a labelled secret that is not hex is key material too", () => {
    // 40 characters, base64-ish, three label words in front of it — and it came
    // back completely unchanged, because `hasAdjacentCredentialLabel` was
    // consulted only for HEX_RUN and the entropy rule demands 64+.
    const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    assertRedacted(
        `My AWS secret access key is ${AWS_SECRET} for prod`,
        AWS_SECRET,
        "labelled-key-material",
        ["My AWS secret access key", "for prod"],
    );

    // The pair, which is the shape it arrives in: the non-secret id was being
    // redacted by the vendor rule while the secret half survived.
    const pair = sanitizeFact(
        `AWS creds for staging: AKIAIOSFODNN7EXAMPLE and the secret key is ${AWS_SECRET}`,
    );
    assert.ok(!pair.text.includes(AWS_SECRET), "the secret half of the pair survived");
    assert.ok(!pair.text.includes("AKIAIOSFODNN7EXAMPLE"));
});

test("the label is still the only discriminator — bare runs pass", () => {
    // The whole design: widening the SHAPE the rule can see must not weaken the
    // gate in front of it, or every identifier this product exists to remember
    // starts disappearing.
    for (const fact of [
        "The blob landed as blob_id=Xj9vKq2mP7nR4tW8yB1cE5gH0dF3sA6uZ2xN8qL4kM7",
        "Pin the build to commit 4f2b8c1e9d7a3f5b6c0e2d4a8b1f3c5e7d9a0b2c",
        "My Sui package id is 0xe80f2feec1c139616a86c9f71210152e2a7ca552b20841f2e192f99f75864437",
        "My delegatePublicKeyHex is 4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b and it is safe to share",
        "The build id is 20260918T0930Z-linux-arm64-release-candidate",
    ]) {
        const out = sanitizeFact(fact);
        assert.equal(out.text, fact, `redacted a legitimate identifier: ${fact}`);
        assert.equal(out.changed, false);
    }
});

// ── findings 6 + 7: the URL rule was quadratic, and mangled ordinary URLs ───

test("an ordinary URL with a query string is not userinfo", () => {
    // The password group excluded `/` and whitespace but not `?` or `=`, so
    // this matched with `app.example.com` as the user and `8443?owner=alice` as
    // the password: host and port destroyed, `corp.com` promoted to hostname,
    // and a notice claiming a credential had been removed when there was none.
    const fact =
        "Our dashboard is at https://app.example.com:8443?owner=alice@corp.com and we deploy Fridays";
    const out = sanitizeFact(fact);
    assert.equal(out.text, fact, "an ordinary URL was mangled");
    assert.equal(out.changed, false);
    assert.equal(out.count, 0, "a redaction was reported where none happened");

    // ...while a real connection string is untouched by the narrowing.
    const real = sanitizeFact("staging is postgres://admin:hunter2@db.internal:5432/app");
    assert.ok(!real.text.includes("hunter2"));
    assert.ok(real.text.includes("db.internal:5432/app"), "the host was lost");
});

test("a long passage is screened in linear time", () => {
    // `URL_USERINFO`'s scheme repeat was unbounded, so it was tried and
    // abandoned at every start offset: 30 KB took 317 ms, 60 KB 1254 ms and
    // 120 KB 4814 ms. `memwal_analyze` takes a whole transcript, the sidecar is
    // single-threaded and a tools/call times out at 60 s, so a long paste was a
    // stall for every other caller too.
    //
    // The budget is deliberately loose — this is a guard against a quadratic
    // pattern coming back, not a benchmark, and CI machines are noisy. The
    // shape is what matters: 4x the input must not be 16x the time.
    const worst = "a".repeat(120 * 1024);
    const started = Date.now();
    sanitizeFact(worst);
    const elapsed = Date.now() - started;
    assert.ok(
        elapsed < 1000,
        `120 KB took ${elapsed} ms — a redaction pattern has gone superlinear again`,
    );

    const small = "a".repeat(30 * 1024);
    const t0 = Date.now();
    sanitizeFact(small);
    const smallMs = Math.max(Date.now() - t0, 1);
    assert.ok(
        elapsed / smallMs < 12,
        `120 KB/30 KB ratio was ${(elapsed / smallMs).toFixed(1)}x — that is quadratic, not linear`,
    );
});

// ── finding 4: a secret split across bulk entries ──────────────────────────

test("a credential split across two bulk entries is still caught", () => {
    // The reporter's case. Every label-gated rule searches a window inside ONE
    // string, so putting the label in one entry and the value in the next was
    // a way past all of them — including the rule that exists specifically for
    // MemWal's own delegate private key.
    const SEED = "4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b";
    const split = sanitizeFactBatch([
        "my delegate private key for the mainnet account",
        SEED,
    ]);
    assert.ok(
        !split.map((r) => r.text).join("\n").includes(SEED),
        "the delegate private key survived being split across entries",
    );
    assert.equal(split[1].refusal, "credential-only", "a bare key must be dropped, not stored");
    assert.equal(split[0].refusal, undefined, "the label entry is a fact and should survive");

    // The same value with filler words around it, and with the label AFTER it.
    for (const facts of [
        ["my delegate private key for the mainnet account", `the value to use is ${SEED} for that account`],
        [SEED, "that is my delegate private key"],
        ["I set up a second laptop", "my delegate private key is below", SEED],
    ]) {
        const out = sanitizeFactBatch(facts);
        assert.ok(
            !out.map((r) => r.text).join("\n").includes(SEED),
            `the key survived: ${JSON.stringify(facts)}`,
        );
    }
});

// The passage path (`memwal_analyze`) splits on lines and used to screen each
// one alone, so the same split the batch test above catches was stored
// verbatim (WALM-687). `sanitizePassage` now reuses `sanitizeFactBatch`.

test("a credential split across two passage lines is still caught", () => {
    const SEED = "4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b";
    const label = "my delegate private key for the mainnet account";
    const out = sanitizePassage(`${label}\n${SEED}`);
    assert.equal(out.refusal, undefined, "the label line is a fact and should survive");
    assert.equal(out.changed, true);
    assert.ok(out.count >= 1);
    assert.ok(!out.text.includes(SEED), "the delegate private key survived being split across lines");
    assert.ok(out.text.includes(label), "the label line was dropped with the key");
    assert.ok(
        out.kinds.includes("labelled-key-material"),
        `expected labelled-key-material, got ${out.kinds}`,
    );
    assert.ok(out.dropped.some((d) => d.reason === "credential-only"));
    assert.ok(!JSON.stringify(out.dropped).includes(SEED), "dropped echoed the key");
    assert.ok(!droppedSpanNotice(out.dropped, out.segments).includes(SEED));
});

test("a non-hex opaque credential split across passage lines is removed", () => {
    const token = "zQ8vK2mNp4RsT6uWxY1aB3cD5eF7gH9jL0nP2q";
    const out = sanitizePassage(
        `the api key for the staging bucket is\n${token}\nkeep it safe`,
    );
    assert.equal(out.refusal, undefined);
    assert.equal(out.changed, true);
    assert.ok(out.count >= 1);
    assert.ok(!out.text.includes(token), "the opaque token survived the line break");
    assert.ok(out.text.includes("the api key for the staging bucket is"));
    assert.ok(out.text.includes("keep it safe"));
    assert.ok(
        out.kinds.includes("labelled-key-material"),
        `expected labelled-key-material, got ${out.kinds}`,
    );
    assert.ok(!JSON.stringify(out.dropped).includes(token));
});

test("a delegatePrivateKey value on the next JSON line is removed", () => {
    const SEED = "4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b";
    const out = sanitizePassage(
        [
            "Notes from the credentials file on this laptop:",
            '"delegatePrivateKey":',
            `"${SEED}"`,
            "I use the work namespace there.",
        ].join("\n"),
    );
    assert.equal(out.refusal, undefined);
    assert.equal(out.changed, true);
    assert.ok(out.count >= 1);
    assert.ok(!out.text.includes(SEED), "the JSON value on its own line was stored");
    assert.ok(out.text.includes("delegatePrivateKey"), "the label line was dropped with the key");
    assert.ok(out.text.includes("work namespace"));
    assert.ok(
        out.kinds.includes("labelled-key-material"),
        `expected labelled-key-material, got ${out.kinds}`,
    );
    assert.ok(!JSON.stringify(out.dropped).includes(SEED));
});

test("a passage of identifiers with no credential label is unchanged", () => {
    // Same gate as the batch screen: widening passage screening to neighbouring
    // lines must not start eating digests, package ids or blob ids.
    const lines = [
        "The release digest is 4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b",
        "My Sui package id is 0xe80f2feec1c139616a86c9f71210152e2a7ca552b20841f2e192f99f75864437",
        "The blob landed as blob_id=Xj9vKq2mP7nR4tW8yB1cE5gH0dF3sA6uZ2xN8qL4kM7",
        "I always use pnpm",
    ];
    const passage = lines.join("\n");
    const out = sanitizePassage(passage);
    assert.equal(out.text, passage);
    assert.equal(out.changed, false);
    assert.equal(out.count, 0);
    assert.deepEqual(out.kinds, []);
    assert.deepEqual(out.dropped, []);
});

test("a lone identifier far from a credential label survives a passage", () => {
    // A distant label must not make every bare blob id / SHA in the passage
    // count as labelled key material (passage bareScope is neighbours-only).
    const lines = [
        "user: I rotated my delegate key yesterday, all good now.",
        ...Array.from({ length: 10 }, (_, i) => `assistant: step ${i} done`),
        "Xj9vKq2mP7nR4tW8yB1cE5gH0dF3sA6uZ2xN8qL4kM7",
        "4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b",
    ];
    const out = sanitizePassage(lines.join("\n"));
    assert.deepEqual(out.dropped, []);
    assert.ok(out.text.includes("Xj9vKq2mP7nR4tW8yB1cE5gH0dF3sA6uZ2xN8qL4kM7"));
    assert.ok(out.text.includes("4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b"));
});

test("a credential separated by a blank line is still caught in a passage", () => {
    // Blank lines are omitted from the batch screen so label and value stay
    // neighbours even with an empty line between them.
    const SEED = "4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b";
    const label = "my delegate private key for mainnet:";
    const out = sanitizePassage(`${label}\n\n${SEED}\n\nthanks`);
    assert.equal(out.refusal, undefined);
    assert.equal(out.changed, true);
    assert.ok(out.count >= 1);
    assert.ok(!out.text.includes(SEED), "the seed survived a blank line between label and value");
    assert.ok(out.text.includes(label));
    assert.ok(out.text.includes("thanks"));
    assert.ok(
        out.kinds.includes("labelled-key-material"),
        `expected labelled-key-material, got ${out.kinds}`,
    );
    assert.ok(out.dropped.some((d) => d.reason === "credential-only"));
    assert.ok(!JSON.stringify(out.dropped).includes(SEED));
});

test("the batch screen does not fire without a label anywhere in it", () => {
    // Cross-entry awareness widens what counts as adjacent, which is exactly
    // the kind of change that starts eating identifiers. The gate is still the
    // label: a batch with none must be byte-for-byte untouched.
    const facts = [
        "The release digest is 4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b",
        "My Sui package id is 0xe80f2feec1c139616a86c9f71210152e2a7ca552b20841f2e192f99f75864437",
        "The blob landed as blob_id=Xj9vKq2mP7nR4tW8yB1cE5gH0dF3sA6uZ2xN8qL4kM7",
        "I always use pnpm",
    ];
    const out = sanitizeFactBatch(facts);
    assert.deepEqual(out.map((r) => r.text), facts);
    assert.deepEqual(out.map((r) => r.changed), [false, false, false, false]);
});

test("per-entry refusal granularity survives the batch screen", () => {
    // The property that already worked: one bad entry is dropped and the rest
    // of the batch still lands.
    const out = sanitizeFactBatch([
        "I always use pnpm",
        "sk-abcdefghijklmnopqrstuvwxyz0123",
        "Please don't save this one",
        "Deploy on Thursdays",
    ]);
    assert.equal(out[0].refusal, undefined);
    assert.equal(out[0].text, "I always use pnpm");
    assert.equal(out[1].refusal, "credential-only");
    assert.equal(out[2].refusal, "no-save-directive");
    assert.equal(out[3].text, "Deploy on Thursdays");
});

// ── finding 8: one stray line discarded a whole transcript ─────────────────

const TRANSCRIPT = [
    "user: I always use pnpm for every project",
    "assistant: noted",
    "user: my staging box is app.example.com:8443",
    "assistant: got it",
    "user: my bank PIN is 4821 - don't save this part",
    "assistant: understood",
    "user: I deploy on Thursdays and never on Fridays",
    "assistant: makes sense",
].join("\n");

test("one do-not-save line drops its span, not the whole transcript", () => {
    const out = sanitizePassage(TRANSCRIPT);
    assert.equal(out.refusal, undefined, "the whole passage was discarded again");
    assert.ok(!out.text.includes("4821"), "the thing they asked not to save was kept");
    assert.ok(!out.text.includes("don't save this part"));
    // Everything else survived, on both sides of the dropped span.
    assert.ok(out.text.includes("I always use pnpm for every project"));
    assert.ok(out.text.includes("app.example.com:8443"));
    assert.ok(out.text.includes("I deploy on Thursdays"));
    // And the caller is told what went, by position and reason — never by text.
    assert.ok(out.dropped.length > 0);
    assert.ok(out.dropped.every((d) => d.reason === "no-save-directive"));
    const notice = droppedSpanNotice(out.dropped, out.segments);
    assert.match(notice, /span\(s\) were dropped/);
    assert.ok(!notice.includes("4821"), "the notice echoed the dropped content");
});

test("a directive takes its own paragraph with it", () => {
    // Scoping per line would save the PIN and drop only the sentence asking
    // not to, which is the one outcome worse than dropping too much.
    const out = sanitizePassage(
        "I always use pnpm\n\nMy bank PIN is 4821\ndon't save this\n\nI deploy on Thursdays",
    );
    assert.equal(out.refusal, undefined);
    assert.ok(!out.text.includes("4821"), "the directive's neighbour was saved anyway");
    assert.ok(out.text.includes("I always use pnpm"));
    assert.ok(out.text.includes("I deploy on Thursdays"));
});

test("a fenced transcript is analysed, a fenced code paste is still refused", () => {
    // The tool documents a fenced transcript as its canonical input, and
    // refused exactly that as pasted content.
    const fenced = sanitizePassage("```\n" + TRANSCRIPT + "\n```");
    assert.equal(fenced.refusal, undefined, "a fenced transcript was discarded");
    assert.ok(fenced.text.includes("I always use pnpm for every project"));
    assert.ok(!fenced.text.includes("4821"));

    // A short fence, or one carrying a language tag, is a paste and stays one.
    assert.equal(
        sanitizePassage("```\nERROR 500 from the vendor API\n  at handler (index.js:42)\n```")
            .refusal,
        "pasted-content",
    );
    assert.equal(
        sanitizePassage('```json\n{\n  "a": 1,\n  "b": 2,\n  "c": 3,\n  "d": 4\n}\n```').refusal,
        "pasted-content",
    );
    // ...and a fence INSIDE a passage is dropped without taking the rest.
    const mixed = sanitizePassage(
        "I always use pnpm\n\n```\nERROR 500\n```\n\nI deploy on Thursdays",
    );
    assert.equal(mixed.refusal, undefined);
    assert.ok(mixed.text.includes("I always use pnpm"));
    assert.ok(mixed.text.includes("I deploy on Thursdays"));
    assert.ok(!mixed.text.includes("ERROR 500"));
    assert.ok(mixed.dropped.some((d) => d.reason === "pasted-content"));
});

test("a passage with nothing left is still refused outright", () => {
    // Scoping the refusal must not turn "save nothing" into "save something".
    const out = sanitizePassage("My bank PIN is 4821 — don't save this.");
    assert.equal(out.refusal, "no-save-directive");
    assert.equal(out.text, "");
    assert.ok(!out.text.includes("4821"));
});

test("a clean passage is forwarded byte-for-byte", () => {
    const clean = "I always use pnpm, TypeScript strict mode, and deploy on Thursdays.";
    const out = sanitizePassage(clean);
    assert.equal(out.text, clean);
    assert.equal(out.changed, false);
    assert.deepEqual(out.dropped, []);
    assert.equal(droppedSpanNotice(out.dropped, out.segments), "");
});

test("db_pass, encryption_key, and priv_key assignments are redacted (#1052)", () => {
    const V = "hunter2-prod-9xQ";
    const labels = [
        "db_pass",
        "dbpass",
        "DB_PASS",
        "encryption_key",
        "enc_key",
        "ENCRYPTION_KEY",
        "priv_key",
        "privkey",
        "private_key",
        "db_password",
    ];
    for (const label of labels) {
        const fact = `My local override file has ${label}=${V} and I never commit it`;
        assertRedacted(fact, V, "credential-assignment", [
            "local override file",
            "never commit it",
            `${label}=`,
        ]);
    }

    const batch = sanitizeFactBatch(
        labels.map((label) => `staging ${label}=${V} stays out of git`),
    );
    for (const [i, result] of batch.entries()) {
        assert.equal(result.refusal, undefined, labels[i]);
        assert.ok(!result.text.includes(V), `batch kept ${labels[i]}=${V}: ${result.text}`);
        assert.ok(result.text.includes(`${labels[i]}=`), result.text);
    }

    const passage = sanitizePassage(
        [
            "I always use pnpm",
            ...labels.map((label) => `staging ${label}=${V} stays out of git`),
            "I deploy on Thursdays",
        ].join("\n"),
    );
    assert.equal(passage.refusal, undefined);
    assert.ok(!passage.text.includes(V), passage.text);
    for (const label of labels) {
        assert.ok(passage.text.includes(`${label}=`), passage.text);
    }
    assert.ok(passage.text.includes("I always use pnpm"));
    assert.ok(passage.text.includes("I deploy on Thursdays"));

    for (const fact of [
        "My password manager is 1Password and I rotate keys every quarter.",
        "The compass=north bearing is what the field notes record.",
        `My local override file has mypass=${V} and I never commit it`,
        `My local override file has bypass=${V} and I never commit it`,
    ]) {
        const out = sanitizeFact(fact);
        assert.equal(out.text, fact, `changed a clean fact: ${fact}`);
        assert.equal(out.changed, false);
    }
});

test("hex beside the new credential labels is key material too (#1052)", () => {
    const HEX = "4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b";
    const labels = [
        "db_pass",
        "dbpass",
        "DB_PASS",
        "db_password",
        "encryption_key",
        "enc_key",
        "ENCRYPTION_KEY",
        "priv_key",
        "privkey",
    ];
    for (const label of labels) {
        for (const fact of [
            `Notes from setup: ${label} ${HEX} on this laptop`,
            `Notes from setup: ${HEX} is my ${label} for this laptop`,
        ]) {
            const out = sanitizeFact(fact);
            assert.equal(out.refusal, undefined, fact);
            assert.ok(!out.text.includes(HEX), `hex survived: ${fact}`);
            assert.ok(out.text.includes("Notes from setup"), fact);
        }
    }

    for (const fact of [
        `Notes from setup: ${HEX} is mypass for this laptop`,
        `Pin the build to commit ${HEX.slice(0, 40)} mypass`,
    ]) {
        const out = sanitizeFact(fact);
        assert.equal(out.text, fact, `mypass must not label the preceding id: ${fact}`);
        assert.equal(out.changed, false);
    }

    const split = sanitizeFactBatch([
        "my encryption_key for the staging box",
        HEX,
    ]);
    assert.ok(!split.map((r) => r.text).join("\n").includes(HEX));
    assert.equal(split[1].refusal, "credential-only");
    assert.equal(split[0].refusal, undefined);
});

test("the word pass is ordinary English, not a credential (#1052)", () => {
    const sha = "4f2b8c1e9d7a3f5b6c0e2d4a8b1f3c5e7d9a0b2c";
    const hex = "4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b";
    for (const fact of [
        "Our CI config has pass: true for the smoke suite",
        `I need to pass this commit sha ${sha} to the team`,
        `${hex} is my pass`,
    ]) {
        const out = sanitizeFact(fact);
        assert.equal(out.text, fact, `changed a clean fact: ${fact}`);
        assert.equal(out.changed, false);
    }
});
