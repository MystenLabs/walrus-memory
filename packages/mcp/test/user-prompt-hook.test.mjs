/**
 * UserPromptSubmit injects one full decision rubric per session, then a
 * one-line nudge. It must not classify remember vs recall from English
 * keywords — every substantive prompt in a fresh session gets the same text.
 *
 * WALM-642 made the save half of that rubric depend on the user's standing
 * automatic-memory answer, so "the same text" is now per state: the tests below
 * pin the ON variant by asking for it explicitly, and `auto-save-optin.test.mjs`
 * pins what an answered-no and an unanswered install inject instead. Every run
 * is pointed at an empty MEMWAL_CREDS_DIR so the developer's own
 * ~/.memwal/settings.json cannot decide the result.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
    DECISION_RUBRIC,
    DECISION_RUBRIC_NUDGE,
} from "../plugin/scripts/lib/decision-rubric.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const HOOK = resolve(__dirname, "../plugin/scripts/on_user_prompt.mjs");
const EMPTY_CREDS_DIR = mkdtempSync(join(tmpdir(), "memwal-hook-test-"));
// These cases are about classification, not consent: publish a consented state
// in the isolated trusted state dir so they test the ON rubric.
writeFileSync(
    join(EMPTY_CREDS_DIR, "auto-save-state.json"),
    JSON.stringify({
        version: 1,
        enabled: true,
        state: "on",
        source: "settings",
        pendingConsent: false,
        updatedAt: new Date().toISOString(),
    }),
);

function runHook(prompt, sessionId = `test-${Math.random().toString(16).slice(2)}`) {
    const result = spawnSync(process.execPath, [HOOK], {
        input: JSON.stringify({ prompt, session_id: sessionId }),
        encoding: "utf8",
        env: {
            ...process.env,
            MEMWAL_CREDS_DIR: EMPTY_CREDS_DIR,
        },
    });
    assert.equal(result.status, 0, result.stderr);
    if (!result.stdout.trim()) return "";
    const parsed = JSON.parse(result.stdout);
    return parsed.hookSpecificOutput?.additionalContext ?? "";
}

const SUBSTANTIVE = [
    "What do you remember about how I like to work, my coffee order, and my staging canary nickname?",
    "A few things about how I work: I always use pnpm, TypeScript strict mode, and my coffee order is a matcha oat latte. My staging canary nickname is coral-fox-77.",
    "Can you remember that I always use pnpm?",
    "Tell me what you remember about how I like to work",
    "Tui luôn dùng pnpm và order cafe là matcha oat latte, nickname review là cedar-wren-11.",
    "Ban nho cafe order cua toi la gi?",
    "Remeber that I always use pnpm and my canary is cedar-wren-11.",
];

test("fresh-session substantive prompts produce byte-identical output", () => {
    const outputs = SUBSTANTIVE.map((prompt) => runHook(prompt));
    assert.ok(outputs.length > 1);
    for (const ctx of outputs) {
        assert.equal(ctx, outputs[0]);
        assert.doesNotMatch(ctx, /The user is referencing earlier work/);
        assert.doesNotMatch(ctx, /The user just stated a durable fact/);
    }
    assert.equal(outputs[0], DECISION_RUBRIC);
});

test("later turns in the same session get the one-line nudge", () => {
    const sessionId = `session-${Math.random().toString(16).slice(2)}`;
    const first = runHook(SUBSTANTIVE[0], sessionId);
    const second = runHook(SUBSTANTIVE[1], sessionId);
    assert.equal(first, DECISION_RUBRIC);
    assert.equal(second, DECISION_RUBRIC_NUDGE);
});

test("terse Vietnamese preference is not skipped", () => {
    const ctx = runHook("Tui thích pnpm");
    assert.equal(ctx, DECISION_RUBRIC);
});

test("short prompts stay quiet", () => {
    assert.equal(runHook("ok"), "");
    assert.equal(runHook("yes"), "");
});
