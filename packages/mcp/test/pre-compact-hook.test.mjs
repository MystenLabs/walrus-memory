import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
    publishHookState,
    AUTO_SAVE_ENV,
} from "../dist/auto-save.js";
import {
    SECRET_EXCLUSION_RULES,
    PRE_COMPACT_PROMPT,
} from "../dist/memory-policy.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PLUGIN_ROOT = resolve(__dirname, "../plugin");
const HOOK_SCRIPT = join(PLUGIN_ROOT, "scripts", "on_pre_compact.mjs");
const HOOKS_JSON = join(PLUGIN_ROOT, "hooks.json");

function freshCredsDir() {
    return mkdtempSync(join(tmpdir(), "memwal-precompact-test-"));
}

function writeSettings(dir, value) {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "settings.json"), JSON.stringify(value));
    const saved = process.env.MEMWAL_CREDS_DIR;
    const savedAutoSave = process.env[AUTO_SAVE_ENV];
    try {
        process.env.MEMWAL_CREDS_DIR = dir;
        delete process.env[AUTO_SAVE_ENV];
        publishHookState();
    } finally {
        if (saved === undefined) delete process.env.MEMWAL_CREDS_DIR;
        else process.env.MEMWAL_CREDS_DIR = saved;
        if (savedAutoSave === undefined) delete process.env[AUTO_SAVE_ENV];
        else process.env[AUTO_SAVE_ENV] = savedAutoSave;
    }
}

function runPreCompactHook(env = {}, input = {}) {
    return spawnSync(process.execPath, [HOOK_SCRIPT], {
        input: JSON.stringify(input),
        encoding: "utf8",
        env: {
            ...process.env,
            ...env,
        },
    });
}

test("hooks.json registers PreCompact pointing to on_pre_compact.mjs", () => {
    const raw = readFileSync(HOOKS_JSON, "utf8");
    const parsed = JSON.parse(raw);
    assert.ok(parsed.hooks, "hooks object must exist");
    assert.ok(Array.isArray(parsed.hooks.PreCompact), "PreCompact hook array must exist");
    assert.ok(parsed.hooks.PreCompact.length > 0, "PreCompact hook array must not be empty");

    const commands = [];
    for (const group of parsed.hooks.PreCompact) {
        for (const hook of group.hooks || []) {
            if (hook.command) commands.push(hook.command);
        }
    }

    assert.ok(
        commands.some((cmd) => cmd.includes("on_pre_compact.mjs")),
        `hooks.json must register on_pre_compact.mjs: ${JSON.stringify(commands)}`
    );
});

test("on_pre_compact.mjs outputs nothing and exits 0 when autoSave is false via settings", () => {
    const dir = freshCredsDir();
    try {
        writeSettings(dir, { autoSave: false });
        const result = runPreCompactHook({ MEMWAL_CREDS_DIR: dir });
        assert.equal(result.status, 0, result.stderr);
        assert.equal(result.stdout.trim(), "");
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
});

test("on_pre_compact.mjs outputs nothing and exits 0 when autoSave is false via MEMWAL_AUTO_SAVE env", () => {
    const dir = freshCredsDir();
    try {
        writeSettings(dir, { autoSave: true });
        const result = runPreCompactHook({
            MEMWAL_CREDS_DIR: dir,
            [AUTO_SAVE_ENV]: "false",
        });
        assert.equal(result.status, 0, result.stderr);
        assert.equal(result.stdout.trim(), "");
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
});

test("on_pre_compact.mjs outputs nothing and exits 0 when autoSave is unset", () => {
    const dir = freshCredsDir();
    try {
        const result = runPreCompactHook({
            MEMWAL_CREDS_DIR: dir,
            [AUTO_SAVE_ENV]: undefined,
        });
        assert.equal(result.status, 0, result.stderr);
        assert.equal(result.stdout.trim(), "");
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
});

test("on_pre_compact.mjs outputs valid JSON with hookEventName PreCompact and secret exclusion rules when autoSave is enabled", () => {
    const dir = freshCredsDir();
    try {
        writeSettings(dir, { autoSave: true });
        const result = runPreCompactHook({
            MEMWAL_CREDS_DIR: dir,
            [AUTO_SAVE_ENV]: undefined,
        });
        assert.equal(result.status, 0, result.stderr);
        assert.ok(result.stdout.trim().length > 0, "stdout should not be empty");

        const parsed = JSON.parse(result.stdout);
        assert.ok(parsed.hookSpecificOutput, "hookSpecificOutput must exist");
        assert.equal(parsed.hookSpecificOutput.hookEventName, "PreCompact");

        const context = parsed.hookSpecificOutput.additionalContext;
        assert.ok(typeof context === "string", "additionalContext must be a string");
        assert.match(context, /Before the conversation context is compacted/);
        assert.match(context, /memwal_remember/);
        assert.match(context, /memwal_remember_bulk/);
        assert.ok(context.includes(SECRET_EXCLUSION_RULES), "context must contain SECRET_EXCLUSION_RULES");
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
});

test("PRE_COMPACT_PROMPT meets behavioral and secret exclusion specifications", () => {
    assert.match(PRE_COMPACT_PROMPT, /Before the conversation context is compacted/);
    assert.match(PRE_COMPACT_PROMPT, /durable user preferences/);
    assert.match(PRE_COMPACT_PROMPT, /architectural decisions/);
    assert.match(PRE_COMPACT_PROMPT, /project conventions/);
    assert.match(PRE_COMPACT_PROMPT, /resolved bug root causes/);
    assert.match(PRE_COMPACT_PROMPT, /memwal_remember/);
    assert.match(PRE_COMPACT_PROMPT, /memwal_remember_bulk/);
    assert.match(PRE_COMPACT_PROMPT, /ephemeral progress notes/);
    assert.match(PRE_COMPACT_PROMPT, /raw command output/);
    assert.ok(PRE_COMPACT_PROMPT.includes(SECRET_EXCLUSION_RULES));
});
