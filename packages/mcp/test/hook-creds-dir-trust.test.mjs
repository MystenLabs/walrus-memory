import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCRIPTS = resolve(__dirname, "../plugin/scripts");

const SAVE_RUBRIC = /call memwal_remember \(or memwal_remember_bulk for several\)/;

test("a repo-relative MEMWAL_CREDS_DIR cannot publish the hook's consent answer", async (t) => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "memwal-hookdir-home-")));
    const repo = realpathSync(mkdtempSync(join(tmpdir(), "memwal-hookdir-repo-")));
    t.after(() => {
        rmSync(home, { recursive: true, force: true });
        rmSync(repo, { recursive: true, force: true });
    });
    mkdirSync(join(repo, ".git"), { recursive: true });
    mkdirSync(join(repo, ".memwal"), { recursive: true });
    writeFileSync(
        join(repo, ".memwal", "auto-save-state.json"),
        JSON.stringify({
            version: 1,
            enabled: true,
            state: "on",
            source: "settings",
            pendingConsent: false,
            updatedAt: new Date().toISOString(),
        }),
    );

    const result = spawnSync(process.execPath, [join(SCRIPTS, "on_user_prompt.mjs")], {
        cwd: repo,
        input: JSON.stringify({
            session_id: `walm642-credsdir-${Date.now()}-${Math.random().toString(16).slice(2)}`,
            prompt: "I prefer pnpm",
        }),
        encoding: "utf8",
        env: {
            ...process.env,
            HOME: home,
            USERPROFILE: home,
            MEMWAL_CREDS_DIR: ".memwal",
        },
    });
    assert.equal(result.status, 0, `on_user_prompt.mjs exited ${result.status}: ${result.stderr}`);
    const injected = result.stdout.trim()
        ? (JSON.parse(result.stdout).hookSpecificOutput?.additionalContext ?? "")
        : "";
    assert.doesNotMatch(
        injected,
        SAVE_RUBRIC,
        "a repo-relative MEMWAL_CREDS_DIR turned automatic memory on",
    );

    const previous = { home: process.env.HOME, profile: process.env.USERPROFILE };
    const previousCredsDir = process.env.MEMWAL_CREDS_DIR;
    const previousCwd = process.cwd();
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    process.env.MEMWAL_CREDS_DIR = ".memwal";
    process.chdir(repo);
    t.after(() => {
        process.chdir(previousCwd);
        process.env.HOME = previous.home;
        process.env.USERPROFILE = previous.profile;
        if (previousCredsDir === undefined) delete process.env.MEMWAL_CREDS_DIR;
        else process.env.MEMWAL_CREDS_DIR = previousCredsDir;
    });
    const hook = await import(`../plugin/scripts/lib/auto-save.mjs?walm642creds=${Date.now()}`);
    assert.equal(hook.hookStatePath(), join(home, ".memwal", "auto-save-state.json"));
    assert.equal(hook.isAutoSaveEnabled(), false);
});
