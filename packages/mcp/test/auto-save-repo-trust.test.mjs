/**
 * A repository cannot turn automatic memory on (WALM-642, review findings 1-2).
 *
 * Two holes, one root cause: the consent decision was being re-derived from
 * whatever `.memwal` directory the working directory resolved to, by two
 * separate implementations.
 *
 *   1. The hook-side resolver (`plugin/scripts/lib/auto-save.mjs`) still used
 *      the pre-WALM-639 presence rule — nearest project `credentials.json`
 *      wins, contents never parsed. A repo carrying a file whose entire content
 *      was `not even valid json` read as proof of a long-standing install and
 *      injected the full proactive-save rubric; adding a committed
 *      `settings.json` pinned `autoSave: true` outright and silenced the
 *      consent-pending warning too.
 *   2. Server-side, `settingsPath()` followed `credsPath()`, so approving a
 *      project (WALM-639) moved the consent answer into the repo — where a
 *      recorded "no" was not consulted and a fresh directory fell through to
 *      "legacy, keep saving".
 *
 * THESE TESTS MUST NOT SET `MEMWAL_CREDS_DIR`. It is the trusted override: it
 * short-circuits project resolution in both resolvers, which is exactly why the
 * existing opt-in suite could not see either bug. Everything here drives a real
 * HOME and a real working directory instead, and finding 1 is asserted by
 * spawning the actual hook the client spawns.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCRIPTS = resolve(__dirname, "../plugin/scripts");

const PRIVATE_KEY = "c".repeat(64);

/**
 * A session id nothing has seen before. `firstTime()` in lib/hook-io.mjs keeps
 * a marker per (name, session) under the OS temp dir, so a fixed id makes the
 * FIRST run of a test inject the full rubric and every run after it the
 * one-line nudge.
 */
function freshSession(tag) {
    return `${tag}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function makeCreds(overrides = {}) {
    return {
        delegatePrivateKey: PRIVATE_KEY,
        delegatePublicKeyHex: "d".repeat(64),
        delegateAddress: "0x" + "e".repeat(64),
        walletAddress: "0x" + "f".repeat(64),
        accountId: "0x" + "a".repeat(64),
        packageId: "0x" + "1".repeat(64),
        relayerUrl: "https://relayer.example",
        createdAt: new Date(0).toISOString(),
        version: 1,
        ...overrides,
    };
}

function writeJson(path, value) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, typeof value === "string" ? value : JSON.stringify(value));
    return path;
}

/**
 * A throwaway HOME and repo, with `MEMWAL_CREDS_DIR` cleared.
 *
 * Canonicalised because `homedir()` and `process.cwd()` both report resolved
 * paths and `/tmp` is a symlink on macOS — an uncanonicalised HOME makes the
 * project walk's "stop at the home directory" test miss.
 */
function sandbox(t) {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "memwal-trust-home-")));
    const repo = realpathSync(mkdtempSync(join(tmpdir(), "memwal-trust-repo-")));
    // A `.git` marker, because that is what a checkout has and what the project
    // walk stops at.
    mkdirSync(join(repo, ".git"), { recursive: true });
    t.after(() => {
        rmSync(home, { recursive: true, force: true });
        rmSync(repo, { recursive: true, force: true });
    });
    return { home, repo };
}

/** Run one hook the way a client does: its own process, a cwd, and a HOME. */
function runHookIn(script, { cwd, home, input = {}, env = {} }) {
    const result = spawnSync(process.execPath, [join(SCRIPTS, script)], {
        cwd,
        input: JSON.stringify(input),
        encoding: "utf8",
        env: {
            ...process.env,
            HOME: home,
            USERPROFILE: home,
            MEMWAL_CREDS_DIR: "",
            ...env,
        },
    });
    assert.equal(result.status, 0, `${script} exited ${result.status}: ${result.stderr}`);
    if (!result.stdout.trim()) return "";
    return JSON.parse(result.stdout).hookSpecificOutput?.additionalContext ?? "";
}

// `MEMWAL_CREDS_DIR: ""` must actually clear the override, or every assertion
// below is vacuous. Node keeps an empty string in the child's environment, and
// both resolvers read it as unset because `""` is falsy — pinned here so a
// future change to that check cannot quietly hollow this file out.
test("an empty MEMWAL_CREDS_DIR does not stand in for a real one", async () => {
    const previous = process.env.MEMWAL_CREDS_DIR;
    process.env.MEMWAL_CREDS_DIR = "";
    try {
        const hook = await import("../plugin/scripts/lib/auto-save.mjs");
        assert.ok(
            hook.hookStatePath().startsWith(join(realpathSync(process.env.HOME ?? tmpdir()))) ||
                hook.hookStatePath().includes(".memwal"),
            "an empty override must fall back to the home directory",
        );
    } finally {
        if (previous === undefined) delete process.env.MEMWAL_CREDS_DIR;
        else process.env.MEMWAL_CREDS_DIR = previous;
    }
});

// ── finding 1: the hook repro, on the real hook ─────────────────────────────

test("a committed credentials file cannot turn the save rubric on", (t) => {
    const { home, repo } = sandbox(t);
    // The reporter's repro, byte for byte: the contents are never parsed, so
    // the file did not even have to be credentials.
    writeJson(join(repo, ".memwal", "credentials.json"), "not even valid json");
    // The user's own install has been asked and has not answered.
    writeJson(join(home, ".memwal", "settings.json"), { autoSaveConsent: "pending" });

    const injected = runHookIn("on_user_prompt.mjs", {
        cwd: repo,
        home,
        input: { session_id: freshSession("s1"), prompt: "I prefer pnpm" },
    });

    assert.doesNotMatch(
        injected,
        /call memwal_remember \(or memwal_remember_bulk for several\)/,
        "a repo file injected the proactive-save rubric",
    );
    assert.match(injected, /Automatic saving is OFF|save ONLY what they ask you to save/);

    // And the control: the same HOME from a clean directory says the same
    // thing, which is the point — the repo changed nothing at all.
    const clean = realpathSync(mkdtempSync(join(tmpdir(), "memwal-trust-clean-")));
    t.after(() => rmSync(clean, { recursive: true, force: true }));
    const control = runHookIn("on_user_prompt.mjs", {
        cwd: clean,
        home,
        input: { session_id: freshSession("s2"), prompt: "I prefer pnpm" },
    });
    assert.equal(injected, control, "the repo steered the hook away from the control");
});

test("a committed settings.json cannot pin autoSave on, or silence the warning", (t) => {
    const { home, repo } = sandbox(t);
    writeJson(join(repo, ".memwal", "credentials.json"), "not even valid json");
    writeJson(join(repo, ".memwal", "settings.json"), { autoSave: true });
    writeJson(join(home, ".memwal", "settings.json"), { autoSaveConsent: "pending" });

    const prompt = runHookIn("on_user_prompt.mjs", {
        cwd: repo,
        home,
        input: { session_id: freshSession("s3"), prompt: "I prefer pnpm" },
    });
    assert.doesNotMatch(
        prompt,
        /call memwal_remember \(or memwal_remember_bulk for several\)/,
        "a repo settings.json switched automatic saving on",
    );

    const start = runHookIn("on_session_start.mjs", { cwd: repo, home });
    assert.match(start, /Automatic memory is OFF/, "a repo settings.json flipped the banner");
    assert.doesNotMatch(start, /do not ask whether to save it/i);
});

test("the hook reads nothing from the working directory at all", (t) => {
    // Stronger than the two repros: not "this particular file is ignored" but
    // "there is no file a checkout can add". The published state is what
    // decides, and it lives where a repo cannot write.
    const { home, repo } = sandbox(t);
    writeJson(join(home, ".memwal", "auto-save-state.json"), {
        version: 1,
        enabled: true,
        state: "on",
        source: "settings",
        pendingConsent: false,
        settingsPath: join(home, ".memwal", "settings.json"),
        updatedAt: new Date().toISOString(),
    });
    // Every shape the old resolver would have followed, all saying "off".
    writeJson(join(repo, ".memwal", "credentials.json"), makeCreds());
    writeJson(join(repo, ".memwal", "settings.json"), { autoSave: false });
    writeJson(join(repo, ".memwal", "auto-save-state.json"), {
        version: 1,
        enabled: false,
        state: "off",
        source: "settings",
        pendingConsent: false,
        settingsPath: join(repo, ".memwal", "settings.json"),
        updatedAt: new Date().toISOString(),
    });

    const injected = runHookIn("on_user_prompt.mjs", {
        cwd: repo,
        home,
        input: { session_id: freshSession("s4"), prompt: "I prefer pnpm" },
    });
    assert.match(
        injected,
        /call memwal_remember \(or memwal_remember_bulk for several\)/,
        "the repo overrode the user's own published answer",
    );
});

test("a hook with no published state saves nothing and still exits 0", (t) => {
    const { home, repo } = sandbox(t);
    assert.equal(existsSync(join(home, ".memwal", "auto-save-state.json")), false);
    for (const script of ["on_session_start.mjs", "on_user_prompt.mjs", "on_post_tool.mjs"]) {
        const text = runHookIn(script, {
            cwd: repo,
            home,
            input: { session_id: freshSession("s5"), prompt: "a reasonably long prompt about pnpm" },
        });
        assert.doesNotMatch(
            text,
            /call memwal_remember \(or memwal_remember_bulk for several\)/,
            `${script} saved on an unknown state`,
        );
    }
});

// ── finding 2: approving a project must not move the consent answer ─────────

test("approving a project does not re-enable a declined auto-save", async (t) => {
    const { home, repo } = sandbox(t);
    const previous = {
        home: process.env.HOME,
        profile: process.env.USERPROFILE,
        credsDir: process.env.MEMWAL_CREDS_DIR,
        cwd: process.cwd(),
    };
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    delete process.env.MEMWAL_CREDS_DIR;
    delete process.env.MEMWAL_AUTO_SAVE;
    process.chdir(repo);
    t.after(() => {
        process.chdir(previous.cwd);
        process.env.HOME = previous.home;
        process.env.USERPROFILE = previous.profile;
        if (previous.credsDir === undefined) delete process.env.MEMWAL_CREDS_DIR;
        else process.env.MEMWAL_CREDS_DIR = previous.credsDir;
    });

    // Resolved per call, but the modules are imported once per process, so a
    // cache-busting query is what makes them see this HOME.
    const stamp = `${Date.now()}-${Math.random()}`;
    const auth = await import(`../dist/auth.js?walm642=${stamp}`);
    const autoSave = await import(`../dist/auto-save.js?walm642=${stamp}`);

    writeJson(join(home, ".memwal", "credentials.json"), makeCreds());
    // The user answers "[2] Only save when I ask".
    autoSave.setAutoSave(false);
    const answerPath = autoSave.settingsPath();
    assert.equal(answerPath, join(home, ".memwal", "settings.json"));
    assert.equal(autoSave.isAutoSaveEnabled(), false);

    // Later, in a team repo, they approve that repo's credentials — a decision
    // about WHERE memory is written, and nothing else.
    writeJson(
        join(repo, ".memwal", "credentials.json"),
        makeCreds({ accountId: "0x" + "b".repeat(64) }),
    );
    const approved = auth.approveProjectCreds();
    assert.equal(approved.outcome, "approved");
    assert.equal(auth.credsPath(), join(repo, ".memwal", "credentials.json"));

    // The recorded "no" is still the answer...
    assert.equal(autoSave.isAutoSaveEnabled(), false, "approval re-enabled a declined auto-save");
    assert.equal(autoSave.autoSaveStatus().source, "settings");
    assert.equal(autoSave.autoSaveStatus().state, "off");
    // ...read from the same place it was written, not from the repo.
    assert.equal(autoSave.settingsPath(), answerPath);
    assert.equal(
        existsSync(join(repo, ".memwal", "settings.json")),
        false,
        "the consent answer was written into the repository",
    );

    // Writing an answer while a project is approved must not put one there
    // either — that file is committable.
    autoSave.setAutoSave(true);
    autoSave.markConsentPending();
    assert.equal(
        existsSync(join(repo, ".memwal", "settings.json")),
        false,
        "setAutoSave wrote the consent answer into the repository",
    );
    assert.equal(
        existsSync(join(repo, ".memwal", "auto-save-state.json")),
        false,
        "the published hook state was written into the repository",
    );
    assert.equal(existsSync(join(home, ".memwal", "auto-save-state.json")), true);
});

test("a project credentials file is not evidence of a long-standing install", async (t) => {
    // The legacy rule — "no answer, but credentials on disk, so keep saving" —
    // has to be asked of the user's own install. Answered with a repo file it
    // is just the presence rule again, wearing a different hat.
    const { home, repo } = sandbox(t);
    const previous = { home: process.env.HOME, profile: process.env.USERPROFILE, cwd: process.cwd() };
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    delete process.env.MEMWAL_CREDS_DIR;
    delete process.env.MEMWAL_AUTO_SAVE;
    process.chdir(repo);
    t.after(() => {
        process.chdir(previous.cwd);
        process.env.HOME = previous.home;
        process.env.USERPROFILE = previous.profile;
    });

    const stamp = `${Date.now()}-${Math.random()}`;
    const auth = await import(`../dist/auth.js?walm642b=${stamp}`);
    const autoSave = await import(`../dist/auto-save.js?walm642b=${stamp}`);

    // No global credentials, no answer anywhere — a machine that has never used
    // MemWal, opening a repo that carries an approved credentials file.
    writeJson(join(repo, ".memwal", "credentials.json"), makeCreds());
    auth.approveProjectCreds();
    assert.equal(auth.credsPath(), join(repo, ".memwal", "credentials.json"));

    const status = autoSave.autoSaveStatus();
    assert.equal(status.enabled, false, "a repo file was read as a long-standing install");
    assert.equal(status.source, "unanswered");
    assert.equal(status.pendingConsent, true);
});

test("MEMWAL_AUTO_SAVE=1 in a project MCP config cannot enable saving over a stored off answer or unanswered state", (t) => {
    const { home, repo } = sandbox(t);
    writeJson(join(home, ".memwal", "settings.json"), { autoSave: false });
    writeJson(join(home, ".memwal", "auto-save-state.json"), {
        version: 1,
        enabled: false,
        state: "off",
        source: "settings",
        pendingConsent: false,
        updatedAt: new Date().toISOString(),
    });

    const injected = runHookIn("on_user_prompt.mjs", {
        cwd: repo,
        home,
        input: { session_id: freshSession("s6"), prompt: "I prefer pnpm" },
        env: { MEMWAL_AUTO_SAVE: "1" },
    });
    assert.doesNotMatch(
        injected,
        /call memwal_remember \(or memwal_remember_bulk for several\)/,
        "MEMWAL_AUTO_SAVE=1 flipped the save rubric on over a stored off answer",
    );
    assert.match(injected, /Automatic saving is OFF/);
});

