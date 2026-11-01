/**
 * Automatic saving is ON, once a human has been asked (WALM-642).
 *
 * The thing being governed is narrow and worth naming: saving something the
 * user did not ask to have saved. A direct request ("remember that ...") is not
 * gated, and neither is recall — so these tests check both that the guidance
 * goes quiet when the answer is "off" AND that nothing else goes quiet with it.
 *
 * Three states, and the two unset ones are the interesting half: an install
 * that predates the consent prompt keeps saving (that is its status quo, not a
 * new grant), while one created after it saves nothing until someone answers.
 *
 * Both halves of the opt-in are covered, because they are two separate
 * implementations of the same rule: the TypeScript one the MCP server reads,
 * and the plain-`.mjs` one the plugin hooks read. The hooks are spawned by the
 * client, not by this package, so they cannot share the compiled module and a
 * divergence between the two would be invisible.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { Readable, Writable } from "node:stream";
import { mkdtempSync, mkdirSync, readFileSync, statSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
    autoSaveStatus,
    isAutoSaveEnabled,
    markConsentPending,
    parseBooleanSetting,
    publishHookState,
    setAutoSave,
    settingsPath,
    hookStatePath,
    AUTO_SAVE_ENV,
} from "../dist/auto-save.js";
import {
    askAutoSaveConsent,
    interpretConsentAnswer,
    CONSENT_PROMPT,
} from "../dist/consent.js";
import * as hookAutoSave from "../plugin/scripts/lib/auto-save.mjs";
import { parseArgs, helpText } from "../dist/index.js";
import { TOOL_DEFINITIONS } from "../dist/auth-required.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCRIPTS = resolve(__dirname, "../plugin/scripts");

/** A fresh, empty `.memwal` directory, so no developer's real settings leak in. */
function freshCredsDir() {
    const dir = mkdtempSync(join(tmpdir(), "memwal-autosave-"));
    return dir;
}

/**
 * Write an answer AND publish the resolved state, which is what the server
 * does on every write and every start-up. The hooks read only the published
 * state now (WALM-642), so a test that wrote settings.json alone would be
 * testing a machine whose MCP server had never run.
 */
function writeSettings(dir, value) {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "settings.json"), JSON.stringify(value));
    withEnv({ MEMWAL_CREDS_DIR: dir, [AUTO_SAVE_ENV]: undefined }, () =>
        publishHookState(),
    );
}

/** Run one hook with a controlled environment and return its injected text. */
function runHook(script, input, env) {
    const result = spawnSync(process.execPath, [join(SCRIPTS, script)], {
        input: JSON.stringify(input),
        encoding: "utf8",
        env: { ...process.env, ...env },
    });
    assert.equal(result.status, 0, result.stderr);
    if (!result.stdout.trim()) return "";
    return JSON.parse(result.stdout).hookSpecificOutput?.additionalContext ?? "";
}

/** Run `fn` with env vars set, restoring them afterwards. */
function withEnv(vars, fn) {
    const saved = {};
    for (const [k, v] of Object.entries(vars)) {
        saved[k] = process.env[k];
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
    }
    try {
        return fn();
    } finally {
        for (const [k, v] of Object.entries(saved)) {
            if (v === undefined) delete process.env[k];
            else process.env[k] = v;
        }
    }
}

// ── the resolver ────────────────────────────────────────────────────────────

test("a new install saves nothing until someone answers", () => {
    const dir = freshCredsDir();
    withEnv({ MEMWAL_CREDS_DIR: dir, [AUTO_SAVE_ENV]: undefined }, () => {
        markConsentPending();
        assert.equal(isAutoSaveEnabled(), false);
        assert.deepEqual(autoSaveStatus(), {
            enabled: false,
            state: "unset",
            source: "unanswered",
            pendingConsent: true,
            path: join(dir, "settings.json"),
        });
    });
    rmSync(dir, { recursive: true, force: true });
});

test("an install that predates the prompt keeps saving, and is still asked", () => {
    // No settings file at all, credentials on disk: someone who has been
    // auto-saving since before this setting existed. Switching them off would
    // be a regression dressed up as caution.
    const dir = freshCredsDir();
    withEnv({ MEMWAL_CREDS_DIR: dir, [AUTO_SAVE_ENV]: undefined }, () => {
        writeFileSync(join(dir, "credentials.json"), "{}");
        const status = autoSaveStatus();
        assert.equal(status.enabled, true);
        assert.equal(status.state, "unset");
        assert.equal(status.source, "legacy");
        // Carried over, not granted — so the question is still owed.
        assert.equal(status.pendingConsent, true);
    });
    rmSync(dir, { recursive: true, force: true });
});

test("the pending stamp stops a headless sign-in maturing into consent", () => {
    // Without the stamp, a brand-new install that signs in through the
    // `memwal_login` tool would be indistinguishable from a long-standing user
    // the moment credentials appear, and would start saving with nobody ever
    // having been asked.
    const dir = freshCredsDir();
    withEnv({ MEMWAL_CREDS_DIR: dir, [AUTO_SAVE_ENV]: undefined }, () => {
        markConsentPending();
        writeFileSync(join(dir, "credentials.json"), "{}");
        const status = autoSaveStatus();
        assert.equal(status.enabled, false, "consent by never being asked");
        assert.equal(status.source, "unanswered");
        assert.equal(status.pendingConsent, true);
    });
    rmSync(dir, { recursive: true, force: true });
});

test("an answer is read back, either way, and is never asked for again", () => {
    const dir = freshCredsDir();
    withEnv({ MEMWAL_CREDS_DIR: dir, [AUTO_SAVE_ENV]: undefined }, () => {
        markConsentPending();

        setAutoSave(true);
        assert.equal(isAutoSaveEnabled(), true);
        assert.equal(autoSaveStatus().state, "on");
        assert.equal(autoSaveStatus().source, "settings");
        assert.equal(autoSaveStatus().pendingConsent, false);

        // Declining must cost nothing and must not be nagged at.
        setAutoSave(false);
        assert.equal(isAutoSaveEnabled(), false);
        assert.equal(autoSaveStatus().state, "off");
        assert.equal(
            autoSaveStatus().pendingConsent,
            false,
            "a declined answer must not put the question back",
        );
        // Even with credentials present — the rule that keeps a pre-existing
        // install saving must not resurrect a deliberate "no".
        writeFileSync(join(dir, "credentials.json"), "{}");
        assert.equal(isAutoSaveEnabled(), false);
        assert.equal(autoSaveStatus().pendingConsent, false);
    });
    rmSync(dir, { recursive: true, force: true });
});

test("the settings file is not world-readable and keeps unrelated keys", () => {
    const dir = freshCredsDir();
    withEnv({ MEMWAL_CREDS_DIR: dir, [AUTO_SAVE_ENV]: undefined }, () => {
        writeSettings(dir, { somethingElse: "keep me" });
        setAutoSave(true);
        const path = settingsPath();
        assert.equal(statSync(path).mode & 0o777, 0o600);
        const parsed = JSON.parse(readFileSync(path, "utf8"));
        assert.equal(parsed.somethingElse, "keep me");
        assert.equal(parsed.autoSave, true);
    });
    rmSync(dir, { recursive: true, force: true });
});

test("MEMWAL_AUTO_SAVE can turn saving off, but never on over a declined or unanswered state", () => {
    const dir = freshCredsDir();
    withEnv({ MEMWAL_CREDS_DIR: dir, [AUTO_SAVE_ENV]: undefined }, () => {
        // A project-supplied MEMWAL_AUTO_SAVE=1 must not flip auto-save on over
        // a stored `autoSave: false`, nor report `enabled: true` alongside `state: "off"`.
        setAutoSave(false);
        withEnv({ [AUTO_SAVE_ENV]: "1" }, () => {
            assert.equal(isAutoSaveEnabled(), false);
            assert.deepEqual(autoSaveStatus(), {
                enabled: false,
                state: "off",
                source: "settings",
                pendingConsent: false,
                path: join(dir, "settings.json"),
            });
            assert.equal(hookAutoSave.isAutoSaveEnabled(), false);
            assert.deepEqual(hookAutoSave.autoSaveStatus(), {
                enabled: false,
                state: "off",
                source: "settings",
                pendingConsent: false,
            });
        });

        // Turning automatic saving OFF for one process via MEMWAL_AUTO_SAVE=0 is
        // still honoured and reports a self-consistent `state: "off"`.
        setAutoSave(true);
        withEnv({ [AUTO_SAVE_ENV]: "0" }, () => {
            assert.equal(isAutoSaveEnabled(), false);
            assert.deepEqual(autoSaveStatus(), {
                enabled: false,
                state: "off",
                source: "env",
                pendingConsent: false,
                path: join(dir, "settings.json"),
            });
            assert.equal(hookAutoSave.isAutoSaveEnabled(), false);
            assert.deepEqual(hookAutoSave.autoSaveStatus(), {
                enabled: false,
                state: "off",
                source: "env",
                pendingConsent: false,
            });
        });
    });
    rmSync(dir, { recursive: true, force: true });

    // When no stored answer exists, MEMWAL_AUTO_SAVE=1 cannot grant consent or
    // suppress the prompt (`pendingConsent` remains true).
    const unanswered = freshCredsDir();
    withEnv({ MEMWAL_CREDS_DIR: unanswered, [AUTO_SAVE_ENV]: undefined }, () => {
        markConsentPending();
        withEnv({ [AUTO_SAVE_ENV]: "1" }, () => {
            assert.equal(isAutoSaveEnabled(), false);
            assert.equal(autoSaveStatus().state, "unset");
            assert.equal(autoSaveStatus().source, "unanswered");
            assert.equal(autoSaveStatus().pendingConsent, true);
            assert.equal(hookAutoSave.isAutoSaveEnabled(), false);
            assert.equal(hookAutoSave.autoSaveStatus().pendingConsent, true);
        });
    });
    rmSync(unanswered, { recursive: true, force: true });

    // On a legacy install with no stored answer, MEMWAL_AUTO_SAVE=off disables
    // unprompted saving for this process while keeping `pendingConsent: true`
    // so the user is still asked at their next interactive login.
    const legacy = freshCredsDir();
    withEnv({ MEMWAL_CREDS_DIR: legacy, [AUTO_SAVE_ENV]: undefined }, () => {
        writeFileSync(join(legacy, "credentials.json"), "{}");
        publishHookState();
        withEnv({ [AUTO_SAVE_ENV]: "off" }, () => {
            assert.equal(isAutoSaveEnabled(), false);
            assert.equal(autoSaveStatus().state, "off");
            assert.equal(autoSaveStatus().source, "env");
            assert.equal(autoSaveStatus().pendingConsent, true);
            assert.equal(hookAutoSave.isAutoSaveEnabled(), false);
            assert.equal(hookAutoSave.autoSaveStatus().state, "off");
            assert.equal(hookAutoSave.autoSaveStatus().source, "env");
            assert.equal(hookAutoSave.autoSaveStatus().pendingConsent, true);
        });
    });
    rmSync(legacy, { recursive: true, force: true });
});

test("an unreadable or unparseable value is not consent", () => {
    // Every one of these means "I could not tell", and the safe reading of
    // that is off — not on, and not a crash.
    for (const raw of [undefined, "", "   ", "maybe", "2", "ON!"]) {
        assert.equal(parseBooleanSetting(raw), null, `"${raw}" should be unparseable`);
    }
    assert.equal(parseBooleanSetting("yes"), true);
    assert.equal(parseBooleanSetting(" OFF "), false);

    const dir = freshCredsDir();
    withEnv({ MEMWAL_CREDS_DIR: dir, [AUTO_SAVE_ENV]: undefined }, () => {
        writeFileSync(join(dir, "settings.json"), "{ not json");
        assert.equal(isAutoSaveEnabled(), false);
        assert.equal(autoSaveStatus().state, "unset");
        assert.equal(autoSaveStatus().pendingConsent, true);
    });
    rmSync(dir, { recursive: true, force: true });
});

test("the hook reads the published state rather than resolving anything itself", () => {
    // The two implementations used to be hand-written mirrors and drifted
    // apart, which is how a repo file came to switch automatic memory on
    // (WALM-642). There is one resolver now: this asserts the hook reports what
    // the server published, on every state, and that publishing is what moves
    // it.
    const dir = freshCredsDir();
    withEnv({ MEMWAL_CREDS_DIR: dir, [AUTO_SAVE_ENV]: undefined }, () => {
        assert.equal(hookAutoSave.hookStatePath(), hookStatePath());

        markConsentPending();
        assert.equal(hookAutoSave.isAutoSaveEnabled(), false);
        assert.equal(hookAutoSave.autoSaveStatus().source, "unanswered");

        setAutoSave(true);
        assert.equal(hookAutoSave.isAutoSaveEnabled(), isAutoSaveEnabled());
        assert.equal(hookAutoSave.isAutoSaveEnabled(), true);
        assert.equal(hookAutoSave.autoSaveStatus().source, "settings");
        assert.equal(hookAutoSave.autoSaveStatus().pendingConsent, false);

        withEnv({ [AUTO_SAVE_ENV]: "off" }, () => {
            assert.equal(hookAutoSave.isAutoSaveEnabled(), false);
            assert.equal(hookAutoSave.autoSaveStatus().source, "env");
        });

        // An answer the server has not published yet is not one the hook may
        // act on: it has no way to tell a stale file from a current one, so
        // "cannot tell" has to read as off.
        rmSync(hookStatePath(), { force: true });
        assert.equal(hookAutoSave.isAutoSaveEnabled(), false);
        assert.equal(hookAutoSave.autoSaveStatus().source, "unavailable");
        assert.equal(hookAutoSave.autoSaveStatus().pendingConsent, true);
        assert.equal(isAutoSaveEnabled(), true, "the server's own answer is unchanged");
    });
    rmSync(dir, { recursive: true, force: true });
});

test("a published state this build does not understand fails safe", () => {
    const dir = freshCredsDir();
    withEnv({ MEMWAL_CREDS_DIR: dir, [AUTO_SAVE_ENV]: undefined }, () => {
        setAutoSave(true);
        assert.equal(hookAutoSave.isAutoSaveEnabled(), true);
        for (const corrupt of [
            "{ not json",
            JSON.stringify({ version: 99, enabled: true }),
            JSON.stringify({ version: 1, enabled: "yes" }),
            JSON.stringify({ version: 1, enabled: true, state: "off" }),
            JSON.stringify({ version: 1, enabled: false, state: "on" }),
            JSON.stringify({ version: 1 }),
            "null",
        ]) {
            writeFileSync(hookStatePath(), corrupt);
            assert.equal(
                hookAutoSave.isAutoSaveEnabled(),
                false,
                `treated as consent: ${corrupt}`,
            );
            assert.equal(hookAutoSave.autoSaveStatus().source, "unavailable");
        }
    });
    rmSync(dir, { recursive: true, force: true });
});

// ── the hooks ───────────────────────────────────────────────────────────────

test("SessionStart goes quiet about saving when the user answered no", () => {
    const dir = freshCredsDir();
    writeSettings(dir, { autoSave: false });
    const off = runHook("on_session_start.mjs", {}, { MEMWAL_CREDS_DIR: dir });

    assert.match(off, /Automatic memory is OFF/);
    assert.match(off, /Save ONLY what the user asks you to save/);
    // The unprompted-save instruction is the thing that must be gone.
    assert.doesNotMatch(off, /do not ask whether to save it/i);
    // ...and the things that must NOT be gone with it.
    assert.match(off, /memwal_recall/);
    assert.match(off, /memwal_restore/);
    assert.match(off, /auto-save on/);

    writeSettings(dir, { autoSave: true });
    const on = runHook("on_session_start.mjs", {}, { MEMWAL_CREDS_DIR: dir });
    assert.match(on, /Automatic memory is ON/);
    assert.match(on, /do not ask whether to save it/i);

    // The rules ride on both.
    for (const text of [off, on]) {
        assert.match(text, /NEVER save a credential/);
    }
    rmSync(dir, { recursive: true, force: true });
});

test("UserPromptSubmit injects a save-nothing rubric when the user answered no", () => {
    const dir = freshCredsDir();
    writeSettings(dir, { autoSave: false });
    const prompt = "I always use pnpm and my staging canary is coral-fox-77.";

    const off = runHook(
        "on_user_prompt.mjs",
        { prompt, session_id: `off-${Math.random().toString(16).slice(2)}` },
        { MEMWAL_CREDS_DIR: dir },
    );
    assert.match(off, /Automatic saving is OFF/);
    assert.match(off, /save ONLY what they ask you to save/);
    assert.doesNotMatch(off, /call memwal_remember \(or memwal_remember_bulk for several\)/);
    // Recall stays on: it reads, it does not write.
    assert.match(off, /call memwal_recall first/);
    assert.match(off, /NEVER save a credential/);

    writeSettings(dir, { autoSave: true });
    const on = runHook(
        "on_user_prompt.mjs",
        { prompt, session_id: `on-${Math.random().toString(16).slice(2)}` },
        { MEMWAL_CREDS_DIR: dir },
    );
    assert.match(on, /call memwal_remember \(or memwal_remember_bulk for several\)/);
    assert.match(on, /NEVER save a credential/);
    rmSync(dir, { recursive: true, force: true });
});

test("PostToolUse stops nudging a save after an error when the user answered no", () => {
    const dir = freshCredsDir();
    writeSettings(dir, { autoSave: false });
    // Must trip `detectError` in lib/signals.mjs (a strong marker) and clear
    // the hook's 50-character minimum, or the hook stays silent for reasons
    // that have nothing to do with the opt-in.
    const errorOutput =
        "fatal: could not read from remote repository — please make sure you " +
        "have the correct access rights and the repository exists.";
    const input = { tool_name: "Bash", tool_response: { stdout: "", stderr: errorOutput } };

    const off = runHook("on_post_tool.mjs", input, { MEMWAL_CREDS_DIR: dir });
    assert.match(off, /memwal_recall/);
    assert.match(off, /Automatic saving is OFF/);
    assert.doesNotMatch(off, /save the fix with memwal_remember/);

    writeSettings(dir, { autoSave: true });
    const on = runHook("on_post_tool.mjs", input, { MEMWAL_CREDS_DIR: dir });
    assert.match(on, /save the fix with memwal_remember/);
    // Error output is where a credential most often is; say so at the nudge.
    assert.match(on, /Never save passwords, keys, tokens/);
    rmSync(dir, { recursive: true, force: true });
});

test("a hook with saving off still exits 0 and never blocks the session", () => {
    const dir = freshCredsDir();
    writeSettings(dir, { autoSave: false });
    for (const script of ["on_session_start.mjs", "on_user_prompt.mjs", "on_post_tool.mjs"]) {
        const result = spawnSync(process.execPath, [join(SCRIPTS, script)], {
            input: JSON.stringify({ prompt: "a reasonably long prompt about pnpm" }),
            encoding: "utf8",
            env: { ...process.env, MEMWAL_CREDS_DIR: dir },
        });
        assert.equal(result.status, 0, `${script}: ${result.stderr}`);
    }
    rmSync(dir, { recursive: true, force: true });
});

// ── the surface a user actually turns it on from ────────────────────────────

// ── the consent question ────────────────────────────────────────────────────

test("the prompt names the consequence, leads with permanence, and hedges the redaction", () => {
    // These are the three wording rules the change exists for, so they are
    // asserted rather than left to a reviewer's memory.
    assert.match(CONSENT_PROMPT, /writes it to your memory without asking each time/);
    assert.match(CONSENT_PROMPT, /Saved memories are permanent/);
    assert.match(CONSENT_PROMPT, /immutable/);
    assert.match(CONSENT_PROMPT, /cannot\s+delete one that is already saved/);
    assert.match(CONSENT_PROMPT, /safety net, not a\s+guarantee/);
    // Permanence comes first among the bullets — it is the fact that changes
    // the answer.
    const bullets = CONSENT_PROMPT.split("\n").filter((l) => l.trim().startsWith("- "));
    assert.equal(bullets.length, 3);
    assert.match(bullets[0], /permanent/);
    // Both options are offered plainly; declining is not dressed as a warning.
    assert.match(CONSENT_PROMPT, /\[1\] Save automatically/);
    assert.match(CONSENT_PROMPT, /\[2\] Only save when I ask/);
    assert.match(CONSENT_PROMPT, /auto-save on\|off/);
});

test("Enter takes option 1, and anything unrecognised re-asks rather than assuming", () => {
    assert.equal(interpretConsentAnswer(""), true);
    assert.equal(interpretConsentAnswer("  "), true);
    assert.equal(interpretConsentAnswer("1"), true);
    assert.equal(interpretConsentAnswer("2"), false);
    // A typo is not an answer to a question about permanent storage.
    for (const raw of ["y", "n", "3", "yes", "maybe", "11"]) {
        assert.equal(interpretConsentAnswer(raw), null, `"${raw}" must re-ask`);
    }
});

/** Drive the prompt with scripted lines and collect what it wrote. */
async function runPrompt(lines, { isTTY = true } = {}) {
    const written = [];
    const input = Readable.from(lines.map((l) => `${l}\n`));
    const output = new Writable({
        write(chunk, _enc, cb) {
            written.push(chunk.toString());
            cb();
        },
    });
    const answer = await askAutoSaveConsent({ input, output, isTTY });
    return { answer, output: written.join("") };
}

test("an answer is taken from the terminal, and a bad one is re-asked", async () => {
    assert.equal((await runPrompt(["1"])).answer, true);
    assert.equal((await runPrompt([""])).answer, true);
    assert.equal((await runPrompt(["2"])).answer, false);

    const retried = await runPrompt(["banana", "2"]);
    assert.equal(retried.answer, false);
    assert.match(retried.output, /Please answer 1 or 2/);
    // The question is put again, not assumed away.
    assert.equal(retried.output.split("Your choice").length - 1, 2);
});

test("a closed stream is not an answer, and does not hang", async () => {
    // Ctrl-D, a killed terminal, a closed pipe. Recording a choice here would
    // be recording one the user never made.
    const { answer } = await runPrompt([]);
    assert.equal(answer, null);
});

test("the prompt refuses to run without a TTY", async () => {
    // Belt and braces with main()'s own check: a prompt with nobody in front of
    // it is a hang, and this one would hang an MCP server's startup.
    const { answer, output } = await runPrompt(["1"], { isTTY: false });
    assert.equal(answer, null);
    assert.equal(output, "", "nothing may be written to a non-interactive stream");
});

test("`auto-save` parses as a subcommand, and a bare one only reports", () => {
    // A bare `auto-save` must not be read as consent to turn it ON — the
    // difference between reporting a setting and changing one.
    assert.equal(parseArgs(["auto-save"]).autoSave, "status");
    assert.equal(parseArgs(["auto-save", "on"]).autoSave, "on");
    assert.equal(parseArgs(["auto-save", "off"]).autoSave, "off");
    assert.equal(parseArgs(["auto-save", "status"]).autoSave, "status");
    assert.equal(parseArgs(["--auto-save", "on"]).autoSave, "on");

    // Not a flag, so it must not be reported as an unrecognised one.
    assert.deepEqual(parseArgs(["auto-save", "on"]).unknown, []);
    // ...and it must not collide with the other subcommand.
    assert.equal(parseArgs(["login"]).autoSave, undefined);
    assert.equal(parseArgs(["auto-save", "on"]).forceLogin, false);
});

test("a typo'd flag does not swallow the subcommand or its value", () => {
    // `--typo` consumes one following token as its value — unless that token
    // is a command. Without the exemption `memwal-mcp --typo auto-save on`
    // would silently run the server instead.
    const parsed = parseArgs(["--typo", "auto-save", "on"]);
    assert.deepEqual(parsed.unknown, ["--typo"]);
    assert.equal(parsed.autoSave, "on");
});

test("--help tells the user the setting exists and that login asks for it", () => {
    // The plugin install path never shows a terminal, so --help and the
    // post-login summary are where the choice reaches a person.
    const help = helpText();
    assert.match(help, /auto-save on\|off/);
    assert.match(help, /login` asks/);
    assert.match(help, /nothing is saved unprompted until you/);
    assert.match(help, /MEMWAL_AUTO_SAVE/);
    // Permanence is stated here too — it is the fact that changes the answer.
    assert.match(help, /permanent/);
    // And that credentials are stripped regardless of which way it is set.
    assert.match(help, /Credentials/);
    assert.match(help, /not a guarantee/);
});

// ── the non-interactive path ────────────────────────────────────────────────

test("a non-TTY run never prompts, never hangs, and says where things stand", () => {
    // Every MCP client spawn lands here. The failure this guards against is not
    // a wrong answer, it is a server that never finishes starting because
    // something is waiting on a stdin no human is attached to.
    const dir = freshCredsDir();
    const result = spawnSync(
        process.execPath,
        [resolve(__dirname, "../dist/bin/memwal-mcp.js"), "auto-save"],
        {
            // Piped, not inherited: `process.stdin.isTTY` is undefined here,
            // exactly as it is under an MCP client.
            input: "",
            encoding: "utf8",
            timeout: 10_000,
            env: { ...process.env, MEMWAL_CREDS_DIR: dir },
        },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.notEqual(result.signal, "SIGTERM", "the process hung waiting on stdin");
    // Reports, does not ask.
    assert.doesNotMatch(result.stderr, /Your choice/);
    assert.doesNotMatch(result.stderr, /Save automatically/);
    assert.match(result.stderr, /Automatic memory: (ON|OFF)/);
    rmSync(dir, { recursive: true, force: true });
});

test("consent is not reachable from anything the model can call", () => {
    // The single most important constraint in this change: a model answering
    // on the user's behalf is not consent. The question lives in consent.ts,
    // is called only from main() behind `process.stdin.isTTY`, and must never
    // appear in a tool list, a tool description or the instructions.
    const toolSurfaces = [
        readFileSync(resolve(__dirname, "../dist/auth-required.js"), "utf8"),
        readFileSync(resolve(__dirname, "../dist/instructions.js"), "utf8"),
        readFileSync(resolve(__dirname, "../dist/bridge.js"), "utf8"),
    ].join("\n");
    assert.doesNotMatch(toolSurfaces, /askAutoSaveConsent/);
    assert.doesNotMatch(toolSurfaces, /CONSENT_PROMPT/);
    assert.doesNotMatch(toolSurfaces, /Your choice \[1\/2\]/);

    // And no tool is named for it.
    const names = TOOL_DEFINITIONS.map((t) => t.name);
    assert.ok(!names.some((n) => /consent|auto_?save/i.test(n)), names.join(", "));
});
