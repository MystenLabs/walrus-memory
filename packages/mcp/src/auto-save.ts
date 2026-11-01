/**
 * Automatic-save consent (WALM-642).
 *
 * Saving a fact the user explicitly asked for has never needed permission and
 * still does not. What this module governs is the other thing the package does:
 * saving what it judges durable, without being asked. That is what MemWal is
 * for — so it is ON — but a person has to have been told what it means first.
 *
 * ── Three states, not two ───────────────────────────────────────────────────
 * `off` and `on` are answers. `unset` is the absence of one, and it is not the
 * same as `off`:
 *
 *   - **Answered** (`autoSave: true|false` in settings.json) — from the login
 *     prompt or from `memwal-mcp auto-save on|off`. Nothing re-asks.
 *   - **Unset on an install that predates this change** — no settings file at
 *     all, but credentials on disk. These users have been auto-saving all
 *     along; switching them off would be a regression dressed up as caution, so
 *     saving CONTINUES and the question is put to them at their next
 *     interactive login.
 *   - **Unset on a new install** (`autoSaveConsent: "pending"`, stamped the
 *     moment a post-change install first appears) — nobody has been asked, so
 *     nothing is saved unprompted until someone answers. Explicit tool calls
 *     and recall keep working the whole time.
 *
 * The stamp is what separates the last two. Without it a headless install could
 * sign in through the `memwal_login` tool, look indistinguishable from a
 * long-standing user, and start saving on its own — consent by never having
 * been asked.
 *
 * ── Where the answer lives: the trusted state dir, and nowhere else ─────────
 * The answer is a decision about the HUMAN, not about a credentials directory.
 * It used to be stored beside whichever `credentials.json` won resolution,
 * which had two consequences, both wrong:
 *
 *   1. Approving a project's credentials (WALM-639) moved `settingsPath()`
 *      into the repository. A user who had already answered "off" globally got
 *      a directory with no answer in it, fell through to the legacy
 *      "credentials exist, so keep saving" rule, and had automatic memory
 *      switched back ON by an approval that was only ever about where writes
 *      go. The recorded "no" was never consulted there.
 *   2. `setAutoSave` / `markConsentPending` then wrote the consent answer INTO
 *      the repository, where it could be committed and shipped to everyone
 *      else who cloned it.
 *
 * So consent now lives in the trusted state dir — `MEMWAL_CREDS_DIR` when it is
 * set, else `~/.memwal` — the same directory auth.ts keeps the project-approval
 * store in, and for the same reason: a record a repository can write is a
 * repository approving itself. Project scoping of CREDENTIALS is unchanged;
 * project scoping of CONSENT is gone.
 *
 * The legacy probe reads the trusted directory's own `credentials.json` for the
 * same reason. "Has this person used MemWal before" must not be answerable by a
 * file inside a checkout.
 *
 * ── How the hooks see it ───────────────────────────────────────────────────
 * The plugin's hooks are separate processes: a hook is spawned by the client,
 * not by this package, and inherits none of the MCP server's `env` or argv. The
 * hooks used to re-derive the whole resolution in plain ESM, and the two
 * implementations drifted — the hook side kept the pre-WALM-639 presence rule,
 * so a committed `.memwal/credentials.json` (contents never parsed, only
 * `existsSync`) turned automatic memory on for anyone who opened the repo.
 *
 * Re-deriving is the bug, so the hooks no longer do it. This module publishes
 * the RESOLVED state to `auto-save-state.json` in the trusted state dir, and
 * the hooks read only that. A repository cannot write there, the hooks do no
 * resolution of their own, and a hook that cannot read the file fails safe
 * (automatic memory off). See `plugin/scripts/lib/auto-save.mjs`.
 */
import { dirname, join } from "node:path";
import {
    chmodSync,
    existsSync,
    mkdirSync,
    readFileSync,
    writeFileSync,
} from "node:fs";
import { projectApprovalsPath } from "./auth.js";
import { log } from "./logger.js";

/** Env var that pins automatic saving off for one MCP server process. */
export const AUTO_SAVE_ENV = "MEMWAL_AUTO_SAVE";

const SETTINGS_FILE = "settings.json";
const CREDS_FILE = "credentials.json";
/** Resolved state the plugin hooks read. Never written inside a repository. */
const HOOK_STATE_FILE = "auto-save-state.json";
/** Bumped if the hook-facing shape ever changes incompatibly. */
const HOOK_STATE_VERSION = 1;

/**
 * Where records a repository must not be able to write are kept:
 * `MEMWAL_CREDS_DIR` when set, else `~/.memwal`.
 *
 * Derived from `projectApprovalsPath()` rather than recomputed, so this file
 * and auth.ts cannot drift apart the way the hook copy did. auth.ts owns the
 * definition; this reads it back.
 */
function trustedStateDir(): string {
    return dirname(projectApprovalsPath());
}

/** Where the answer is stored. Outside every repository, on purpose. */
export function settingsPath(): string {
    return join(trustedStateDir(), SETTINGS_FILE);
}

/** Where the resolved state is published for the plugin hooks to read. */
export function hookStatePath(): string {
    return join(trustedStateDir(), HOOK_STATE_FILE);
}

/** Shape of `settings.json`. Unknown keys are preserved on write. */
interface MemWalSettings {
    /** Present only once the question has actually been answered. */
    autoSave?: boolean;
    /** `"pending"` marks an install created after WALM-642 with no answer yet. */
    autoSaveConsent?: string;
    [key: string]: unknown;
}

/**
 * Parse a human-written boolean. Returns null for "not set" and for anything
 * unparseable — an unreadable value must not be read as an answer.
 */
export function parseBooleanSetting(raw: string | undefined | null): boolean | null {
    if (raw === undefined || raw === null) return null;
    const v = raw.trim().toLowerCase();
    if (v === "") return null;
    if (["1", "true", "on", "yes", "y", "enable", "enabled"].includes(v)) return true;
    if (["0", "false", "off", "no", "n", "disable", "disabled"].includes(v)) return false;
    return null;
}

function readSettings(): MemWalSettings {
    const path = settingsPath();
    if (!existsSync(path)) return {};
    try {
        const parsed = JSON.parse(readFileSync(path, "utf8"));
        return parsed && typeof parsed === "object" ? (parsed as MemWalSettings) : {};
    } catch {
        // A corrupt settings file is not an answer. Fall through to unset.
        return {};
    }
}

function writeSettings(next: MemWalSettings): string {
    const path = settingsPath();
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    writeFileSync(path, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600 });
    // `writeFileSync`'s `mode` follows POSIX `open()`: the kernel applies it
    // when it CREATES the inode and ignores it for one that already exists, so
    // a file left permissive by anything else would keep its old mode forever.
    // Unlike credentials.json (see `writeSecretFile` in auth.ts) there is no
    // secret in flight here, so tightening afterwards is enough — no reader can
    // learn anything from the window, only whether the flag is set.
    chmodSync(path, 0o600);
    return path;
}

/** `on`/`off` are answers; `unset` means nobody has been asked yet. */
export type AutoSaveState = "on" | "off" | "unset";

export type AutoSaveSource =
    /** `MEMWAL_AUTO_SAVE=0` in this process's environment. */
    | "env"
    /** An answer written to settings.json. */
    | "settings"
    /** Unset, on an install that predates the consent prompt — keeps saving. */
    | "legacy"
    /** Unset, on an install created after it — saves nothing until answered. */
    | "unanswered";

export interface AutoSaveStatus {
    /** Whether this process may save without being asked. */
    enabled: boolean;
    /** The stored answer, or `unset`. */
    state: AutoSaveState;
    source: AutoSaveSource;
    /** True while the question is still owed a human answer. */
    pendingConsent: boolean;
    /** Where an answer lives (or would be written). */
    path: string;
}

/**
 * Resolve the current state: a disabling `MEMWAL_AUTO_SAVE` override, then the
 * stored answer, then the unset rules above.
 */
export function autoSaveStatus(): AutoSaveStatus {
    const path = settingsPath();
    const settings = readSettings();
    const answered =
        typeof settings.autoSave === "boolean" ? settings.autoSave : null;
    const state: AutoSaveState =
        answered === null ? "unset" : answered ? "on" : "off";

    const fromEnv = parseBooleanSetting(process.env[AUTO_SAVE_ENV]);
    if (fromEnv === false) {
        // Turning automatic saving OFF for this process is always safe.
        // Turning it ON from `process.env` is refused for the same reason
        // `credsDirOverride()` refuses a project path: an MCP client reads
        // `.cursor/mcp.json`, `.vscode/mcp.json`, or `.claude/settings.json`
        // out of the checkout and passes its `env` block here, so a truthy
        // `MEMWAL_AUTO_SAVE` cannot be distinguished from a repository
        // granting itself consent or overriding a stored `autoSave: false`.
        // If no stored answer exists yet, `pendingConsent` stays true so
        // interactive `login` still prompts.
        return {
            enabled: false,
            state: "off",
            source: "env",
            pendingConsent: answered === null,
            path,
        };
    }

    if (answered !== null) {
        return { enabled: answered, state, source: "settings", pendingConsent: false, path };
    }

    // Unset. Which way it falls depends on whether this install was ever in a
    // position to have been asked — see the module comment. The probe is the
    // TRUSTED directory's credentials file, never a project one: "has this
    // person used MemWal before" must not be answerable by a checkout.
    const stamped = settings.autoSaveConsent === "pending";
    const preExisting = !stamped && existsSync(join(trustedStateDir(), CREDS_FILE));
    return {
        enabled: preExisting,
        state: "unset",
        source: preExisting ? "legacy" : "unanswered",
        pendingConsent: true,
        path,
    };
}

/**
 * True when this process may save without being asked.
 *
 * Read at call time, never cached: the answer can be written between calls in
 * the same process.
 */
export function isAutoSaveEnabled(): boolean {
    return autoSaveStatus().enabled;
}

/** True while a human still owes the consent question an answer. */
export function isConsentPending(): boolean {
    return autoSaveStatus().pendingConsent;
}

/** The file the plugin hooks read. Contains no secret — only the answer. */
export interface HookAutoSaveState {
    version: number;
    enabled: boolean;
    state: AutoSaveState;
    source: AutoSaveSource;
    pendingConsent: boolean;
    /** The settings file this was resolved from, for diagnosis only. */
    settingsPath: string;
    updatedAt: string;
}

/**
 * Publish the resolved state where the plugin hooks can read it.
 *
 * This is the whole hook contract: the hooks do no resolution, consult no
 * project directory and parse no credentials file — they read this one file out
 * of the trusted state dir, or they fail safe. Called at every point the answer
 * can change (`setAutoSave`, `markConsentPending`) and once at start-up, so a
 * hook spawned in the same session as an MCP server sees the current answer.
 *
 * Best effort: a read-only or missing home directory must not stop the server
 * from running, and a hook that finds no file already behaves as "off".
 */
export function publishHookState(): HookAutoSaveState | null {
    const status = autoSaveStatus();
    const payload: HookAutoSaveState = {
        version: HOOK_STATE_VERSION,
        enabled: status.enabled,
        state: status.state,
        source: status.source,
        pendingConsent: status.pendingConsent,
        settingsPath: status.path,
        updatedAt: new Date().toISOString(),
    };
    const path = hookStatePath();
    try {
        mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
        writeFileSync(path, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 });
        chmodSync(path, 0o600);
        return payload;
    } catch (err) {
        log.warn("autosave.publish_failed", {
            path,
            error: err instanceof Error ? err.message : String(err),
        });
        return null;
    }
}

/**
 * Record the answer, preserving any other keys already in the file. Clears the
 * pending stamp — the question has been answered and must not be asked again.
 */
export function setAutoSave(enabled: boolean): { path: string; enabled: boolean } {
    const next: MemWalSettings = { ...readSettings(), autoSave: enabled };
    delete next.autoSaveConsent;
    const path = writeSettings(next);
    publishHookState();
    log.info("autosave.set", { enabled, path });
    return { path, enabled };
}

/**
 * Mark this install as created after the consent prompt existed, so an unset
 * state here is read as "never asked" rather than "long-standing user".
 *
 * Called once when a brand-new install first appears — before the signed-out
 * server boots, and immediately after a first interactive login — so that an
 * abandoned or headless sign-in cannot mature into automatic saving nobody
 * agreed to. A no-op once any answer exists.
 */
export function markConsentPending(): void {
    const settings = readSettings();
    if (typeof settings.autoSave === "boolean") return;
    if (settings.autoSaveConsent === "pending") return;
    writeSettings({ ...settings, autoSaveConsent: "pending" });
    publishHookState();
    log.info("autosave.consent_pending", { path: settingsPath() });
}

/** One line for a TTY, naming the state, where it came from, and how to flip it. */
export function autoSaveSummary(): string {
    const status = autoSaveStatus();
    const where =
        status.source === "env"
            ? `from ${AUTO_SAVE_ENV}`
            : status.source === "settings"
              ? `from ${status.path}`
              : status.source === "legacy"
                ? "carried over from before this setting existed"
                : "not answered yet";
    const how = status.enabled
        ? "Turn it off with `memwal-mcp auto-save off`."
        : "Turn it on with `memwal-mcp auto-save on`. Facts you explicitly ask to save are stored either way.";
    return `Automatic memory: ${status.enabled ? "ON" : "OFF"} (${where}). ${how}`;
}

/**
 * The single line a non-interactive run prints while consent is outstanding.
 *
 * Non-TTY is every MCP client spawn, so this is stderr-only and says what is
 * happening rather than asking anything — there is no human on the other end of
 * this stdin, and a prompt here would hang the server forever.
 */
export function pendingConsentNotice(): string | null {
    const status = autoSaveStatus();
    if (!status.pendingConsent) return null;
    return status.enabled
        ? "Automatic memory is ON, carried over from before this setting existed. " +
              "Run `memwal-mcp auto-save on|off` in a terminal to confirm or change it."
        : "Automatic memory is waiting on your answer, so nothing is being saved " +
              "unprompted yet (facts you explicitly ask to save still are). Run " +
              "`memwal-mcp login` in a terminal to answer, or set it directly with " +
              "`memwal-mcp auto-save on|off`.";
}
