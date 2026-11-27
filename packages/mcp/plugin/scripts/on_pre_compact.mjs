/**
 * PreCompact hook. Performs a synchronous host-compatible pre-compaction save
 * of durable facts to Walrus Memory before Claude Code context compaction.
 *
 * Claude Code PreCompact contract:
 * - Exit code 0 with empty stdout allows compaction to proceed.
 * - PreCompact has NO PreCompactHookSpecificOutput variant in Claude Code.
 * - Claude Code discards `systemMessage` and `continue` on PreCompact.
 * - The hook receives `{ session_id, transcript_path, cwd, hook_event_name: "PreCompact", trigger, custom_instructions }`
 *   on stdin and blocks synchronously until this process exits 0.
 *
 * When automatic saving is off or unset, exits immediately with code 0 and empty stdout.
 */
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync } from "node:fs";
import { readStdin } from "./lib/hook-io.mjs";
import { isAutoSaveEnabled } from "./lib/auto-save.mjs";
import { ensureTrustedEntry } from "./lib/mcp-launch.mjs";

const input = readStdin();

if (!isAutoSaveEnabled()) {
    process.exit(0);
}

try {
    let preCompactPath;
    const localMonorepoDist = fileURLToPath(new URL("../../dist/pre-compact.js", import.meta.url));
    if (existsSync(localMonorepoDist)) {
        preCompactPath = localMonorepoDist;
    } else {
        const entry = ensureTrustedEntry();
        const distDir = dirname(dirname(entry));
        const installedPath = join(distDir, "pre-compact.js");
        if (existsSync(installedPath)) {
            preCompactPath = installedPath;
        }
    }

    if (preCompactPath) {
        const { runPreCompactSave } = await import(preCompactPath);
        await runPreCompactSave(input);
    }
} catch {
    // Hooks must never fail, crash, or block session compaction
}

process.exit(0);
