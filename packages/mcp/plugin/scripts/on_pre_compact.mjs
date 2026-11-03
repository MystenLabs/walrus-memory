/**
 * PreCompact hook. Remind the agent to review the session and save durable
 * facts to Walrus Memory before context compaction.
 *
 * Automatic saving is required. When automatic saving is off, this hook
 * exits quietly with code 0 and emits nothing.
 */
import { readStdin, emitContext } from "./lib/hook-io.mjs";
import { PRE_COMPACT_PROMPT } from "./lib/memory-policy.mjs";
import { isAutoSaveEnabled } from "./lib/auto-save.mjs";

readStdin();

if (!isAutoSaveEnabled()) process.exit(0);

emitContext("PreCompact", PRE_COMPACT_PROMPT);
process.exit(0);
