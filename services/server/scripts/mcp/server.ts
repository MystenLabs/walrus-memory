import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createRequire } from "node:module";
import { applyAgentClientFromServer } from "./agent-client.js";
import type { MemWalSession } from "./auth.js";
import { registerTools } from "./tools/index.js";
import { MCP_MAX_TOOL_INPUT_ELEMENTS } from "./limits.js";
import {
    SECRET_EXCLUSION_RULES,
    AUTO_SAVE_OPT_IN_RULE,
} from "./tools/memory-policy.js";

const requirePkg = createRequire(import.meta.url);

/** Version of the Node package that actually serves MCP, reported as
 * `serverInfo.version`. Previously hardcoded to "0.0.1", which matched neither
 * this package (0.1.0) nor the relayer crate, so handshake logs could not tell
 * you what a user was running (WALM-324). `../package.json` resolves to
 * scripts/package.json both locally and in the image (see Dockerfile). */
const PACKAGE_VERSION: string =
    (requirePkg("../package.json") as { version?: string }).version ?? "0.0.0";

/**
 * Injected into the client's system prompt during the `initialize` handshake.
 *
 * This is the only proactive-usage channel that survives lazy tool loading.
 * Claude Desktop and Codex stopped putting MCP tool schemas in context until a
 * tool is explicitly loaded, so the "call this PROACTIVELY" guidance that lives
 * in tools/remember.ts never reaches the model: it sees no memory tool, then
 * either offers its own built-in memory or denies the tool exists (WALM-324).
 * `instructions` travels with `initialize`, before any `tools/list`, so lazy
 * loading cannot strip it.
 *
 * The secret-exclusion and opt-in paragraphs are not written out here: they are
 * pulled from tools/memory-policy.ts, the copy this package owns of the block
 * shared with the MCP client and the plugin hooks (WALM-642).
 *
 * Keep roughly in sync with the plugin's SessionStart hook, which delivers
 * equivalent text on the plugin install path:
 *   packages/mcp/plugin/scripts/on_session_start.mjs
 * The two cannot share a constant: this file belongs to the standalone
 * `memwal-server-scripts` npm package, which has no workspace link to
 * packages/mcp.
 */
const INSTRUCTIONS = [
    "Walrus Memory is this user's persistent memory system, exposed through the memwal_* tools.",
    "It survives across sessions, clients, and machines.",
    "Prefer these tools over any built-in or local memory feature so the user's memory stays",
    "portable and encrypted on Walrus.",
    "",
    "RECALL: before answering anything that touches past work, prior decisions, the user's",
    "preferences, or facts you may have stored earlier, call memwal_recall. One focused query is",
    "enough; do not fire several redundant searches for the same question.",
    "",
    "REMEMBER: when the user states a preference, decision, constraint, correction, identity",
    "detail, recurring workflow, or a configuration value such as a hostname, port, region or",
    "id, call memwal_remember in that same turn, before you finish replying. Do not ask whether",
    "to save it and do not wait to be asked: acknowledging the fact in your reply does not store",
    "it, and it is lost when the conversation ends. Pass the complete statement rather than a",
    "summary. Skip one-off tasks, the current file or bug, and small talk. Use",
    "memwal_remember_bulk when several distinct facts arrived at once.",
    "",
    // WALM-642. Verbatim from tools/memory-policy.ts, which the tool
    // descriptions state too, so instructions and descriptions cannot drift
    // into telling the model two different things about secrets.
    AUTO_SAVE_OPT_IN_RULE,
    "",
    SECRET_EXCLUSION_RULES,
    "",
    "By default memwal_remember and memwal_remember_bulk return in ~1s once the relayer has",
    "accepted the job (job_id / job_ids). The Walrus write continues in the background (~30-60s)",
    "and the fact is NOT stored yet. That is the normal result. Do not claim it is saved.",
    "Do NOT re-send the same text — that queues duplicates. Resolve with memwal_remember_status",
    "(job_id, or job_ids for a whole batch). Only a blob_id in the tool reply means the fact is",
    "already stored (that happens when an optional wait budget was set and the write finished).",
    "",
    "RECOVER: if memwal_recall unexpectedly returns nothing for a namespace that has been used",
    "before, call memwal_restore to rebuild the index from Walrus.",
    "",
    "If a memwal_* tool is not currently loaded, load it and use it. Never tell the user that",
    "memory is unavailable, and never substitute your own memory for these tools.",
].join("\n");

/**
 * Build a fully-configured Walrus Memory MCP server for a single authenticated
 * session. The transport is NOT attached here — `index.ts` is responsible
 * for choosing SSE (default) or future transports.
 *
 * One McpServer per session — same pattern as Mailgate. Tools share the
 * session-scoped Walrus Memory SDK client so each call signs with the caller's
 * delegate key, not a shared server key.
 */
export function createMcpServer(session: MemWalSession): McpServer {
    const server = new McpServer(
        {
            name: "memwal",
            version: PACKAGE_VERSION,
        },
        {
            instructions: INSTRUCTIONS,
            maxToolInputElements: MCP_MAX_TOOL_INPUT_ELEMENTS,
        },
    );

    registerTools(server, session);

    // SDK populates getClientVersion() during initialize; this fires after
    // the client sends `notifications/initialized`.
    server.server.oninitialized = () => {
        applyAgentClientFromServer(server, session);
    };

    return server;
}
