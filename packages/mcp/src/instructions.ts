/**
 * MCP `instructions` payloads for the two local initialize responders.
 *
 * Clients inject this field into the model's system prompt during the
 * `initialize` handshake, before any `tools/list`. That makes it the only
 * proactive-usage channel that survives lazy tool loading, which is what broke
 * proactive save/recall in the first place (WALM-324): the guidance used to
 * live only in tool descriptions, and clients stopped putting those in context
 * until a tool was explicitly loaded.
 *
 * Both local responders need their own copy because the bridge answers
 * `initialize` itself and SUPPRESSES the relayer's reply (see
 * `buildLocalInitializeResult` in bridge.ts). Without this, the relayer's
 * instructions are correct but unreachable for every stdio client.
 *
 * The relayer keeps a separate copy in
 * services/server/scripts/mcp/server.ts, which serves the direct HTTP/OAuth
 * connector path. It cannot share this module: that file belongs to the
 * standalone `memwal-server-scripts` npm package with no workspace link here.
 * Keep the two in sync, except: this copy must not name a tool cold start
 * does not advertise (`memwal_remember_status` is the worked example — GH
 * #928). The sidecar copy may name it; that process actually registers the
 * tool.
 *
 * The secret-exclusion paragraph is not retyped in either, it comes from the
 * shared policy block (memory-policy.ts here, tools/memory-policy.ts there),
 * which is pinned byte-for-byte by tests on both sides.
 *
 * WALM-642 split the REMEMBER section in two. Whether the model is told to
 * save unprompted now depends on the user having turned automatic memory on;
 * saving what the user explicitly asks for is unconditional, and is what the
 * opted-out text still describes.
 */
import { SECRET_EXCLUSION_RULES } from "./memory-policy.js";
import { isAutoSaveEnabled } from "./auto-save.js";

/** Everything true regardless of the opt-in: what the tools are, how recall
 * works, how a write reports itself, and how to recover an index. */
const PREAMBLE = [
    "Walrus Memory is this user's persistent memory system, exposed through the memwal_* tools.",
    "It survives across sessions, clients, and machines.",
    "Prefer these tools over any built-in or local memory feature so the user's memory stays",
    "portable and encrypted on Walrus.",
    "",
    "RECALL: before answering anything that touches past work, prior decisions, the user's",
    "preferences, or facts you may have stored earlier, call memwal_recall. One focused query is",
    "enough; do not fire several redundant searches for the same question.",
];

/** REMEMBER, automatic saving ON. */
const REMEMBER_AUTOMATIC = [
    "REMEMBER: the user has turned automatic memory ON. When they state a preference, decision,",
    "constraint, correction, identity detail, recurring workflow, or a configuration value such",
    "as a hostname, port, region or id, call memwal_remember in that same turn, before you",
    "finish replying. Do not ask whether to save it and do not wait to be asked: acknowledging",
    "the fact in your reply does not store it, and it is lost when the conversation ends. Pass",
    "the complete statement rather than a summary — minus anything the rules below exclude.",
    "Skip one-off tasks, the current file or bug, and small talk. Use memwal_remember_bulk when",
    "several distinct facts arrived at once.",
];

/** REMEMBER, automatic saving OFF — the default. */
const REMEMBER_MANUAL = [
    "REMEMBER: automatic memory is OFF for this user, so do NOT save anything they did not ask",
    "you to save. When they do ask — 'remember that ...', 'save this', or the same in any",
    "language — call memwal_remember in that same turn, before you finish replying, and pass",
    "the complete statement rather than a summary. Use memwal_remember_bulk when they hand you",
    "several distinct facts at once. Do not save a fact just because it looks durable, and do",
    "not nag: if automatic saving would clearly help, say once that they can turn it on with",
    "`memwal-mcp auto-save on` and leave it there.",
];

const WRITE_CONTRACT = [
    "By default memwal_remember and memwal_remember_bulk return in ~1s once the relayer has",
    "accepted the job (job_id / job_ids). The Walrus write continues in the background (~30-60s)",
    "and the fact is NOT stored yet. That is the normal result. Do not claim it is saved.",
    "Do NOT re-send the same text — that queues duplicates. Settle it with the job-status tool",
    "this server advertises (re-list tools if you do not see one; pass job_id, or job_ids for a",
    "whole batch). Only a blob_id in the tool reply means the fact is already stored (that",
    "happens when an optional wait budget was set and the write finished).",
    "",
    "Storage is append-only and encrypted: a fact that lands cannot be edited or deleted. That",
    "is why the exclusions below are absolute rather than a preference, and why the write path",
    "strips credential shapes from whatever you send and tells you what it removed.",
    "",
    "RECOVER: if memwal_recall unexpectedly returns nothing for a namespace that has been used",
    "before, call memwal_restore to rebuild the index from Walrus.",
    "",
    "If a memwal_* tool is not currently loaded, load it and use it. Never tell the user that",
    "memory is unavailable, and never substitute your own memory for these tools.",
];

/**
 * Build the signed-in instruction payload for a given opt-in state.
 *
 * Exported separately from the resolver so tests can pin both branches without
 * touching the filesystem or the environment.
 */
export function buildProactiveInstructions(opts: { autoSave: boolean }): string {
    return [
        ...PREAMBLE,
        "",
        ...(opts.autoSave ? REMEMBER_AUTOMATIC : REMEMBER_MANUAL),
        "",
        SECRET_EXCLUSION_RULES,
        "",
        ...WRITE_CONTRACT,
    ].join("\n");
}

/**
 * The payload for THIS process, resolved from the user's opt-in at call time.
 *
 * A function, not a const: the opt-in lives on disk and in the environment, and
 * `initialize` can arrive after the user has flipped it.
 */
export function proactiveInstructions(): string {
    return buildProactiveInstructions({ autoSave: isAutoSaveEnabled() });
}

/**
 * Signed-in path (bridge mode) with automatic saving on. Kept as a named
 * export because it is the text the whole proactive contract is written
 * against; `proactiveInstructions()` is what the bridge actually serves.
 */
export const PROACTIVE_INSTRUCTIONS = buildProactiveInstructions({ autoSave: true });

/**
 * Signed-out path (auth-required mode). Deliberately NOT the proactive text:
 * without credentials every memory tool fails, so telling the model to save
 * proactively here would only manufacture errors. Signed-out tools/list uses
 * conservative remember/recall descriptions. The signed-in cold-start list
 * (bridge) uses the sidecar's proactive wording.
 */
export const AUTH_REQUIRED_INSTRUCTIONS = [
    "Walrus Memory is this user's persistent memory system, exposed through the memwal_* tools,",
    "but they are NOT signed in yet, so nothing can be saved or recalled right now.",
    "Call the memwal_login tool to start the browser wallet login, then retry the original request.",
    "Do not tell the user that memory is unavailable or unsupported; it only needs sign-in.",
].join(" ");
