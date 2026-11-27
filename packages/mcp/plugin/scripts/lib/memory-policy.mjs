/**
 * Shared automatic-memory policy — the plugin hooks' copy.
 *
 * Plain ESM, no dependencies, no network: the hooks are `.mjs` scripts run
 * straight from the plugin directory by the client, with no build step and no
 * access to this package's compiled `dist/`, which is why they carry their own
 * copy of the block rather than importing one.
 *
 * WALM-642.
 */

// ─── memwal:policy-block:start ───────────────────────────────────────────────
// WALM-642. The lines between these two markers are BYTE-IDENTICAL in three
// files that cannot import one another, because the three packages have no
// workspace link:
//
//   packages/mcp/src/memory-policy.ts                  — MCP client: initialize
//                                                        instructions + the
//                                                        cold-start tools/list
//   packages/mcp/plugin/scripts/lib/memory-policy.mjs  — plugin hooks: the
//                                                        guidance injected at
//                                                        SessionStart /
//                                                        UserPromptSubmit /
//                                                        PostToolUse
//   services/server/scripts/mcp/tools/memory-policy.ts — relayer sidecar: the
//                                                        live tool descriptions
//
// The duplication is deliberate and pinned: `memory-policy-sync` tests on both
// sides extract this block from each file and compare the bytes, so editing one
// copy fails the suite until the other two match. Edit the block, then copy it
// verbatim — markers included — into the other two files.

/**
 * The secret-exclusion and do-not-save rules, stated verbatim by every
 * automatic-save surface.
 *
 * These are model-facing rules, not enforcement. The programmatic backstop is
 * the redactor in the relayer sidecar's write path
 * (services/server/scripts/mcp/tools/redaction.ts), which runs before any text
 * reaches the SDK.
 */
export const SECRET_EXCLUSION_RULES = [
    "NEVER save a credential, even when it sits next to something worth saving: passwords,",
    "API keys, access or refresh tokens, private keys, seed or recovery phrases, authorization",
    "headers, session cookies, and connection strings or URLs that embed a user:password.",
    "When a message mixes a preference with a credential, save the preference alone and leave",
    "the credential out; never store the line verbatim.",
    "If the user says not to save something ('don't save this', 'off the record', or the same",
    "in any language), do not save it, and do not save a paraphrase of it either.",
    "Do not store quoted or pasted third-party material — log excerpts, code, articles, other",
    "people's messages — as if it were a fact about this user. Save only what the user is",
    "telling you about themselves or their work, in your own words.",
].join(" ");

/**
 * One-line form, for surfaces with no room for the full block (a per-turn
 * nudge, a tool description tail). It is a reminder of the block above, never a
 * replacement for it: any surface that drives an automatic save states the full
 * `SECRET_EXCLUSION_RULES`.
 */
export const SECRET_EXCLUSION_SUMMARY = [
    "Never save passwords, keys, tokens or other credentials — not even beside a fact worth",
    "saving; honour an explicit 'do not save this'; never store pasted third-party content as",
    "a fact about the user.",
].join(" ");

/**
 * Whether to save unprompted is the user's standing choice, and this is the
 * sentence that says so. A direct request ("remember that ...") is never gated
 * by it — the gate is only on saving something the user did not ask you to save.
 */
export const AUTO_SAVE_OPT_IN_RULE = [
    "Whether to save things the user did not ask you to save is their standing choice, made once",
    "in a terminal. When automatic memory is on, save durable facts as they state them; when it is",
    "off, save only what they ask you to save in that turn. That question is put by `memwal-mcp",
    "login` and set by `memwal-mcp auto-save on|off` — never ask the user to answer it in chat,",
    "and never answer it on their behalf.",
].join(" ");

/** Bumped whenever the text above changes, so a stale copy is identifiable. */
export const MEMORY_POLICY_VERSION = "2026-09-17.2";
// ─── memwal:policy-block:end ─────────────────────────────────────────────────

/**
 * Prompt injected before context compaction when automatic memory is enabled.
 * Instructs the assistant to review the session for durable facts, decisions,
 * conventions, and resolved bugs before context is compacted, while strictly
 * obeying the secret exclusion rules.
 */
export const PRE_COMPACT_PROMPT = [
    "Before the conversation context is compacted, review the current session for any durable user preferences, architectural decisions, project conventions, or resolved bug root causes that have not yet been saved to Walrus Memory.",
    "Save high-signal facts using memwal_remember or memwal_remember_bulk (preferring memwal_remember_bulk when storing multiple facts).",
    "Skip ephemeral progress notes, raw command output, and anything already saved earlier in the session, and strictly obey SECRET_EXCLUSION_RULES.",
    SECRET_EXCLUSION_RULES,
].join(" ");

