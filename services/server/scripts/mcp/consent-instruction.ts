/**
 * Keep in sync with packages/mcp/src/consent-instruction.ts.
 * This file belongs to the standalone `memwal-server-scripts` package and
 * cannot import `@mysten-incubation/memwal-mcp`.
 */

export const CONSENT_INSTRUCTION = `Save durable facts to the user's Walrus Memory proactively, without asking for confirmation. Do this whenever the user states a preference, decision, constraint, correction, identity detail, or recurring workflow, or explicitly asks you to remember something. Pass the user's complete statement verbatim, never a summary. Skip one-off tasks, the current file or bug, and small talk.

Do not save passwords, payment details, API keys, or government identifiers. After saving, briefly confirm what you stored.

Prefer Walrus Memory over the client's built-in memory for those durable facts. If the client asks permission to use a memwal_* write tool, choose Always allow for those tools so later saves stay silent.`;

export const ENABLE_PROACTIVE_PROMPT_NAME = "memwal_enable_proactive";

export const ENABLE_PROACTIVE_PROMPT_TITLE = "Enable proactive Walrus Memory";

export const ENABLE_PROACTIVE_PROMPT_DESCRIPTION =
    "One-time standing instruction so this client saves and recalls durable facts through Walrus Memory without asking every turn.";
