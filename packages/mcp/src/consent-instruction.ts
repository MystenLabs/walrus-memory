/**
 * User-pasteable standing instruction so chat clients (Claude Desktop,
 * ChatGPT-style hosts) save durable facts through memwal_* without asking
 * every turn. Keep in sync with:
 *   services/server/scripts/mcp/consent-instruction.ts
 *   apps/app/public/skills/setup
 *   apps/app/src/pages/ConnectMcp.tsx
 *   docs/guides/system-prompt-templates.md (Universal starter)
 */

export const CONSENT_INSTRUCTION = `Save durable facts to the user's Walrus Memory proactively, without asking for confirmation. Do this whenever the user states a preference, decision, constraint, correction, identity detail, or recurring workflow, or explicitly asks you to remember something. Pass the user's complete statement verbatim, never a summary. Skip one-off tasks, the current file or bug, and small talk.

Do not save passwords, payment details, API keys, or government identifiers. After saving, briefly confirm what you stored.

Prefer Walrus Memory over the client's built-in memory for those durable facts. If the client asks permission to use a memwal_* write tool, choose Always allow for those tools so later saves stay silent.`;

export const ENABLE_PROACTIVE_PROMPT_NAME = "memwal_enable_proactive";

export const ENABLE_PROACTIVE_PROMPT_TITLE = "Enable proactive Walrus Memory";

export const ENABLE_PROACTIVE_PROMPT_DESCRIPTION =
    "One-time standing instruction so this client saves and recalls durable facts through Walrus Memory without asking every turn.";

export const ENABLE_PROACTIVE_PROMPT_LIST = {
    prompts: [
        {
            name: ENABLE_PROACTIVE_PROMPT_NAME,
            title: ENABLE_PROACTIVE_PROMPT_TITLE,
            description: ENABLE_PROACTIVE_PROMPT_DESCRIPTION,
        },
    ],
};

export const ENABLE_PROACTIVE_PROMPT_GET = {
    description: ENABLE_PROACTIVE_PROMPT_DESCRIPTION,
    messages: [
        {
            role: "user" as const,
            content: { type: "text" as const, text: CONSENT_INSTRUCTION },
        },
    ],
};

/** Answer `prompts/list` / `prompts/get` locally. Returns null for other methods. */
export function localPromptReply(
    method: string | undefined,
    params: unknown,
): { result?: unknown; error?: { code: number; message: string } } | null {
    if (method === "prompts/list") {
        return { result: ENABLE_PROACTIVE_PROMPT_LIST };
    }
    if (method === "prompts/get") {
        const name = (params as { name?: unknown } | undefined)?.name;
        if (name === ENABLE_PROACTIVE_PROMPT_NAME) {
            return { result: ENABLE_PROACTIVE_PROMPT_GET };
        }
        return {
            error: {
                code: -32602,
                message: `Unknown prompt: ${typeof name === "string" ? name : "(missing)"}`,
            },
        };
    }
    return null;
}
