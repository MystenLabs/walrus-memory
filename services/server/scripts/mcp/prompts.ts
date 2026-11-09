import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
    CONSENT_INSTRUCTION,
    ENABLE_PROACTIVE_PROMPT_DESCRIPTION,
    ENABLE_PROACTIVE_PROMPT_NAME,
    ENABLE_PROACTIVE_PROMPT_TITLE,
} from "./consent-instruction.js";

/** MCP `/` prompt fallback for hosts that do not inject initialize.instructions. */
export function registerPrompts(server: McpServer): void {
    server.registerPrompt(
        ENABLE_PROACTIVE_PROMPT_NAME,
        {
            title: ENABLE_PROACTIVE_PROMPT_TITLE,
            description: ENABLE_PROACTIVE_PROMPT_DESCRIPTION,
        },
        () => ({
            description: ENABLE_PROACTIVE_PROMPT_DESCRIPTION,
            messages: [
                {
                    role: "user",
                    content: { type: "text", text: CONSENT_INSTRUCTION },
                },
            ],
        }),
    );
}
