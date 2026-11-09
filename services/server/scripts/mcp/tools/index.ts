import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { MemWalSession } from "../auth.js";

import { registerRememberTool } from "./remember.js";
import { registerRememberStatusTool } from "./remember-status.js";
import { registerRememberBulkTool } from "./remember-bulk.js";
import { registerRecallTool } from "./recall.js";
import { registerAnalyzeTool } from "./analyze.js";
import { registerRestoreTool } from "./restore.js";
import { registerHealthTool } from "./health.js";
import { registerNamespacesTool } from "./namespaces.js";

/**
 * Register every non-manual MemWal tool on the given server. Manual-mode
 * methods (rememberManual, recallManual) are intentionally excluded per the
 * MCP-server scope: agents authenticate with a delegate key and rely on the
 * relayer for SEAL encrypt/decrypt + Walrus storage.
 */
export function registerTools(server: McpServer, session: MemWalSession): void {
    // Fail closed: the relayer states the granted scope explicitly on every
    // forwarded request — the resolved grant for OAuth callers, and the full
    // read+write scope for legacy delegate-key callers. An absent or empty
    // scope therefore means the relayer never vouched for this request, so it
    // grants nothing rather than everything.
    const granted = new Set(session.oauthScope?.split(/\s+/).filter(Boolean));
    const canRead = granted.has("memwal:read");
    const canWrite = granted.has("memwal:write");

    if (canWrite) {
        registerRememberTool(server, session);
        registerRememberStatusTool(server, session);
        registerRememberBulkTool(server, session);
        registerAnalyzeTool(server, session);
        registerRestoreTool(server, session);
    }
    if (canRead) {
        registerRecallTool(server, session);
        registerNamespacesTool(server, session);
        registerHealthTool(server, session);
    }
}

export {
    registerRememberTool,
    registerRememberStatusTool,
    registerRememberBulkTool,
    registerRecallTool,
    registerAnalyzeTool,
    registerRestoreTool,
    registerNamespacesTool,
    registerHealthTool,
};
