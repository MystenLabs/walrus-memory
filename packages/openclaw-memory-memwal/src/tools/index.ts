/**
 * Agent-callable tools: require tools.allow config to be visible to the LLM.
 *
 * Registered as factories so each call is pinned to the calling agent's
 * namespace from ctx.sessionKey. An omitted namespace uses that agent.
 * A model-supplied namespace is accepted only when it matches.
 */

import type { MemWal } from "@mysten-incubation/memwal";
import { registerSearchTool } from "./search.js";
import { registerStoreTool } from "./store.js";
import type { PluginConfig } from "../types.js";

/** Register all agent-callable tools. */
export function registerTools(api: any, client: MemWal, config: PluginConfig): void {
  registerSearchTool(api, client, config);
  registerStoreTool(api, client, config);
}
