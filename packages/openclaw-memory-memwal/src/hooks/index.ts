/**
 * Lifecycle hooks: the invisible memory layer.
 *
 * Each agent gets its own namespace derived from ctx.sessionKey.
 * Same key, same account: isolation via server-side namespace scoping.
 */

import type { MemWal } from "@mysten-incubation/memwal";
import { registerRecallHook } from "./recall.js";
import { registerCaptureHook } from "./capture.js";
import type { PluginConfig } from "../types.js";

/** Register all lifecycle hooks based on config toggles. */
export function registerHooks(api: any, client: MemWal, config: PluginConfig): void {
  if (config.autoRecall) registerRecallHook(api, client, config);
  if (config.autoCapture) registerCaptureHook(api, client, config);
}
