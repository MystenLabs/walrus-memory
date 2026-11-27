/**
 * OpenClaw Memory Plugin: Walrus Memory
 *
 * Encrypted, decentralized long-term memory via Walrus Memory.
 *
 * Components:
 *   hooks/: before_prompt_build (auto-recall), agent_end (auto-capture)
 *   tools/: memory_search, memory_store
 *   cli/: openclaw memwal search and stats
 *   config.ts: Config parsing, namespace resolution, sender isolation
 *   format.ts: Memory formatting, tag injection and stripping, prompt safety
 *   capture.ts: Capture filtering, injection detection
 *   types.ts: Shared TypeScript types
 *
 * Per-agent and per-sender isolation via namespaces:
 *   Each OpenClaw agent and sender gets its own namespace.
 *   Same key, same account: isolation scoped at the server level.
 */

import { MemWal } from "@mysten-incubation/memwal";
import { parseConfig, keyPreview } from "./config.js";
import { registerHooks } from "./hooks/index.js";
import { registerTools } from "./tools/index.js";
import { registerCli } from "./cli/index.js";

export default {
  id: "memory-memwal",
  name: "Walrus Memory",
  description: "Encrypted, decentralized long-term memory via Walrus Memory",
  kind: "memory" as const,

  /** Initialize the Walrus Memory client and register all plugin components. */
  register(api: any) {
    const config = parseConfig(api.pluginConfig);

    const client = MemWal.create({
      key: config.privateKey,
      accountId: config.accountId,
      serverUrl: config.serverUrl,
    });

    api.logger.info(
      `memory-memwal: registered (server: ${config.serverUrl}, ` +
      `key: ${keyPreview(config.privateKey)}, ` +
      `namespace: ${config.defaultNamespace})`,
    );

    registerHooks(api, client, config);
    registerTools(api, client, config);
    registerCli(api, client, config);

    // Health check service
    api.registerService({
      id: "memory-memwal",
      async start() {
        try {
          const health = await client.health();
          api.logger.info(
            `memory-memwal: connected (status: ${health.status}, version: ${health.version})`,
          );
        } catch (err) {
          api.logger.warn(
            `memory-memwal: health check failed: ${String(err)}`,
          );
        }
      },
      stop() {
        api.logger.info("memory-memwal: stopped");
      },
    });
  },
};
