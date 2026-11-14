/**
 * Auto-recall hook: before_prompt_build.
 */

import type { MemWal } from "@mysten-incubation/memwal";
import { resolveAgent, resolveScopedAgent } from "../config.js";
import { looksLikeInjection } from "../capture.js";
import { formatMemoriesForPrompt, withTimeout } from "../format.js";
import type { PluginConfig } from "../types.js";
import { MIN_PROMPT_LENGTH } from "../constants.js";

/** Register the before_prompt_build hook for auto-recall. */
export function registerRecallHook(api: any, client: MemWal, config: PluginConfig): void {
  api.on("before_prompt_build", async (event: any, ctx: any) => {
    if (!event.prompt || event.prompt.length < MIN_PROMPT_LENGTH) return;

    const scoped = resolveScopedAgent(config, ctx, event);
    if (scoped.isolationMode === "missing_identity" || !scoped.namespace) {
      api.logger.warn(
        "memwal: skipping auto-recall because isolateBySender is enabled and no sender or session identity was provided",
      );
      return undefined;
    }

    const { namespace, sharedNamespace, agentId } = scoped;
    const base = resolveAgent(config.defaultNamespace, ctx?.sessionKey);
    const legacyNamespace = base.legacyNamespace;
    const namespaceInstruction =
      "Memory tools are pinned to the calling agent's namespace.";

    const minRelevance = config.minRelevance ?? 0.3;
    const maxResults = config.maxRecallResults ?? 5;
    const timeoutMs = config.requestTimeoutMs ?? 10_000;

    try {
      // Each read carries its own deadline. recall() self-aborts after 15s,
      // but compatibility preflight ahead of it does not, and
      // Promise.allSettled below waits for every promise, so one namespace
      // holding its socket open would stall the whole turn if the deadline
      // wrapped the pair instead of each read.
      const recallPromises = [
        withTimeout(
          () => client.recall(event.prompt, maxResults, namespace),
          timeoutMs,
          "auto-recall",
        ),
      ];

      // In isolated mode with shared namespace enabled, query shared namespace
      const hasSharedRead =
        scoped.isolationMode !== "disabled" &&
        Boolean(sharedNamespace && sharedNamespace !== namespace);

      if (hasSharedRead && sharedNamespace) {
        recallPromises.push(
          withTimeout(
            () => client.recall(event.prompt, maxResults, sharedNamespace),
            timeoutMs,
            "auto-recall (shared namespace)",
          ),
        );
      }

      // In legacy mode, dual-read from legacy namespace if present
      if (scoped.isolationMode === "disabled" && legacyNamespace && legacyNamespace !== namespace) {
        recallPromises.push(
          withTimeout(
            () => client.recall(event.prompt, maxResults, legacyNamespace),
            timeoutMs,
            "auto-recall (legacy namespace)",
          ),
        );
      }

      const resultsList = await Promise.allSettled(recallPromises);
      const primaryResult = resultsList[0];
      if (primaryResult?.status === "rejected") {
        api.logger.warn(
          `memory-memwal: canonical recall failed: ${String(primaryResult.reason)}`,
        );
      }

      let relevant: any[] = [];

      if (scoped.isolationMode === "disabled") {
        // Legacy mode: global distance ranking across canonical and legacy
        const candidates: any[] = [];
        const seen = new Set<string>();

        for (const res of resultsList) {
          if (res.status === "fulfilled" && res.value?.results?.length) {
            for (const item of res.value.results) {
              const key = (item as any).id || item.blob_id || item.text;
              if (!seen.has(key)) {
                seen.add(key);
                candidates.push(item);
              }
            }
          }
        }

        const filtered = candidates.filter(
          (r: any) =>
            (1 - r.distance) >= minRelevance &&
            !looksLikeInjection(r.text),
        );

        if (!filtered.length) {
          return { appendSystemContext: namespaceInstruction };
        }

        filtered.sort((a: any, b: any) => a.distance - b.distance);
        relevant = filtered.slice(0, maxResults);
      } else {
        // Isolated mode: keep sender-scoped memories first, then fill from shared
        const senderCandidates: any[] = [];
        const sharedCandidates: any[] = [];
        const seen = new Set<string>();

        if (primaryResult?.status === "fulfilled" && primaryResult.value?.results?.length) {
          for (const item of primaryResult.value.results) {
            const key = (item as any).id || item.blob_id || item.text;
            if (!seen.has(key)) {
              seen.add(key);
              senderCandidates.push(item);
            }
          }
        }

        if (resultsList.length > 1) {
          for (let i = 1; i < resultsList.length; i++) {
            const res = resultsList[i];
            if (res?.status === "fulfilled" && res.value?.results?.length) {
              for (const item of res.value.results) {
                const key = (item as any).id || item.blob_id || item.text;
                if (!seen.has(key)) {
                  seen.add(key);
                  sharedCandidates.push(item);
                }
              }
            }
          }
        }

        const filterItem = (r: any) =>
          (1 - r.distance) >= minRelevance &&
          !looksLikeInjection(r.text);

        const filteredSender = senderCandidates.filter(filterItem);
        filteredSender.sort((a: any, b: any) => a.distance - b.distance);

        const filteredShared = sharedCandidates.filter(filterItem);
        filteredShared.sort((a: any, b: any) => a.distance - b.distance);

        const combined = [...filteredSender, ...filteredShared];
        if (!combined.length) {
          return { appendSystemContext: namespaceInstruction };
        }

        relevant = combined.slice(0, maxResults);
      }

      api.logger.info(
        `memory-memwal: auto-recall injected ${relevant.length} memories ` +
        `(agent: ${agentId}, namespace: ${namespace})`,
      );

      return {
        prependContext: formatMemoriesForPrompt(
          relevant.map((r: any) => ({ text: r.text })),
        ),
        appendSystemContext: namespaceInstruction,
      };
    } catch (err) {
      api.logger.warn(
        `memory-memwal: auto-recall failed: ${String(err)}`,
      );
      return { appendSystemContext: namespaceInstruction };
    }
  });
}
