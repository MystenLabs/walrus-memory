/**
 * memory_search tool: semantic recall.
 *
 * Requires tools.allow config to be visible to the LLM.
 * Registered as a factory so the search is pinned to ctx.sessionKey.
 * An omitted namespace uses that agent. Any other namespace is rejected.
 */

import type { MemWal } from "@mysten-incubation/memwal";
import { Type } from "@sinclair/typebox";
import { looksLikeInjection } from "../capture.js";
import { resolveScopedToolNamespace } from "../config.js";
import { escapeForPrompt, relevancePercent, relevanceRatio, toolError, withTimeout } from "../format.js";
import type { PluginConfig } from "../types.js";
import { DEFAULT_SEARCH_LIMIT } from "../constants.js";

export type SearchToolConfig = Pick<PluginConfig, "defaultNamespace"> &
  Partial<Pick<PluginConfig, "isolateBySender" | "includeSharedNamespaceOnRecall" | "requestTimeoutMs">>;

function normalizeSearchConfig(config: SearchToolConfig | string): {
  defaultNamespace: string;
  isolateBySender: boolean;
  includeSharedNamespaceOnRecall: boolean;
  requestTimeoutMs: number;
} {
  if (typeof config === "string") {
    return {
      defaultNamespace: config,
      isolateBySender: false,
      includeSharedNamespaceOnRecall: false,
      requestTimeoutMs: 10_000,
    };
  }
  return {
    defaultNamespace: config.defaultNamespace ?? "default",
    isolateBySender: Boolean(config.isolateBySender),
    includeSharedNamespaceOnRecall: Boolean(config.includeSharedNamespaceOnRecall),
    requestTimeoutMs: config.requestTimeoutMs ?? 10_000,
  };
}

/** Register the memory_search agent tool. */
export function registerSearchTool(api: any, client: MemWal, config: SearchToolConfig | string): void {
  const normConfig = normalizeSearchConfig(config);

  api.registerTool(
    (ctx?: any) => ({
      name: "memory_search",
      label: "Memory Search",
      description:
        "Search long-term memory for relevant past information, facts, " +
        "preferences, and decisions. Returns memories ranked by relevance. " +
        "The search is pinned to the calling agent's namespace.",
      parameters: Type.Object({
        query: Type.String({ description: "Search query" }),
        limit: Type.Optional(
          Type.Number({ description: "Max results (default: 5)" }),
        ),
        namespace: Type.Optional(
          Type.String({
            description:
              "Calling agent's namespace. Omit to use it. Any other namespace is rejected.",
          }),
        ),
      }),
      async execute(_id: string, params: any) {
        const { query, limit = DEFAULT_SEARCH_LIMIT, namespace } = params;
        const resolved = resolveScopedToolNamespace(
          normConfig,
          ctx,
          namespace,
          { allowSharedRecall: true },
        );

        if (resolved.error || !resolved.namespace) {
          const errCode = resolved.error ?? "namespace_rejected";
          const message =
            errCode === "cross_sender_namespace_forbidden"
              ? "Cross-sender memory access is forbidden."
              : errCode === "sender_identity_required"
                ? "Sender identity is required when sender isolation is enabled."
                : "Namespace is pinned to the calling agent.";
          return {
            error: errCode,
            message,
            content: [{ type: "text", text: message }],
            details: { error: errCode, message },
          };
        }

        const ns = resolved.namespace;

        try {
          const result = await withTimeout(
            () => client.recall(query, limit, ns),
            normConfig.requestTimeoutMs,
            "memory_search",
          );

          if (!result.results?.length) {
            return {
              content: [
                { type: "text", text: "No relevant memories found." },
              ],
              details: { count: 0, namespace: ns },
            };
          }

          // Filter out injection attempts and escape text before returning
          // to the LLM: same protection as the recall hook path
          const safe = result.results.filter(
            (r: any) => !looksLikeInjection(r.text),
          );

          if (!safe.length) {
            return {
              content: [
                { type: "text", text: "No relevant memories found." },
              ],
              details: { count: 0, namespace: ns },
            };
          }

          // Cosine distance is [0, 2]; clamp so orthogonal or opposite hits
          // cannot print a negative relevance percentage (GH #798).
          const formatted = safe
            .map((r: any, i: number) => {
              const relevance = relevancePercent(r.distance);
              return `${i + 1}. ${escapeForPrompt(r.text)} (${relevance}% relevance)`;
            })
            .join("\n");

          return {
            content: [
              {
                type: "text",
                text: `Found ${safe.length} memories:\n\n${formatted}`,
              },
            ],
            details: {
              count: safe.length,
              namespace: ns,
              memories: safe.map((r: any) => ({
                text: r.text,
                blob_id: r.blob_id,
                relevance: relevanceRatio(r.distance),
              })),
            },
          };
        } catch (err) {
          return toolError("Memory search failed", err);
        }
      },
    }),
    { name: "memory_search" },
  );
}
