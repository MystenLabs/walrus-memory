/**
 * memory_search tool — semantic recall.
 *
 * Requires tools.allow config to be visible to the LLM.
 * Registered as a factory so the search is pinned to ctx.sessionKey.
 * An omitted namespace uses that agent. Any other namespace is rejected.
 */

import type { MemWal } from "@mysten-incubation/memwal";
import { Type } from "@sinclair/typebox";
import { looksLikeInjection } from "../capture.js";
import { resolveToolNamespace } from "../config.js";
import { escapeForPrompt, relevancePercent, relevanceRatio, toolError, withTimeout } from "../format.js";
import type { PluginConfig } from "../types.js";
import { DEFAULT_SEARCH_LIMIT } from "../constants.js";

/** Register the memory_search agent tool. */
export function registerSearchTool(api: any, client: MemWal, config: PluginConfig): void {
  api.registerTool(
    (ctx?: { sessionKey?: string }) => ({
      name: "memory_search",
      label: "Memory Search",
      description:
        "Search long-term memory for relevant past information, facts, " +
        "preferences, and decisions. Returns memories ranked by relevance. " +
        "The search is pinned to the calling agent's namespace. " +
        "When <memwal-memories> is already injected in the prompt context by auto-recall, " +
        "use those recalled memories directly and avoid calling memory_search with the same query. " +
        "Call memory_search at most once per turn with a specific, focused query when " +
        "auto-recall is disabled, when no <memwal-memories> block was injected, " +
        "when the conversation shifts to a topic not covered by <memwal-memories>, " +
        "or when specific details are missing from the recalled entries.",
      parameters: Type.Object({
        query: Type.String({
          description:
            "Specific, focused search query. When <memwal-memories> is already injected in the prompt context, " +
            "use recalled memories directly and query only when specific details are missing or for topics not covered by them.",
        }),
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
        const ns = resolveToolNamespace(config.defaultNamespace, ctx?.sessionKey, namespace);
        if (!ns) {
          return {
            content: [{ type: "text", text: "Namespace is pinned to the calling agent." }],
            details: { error: "namespace_rejected" },
          };
        }

        try {
          const result = await withTimeout(
            () => client.recall(query, limit, ns),
            config.requestTimeoutMs,
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
          // to the LLM — same protection as the recall hook path
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

          // Cosine distance is [0, 2]; clamp so orthogonal/opposite hits
          // cannot print a negative relevance % (WALM-441 / GH #798).
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
