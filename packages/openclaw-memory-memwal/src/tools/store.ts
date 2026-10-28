/**
 * memory_store tool — explicit save.
 *
 * Uses analyze() instead of remember() so the server LLM extracts
 * individual facts from the text, producing cleaner, more searchable
 * memories than storing the raw input verbatim.
 */

import type { MemWal } from "@mysten-incubation/memwal";
import { Type } from "@sinclair/typebox";
import { looksLikeInjection } from "../capture.js";
import { resolveToolNamespace } from "../config.js";
import { toolError, withTimeout } from "../format.js";
import type { PluginConfig } from "../types.js";
import { MIN_STORE_TEXT_LENGTH, MAX_FACT_PREVIEW_COUNT, MAX_TEXT_PREVIEW_LENGTH } from "../constants.js";

/** Register the memory_store agent tool. */
export function registerStoreTool(api: any, client: MemWal, config: PluginConfig): void {
  api.registerTool(
    (ctx?: { sessionKey?: string }) => ({
      name: "memory_store",
      label: "Memory Store",
      description:
        "Save important information to encrypted long-term memory. " +
        "Use when the user asks to remember something or when you " +
        "identify important facts worth preserving. " +
        "The write is pinned to the calling agent's namespace.",
      parameters: Type.Object({
        text: Type.String({
          description: "Information to store in memory",
        }),
        namespace: Type.Optional(
          Type.String({
            description:
              "Calling agent's namespace. Omit to use it. Any other namespace is rejected.",
          }),
        ),
        occurredAt: Type.Optional(
          Type.String({
            description:
              "Optional RFC-3339 / ISO-8601 timestamp of when the source " +
              "text or conversation actually occurred (e.g. " +
              "'2024-03-15T14:30:00Z'). The server uses this as the " +
              "temporal anchor for resolving in-turn relative references " +
              "like 'last Friday' or 'yesterday' against. For real-time " +
              "stores, pass the current time. For recounted past events " +
              "where the user is talking about something that happened " +
              "earlier (e.g. 'remember I called Alex last Friday'), OMIT " +
              "this field — do NOT pass the recounted event date while " +
              "leaving relative wording in the text; that produces wrong " +
              "anchors. When unknown, omit; do not guess.",
          }),
        ),
      }),
      async execute(_id: string, params: any) {
        const { text, namespace, occurredAt } = params;
        const ns = resolveToolNamespace(config.defaultNamespace, ctx?.sessionKey, namespace);
        if (!ns) {
          return {
            content: [{ type: "text", text: "Namespace is pinned to the calling agent." }],
            details: { error: "namespace_rejected" },
          };
        }

        // Defence in depth: reject injection on write, not just on read.
        // The recall hook filters on retrieval, but polluted data could
        // surface through other read paths (memory_search, future tools).
        if (looksLikeInjection(text)) {
          return {
            content: [
              {
                type: "text",
                text: "Cannot store text containing disallowed patterns.",
              },
            ],
            details: { error: "injection_rejected" },
          };
        }

        if (!text || text.trim().length < MIN_STORE_TEXT_LENGTH) {
          return {
            content: [
              {
                type: "text",
                text: "Cannot store empty or very short text.",
              },
            ],
            details: { error: "text_too_short" },
          };
        }

        try {
          const result = await withTimeout(
            (signal) =>
              client.analyze(text.trim(), {
                namespace: ns,
                occurredAt,
                ...(signal ? { signal } : {}),
              }),
            config.requestTimeoutMs,
            "memory_store",
          );

          const facts = Array.isArray(result?.facts) ? result.facts : [];
          const factCount = facts.length;
          if (factCount === 0) {
            return {
              content: [
                {
                  type: "text",
                  text: "No memorable facts extracted from the input.",
                },
              ],
              details: {
                action: "none",
                status: result?.status ?? "done",
                namespace: ns,
                factCount: 0,
                facts: [],
              },
            };
          }

          // Show first 3 extracted facts as confirmation, or raw text truncation as fallback
          const preview =
            facts
              .map((f: any) => f.text)
              .slice(0, MAX_FACT_PREVIEW_COUNT)
              .join("; ") || text.slice(0, MAX_TEXT_PREVIEW_LENGTH);

          const jobIds: string[] = Array.isArray(result?.job_ids)
            ? result.job_ids.filter((id: any): id is string => typeof id === "string" && id.length > 0)
            : facts
                .map((f: any) => f?.job_id ?? f?.id)
                .filter((id: any): id is string => typeof id === "string" && id.length > 0);

          const allFactsHaveBlobId = facts.every(
            (f: any) => typeof f?.blob_id === "string" && f.blob_id.length > 0,
          );
          const isAlreadyDone = result?.status === "done" || allFactsHaveBlobId;

          if (isAlreadyDone) {
            return {
              content: [
                {
                  type: "text",
                  text: `Stored ${factCount} fact${factCount === 1 ? "" : "s"}: ${preview}`,
                },
              ],
              details: {
                action: "created",
                status: "done",
                namespace: ns,
                factCount,
                jobIds,
                facts,
              },
            };
          }

          // When the client provides `waitForRememberJobs`, poll the queued
          // jobs within `requestTimeoutMs` so post-acceptance upload failures
          // are surfaced and "Stored" is only reported once jobs reach `done`
          // (GH #1101).
          const waitFn = (client as any).waitForRememberJobs;
          if (jobIds.length > 0 && typeof waitFn === "function") {
            const settled = await waitFn.call(
              client,
              jobIds,
              jobIds.map(() => ns),
              { timeoutMs: config.requestTimeoutMs },
            );
            const itemResults: any[] = Array.isArray(settled?.results)
              ? settled.results
              : Array.isArray(settled?.jobs)
                ? settled.jobs
                : [];
            const byId = new Map<string, any>();
            for (const item of itemResults) {
              if (item && typeof item.id === "string") {
                byId.set(item.id, item);
              }
            }

            const settledFacts = facts.map((f: any, idx: number) => {
              const jid = f?.job_id ?? f?.id ?? jobIds[idx];
              const settledItem = jid ? byId.get(jid) : undefined;
              if (settledItem?.blob_id) {
                return { ...f, blob_id: settledItem.blob_id };
              }
              return f;
            });

            const failedItems = itemResults.filter((r) => r?.status === "failed");
            if (failedItems.length > 0) {
              const errorSummary = failedItems
                .map((r) => `${r.id}: ${r.error ?? "upload failed"}`)
                .join("; ");
              return {
                content: [
                  {
                    type: "text",
                    text:
                      `Failed to store ${failedItems.length} of ${factCount} ` +
                      `fact${factCount === 1 ? "" : "s"} after acceptance (${errorSummary}).`,
                  },
                ],
                details: {
                  action: "failed",
                  status: "failed",
                  error: errorSummary,
                  namespace: ns,
                  factCount,
                  succeeded: settled?.succeeded ?? 0,
                  failed: failedItems.length,
                  jobIds,
                  facts: settledFacts,
                },
              };
            }

            const allSettledDone =
              itemResults.length >= jobIds.length &&
              itemResults.every((r) => r?.status === "done");
            if (allSettledDone) {
              return {
                content: [
                  {
                    type: "text",
                    text: `Stored ${factCount} fact${factCount === 1 ? "" : "s"}: ${preview}`,
                  },
                ],
                details: {
                  action: "created",
                  status: "done",
                  namespace: ns,
                  factCount,
                  jobIds,
                  facts: settledFacts,
                },
              };
            }
          }

          // Jobs are accepted (`status: "pending"`) and not yet stored on Walrus.
          const jobIdSuffix = jobIds.length > 0 ? ` (not stored yet; job_ids=${jobIds.join(",")})` : " (not stored yet)";
          return {
            content: [
              {
                type: "text",
                text: `Accepted ${factCount} fact${factCount === 1 ? "" : "s"}${jobIdSuffix}: ${preview}`,
              },
            ],
            details: {
              action: "accepted",
              status: result?.status ?? "pending",
              namespace: ns,
              factCount,
              jobIds,
              facts,
            },
          };
        } catch (err) {
          return toolError("Failed to store memory", err);
        }
      },
    }),
    { name: "memory_store" },
  );
}
