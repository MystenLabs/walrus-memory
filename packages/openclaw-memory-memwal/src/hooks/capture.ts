/**
 * Auto-capture hook — agent_end.
 *
 * After the LLM finishes a turn, extracts conversation text, filters
 * for capturable content, and sends to Walrus Memory's analyze() endpoint
 * for server-side fact extraction.
 */

import type { MemWal } from "@mysten-incubation/memwal";
import { resolveAgent } from "../config.js";
import { shouldCapture } from "../capture.js";
import {
  extractMessages,
  parseMessageTimestamp,
  withRetry,
  withTimeout,
  type ExtractedMessage,
} from "../format.js";
import type { PluginConfig } from "../types.js";

const MAX_TRACKED_MESSAGES_PER_SCOPE = 1_000;

interface ScopeCaptureState {
  /** Message keys already sent to a successful `analyze()` call. */
  capturedKeys: Set<string>;
  /** Creation / first-seen timestamp per message key so retries across midnight keep their original date. */
  firstSeenAt: Map<string, Date>;
  /** Currently running `analyze()` promise for this scope, if any. */
  inFlight: Promise<unknown> | null;
}

function rememberBoundedKey<T>(setOrMap: Set<string> | Map<string, T>, key: string, value?: T): void {
  if (setOrMap instanceof Set) {
    if (!setOrMap.has(key) && setOrMap.size >= MAX_TRACKED_MESSAGES_PER_SCOPE) {
      const oldest = setOrMap.values().next().value;
      if (oldest !== undefined) setOrMap.delete(oldest);
    }
    setOrMap.add(key);
  } else {
    if (!setOrMap.has(key) && setOrMap.size >= MAX_TRACKED_MESSAGES_PER_SCOPE) {
      const oldest = setOrMap.keys().next().value;
      if (oldest !== undefined) setOrMap.delete(oldest);
    }
    setOrMap.set(key, value as T);
  }
}

/** Register the agent_end hook for auto-capture. */
export function registerCaptureHook(api: any, client: MemWal, config: PluginConfig): void {
  const stateByScope = new Map<string, ScopeCaptureState>();

  function getScopeState(scopeKey: string): ScopeCaptureState {
    let state = stateByScope.get(scopeKey);
    if (!state) {
      state = {
        capturedKeys: new Set<string>(),
        firstSeenAt: new Map<string, Date>(),
        inFlight: null,
      };
      stateByScope.set(scopeKey, state);
    }
    return state;
  }

  api.on("agent_end", async (event: any, ctx: any) => {
    if (!event.success || !event.messages?.length) return;

    const { namespace, agentName } = resolveAgent(config.defaultNamespace, ctx?.sessionKey);
    const scopeKey = `${namespace}\0${ctx?.sessionKey ?? ""}`;
    const state = getScopeState(scopeKey);

    try {
      // Extract both user and assistant messages — the server LLM on analyze()
      // decides what's worth keeping. Assistant messages can contain user
      // commitments, decisions, and summaries that are valuable as memories.
      const extracted = extractMessages(
        event.messages,
        config.captureMaxMessages,
      );

      if (!extracted.length) return;

      const eventTimestamp =
        parseMessageTimestamp(event.occurredAt) ??
        parseMessageTimestamp(event.createdAt) ??
        parseMessageTimestamp(event.created_at) ??
        parseMessageTimestamp(event.timestamp);

      // Record creation / first-seen timestamp for every message in the window
      // before filtering or network calls, so any later retry after midnight
      // still anchors to when the message was created rather than hook retry time.
      const now = new Date();
      for (const msg of extracted) {
        if (!state.firstSeenAt.has(msg.key)) {
          rememberBoundedKey(
            state.firstSeenAt,
            msg.key,
            msg.occurredAt ?? eventTimestamp ?? now,
          );
        }
      }

      // Filter individual messages for capturable content and skip messages
      // already captured on an earlier turn (GH #1106).
      const capturable = extracted.filter((m) => shouldCapture(m.text));
      if (!capturable.length) {
        api.logger.debug?.(
          `memory-memwal: auto-capture skipped — no capturable content ` +
          `(agent: ${agentName}, ${extracted.length} messages checked)`,
        );
        return;
      }

      const uncaptured = capturable.filter((m) => !state.capturedKeys.has(m.key));
      if (!uncaptured.length) {
        api.logger.debug?.(
          `memory-memwal: auto-capture skipped — all ${capturable.length} capturable messages already captured ` +
          `(agent: ${agentName}, namespace: ${namespace})`,
        );
        return;
      }

      // Do not start a second paid extraction for a scope whose previous
      // extraction is still running on the server after a timeout (GH #1095).
      if (state.inFlight) {
        api.logger.debug?.(
          `memory-memwal: auto-capture skipped — previous analyze() still in flight ` +
          `(agent: ${agentName}, namespace: ${namespace})`,
        );
        return;
      }

      // Group uncaptured messages by their UTC calendar date so messages
      // created on different days never share a single shifted occurredAt anchor.
      const batches = new Map<string, { occurredAt: Date; items: ExtractedMessage[] }>();
      for (const msg of uncaptured) {
        const msgTime = msg.occurredAt ?? state.firstSeenAt.get(msg.key) ?? eventTimestamp ?? now;
        const dayKey = msgTime.toISOString().slice(0, 10);
        let batch = batches.get(dayKey);
        if (!batch) {
          batch = { occurredAt: msgTime, items: [] };
          batches.set(dayKey, batch);
        }
        batch.items.push(msg);
      }

      let totalFacts = 0;
      for (const batch of batches.values()) {
        // Numbered list helps the server LLM distinguish separate messages
        // during fact extraction (vs one big wall of text)
        const conversation = batch.items
          .map((m, i) => `${i + 1}. ${m.text}`)
          .join("\n\n");

        const result = await withRetry(() =>
          withTimeout(
            (signal) => {
              const p = client.analyze(conversation, {
                namespace,
                occurredAt: batch.occurredAt,
                ...(signal ? { signal } : {}),
              });
              state.inFlight = p;
              p.then(
                () => {
                  if (state.inFlight === p) state.inFlight = null;
                },
                () => {
                  if (state.inFlight === p) state.inFlight = null;
                },
              );
              return p;
            },
            config.requestTimeoutMs,
            "auto-capture",
          ),
        );

        for (const msg of batch.items) {
          rememberBoundedKey(state.capturedKeys, msg.key);
        }
        totalFacts += result?.facts?.length ?? 0;
      }

      if (totalFacts > 0) {
        api.logger.info(
          `memory-memwal: auto-captured ${totalFacts} facts ` +
          `(agent: ${agentName}, namespace: ${namespace})`,
        );
      }
    } catch (err) {
      api.logger.warn(
        `memory-memwal: auto-capture failed: ${String(err)}`,
      );
    }
  });
}
