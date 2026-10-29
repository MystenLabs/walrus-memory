import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { MemWalSession } from "../auth.js";
import { TOOL_METADATA } from "./annotations.js";
import {
    formatNamespaceSuggestionHint,
    tryListNamespaces,
    type NamespaceEntry,
} from "./namespaces.js";
import { wrapTool } from "./util.js";

const RECALL_INPUT = {
    query: z
        .string()
        .min(1)
        .refine((v) => v.trim().length > 0, "Query cannot be empty.")
        .describe("Natural-language search query to match against stored memories."),
    limit: z
        .number()
        .int()
        .min(1)
        .max(100)
        .default(10)
        .describe("Max number of memories to return (1-100)."),
    namespace: z
        .string()
        .optional()
        .describe(
            "Optional namespace bucket to search within. Defaults to the session's namespace."
        ),
    maxDistance: z
        .number()
        .nonnegative()
        .optional()
        .describe(
            "Optional cosine-distance cutoff (low = similar; 0 = identical). Hits with distance >= maxDistance are dropped. Omit to apply no cutoff. Displayed score is 1 - distance (high = similar); do not treat score as the cutoff."
        ),
} as const;

/** Key deciding whether two results say the same thing: trimmed, internal
 * whitespace collapsed, case-folded. Deliberately exact-after-normalization
 * rather than fuzzy or embedding-based — collapsing two facts that merely
 * resemble each other would silently hide real information. Near-duplicate
 * merging, if ever wanted, belongs behind an explicit opt-in. */
function dedupeKey(text: string): string {
    return text.trim().replace(/\s+/g, " ").toLowerCase();
}

/**
 * Collapse results carrying identical text, keeping the first occurrence.
 *
 * `recall` returns rows ranked best-first, so the survivor is the highest
 * scoring copy.
 *
 * Storing the same fact twice is legitimate: each write is a distinct event
 * with its own blob and timestamp, and there is no content-level uniqueness
 * constraint by design (the only unique index is request idempotency on
 * `remember_jobs (owner, idempotency_key)`). So this does NOT touch the write
 * path. But returning N identical lines spends the model's entire retrieval
 * budget on one fact and crowds out everything else it asked for, which is a
 * read-side problem worth fixing on the read side.
 */
export function collapseDuplicates<T extends { text: string }>(
    results: T[],
): { unique: T[]; collapsed: number } {
    const seen = new Map<string, T>();
    for (const item of results) {
        const key = dedupeKey(item.text);
        if (!seen.has(key)) seen.set(key, item);
    }
    const unique = [...seen.values()];
    return { unique, collapsed: results.length - unique.length };
}

/**
 * Drop hits whose cosine distance is at or above `maxDistance`.
 *
 * Same polarity as the SDK: cosine distance is low-is-similar, keep
 * `distance < maxDistance`. Omit `maxDistance` (or pass a non-number) to
 * leave the list unchanged.
 *
 * TODO(WALM-428): drop this once the sidecar SDK pin moves off 0.0.3 — 0.1.x
 * applies the identical filter inside `recall({ maxDistance })`.
 */
export function filterByMaxDistance<T extends { distance: number }>(
    results: T[],
    maxDistance?: number,
): T[] {
    if (typeof maxDistance !== "number") return results;
    return results.filter((memory) => memory.distance < maxDistance);
}

/**
 * Empty-result copy after the maxDistance filter.
 *
 * Decrypted hits that all missed the cutoff are not a download/decrypt
 * failure, so the decrypt copy must not claim the whole result. But an
 * undecrypted match never had a distance computed, so the cutoff copy cannot
 * speak for it either: when both counts are non-zero, say both rather than
 * letting "outside maxDistance" imply the namespace held nothing relevant.
 */
export function emptyRecallText(
    resultCount: number,
    dropped: number,
    namespaceContext?: {
        activeNamespace: string;
        namespaces: readonly NamespaceEntry[];
        has_more?: boolean;
    },
): string {
    if (resultCount > 0) {
        const unchecked =
            dropped > 0
                ? ` (${dropped} further ${dropped === 1 ? "match was" : "matches were"} never checked against the cutoff: they failed to download or decrypt.)`
                : "";
        return `All matching memories were outside maxDistance.${unchecked}`;
    }
    if (dropped > 0) {
        return `No matching memories could be returned (${dropped} matched but failed to download or decrypt). This is not an empty namespace.`;
    }
    if (namespaceContext) {
        const { activeNamespace, namespaces, has_more } = namespaceContext;
        const activeEntry = namespaces.find((ns) => ns.name === activeNamespace);
        if (activeEntry) {
            if (activeEntry.memory_count === 0) {
                const hint = formatNamespaceSuggestionHint(activeNamespace, namespaces);
                return `No matching memories found (namespace "${activeNamespace}" currently holds 0 memories).${hint ? ` ${hint}` : ""}`;
            }
            return `No matching memories found in namespace "${activeNamespace}" (0 matches among ${activeEntry.memory_count} ${activeEntry.memory_count === 1 ? "memory" : "memories"}).`;
        }
        if (has_more) {
            return `No matching memories found in namespace "${activeNamespace}".`;
        }
        const hint = formatNamespaceSuggestionHint(activeNamespace, namespaces);
        return `No matching memories found (namespace "${activeNamespace}" currently holds 0 memories).${hint ? ` ${hint}` : ""}`;
    }
    return "No matching memories found.";
}

/**
 * Render one recall hit as the line the model sees.
 *
 * `created_at` is the memory's write-time, shown so a model implementing
 * "current state = the newest checkpoint" can order by it directly instead of
 * inferring recency from rank — results are ranked by semantic distance, which
 * carries no recency guarantee (WALM-383).
 *
 * The date is emitted as a bare ISO `YYYY-MM-DD` so string comparison and
 * chronological order agree. Time-of-day is dropped: it costs tokens on every
 * line and same-day checkpoint collisions are rare enough that the model can
 * fall back to rank when two dates tie.
 *
 * An absent or unparseable `created_at` renders no date at all. Both "unknown"
 * and a substituted current date would be worse — the first is noise on every
 * line for older relayers, the second is a wrong answer a newest-wins caller
 * would act on.
 */
export function formatRecallLine(
    memory: { text: string; distance: number; created_at?: unknown },
    index: number,
): string {
    const score = (1 - memory.distance).toFixed(3);
    const distance = memory.distance.toFixed(3);
    const written = isoDateOrNull(memory.created_at);
    const stamp = written ? ` [written=${written}]` : "";
    return `${index + 1}. [score=${score} distance=${distance}]${stamp} ${memory.text}`;
}

/** `YYYY-MM-DD` for a parseable timestamp, else null. */
function isoDateOrNull(value: unknown): string | null {
    if (typeof value !== "string") return null;
    const ms = Date.parse(value);
    if (Number.isNaN(ms)) return null;
    return new Date(ms).toISOString().slice(0, 10);
}

/**
 * memwal_recall — semantic search over the user's Walrus Memory memories.
 *
 * Returns top-K most relevant memories (cosine distance over embeddings),
 * with the original plaintext decrypted server-side via SEAL.
 *
 * Call this PROACTIVELY at the start of a task, or whenever the user
 * references past work, prior decisions, or their preferences — don't wait
 * to be asked.
 */
export function registerRecallTool(
    server: McpServer,
    session: MemWalSession
): void {
    server.registerTool(
        "memwal_recall",
        {
            ...TOOL_METADATA.memwal_recall,
            description:
                "Search the user's Walrus Memory for relevant facts before responding. Call this PROACTIVELY at the start of a task, or whenever the user references past work, prior decisions, their preferences, or anything you may have stored earlier — don't wait to be asked. A single focused query is usually enough — recall is a real retrieval over encrypted storage, so do NOT fire multiple redundant searches for the same question. Returns matching memories ranked by semantic relevance, NOT by date: the most recent memory can fall outside `limit` when an older one happens to match your wording more literally, so do not treat the results as a complete or current view of a namespace. Each result carries `written=YYYY-MM-DD`, the date the memory was saved (not any date its text mentions) — check it rather than assuming the top result is the latest.",
            inputSchema: RECALL_INPUT,
        },
        wrapTool<{ query: string; limit: number; namespace?: string; maxDistance?: number }>(session, "memwal_recall", async ({ query, limit, namespace, maxDistance }) => {
            const result = await session.memwal.recall(query, limit, namespace);
            const droppedRaw = (result as { dropped_count?: unknown }).dropped_count;
            const dropped = typeof droppedRaw === "number" ? droppedRaw : 0;
            const filtered = filterByMaxDistance(result.results, maxDistance);
            if (filtered.length === 0) {
                const activeNamespace =
                    namespace?.trim() || session.namespace?.trim() || "default";
                const discovery =
                    result.results.length === 0 && dropped === 0
                        ? await tryListNamespaces(session, activeNamespace, 50)
                        : null;
                return {
                    content: [
                        {
                            type: "text",
                            text: emptyRecallText(
                                result.results.length,
                                dropped,
                                discovery
                                    ? {
                                          activeNamespace,
                                          namespaces: discovery.namespaces,
                                          has_more: discovery.has_more,
                                      }
                                    : undefined,
                            ),
                        },
                    ],
                };
            }
            const { unique, collapsed } = collapseDuplicates(filtered);
            const lines = unique.map((m, i) => formatRecallLine(m, i));
            // Say what was folded away rather than quietly returning fewer rows
            // than the caller asked for. It also surfaces that the same fact was
            // stored repeatedly, which is usually worth knowing.
            if (collapsed > 0) {
                lines.push(
                    `\n(${collapsed} duplicate ${collapsed === 1 ? "copy" : "copies"} of the above collapsed; the same fact is stored more than once.)`
                );
            }
            if (dropped > 0) {
                lines.push(
                    `\n(${dropped} additional matches could not be decrypted and were omitted.)`,
                );
            }
            return {
                content: [
                    {
                        type: "text",
                        text: lines.join("\n"),
                    },
                ],
            };
        })
    );
}
