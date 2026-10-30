import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { MemWalSession } from "../auth.js";
import { TOOL_METADATA } from "./annotations.js";
import { wrapTool } from "./util.js";

export interface NamespaceEntry {
    name: string;
    memory_count: number;
    storage_used?: number;
    updated_at?: string;
}

export interface NamespacesPage {
    namespaces: NamespaceEntry[];
    next_cursor?: string | null;
    has_more?: boolean;
}

const NAMESPACES_INPUT = {
    limit: z
        .number()
        .int()
        .min(1)
        .max(500)
        .default(100)
        .describe("Max number of namespaces to return per page (1-500)."),
    cursor: z
        .string()
        .min(1)
        .optional()
        .describe("Pagination cursor (`next_cursor` from a previous call)."),
} as const;

/**
 * Standard Levenshtein edit distance between two strings (case-folded).
 */
export function editDistance(a: string, b: string): number {
    const s = a.toLowerCase();
    const t = b.toLowerCase();
    if (s === t) return 0;
    if (s.length === 0) return t.length;
    if (t.length === 0) return s.length;

    const prev = new Array<number>(t.length + 1);
    const curr = new Array<number>(t.length + 1);
    for (let j = 0; j <= t.length; j++) prev[j] = j;

    for (let i = 1; i <= s.length; i++) {
        curr[0] = i;
        for (let j = 1; j <= t.length; j++) {
            const cost = s[i - 1] === t[j - 1] ? 0 : 1;
            curr[j] = Math.min(
                prev[j] + 1,
                curr[j - 1] + 1,
                prev[j - 1] + cost,
            );
        }
        for (let j = 0; j <= t.length; j++) prev[j] = curr[j];
    }
    return prev[t.length];
}

/**
 * Check whether `candidate` is a close typo/prefix/substring match for `target`.
 */
export function isCloseNamespaceMatch(target: string, candidate: string): boolean {
    const a = target.trim().toLowerCase();
    const b = candidate.trim().toLowerCase();
    if (!a || !b || a === b) return false;
    const dist = editDistance(a, b);
    if (dist <= 3) return true;
    if (a.length >= 3 && b.length >= 3 && (a.includes(b) || b.includes(a))) {
        return true;
    }
    return false;
}

function formatMemoryCount(count: number): string {
    return `${count} ${count === 1 ? "memory" : "memories"}`;
}

/**
 * Rank and partition non-empty namespaces relative to `targetNamespace`,
 * returning close matches first (ordered by edit distance, then memory count)
 * followed by remaining non-empty namespaces.
 */
export function rankNamespaceSuggestions(
    targetNamespace: string,
    namespaces: readonly NamespaceEntry[],
): { close: NamespaceEntry[]; others: NamespaceEntry[] } {
    const nonEmpty = namespaces.filter(
        (ns) =>
            typeof ns?.name === "string" &&
            ns.name.length > 0 &&
            ns.name !== targetNamespace &&
            typeof ns.memory_count === "number" &&
            ns.memory_count > 0,
    );

    const close: NamespaceEntry[] = [];
    const others: NamespaceEntry[] = [];
    for (const ns of nonEmpty) {
        if (isCloseNamespaceMatch(targetNamespace, ns.name)) {
            close.push(ns);
        } else {
            others.push(ns);
        }
    }

    close.sort((x, y) => {
        const d = editDistance(targetNamespace, x.name) - editDistance(targetNamespace, y.name);
        if (d !== 0) return d;
        return y.memory_count - x.memory_count;
    });
    others.sort((x, y) => y.memory_count - x.memory_count);

    return { close, others };
}

/**
 * Format the suggestion suffix when an agent queries or restores an empty or
 * misspelled namespace while other namespaces on the account hold memories.
 */
export function formatNamespaceSuggestionHint(
    targetNamespace: string,
    namespaces: readonly NamespaceEntry[],
    maxListed = 5,
): string {
    const { close, others } = rankNamespaceSuggestions(targetNamespace, namespaces);
    if (close.length === 0 && others.length === 0) {
        return "";
    }

    const parts: string[] = [];
    if (close.length > 0) {
        const top = close.slice(0, 3);
        if (top.length === 1) {
            parts.push(
                `Did you mean namespace "${top[0].name}" (${formatMemoryCount(top[0].memory_count)})?`,
            );
        } else {
            const formatted = top
                .map((ns) => `"${ns.name}" (${formatMemoryCount(ns.memory_count)})`)
                .join(", ");
            parts.push(`Did you mean: ${formatted}?`);
        }
    }

    const combined = [...close, ...others].slice(0, maxListed);
    const listStr = combined
        .map((ns) => `"${ns.name}" (${ns.memory_count})`)
        .join(", ");
    const moreCount = close.length + others.length - combined.length;
    const moreSuffix = moreCount > 0 ? `, +${moreCount} more` : "";
    parts.push(`Existing namespaces: ${listStr}${moreSuffix}.`);

    return parts.join(" ");
}

export interface DiscoveredNamespaces {
    namespaces: NamespaceEntry[];
    has_more: boolean;
}

/**
 * Best-effort call to `session.memwal.listNamespaces()`.
 * Paginate until `targetNamespace` is found or pagination completes,
 * up to `maxPages` pages. Never throws so unit tests with partial stubs
 * or older relayers degrade gracefully without failing callers.
 */
export async function tryListNamespaces(
    session: MemWalSession | undefined,
    targetNamespaceOrLimit?: string | number,
    limit = 50,
    maxPages = 5,
): Promise<DiscoveredNamespaces | null> {
    const fn = (
        session?.memwal as
            | { listNamespaces?: (opts?: { limit?: number; cursor?: string }) => Promise<NamespacesPage> }
            | undefined
    )?.listNamespaces;
    if (typeof fn !== "function") return null;

    const targetNamespace =
        typeof targetNamespaceOrLimit === "string" ? targetNamespaceOrLimit : undefined;
    const pageSize =
        typeof targetNamespaceOrLimit === "number" ? targetNamespaceOrLimit : limit;

    try {
        const all: NamespaceEntry[] = [];
        let cursor: string | undefined;
        let hasMore = false;
        for (let pageIdx = 0; pageIdx < maxPages; pageIdx++) {
            const page = await fn.call(session!.memwal, { limit: pageSize, cursor });
            if (!page || !Array.isArray(page.namespaces)) return null;
            all.push(...page.namespaces);
            hasMore = page.has_more === true;
            if (!hasMore || !page.next_cursor) {
                break;
            }
            if (targetNamespace && page.namespaces.some((ns) => ns.name === targetNamespace)) {
                break;
            }
            cursor = page.next_cursor;
        }
        return { namespaces: all, has_more: hasMore };
    } catch {
        return null;
    }
}

/**
 * Format the output of `memwal_namespaces`.
 */
export function formatNamespacesResult(page: NamespacesPage): string {
    const nonEmpty = (page.namespaces ?? []).filter(
        (ns) => typeof ns?.name === "string" && (ns.memory_count ?? 0) > 0,
    );
    if (nonEmpty.length === 0) {
        return "No namespaces with stored memories found for this account.";
    }
    const lines = [
        `Namespaces (${nonEmpty.length}${page.has_more ? "+" : ""}):`,
        ...nonEmpty.map((ns) => {
            const bytes =
                typeof ns.storage_used === "number"
                    ? `, storage_used=${ns.storage_used}B`
                    : "";
            const updated =
                typeof ns.updated_at === "string" && ns.updated_at.length >= 10
                    ? `, updated=${ns.updated_at.slice(0, 10)}`
                    : "";
            return `- "${ns.name}": ${formatMemoryCount(ns.memory_count)}${bytes}${updated}`;
        }),
    ];
    if (page.has_more && page.next_cursor) {
        lines.push(`\nMore namespaces available (next_cursor="${page.next_cursor}").`);
    }
    return lines.join("\n");
}

/**
 * memwal_namespaces — list namespaces that hold memories for this account.
 */
export function registerNamespacesTool(
    server: McpServer,
    session: MemWalSession,
): void {
    server.registerTool(
        "memwal_namespaces",
        {
            ...TOOL_METADATA.memwal_namespaces,
            description:
                "List the namespaces that hold memories in this Walrus Memory account, with each namespace's memory count and storage used (metadata only, no decryption). Call this when memwal_recall or memwal_restore reports 0 memories in a namespace, or when connecting to an unfamiliar account so you can discover existing namespaces instead of guessing.",
            inputSchema: NAMESPACES_INPUT,
        },
        wrapTool<{ limit: number; cursor?: string }>(
            session,
            "memwal_namespaces",
            async ({ limit, cursor }) => {
                const page = await session.memwal.listNamespaces({ limit, cursor });
                return {
                    content: [
                        {
                            type: "text",
                            text: formatNamespacesResult(page),
                        },
                    ],
                };
            },
        ),
    );
}
