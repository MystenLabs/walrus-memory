import type { ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";

interface RemoteToolMetadata {
    title: string;
    annotations: ToolAnnotations;
}

/** Metadata surfaced to MCP clients through `tools/list`. */
export const TOOL_METADATA = {
    memwal_remember: {
        title: "Remember a Fact",
        annotations: { readOnlyHint: false, destructiveHint: false },
    },
    memwal_remember_bulk: {
        title: "Remember Multiple Facts",
        annotations: { readOnlyHint: false, destructiveHint: false },
    },
    memwal_remember_status: {
        title: "Check a Remember Job",
        // Reads the state of a write already in flight; starts no new work.
        annotations: { readOnlyHint: true, destructiveHint: false },
    },
    memwal_analyze: {
        title: "Analyze and Remember",
        // Context recall may remove stale vector rows for blobs confirmed absent.
        annotations: { readOnlyHint: false, destructiveHint: true },
    },
    memwal_restore: {
        title: "Restore Memory Index",
        annotations: { readOnlyHint: false, destructiveHint: false },
    },
    memwal_recall: {
        title: "Recall Memories",
        // Search. Stale-row cleanup when a Walrus blob is already gone is
        // incidental; advertising destructiveHint would make clients gate the
        // proactive recall this tool exists to encourage.
        annotations: { readOnlyHint: true, destructiveHint: false },
    },
    memwal_namespaces: {
        title: "List Memory Namespaces",
        annotations: { readOnlyHint: true, destructiveHint: false },
    },
    memwal_health: {
        title: "Check Walrus Memory Health",
        annotations: { readOnlyHint: true, destructiveHint: false },
    },
} as const satisfies Record<string, RemoteToolMetadata>;
