import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { MemWalSession } from "../auth.js";
import { TOOL_METADATA } from "./annotations.js";
import { wrapTool, walruscanBlobUrl, normalizeMcpNamespace } from "./util.js";
import { SECRET_EXCLUSION_RULES, AUTO_SAVE_OPT_IN_RULE } from "./memory-policy.js";
import { sanitizeFact, redactionNotice, refusalNotice } from "./redaction.js";
import {
    REMEMBER_WAIT_MS,
    REMEMBER_POLL_INTERVAL_MS,
    isStillRunning,
    nameJobError,
    pendingMessage,
    withAcceptDeadline,
    withWaitDeadline,
    withRelayerRetry,
    derivedIdempotencyKey,
} from "./remember-wait.js";

const REMEMBER_INPUT = {
    text: z
        .string()
        .min(1)
        .describe(
            "The full, detailed fact to save. Pass the COMPLETE statement — do not summarize. Leave credentials out: passwords, API keys, tokens, private keys, seed phrases, auth headers and URLs with an embedded user:password are stripped before the write and never stored."
        ),
    namespace: z
        .string()
        .optional()
        .describe(
            "Optional namespace bucket. Defaults to the session's namespace when omitted."
        ),
} as const;

/**
 * memwal_remember — persist a durable fact to MemWal.
 *
 * Returns as soon as the blob is written end-to-end (embed → SEAL encrypt →
 * Walrus upload → on-chain) when that happens inside `REMEMBER_WAIT_MS`.
 * Otherwise it returns the job_id and says plainly that the fact is not saved
 * yet — see `remember-wait.ts` for why the old always-block behaviour cost
 * 30–75s per call.
 *
 * Call this PROACTIVELY whenever the user reveals a durable fact about
 * themselves or the project (preference, decision, constraint, correction,
 * identity, recurring workflow) — you do not need to be explicitly asked.
 * Skip one-off tasks, the current file or bug, and small talk.
 * For several facts at once, prefer `memwal_remember_bulk`.
 */
export function registerRememberTool(
    server: McpServer,
    session: MemWalSession
): void {
    server.registerTool(
        "memwal_remember",
        {
            ...TOOL_METADATA.memwal_remember,
            description:
                "Save a durable fact about the user or project to their Walrus Memory. Call this whenever the user states a preference, decision, constraint, correction, identity detail, or recurring workflow — PROACTIVELY, without being asked, when they have turned automatic memory on. Skip one-off tasks, the current file or bug, and small talk. Pass the full statement; do not summarize. To save several facts at once, use memwal_remember_bulk instead. By default this returns in ~1s once the relayer has accepted the job (job_id) — the Walrus write is still in flight and the fact is NOT stored yet. Do not claim it is saved. Resolve with memwal_remember_status. A blob_id in the same reply means it did land inside an optional wait budget (MEMWAL_MCP_REMEMBER_WAIT_MS). " +
                AUTO_SAVE_OPT_IN_RULE +
                " " +
                SECRET_EXCLUSION_RULES +
                " Walrus storage is append-only: a stored secret cannot be deleted, so this tool strips credential shapes from the text before writing and tells you what it removed.",
            inputSchema: REMEMBER_INPUT,
        },
        wrapTool<{ text: string; namespace?: string }>(session, "memwal_remember", async ({ text, namespace }) => {
            // Runs BEFORE anything reaches the SDK. Walrus is append-only, so a
            // credential that gets written cannot be taken back (WALM-642).
            const safe = sanitizeFact(text);
            if (safe.refusal) {
                return {
                    content: [
                        { type: "text" as const, text: refusalNotice(safe.refusal) },
                    ],
                };
            }
            const notice = redactionNotice(safe.kinds, safe.count);
            const safeText = safe.text;

            // Two steps rather than `rememberAndWait`, because the accept and
            // the wait need separate budgets: acceptance is the part that
            // must succeed, the wait is a courtesy we cut short.
            const cleanNamespace = normalizeMcpNamespace(namespace);
            const resolvedNamespace = cleanNamespace ?? session.namespace ?? "default";
            const accepted = await withAcceptDeadline(
                withRelayerRetry(
                    () =>
                        session.memwal.rememberAsync(safeText, cleanNamespace, {
                            // Ours, not the SDK's random one — see
                            // derivedIdempotencyKey. This is what makes the
                            // accept-timeout message's retry promise true.
                            // Keyed on the REDACTED text, so a retry of the
                            // same fact derives the same key.
                            idempotencyKey: derivedIdempotencyKey(resolvedNamespace, safeText),
                        }),
                    "save this fact",
                ),
                "memwal_remember write",
                { idempotent: true },
            );

            const withNotice = (body: string) =>
                notice ? `${body}\n\n${notice}` : body;

            const pending = (waitedMs: number) => ({
                content: [
                    {
                        type: "text" as const,
                        text: withNotice(pendingMessage(accepted.job_id, waitedMs)),
                    },
                ],
            });

            // A zero budget is the documented fire-and-accept mode. Skip the
            // wait entirely instead of entering a loop that cannot poll.
            if (REMEMBER_WAIT_MS === 0) return pending(0);

            const startedAt = Date.now();
            try {
                const result = await withWaitDeadline(
                    session.memwal.waitForRememberJob(accepted.job_id, {
                        timeoutMs: REMEMBER_WAIT_MS,
                        pollIntervalMs: REMEMBER_POLL_INTERVAL_MS,
                    }),
                    REMEMBER_WAIT_MS,
                );
                return {
                    content: [
                        {
                            type: "text" as const,
                            text: withNotice(
                                `Saved to Walrus Memory. blob_id=${result.blob_id} namespace=${result.namespace}\nExplorer: ${walruscanBlobUrl(result.blob_id)}`,
                            ),
                        },
                    ],
                };
            } catch (err) {
                // Still running at the deadline is the expected path, not a
                // failure — the job is durably accepted and keeps going.
                if (isStillRunning(err)) return pending(Date.now() - startedAt);
                throw nameJobError(err);
            }
        })
    );
}
