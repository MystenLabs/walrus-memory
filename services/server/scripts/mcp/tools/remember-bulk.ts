import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { MemWalSession } from "../auth.js";
import { TOOL_METADATA } from "./annotations.js";
import { wrapTool, explorerFooter } from "./util.js";
import { SECRET_EXCLUSION_RULES, AUTO_SAVE_OPT_IN_RULE } from "./memory-policy.js";
import {
    sanitizeFactBatch,
    redactionNotice,
    refusalMessage,
    type RedactionKind,
} from "./redaction.js";
import {
    REMEMBER_POLL_INTERVAL_MS,
    REMEMBER_WAIT_MS,
    pendingBulkMessage,
    withAcceptDeadline,
    withWaitDeadline,
    withRelayerRetry,
    isStillRunning,
} from "./remember-wait.js";

const REMEMBER_BULK_INPUT = {
    facts: z
        .array(z.string().min(1))
        .min(1)
        .max(20)
        .describe(
            "Array of complete, detailed fact statements to save (1-20). Each entry is one full fact — do not summarize or merge them. Leave credentials out: passwords, API keys, tokens, private keys, seed phrases, auth headers and URLs with an embedded user:password are stripped from each entry before the write and never stored."
        ),
    namespace: z
        .string()
        .optional()
        .describe(
            "Optional namespace bucket applied to every fact. Defaults to the session's namespace when omitted."
        ),
    _idempotency_key: z
        .string()
        .optional()
        .describe("Bridge-injected replay dedup key — agents should not set this."),
} as const;

/**
 * memwal_remember_bulk — persist several durable facts in one batched request.
 *
 * Mirrors `memwal_remember`: returns once every job reaches a terminal state
 * if that happens inside `REMEMBER_WAIT_MS`, and otherwise hands back the
 * job_ids saying plainly that the facts are not saved yet.
 *
 * Blocking here was worse than blocking on a single fact, not better. The
 * server instructions steer an agent to this tool whenever it learned more
 * than one thing, so it is the common path — and a batch is N separate Walrus
 * writes contending for the same upload slots
 * (`WALRUS_UPLOAD_PER_WALLET_CONCURRENCY` defaults to 1), so they land one
 * after another rather than together. Against a 30–75s single-write spread a
 * five-fact batch could exhaust the old fixed 120s budget outright and return
 * nothing but timeouts, having blocked the agent for two minutes first.
 */
export function registerRememberBulkTool(
    server: McpServer,
    session: MemWalSession
): void {
    server.registerTool(
        "memwal_remember_bulk",
        {
            ...TOOL_METADATA.memwal_remember_bulk,
            description:
                "Save multiple durable facts in one call. Use when you learned several distinct facts at once (onboarding details, a list of preferences, decisions from a discussion). Pass an array of complete fact statements (max 20) — do not summarize. Prefer this over repeated memwal_remember calls. By default this returns in ~1s once the relayer has accepted the batch (job_ids) — the Walrus writes are still in flight and the facts are NOT stored yet. Do not claim they are saved. Resolve with memwal_remember_status(job_ids). blob_ids in the same reply mean they landed inside an optional wait budget (MEMWAL_MCP_REMEMBER_WAIT_MS). " +
                AUTO_SAVE_OPT_IN_RULE +
                " " +
                SECRET_EXCLUSION_RULES +
                " Walrus storage is append-only: a stored secret cannot be deleted, so each entry is stripped of credential shapes before writing and entries that are nothing but a secret are dropped, with a note saying which. The batch is screened as a whole, so splitting a credential's label into one entry and its value into another does not get it past the filter.",
            inputSchema: REMEMBER_BULK_INPUT,
        },
        wrapTool<{ facts: string[]; namespace?: string; _idempotency_key?: string }>(session, "memwal_remember_bulk", async ({ facts, namespace, _idempotency_key }) => {
            // Every entry is sanitized BEFORE the batch is handed to the SDK.
            // Walrus is append-only, so a credential that lands cannot be
            // taken back (WALM-642). An entry that survives keeps its safe
            // part; an entry that is only a secret — or that the user asked
            // not to save — is dropped from the batch rather than the whole
            // call failing, so the other facts still land.
            //
            // Screened as a BATCH, not entry by entry: every label-gated rule
            // searches a window inside one string, so a label in one entry and
            // its value in the next defeated all of them — including the one
            // that exists for MemWal's own delegate private key. See
            // `sanitizeFactBatch`.
            const screened = sanitizeFactBatch(facts).map((result, index) => ({
                index,
                result,
            }));
            const kept = screened.filter((s) => !s.result.refusal);
            const dropped = screened.filter((s) => s.result.refusal);
            const droppedNote = dropped.length
                ? `\n\nNOT SAVED (${dropped.length}): ` +
                  dropped
                      .map((d) => `#${d.index + 1} — ${refusalMessage(d.result.refusal!)}`)
                      .join("; ") +
                  ". Do not re-send those; restate any durable fact without the sensitive part instead."
                : "";

            if (kept.length === 0) {
                return {
                    content: [
                        {
                            type: "text" as const,
                            text:
                                `Nothing was saved to Walrus Memory: every fact in this batch was ` +
                                `withheld.${droppedNote}`,
                        },
                    ],
                };
            }

            const redactedKinds: RedactionKind[] = [];
            let redactedCount = 0;
            for (const s of kept) {
                redactedCount += s.result.count;
                for (const kind of s.result.kinds) {
                    if (!redactedKinds.includes(kind)) redactedKinds.push(kind);
                }
            }
            const policyNote =
                [redactionNotice(redactedKinds, redactedCount), droppedNote.trim()]
                    .filter(Boolean)
                    .join("\n\n");

            // The only texts anything below may echo or forward. The originals
            // still hold the secret and must not reach a result line.
            const safeFacts = kept.map((s) => s.result.text);
            const items = safeFacts.map((text) => ({ text, namespace }));
            // Two steps rather than `rememberBulkAndWait`, for the same reason
            // `memwal_remember` splits them: acceptance is the part that must
            // succeed, the wait is a courtesy we cut short.
            // TODO(#1045): forward _idempotency_key once the server
            // upgrades its SDK dep to workspace:* (published 0.1.7
            // lacks the second argument). Until then the key is
            // accepted but not forwarded, so dedup does not fire and
            // the endpoint is still non-idempotent.
            const accepted = await withAcceptDeadline(
                withRelayerRetry(
                    () => session.memwal.rememberBulkAsync(items),
                    "save these facts",
                ),
                "memwal_remember_bulk batch",
                { idempotent: false },
            );

            // Pair each job with its fact up front. Every later branch needs
            // it, and the relayer returns job_ids in input order.
            const entries = accepted.job_ids.map((jobId, i) => ({
                jobId,
                text: safeFacts[i] ?? "",
            }));

            const withNotice = (body: string) =>
                policyNote ? `${body}\n\n${policyNote}` : body;

            const pending = (waitedMs: number) => ({
                content: [
                    {
                        type: "text" as const,
                        text: withNotice(pendingBulkMessage(entries, waitedMs)),
                    },
                ],
            });

            if (REMEMBER_WAIT_MS === 0) return pending(0);

            const startedAt = Date.now();
            const namespaces = items.map(
                (item) => item.namespace ?? session.namespace ?? "default"
            );
            // `waitForRememberJobs` never throws on expiry — it reports the
            // stragglers as `timeout` per item, so a batch can come back part
            // landed and part still in flight. `withWaitDeadline` around it
            // does throw, though: a relayer that goes quiet mid-poll raises
            // MemWalRelayerUnresponsive, and letting that propagate discards
            // every job_id in the batch, leaving the caller nothing to settle
            // accepted writes with. `memwal_remember` already degrades to its
            // pending branch here; so does this.
            let result;
            try {
                result = await withWaitDeadline(
                    session.memwal.waitForRememberJobs(accepted.job_ids, namespaces, {
                        timeoutMs: REMEMBER_WAIT_MS,
                        pollIntervalMs: REMEMBER_POLL_INTERVAL_MS,
                    }),
                    REMEMBER_WAIT_MS,
                );
            } catch (err) {
                if (!isStillRunning(err)) throw err;
                return pending(Date.now() - startedAt);
            }
            const waitedMs = Date.now() - startedAt;

            const unfinished = result.results.flatMap((r, i) =>
                r.status === "timeout" ? [{ jobId: r.id, text: safeFacts[i] ?? "" }] : []
            );
            // Nothing landed inside the budget — the ordinary outcome when the
            // queue is busy. Say so once rather than printing N timeout rows.
            if (unfinished.length === result.results.length) return pending(waitedMs);

            const lines = result.results.map((r, i) => {
                // Label each result with its source fact by index. The SDK
                // returns results in input order, but guard against a length /
                // ordering mismatch so we never print "— undefined".
                // Echo sanitized text only (WALM-642) — never the original facts[].
                const text = safeFacts[i] ?? "";
                // Only a settled row may show a blob_id — see remember-status.ts
                // for why an unfinished write can already carry a real one.
                const blob = r.status === "done" && r.blob_id ? ` blob_id=${r.blob_id}` : "";
                const err = r.error ? ` error=${r.error}` : "";
                // `timeout` is not a failure — the write is still running and
                // its job_id is how the caller settles it later.
                const state = r.status === "timeout" ? `still uploading, job_id=${r.id}` : r.status;
                return `${i + 1}. [${state}]${blob}${err}${text ? ` — ${text}` : ""}`;
            });
            // `result.failed` is total-minus-succeeded, so it counts a
            // still-uploading write as failed — while the tail below says that
            // same job is on its way. An agent reading `failed=` re-sends an
            // in-flight write, which is the duplicate this branch exists to
            // avoid. Count only what actually reached a terminal failure.
            const reallyFailed = result.results.filter(
                (r) => r.status !== "done" && r.status !== "timeout",
            ).length;
            const summary =
                `Saved ${result.succeeded}/${result.total} fact(s) to Walrus Memory` +
                (reallyFailed ? ` (failed=${reallyFailed})` : "") +
                (unfinished.length ? ` (${unfinished.length} still uploading)` : "") +
                ".";
            const footer = result.succeeded > 0 ? `\n\n${explorerFooter()}` : "";
            const tail = unfinished.length
                ? `\n\n${unfinished.length} write(s) are STILL UPLOADING and are NOT saved yet. ` +
                  `Do not claim those facts are stored; resolve them with memwal_remember_status ` +
                  `using job_ids=[${unfinished.map((u) => u.jobId).join(", ")}]. Do not re-send ` +
                  `them — that queues duplicates behind the originals.`
                : "";
            return {
                content: [
                    {
                        type: "text",
                        text: withNotice(
                            (lines.length > 0
                                ? `${summary}\n\n${lines.join("\n")}${footer}`
                                : `${summary}${footer}`) + tail,
                        ),
                    },
                ],
            };
        })
    );
}
