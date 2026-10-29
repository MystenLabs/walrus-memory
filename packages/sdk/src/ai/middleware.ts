/**
 * Walrus Memory AI SDK Integration — withMemWal Middleware
 *
 * Wraps any AI SDK model with automatic memory management.
 *
 * @example
 * ```typescript
 * import { generateText } from "ai"
 * import { withMemWal } from "@mysten-incubation/memwal/ai"
 * import { openai } from "@ai-sdk/openai"
 *
 * const model = withMemWal(openai("gpt-4o"), {
 *   key: process.env.MEMWAL_PRIVATE_KEY,  // Ed25519 delegate private key (hex)
 * })
 *
 * const result = await generateText({
 *   model,
 *   messages: [{ role: "user", content: "What do you know about me?" }]
 * })
 * // → Automatically searches memories, injects context, saves new facts
 * ```
 */

import type { LanguageModelV2 } from "@ai-sdk/provider";
import { wrapLanguageModel } from "ai";
import { MemWal } from "../memwal.js";
import type { MemWalConfig, RecallMemory } from "../types.js";
import {
    formatUntrustedMemories,
    memoryRelevance,
    UNTRUSTED_MEMORY_SYSTEM_INSTRUCTION,
} from "./untrusted-memory.js";

// ============================================================
// Config
// ============================================================

/**
 * Accept both LanguageModelV2 (ai SDK v4/v5) and LanguageModelV3 (ai SDK v6+).
 * We use `any` because LanguageModelV3 may not exist in older @ai-sdk/provider,
 * and the two interfaces are structurally incompatible at the type level.
 * `wrapLanguageModel` from `ai` handles version detection internally.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyLanguageModel = any;

export interface WithMemWalOptions extends MemWalConfig {
    /** Max memories to inject per request (default: 5) */
    maxMemories?: number;
    /** Token budget for recalled memories injected per request. Maps to recall({ maxTokens }). */
    maxTokens?: number;
    /** Auto-save new facts from conversation (default: true) */
    autoSave?: boolean;
    /** Minimum similarity score to include a memory (0-1, default: 0.3) */
    minRelevance?: number;
    /** Enable debug logging (default: false) */
    debug?: boolean;
    /** Optional callback invoked when memory recall fails during transformParams */
    onRecallError?: (error: unknown) => void;
    /** Called when a background auto-save fails. The chat turn still returns.
     * `flush()` also rejects, so a caller waiting on the write can see it. */
    onSaveError?: (error: unknown) => void;
}

// ============================================================
// Middleware
// ============================================================

/**
 * Maximum UTF-8 byte length sent by `withMemWal` to `recall()`.
 * Matches the relayer embedder's `MAX_EMBED_INPUT_BYTES` (16,384 bytes).
 */
export const MAX_EMBED_INPUT_BYTES = 16_384;

/**
 * Maximum UTF-8 byte length sent by `withMemWal` to `analyze()`.
 * Matches the relayer's `MAX_ANALYZE_TEXT_BYTES` (65,536 bytes / 64 KiB).
 */
export const MAX_ANALYZE_INPUT_BYTES = 65_536;

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder();

function sliceUtf8Prefix(encoded: Uint8Array, maxBytes: number): string {
    let end = Math.min(maxBytes, encoded.byteLength);
    // In UTF-8, continuation bytes match 0b10xxxxxx ((byte & 0xc0) === 0x80).
    // Step back to the leading byte so we never slice mid-codepoint.
    while (end > 0 && (encoded[end]! & 0xc0) === 0x80) {
        end--;
    }
    return utf8Decoder.decode(encoded.subarray(0, end));
}

function sliceUtf8Suffix(encoded: Uint8Array, maxBytes: number): string {
    let start = Math.max(0, encoded.byteLength - maxBytes);
    // In UTF-8, continuation bytes match 0b10xxxxxx ((byte & 0xc0) === 0x80).
    // Step forward to the start of the next codepoint so we never slice mid-codepoint.
    while (start < encoded.byteLength && (encoded[start]! & 0xc0) === 0x80) {
        start++;
    }
    return utf8Decoder.decode(encoded.subarray(start));
}

export interface TruncateUtf8Options {
    /**
     * Truncation strategy:
     * - `head`: retains the start of the text up to maxBytes.
     * - `head-tail`: retains both the start and end of the text joined by `\n...\n`,
     *   ensuring questions or instructions placed at the end of large pasted context
     *   are preserved for embedding and similarity search.
     * Defaults to `head`.
     */
    strategy?: "head" | "head-tail";
}

/**
 * Bound `text` to at most `maxBytes` UTF-8 bytes without splitting a
 * multi-byte UTF-8 codepoint across the boundary. (#1037)
 */
export function truncateUtf8Bytes(
    text: string,
    maxBytes: number = MAX_EMBED_INPUT_BYTES,
    options?: TruncateUtf8Options,
): string {
    const encoded = utf8Encoder.encode(text);
    if (encoded.byteLength <= maxBytes) {
        return text;
    }

    if (options?.strategy === "head-tail") {
        const separator = "\n...\n";
        const separatorBytes = 5;
        if (maxBytes <= separatorBytes + 4) {
            return sliceUtf8Prefix(encoded, maxBytes);
        }

        let workingEncoded = encoded;
        if (text.startsWith(" ") || text.startsWith("\t") || text.startsWith("\n")) {
            const trimmed = text.trimStart();
            if (trimmed.length > 0) {
                const trimmedEncoded = utf8Encoder.encode(trimmed);
                if (trimmedEncoded.byteLength <= maxBytes) {
                    return trimmed;
                }
                workingEncoded = trimmedEncoded;
            }
        }

        const available = maxBytes - separatorBytes;
        const headBytes = Math.floor(available / 2);
        const tailBytes = available - headBytes;
        const head = sliceUtf8Prefix(workingEncoded, headBytes);
        const tail = sliceUtf8Suffix(workingEncoded, tailBytes);
        return `${head}${separator}${tail}`;
    }

    const truncated = sliceUtf8Prefix(encoded, maxBytes);
    if (truncated.trim().length === 0) {
        const trimmed = text.trimStart();
        if (trimmed.length > 0) {
            const trimmedEncoded = utf8Encoder.encode(trimmed);
            return trimmedEncoded.byteLength <= maxBytes
                ? trimmed
                : sliceUtf8Prefix(trimmedEncoded, maxBytes);
        }
    }
    return truncated;
}

/**
 * Wrap an AI SDK model with Walrus Memory management
 *
 * BEFORE each LLM call:
 * - Uses the last user message as a search query (bounded to 16 KiB UTF-8)
 * - Recalls relevant memories (server: search → download → decrypt)
 * - Injects relevant memories as nonce-delimited, untrusted user data
 *
 * AFTER each LLM call:
 * - Analyzes and saves important facts (server: LLM extract → embed → encrypt → Walrus → store)
 * - Fire-and-forget — does not block the response
 */
export function withMemWal(
    model: AnyLanguageModel,
    options: WithMemWalOptions
) {
    const memwal = MemWal.create(options);
    const maxMemories = options.maxMemories ?? 5;
    const maxTokens = options.maxTokens;
    const autoSave = options.autoSave ?? true;
    const minRelevance = options.minRelevance ?? 0.3;
    const debug = options.debug ?? false;

    const log = debug
        ? (...args: unknown[]) => console.warn("[Walrus Memory]", ...args)
        : () => { };

    // Fire-and-forget auto-save writes are tracked here so short-lived
    // callers (CLI scripts, serverless handlers) can await them via
    // flush() before the process exits, instead of losing them silently.
    const pendingSaves = new Set<Promise<unknown>>();
    const saveFailures: string[] = [];
    let notingFailure = 0;
    // Tool steps rebuild the prompt without the memory injected on step 1.
    // Keep that recall and put it back, instead of calling recall again.
    let cachedRecall: { key: string; context: string } | null = null;

    function saveInBackground(userMessage: string): void {
        const boundedMessage = truncateUtf8Bytes(userMessage, MAX_ANALYZE_INPUT_BYTES);
        const savePromise = memwal
            .analyze(boundedMessage)
            .catch((err: unknown) => {
                log("Auto-save failed:", err);
                if (saveFailures.length < 8) {
                    const name = err instanceof Error ? err.name : "Error";
                    const message = err instanceof Error ? err.message.split("\n")[0] : "";
                    saveFailures.push(message ? `${name}: ${message}` : name);
                }
                notingFailure += 1;
                try {
                    options.onSaveError?.(err);
                } catch (callbackError) {
                    console.warn("[Walrus Memory] onSaveError threw:", callbackError);
                } finally {
                    notingFailure -= 1;
                }
            });
        pendingSaves.add(savePromise);
        savePromise.finally(() => pendingSaves.delete(savePromise));
    }

    const wrapped = (wrapLanguageModel as any)({
        model,
        middleware: {
            specificationVersion: 'v3', // Required by ai SDK v6+; ignored by v4/v5
            // ============================================================
            // BEFORE: Search memories + inject into prompt
            // ============================================================
            transformParams: async ({ params }: { params: { prompt?: unknown } }) => {
                try {
                    const turnKey = lastUserTurnKey(params.prompt);
                    if (!turnKey) return params;

                    // Tool steps reuse this turn, including a recall that
                    // matched nothing. A user message always recalls again, so
                    // a later fact is not stuck behind the first result.
                    if (
                        cachedRecall &&
                        cachedRecall.key === turnKey &&
                        !isPromptEndingWithUser(params.prompt)
                    ) {
                        if (!cachedRecall.context) return params;
                        return {
                            ...params,
                            prompt: injectMemoryContext(params.prompt, cachedRecall.context),
                        };
                    }

                    const lastUserMessage = findLastUserMessage(params.prompt);
                    if (!lastUserMessage) return params;

                    const recallQuery = truncateUtf8Bytes(lastUserMessage, MAX_EMBED_INPUT_BYTES, {
                        strategy: "head-tail",
                    });
                    const recallResult =
                        maxTokens !== undefined
                            ? await memwal.recall({ query: recallQuery, limit: maxMemories, maxTokens })
                            : await memwal.recall(recallQuery, maxMemories);
                    const relevant = recallResult.results.filter((m: RecallMemory) => {
                        const relevance = memoryRelevance(m?.distance);
                        return relevance !== null && relevance >= minRelevance;
                    });
                    if (relevant.length === 0) {
                        cachedRecall = { key: turnKey, context: "" };
                        return params;
                    }

                    const memoryContext = formatUntrustedMemories(relevant);
                    cachedRecall = { key: turnKey, context: memoryContext };
                    log(`🔍 Found ${relevant.length} relevant memories`);
                    return {
                        ...params,
                        prompt: injectMemoryContext(params.prompt, memoryContext),
                    };
                } catch (error) {
                    console.warn("[Walrus Memory] Recall failed during transformParams:", error);
                    try {
                        options.onRecallError?.(error);
                    } catch (cbError) {
                        console.warn("[Walrus Memory] onRecallError callback threw:", cbError);
                    }
                    return params;
                }
            },

            // ============================================================
            // AFTER: Analyze and save important facts (fire-and-forget)
            // ============================================================
            wrapGenerate: async ({ doGenerate, params }: any) => {
                const result = await doGenerate();

                // Only auto-save on the first step of a user turn, not on
                // intermediate tool steps where the last message is tool/assistant.
                if (autoSave && isPromptEndingWithUser(params.prompt)) {
                    const userMessage = findLastUserMessage(params.prompt);
                    if (userMessage) {
                        saveInBackground(userMessage);
                    }
                }

                return result;
            },

            // Stream variant — needed for streamText()
            wrapStream: async ({ doStream, params }: any) => {
                const result = await doStream();

                // Only auto-save on the first step of a user turn, not on
                // intermediate tool steps where the last message is tool/assistant.
                if (autoSave && isPromptEndingWithUser(params.prompt)) {
                    const userMessage = findLastUserMessage(params.prompt);
                    if (userMessage) {
                        saveInBackground(userMessage);
                    }
                }

                return result;
            },
        },
    });

    wrapped.specificationVersion = model.specificationVersion;

    // Lets short-lived callers await outstanding auto-save writes before
    // exiting, e.g. `await model.flush()` right before `process.exit()`.
    wrapped.flush = async (): Promise<void> => {
        if (notingFailure === 0) {
            await Promise.allSettled([...pendingSaves]);
        }
        if (notingFailure > 0 || saveFailures.length === 0) return;
        const errors = saveFailures.splice(0, saveFailures.length);
        const failure = new Error(
            `MemWal auto-save failed (${errors.length} call(s))`,
        );
        (failure as Error & { cause?: unknown }).cause = errors[0];
        throw failure;
    };

    return wrapped;
}

// ============================================================
// Helpers
// ============================================================

function findLastUserMessage(
    prompt: unknown
): string | null {
    if (!Array.isArray(prompt)) return null;

    for (let i = prompt.length - 1; i >= 0; i--) {
        const msg = prompt[i] as { role?: string; content?: unknown };
        if (msg.role === "user") {
            if (typeof msg.content === "string") return msg.content;
            if (Array.isArray(msg.content)) {
                const textParts = msg.content
                    .filter((p: any) => p.type === "text")
                    .map((p: any) => p.text);
                return textParts.join(" ") || null;
            }
        }
    }
    return null;
}

function isPromptEndingWithUser(prompt: unknown): boolean {
    if (!Array.isArray(prompt) || prompt.length === 0) return false;
    const lastMsg = prompt[prompt.length - 1] as { role?: string; content?: unknown };
    return lastMsg?.role === "user";
}

function lastUserTurnKey(prompt: unknown): string | null {
    if (!Array.isArray(prompt)) return null;
    for (let i = prompt.length - 1; i >= 0; i--) {
        const msg = prompt[i] as { role?: string };
        if (msg?.role !== "user") continue;
        const text = findLastUserMessage(prompt);
        return text ? `${i}\0${text}` : null;
    }
    return null;
}

export function injectMemoryContext(
    prompt: unknown,
    memoryContext: string
): unknown {
    if (!Array.isArray(prompt)) return prompt;

    // Keep the fixed trust policy in a system message, but recalled bytes only
    // in a separate user message. No memory-controlled text receives system
    // priority.
    const lastUserIndex = prompt.reduce(
        (idx: number, m: any, i: number) => (m.role === "user" ? i : idx),
        -1
    );

    const memoryMessage = {
        role: "user" as const,
        content: [{ type: "text" as const, text: memoryContext }],
    };

    const result = [...prompt];
    if (lastUserIndex > 0) {
        result.splice(lastUserIndex, 0, memoryMessage);
    } else {
        result.unshift(memoryMessage);
    }

    const leading = result[0] as { role?: string; content?: unknown };
    if (leading.role === "system") {
        result[0] = {
            ...leading,
            content: `${leading.content}\n\n${UNTRUSTED_MEMORY_SYSTEM_INSTRUCTION}`,
        };
    } else {
        result.unshift({
            role: "system" as const,
            content: UNTRUSTED_MEMORY_SYSTEM_INSTRUCTION,
        });
    }

    return result;
}
