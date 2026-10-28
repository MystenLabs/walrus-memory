import type { AskOptions, AskParams, RecallOptions, RecallParams } from "./types.js";

/** String second argument is a namespace, not options. */
export function resolveLimitOrOptions<T extends { limit?: number; namespace?: string }>(
    method: string,
    limitOrOptions: number | T | undefined | null,
    namespace?: string,
    defaultLimit = 10,
): T {
    if (limitOrOptions == null) {
        return { limit: defaultLimit, namespace } as T;
    }
    if (typeof limitOrOptions === "number") {
        return { limit: limitOrOptions, namespace } as T;
    }
    if (typeof limitOrOptions === "object" && !Array.isArray(limitOrOptions)) {
        // Positional namespace fills an options object that omitted it.
        // An explicit options.namespace still wins, and the caller's object
        // is never mutated. (#1038)
        if (limitOrOptions.namespace === undefined && namespace !== undefined) {
            return { ...limitOrOptions, namespace } as T;
        }
        return limitOrOptions;
    }
    throw new TypeError(invalidSecondArgMessage(method));
}

function invalidSecondArgMessage(method: string): string {
    const firstArg = method === "ask" ? "question" : "query";
    const shared =
        `${method}() second argument must be a number (limit) or an options object, not a string. ` +
        `Namespace belongs in an options object (${method}(${firstArg}, { namespace })) or as the third argument (${method}(${firstArg}, limit, namespace)).`;
    if (method === "recall") {
        return `${shared} Preferred form: recall({ query, namespace }).`;
    }
    if (method === "ask") {
        return `${shared} Preferred form: ask({ question, namespace }).`;
    }
    return shared;
}

/** Normalize object-style and positional `recall()` arguments. */
export function resolveRecallCall(
    queryOrParams: string | RecallParams,
    limitOrOptions?: number | RecallOptions | null,
    namespace?: string,
): { query: string; options: RecallOptions } {
    if (
        queryOrParams !== null &&
        typeof queryOrParams === "object" &&
        !Array.isArray(queryOrParams)
    ) {
        const { query, ...rest } = queryOrParams;
        return { query, options: rest };
    }
    if (typeof queryOrParams !== "string") {
        throw new TypeError(
            "recall() first argument must be a query string or a RecallParams object.",
        );
    }
    return {
        query: queryOrParams,
        options: resolveLimitOrOptions("recall", limitOrOptions, namespace),
    };
}

/** Normalize object-style and positional `ask()` arguments. */
export function resolveAskCall(
    questionOrParams: string | AskParams,
    limitOrOptions?: number | AskOptions | null,
    namespace?: string,
): { question: string; options: AskOptions } {
    if (
        questionOrParams !== null &&
        typeof questionOrParams === "object" &&
        !Array.isArray(questionOrParams)
    ) {
        const { question, ...rest } = questionOrParams;
        return { question, options: rest };
    }
    if (typeof questionOrParams !== "string") {
        throw new TypeError(
            "ask() first argument must be a question string or an AskParams object.",
        );
    }
    return {
        question: questionOrParams,
        options: resolveLimitOrOptions("ask", limitOrOptions, namespace, 5),
    };
}
