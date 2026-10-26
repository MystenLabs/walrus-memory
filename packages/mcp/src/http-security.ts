/** Authenticated MCP requests must not forward credentials or bodies via redirects. */
export function fetchMcp(url: string, init: RequestInit): Promise<Response> {
    return fetch(url, { ...init, redirect: "error" });
}

export function ssePostUrl(relayerUrl: string, endpoint: string): string {
    const url = new URL(endpoint.startsWith("http") ? endpoint : `${relayerUrl.replace(/\/+$/, "")}${endpoint}`);
    if (url.origin !== new URL(relayerUrl).origin || url.username || url.password) {
        throw new Error("MCP SSE endpoint must stay on the configured relayer origin");
    }
    return url.href;
}
