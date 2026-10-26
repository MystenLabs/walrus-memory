/**
 * =============================================================================
 * Walrus Memory MCP — Express mount
 * =============================================================================
 * Exposes `mountMcpRoutes(app)` which attaches `/mcp/sse` + `/mcp/messages`
 * to the sidecar's existing express app. The Rust relayer proxies external
 * `/api/mcp/*` traffic to these internal sidecar routes (same pattern as
 * walrus/seal proxy).
 *
 * Each authenticated client gets its own McpServer + SSEServerTransport. The
 * sidecar stays single-process; sessions are in-memory.
 *
 * Required headers on `/mcp/sse`:
 *   Authorization: Bearer <ed25519-private-key-hex>     (64 hex)
 *   X-MemWal-Account-Id: 0x<sui-object-id>             (66 chars)
 *   X-MemWal-Namespace: <optional namespace default>
 * =============================================================================
 */
import { json, type Request, type Response, type Router } from "express";
import { randomUUID } from "node:crypto";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import type { AuthResolution, MemWalSession } from "./auth.js";
import { McpAuthError, resolveAuth } from "./auth.js";
import {
    applyAgentClient,
    applyAgentClientFromServer,
    CLIENT_NAME_HEADER,
    CLIENT_VERSION_HEADER,
} from "./agent-client.js";
import { createLogger } from "./logger.js";
import { createMcpServer } from "./server.js";
import { MCP_MAX_REQUEST_BODY_BYTES } from "./limits.js";
import { McpRateLimiter, clientIpFromRequest } from "./rateLimit.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const log = createLogger("mcp");
const parseSseBody = json({ limit: MCP_MAX_REQUEST_BODY_BYTES, strict: false });

// Global limiter — caps concurrent MCP sessions per source IP and total. The
// limiter MUST run BEFORE resolveAuth() so a flood of forged bearers cannot
// hold long-lived SSE / streamable transports.
//
// Lazy-initialized: constructed on first use so the limits reflect the
// process.env state at request time (ESM hoists `import` above any top-level
// `process.env.X = ...` assignments in callers — eager init at module load
// would freeze the limits to whatever env existed when this module was
// first evaluated).
let _rateLimiter: McpRateLimiter | null = null;
function rateLimiter(): McpRateLimiter {
    if (_rateLimiter === null) {
        _rateLimiter = new McpRateLimiter();
    }
    return _rateLimiter;
}

function rateLimitDeny(
    res: Response,
    reason: NonNullable<ReturnType<McpRateLimiter["acquire"]>["reason"]>,
    retryAfterSeconds: number | undefined
): void {
    if (retryAfterSeconds && retryAfterSeconds > 0) {
        res.setHeader("retry-after", String(retryAfterSeconds));
    }
    const message =
        reason === "ip_active_cap" || reason === "global_cap"
            ? `MCP rate limit: ${reason}. Close another MCP session, then retry.`
            : `MCP rate limit: ${reason}. Try again in ${retryAfterSeconds ?? 30}s.`;
    res.status(429).json({
        jsonrpc: "2.0",
        error: {
            code: -32000,
            message,
        },
        id: null,
    });
}

interface McpConnection {
    sessionKey: string;
    session: MemWalSession;
    server: McpServer;
    transport: SSEServerTransport;
    cleanup: () => void;
}

/** transport.sessionId → connection. Multiple sessions per delegate are allowed
 * so concurrent MCP clients (Claude Code + Claude.app + Cursor) that share the
 * same delegate key do not evict each other. */
const sessionsById = new Map<string, McpConnection>();

/**
 * Streamable HTTP transport sessions, keyed by the `mcp-session-id` header.
 * Separate from `sessionsById` (which is keyed by SSE transport ids) — the
 * two namespaces never collide because they live on different routes
 * (`/mcp/sse` vs `/mcp`).
 */
interface StreamableConnection {
    sessionKey: string;
    session: MemWalSession;
    server: McpServer;
    transport: StreamableHTTPServerTransport;
    cleanup: () => void;
    lastActiveMs: number;
}

function headerToken(req: Request, name: string): string | null {
    const raw = req.headers[name];
    return typeof raw === "string" ? raw : null;
}

function agentClientFromHeaders(req: Request): {
    name: string | null;
    version: string | null;
} {
    return {
        name: headerToken(req, CLIENT_NAME_HEADER),
        version: headerToken(req, CLIENT_VERSION_HEADER),
    };
}

function identifyConnection(
    server: McpServer,
    session: MemWalSession,
    req: Request,
    fields: Record<string, unknown>,
): void {
    applyAgentClientFromServer(server, session, agentClientFromHeaders(req), fields);
}
const streamableSessions = new Map<string, StreamableConnection>();

/** Abandoned streamable sessions pin per-IP slots until DELETE. Reap idle ones. */
const STREAMABLE_IDLE_MS = 15 * 60_000;
const idleReaper = setInterval(() => {
    const now = Date.now();
    for (const [id, conn] of streamableSessions) {
        if (now - conn.lastActiveMs <= STREAMABLE_IDLE_MS) continue;
        log.info("session.idle_closed", {
            transport: "streamable",
            transportId: id,
        });
        void Promise.resolve(conn.transport.close()).catch(() => conn.cleanup());
        conn.cleanup();
    }
}, 60_000);
idleReaper.unref?.();

function rpcError(res: Response, status: number, message: string): void {
    res.status(status).json({
        jsonrpc: "2.0",
        error: { code: status === 401 ? -32001 : -32603, message },
        id: null,
    });
}

function expressHeadersToWeb(req: Request): Headers {
    const h = new Headers();
    for (const [k, v] of Object.entries(req.headers)) {
        if (Array.isArray(v)) {
            for (const item of v) h.append(k, item);
        } else if (typeof v === "string") {
            h.set(k, v);
        }
    }
    return h;
}

async function handleSse(
    req: Request,
    res: Response,
    relayerUrl: string,
    publicRelayerUrl: string | undefined
): Promise<void> {
    // Rate limit BEFORE resolveAuth — see comment on `rateLimiter` above.
    // resolveAuth only checks header shape, so we must cap concurrent SSE
    // sessions before allocating a transport / heartbeat / proxy stream.
    const limiter = rateLimiter();
    const ip = clientIpFromRequest(req);
    const slot = limiter.acquire(ip);
    if (!slot.ok) {
        log.warn("session.rate_limited", {
            transport: "sse",
            ip,
            reason: slot.reason,
        });
        return rateLimitDeny(res, slot.reason!, slot.retryAfterSeconds);
    }
    const releaseSlot = limiter.releaseFn(ip);

    let auth: AuthResolution;
    try {
        auth = await resolveAuth(expressHeadersToWeb(req), relayerUrl, publicRelayerUrl);
    } catch (err) {
        releaseSlot();
        if (err instanceof McpAuthError) {
            res.setHeader(
                "www-authenticate",
                'Bearer realm="memwal", error="invalid_token"'
            );
            return rpcError(res, err.status, err.message);
        }
        return rpcError(
            res,
            500,
            err instanceof Error ? err.message : String(err)
        );
    }

    // No eviction on same {account, delegate}: multiple MCP clients sharing
    // the same delegate key (Claude Code + Claude.app + Cursor on one
    // machine) must coexist. Each SSE open = independent session keyed by
    // transport.sessionId; POST /messages routes by that id directly.

    // POST endpoint path that SSE clients send messages to. Must match
    // what the Rust relayer exposes externally so the client builds the
    // correct URL. We expose `/api/mcp/messages` publicly; the relayer
    // proxies it to sidecar's `/mcp/messages`. The SSE transport puts
    // this path into the `endpoint` event verbatim.
    const transport = new SSEServerTransport("/api/mcp/messages", res);
    const server = createMcpServer(auth.session);

    // SSE keep-alive — long-running tool calls (remember can take 20-30s
    // for Walrus upload) leave the SSE stream idle. Without bytes flowing,
    // intermediary TCP keep-alives (Node undici on the client, reqwest on
    // the Rust proxy, NAT routers) drop the connection. We push a comment
    // line every 3s so the stream stays warm. Comment lines (`:` prefix)
    // are ignored by the SSE parser per HTML5 EventSource § 9.2.6.
    let beatN = 0;
    const writeHeartbeat = () => {
        if (res.writableEnded) return;
        try {
            res.write(`:keepalive ${++beatN} ${Date.now()}\n\n`);
            (res as { flush?: () => void }).flush?.();
        } catch {
            /* socket already closed — next tick the close handler will tear down */
        }
    };
    // Fire one almost-immediately to confirm the stream is bidirectional
    // before going idle. Subsequent beats every 3s.
    setTimeout(writeHeartbeat, 200);
    const heartbeat = setInterval(writeHeartbeat, 3_000);
    heartbeat.unref?.();

    // Idempotent cleanup tied to THIS transport.
    let cleanedUp = false;
    const cleanup = () => {
        if (cleanedUp) return;
        cleanedUp = true;
        clearInterval(heartbeat);
        sessionsById.delete(transport.sessionId);
        releaseSlot();
        log.info("session.closed", {
            sessionKey: auth.sessionKey,
            transportId: transport.sessionId,
            agentClient: auth.session.agentClient ?? null,
        });
    };

    res.on("close", cleanup);
    transport.onclose = cleanup;

    sessionsById.set(transport.sessionId, {
        sessionKey: auth.sessionKey,
        session: auth.session,
        server,
        transport,
        cleanup,
    });

    // Headers are a best-effort hint (auth-required handoff / reconnect).
    // The first SSE GET usually has none; identity is logged on
    // session.identified once the handshake (or a later header) lands.
    applyAgentClient(auth.session, agentClientFromHeaders(req), {
        transport: "sse",
        transportId: transport.sessionId,
        sessionKey: auth.sessionKey,
    });

    log.info("session.opened", {
        sessionKey: auth.sessionKey,
        accountId: auth.session.accountId,
        delegatePubKey: auth.session.delegatePubKeyHex,
        transportId: transport.sessionId,
    });

    await server.connect(transport);
}

async function handlePostMessage(
    req: Request,
    res: Response,
    relayerUrl: string,
    publicRelayerUrl: string | undefined
): Promise<void> {
    const sessionId = typeof req.query.sessionId === "string" ? req.query.sessionId : undefined;
    if (!sessionId) {
        return rpcError(res, 400, "Missing sessionId query parameter");
    }
    const conn = sessionsById.get(sessionId);
    if (!conn) {
        return rpcError(res, 404, `Unknown sessionId ${sessionId}`);
    }

    let auth: AuthResolution;
    try {
        auth = await resolveAuth(expressHeadersToWeb(req), relayerUrl, publicRelayerUrl);
    } catch (err) {
        if (err instanceof McpAuthError) {
            res.setHeader(
                "www-authenticate",
                'Bearer realm="memwal", error="invalid_token"'
            );
            return rpcError(res, err.status, err.message);
        }
        return rpcError(
            res,
            500,
            err instanceof Error ? err.message : String(err)
        );
    }

    if (conn.sessionKey !== auth.sessionKey) {
        log.warn("session.auth_mismatch", {
            transport: "sse",
            transportId: sessionId,
        });
        return rpcError(
            res,
            403,
            "sessionId does not match authenticated caller"
        );
    }

    // Parse only after authentication and session ownership have succeeded.
    // The legacy SSE transport has no configurable body cap; pass a bounded
    // parsed body instead of letting it read the stream a second time.
    if (!req.is("application/json")) {
        return rpcError(res, 400, "Expected application/json");
    }
    const parsed = await new Promise<boolean>((resolve) => {
        parseSseBody(req, res, (err?: { status?: number }) => {
            if (err) {
                const status = err.status === 413 ? 413 : 400;
                rpcError(res, status, status === 413 ? "MCP request body too large" : "Invalid JSON body");
                resolve(false);
                return;
            }
            resolve(true);
        });
    });
    if (!parsed) return;

    applyAgentClient(conn.session, agentClientFromHeaders(req), {
        transport: "sse",
        transportId: sessionId,
        sessionKey: conn.sessionKey,
    });
    await conn.transport.handlePostMessage(req, res, req.body);
    identifyConnection(conn.server, conn.session, req, {
        transport: "sse",
        transportId: sessionId,
        sessionKey: conn.sessionKey,
    });
}

/**
 * Streamable HTTP transport (MCP 2025-06). One endpoint, three methods:
 *   - POST /mcp  →  client → server JSON-RPC + optional SSE upgrade for the response
 *   - GET  /mcp  →  open server → client SSE stream (long-polling fallback)
 *   - DELETE /mcp  →  end the named session
 *
 * The session lifecycle: the first POST without an `mcp-session-id` header
 * triggers a fresh session (transport's `sessionIdGenerator` mints a UUID).
 * Subsequent requests carry `mcp-session-id: <uuid>` so we route to the
 * same transport instance. On DELETE, the transport closes and we evict.
 */
async function handleStreamableHttp(
    req: Request,
    res: Response,
    relayerUrl: string,
    publicRelayerUrl: string | undefined
): Promise<void> {
    // 1) Auth — bearer + accountId same as SSE path. Cheap to re-run per
    //    request; resolveAuth's on-chain lookup is cached by the SDK once
    //    we mint the Walrus Memory client per session.
    let auth: AuthResolution;
    try {
        auth = await resolveAuth(expressHeadersToWeb(req), relayerUrl, publicRelayerUrl);
    } catch (err) {
        if (err instanceof McpAuthError) {
            res.setHeader(
                "www-authenticate",
                'Bearer realm="memwal", error="invalid_token"'
            );
            return rpcError(res, err.status, err.message);
        }
        return rpcError(
            res,
            500,
            err instanceof Error ? err.message : String(err)
        );
    }

    // 2) Find or create the transport for this `mcp-session-id`. Missing
    //    header on a POST = brand-new session (the SDK assigns one on the
    //    response). Missing header on GET/DELETE = client error.
    const sessionIdHeader = req.headers["mcp-session-id"];
    const sessionId =
        typeof sessionIdHeader === "string" ? sessionIdHeader : undefined;

    const conn = sessionId ? streamableSessions.get(sessionId) : undefined;

    if (conn) {
        // Bind the session id to the bearer/account that opened it. Without
        // this check, anyone who learns the `mcp-session-id` UUID can drive
        // an existing transport under their own (or random) credentials.
        // The session key embeds {accountId, delegatePubKey}, so a
        // mismatch means a different caller is trying to reuse the session.
        if (conn.sessionKey !== auth.sessionKey) {
            log.warn("session.auth_mismatch", {
                transport: "streamable",
                transportId: sessionId,
                expected: conn.sessionKey,
                got: auth.sessionKey,
            });
            return rpcError(
                res,
                403,
                "mcp-session-id does not match authenticated caller"
            );
        }
        conn.lastActiveMs = Date.now();
        // Stamp from headers first when present. Handshake identity is
        // applied after handleRequest because the SDK only exposes
        // clientInfo once initialize has been processed; a request that
        // both initializes and calls a tool can therefore emit tool.call
        // before session.identified.
        applyAgentClient(conn.session, agentClientFromHeaders(req), {
            transport: "streamable",
            transportId: sessionId,
            sessionKey: conn.sessionKey,
        });
        await conn.transport.handleRequest(req, res);
        identifyConnection(conn.server, conn.session, req, {
            transport: "streamable",
            transportId: sessionId,
            sessionKey: conn.sessionKey,
        });
        return;
    }

    if (req.method !== "POST") {
        return rpcError(
            res,
            400,
            "missing mcp-session-id — open a new session with an initial POST"
        );
    }

    // New session — apply the same per-IP cap the SSE path uses BEFORE we
    // allocate a transport. Acquired here (after auth so logs are useful)
    // because we now know we will create a session, but BEFORE
    // `transport.handleRequest` so we don't kick off an upgrade we can't
    // sustain.
    const limiter = rateLimiter();
    const ip = clientIpFromRequest(req);
    const slot = limiter.acquire(ip);
    if (!slot.ok) {
        log.warn("session.rate_limited", {
            transport: "streamable",
            ip,
            reason: slot.reason,
        });
        return rateLimitDeny(res, slot.reason!, slot.retryAfterSeconds);
    }
    const releaseSlot = limiter.releaseFn(ip);

    // Spawn a fresh transport. `sessionIdGenerator` is invoked once on
    // the first message-init response; we cache the connection only
    // after we know the assigned id. Holder (not `let server!`) so a
    // future reorder of assign vs `onsessioninitialized` logs instead of
    // throwing a TDZ ReferenceError.
    let initialized = false;
    const holder: { server: McpServer | null } = { server: null };
    const transport = new StreamableHTTPServerTransport({
        maxRequestBodySize: MCP_MAX_REQUEST_BODY_BYTES,
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (newId: string) => {
            const server = holder.server;
            if (!server) {
                log.error("mcp.streamable_session_without_server", {
                    transportId: newId,
                });
                releaseSlot();
                return;
            }
            initialized = true;
            let cleanedUp = false;
            const cleanup = () => {
                if (cleanedUp) return;
                cleanedUp = true;
                streamableSessions.delete(newId);
                releaseSlot();
                log.info("session.closed", {
                    transport: "streamable",
                    sessionKey: auth.sessionKey,
                    transportId: newId,
                    agentClient: auth.session.agentClient ?? null,
                });
            };
            transport.onclose = cleanup;
            streamableSessions.set(newId, {
                sessionKey: auth.sessionKey,
                session: auth.session,
                server,
                transport,
                cleanup,
                lastActiveMs: Date.now(),
            });
            applyAgentClient(auth.session, agentClientFromHeaders(req), {
                transport: "streamable",
                transportId: newId,
                sessionKey: auth.sessionKey,
            });
            // Identity is logged on session.identified once known (headers
            // or handshake). Streamable init runs before the SDK stores
            // clientInfo, so agentClient is usually still empty here.
            log.info("session.opened", {
                transport: "streamable",
                sessionKey: auth.sessionKey,
                accountId: auth.session.accountId,
                delegatePubKey: auth.session.delegatePubKeyHex,
                transportId: newId,
            });
        },
    });

    // Belt-and-braces release: `releaseSlot` is one-shot, so wiring it to
    // every plausible terminal path is safe. `onsessioninitialized` overrides
    // `transport.onclose` with `cleanup` (which also calls releaseSlot), and
    // the catch below handles handleRequest throwing before init completes.
    transport.onclose = releaseSlot;

    holder.server = createMcpServer(auth.session);
    try {
        await holder.server.connect(transport);
        // The SDK's handleRequest takes the raw IncomingMessage. We
        // intentionally do NOT pre-parse the body — express.json() is not
        // mounted on this route so req still has the raw stream.
        // The transport reads the body itself.
        await transport.handleRequest(req, res);
        identifyConnection(holder.server, auth.session, req, {
            transport: "streamable",
            transportId: transport.sessionId ?? null,
            sessionKey: auth.sessionKey,
        });
        if (!initialized) {
            releaseSlot();
            await transport.close().catch((err) => {
                log.warn("mcp.streamable_uninitialized_close_failed", {
                    err: err instanceof Error ? err.message : String(err),
                });
            });
        }
    } catch (err) {
        releaseSlot();
        throw err;
    }
}

export interface MountMcpOptions {
    /**
     * Relayer base URL that tool calls hit. Default: `http://127.0.0.1:3001`
     * — loopback, because that is where the relayer this sidecar belongs to
     * listens. Pointing it at a public origin sends every tool call out of
     * the process and back through the edge.
     */
    relayerUrl?: string;
    /**
     * The relayer's public origin, when the deployment states one. Reported by
     * `memwal_health` as the network the session is bound to. Deliberately
     * separate from `relayerUrl`, which is only the address the sidecar dials
     * and is loopback on every deployment that does not override it.
     */
    publicRelayerUrl?: string;
}

/**
 * Attach MCP routes to a sidecar express app. The relayer proxies external
 * `/api/mcp/*` traffic to these internal `/mcp/*` routes.
 *
 *   GET  /mcp/sse              open SSE stream (auth required)
 *   POST /mcp/messages         JSON-RPC messages (auth is re-checked and
 *                              bound to the session opener)
 */
export function mountMcpRoutes(
    // `Router`, not `Express`: this only ever calls `.get` / `.post` /
    // `.delete`, all of which `Router` provides, and `Express` extends
    // `Router` so existing app-level callers are unaffected. Typing it as
    // `Express` rejected the `express.Router()` the integration test mounts.
    app: Router,
    options: MountMcpOptions = {}
): void {
    const relayerUrl = options.relayerUrl ?? "http://127.0.0.1:3001";
    const publicRelayerUrl = options.publicRelayerUrl;

    app.get("/mcp/sse", async (req, res) => {
        try {
            await handleSse(req, res, relayerUrl, publicRelayerUrl);
        } catch (err) {
            log.error("mcp.sse.error", {
                err: err instanceof Error ? err.message : String(err),
            });
            if (!res.headersSent) {
                rpcError(res, 500, err instanceof Error ? err.message : String(err));
            }
        }
    });

    app.post(
        "/mcp/messages",
        // Body parsing runs inside handlePostMessage, after session auth.
        async (req, res) => {
            try {
                await handlePostMessage(req, res, relayerUrl, publicRelayerUrl);
            } catch (err) {
                log.error("mcp.post.error", {
                    err: err instanceof Error ? err.message : String(err),
                });
                if (!res.headersSent) {
                    rpcError(res, 500, err instanceof Error ? err.message : String(err));
                }
            }
        }
    );

    // Streamable HTTP transport (MCP 2025-06 spec) — single endpoint that
    // supersedes the SSE+POST split. Auth on every request because the
    // transport is stateless across HTTP requests; the bearer is cheap to
    // re-validate (one Sui RPC lookup, cached in resolveAuth).
    //
    // The endpoint accepts GET (open SSE stream for server→client),
    // POST (JSON-RPC envelopes both directions), and DELETE (close
    // session). All three are routed through the same handler — the
    // SDK's `transport.handleRequest()` figures out which based on
    // req.method.
    const streamableHandler = async (req: Request, res: Response) => {
        try {
            await handleStreamableHttp(req, res, relayerUrl, publicRelayerUrl);
        } catch (err) {
            log.error("mcp.streamable.error", {
                err: err instanceof Error ? err.message : String(err),
            });
            if (!res.headersSent) {
                rpcError(res, 500, err instanceof Error ? err.message : String(err));
            }
        }
    };
    app.get("/mcp", streamableHandler);
    app.post("/mcp", streamableHandler);
    app.delete("/mcp", streamableHandler);

    log.info("mcp.routes.mounted", {
        routes: [
            "GET /mcp/sse",
            "POST /mcp/messages",
            "GET|POST|DELETE /mcp (streamable HTTP)",
        ],
        relayerUrl,
        publicRelayerUrl: publicRelayerUrl ?? null,
    });
}

/** Active session count for /healthz observability. */
export function getMcpSessionCount(): number {
    return sessionsById.size + streamableSessions.size;
}

/** Gracefully close all active MCP transports during sidecar shutdown. */
export async function shutdownMcpSessions(): Promise<void> {
    log.info("mcp.shutting_down", { active_sessions: getMcpSessionCount() });
    for (const conn of sessionsById.values()) {
        try {
            await conn.transport.close();
        } catch (err) {
            log.warn("mcp.session.close_failed", {
                sessionKey: conn.sessionKey,
                err: err instanceof Error ? err.message : String(err),
            });
        }
    }
    for (const conn of streamableSessions.values()) {
        try {
            await conn.transport.close();
        } catch (err) {
            log.warn("mcp.streamable_session.close_failed", {
                sessionKey: conn.sessionKey,
                err: err instanceof Error ? err.message : String(err),
            });
        }
    }
}

// Re-export auth + tool types so sidecar can introspect if needed.
export type { MemWalSession } from "./auth.js";
export { McpAuthError, resolveAuth } from "./auth.js";
