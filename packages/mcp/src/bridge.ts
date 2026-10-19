/**
 * stdio ↔ remote-SSE bridge.
 *
 * The MCP client (Cursor, Claude Desktop, etc.) speaks **stdio** MCP — JSON
 * lines on stdin, JSON lines on stdout. The Walrus Memory relayer speaks **remote
 * SSE** MCP at `/api/mcp/sse` + `/api/mcp/messages`. This module glues the
 * two together so the user only adds a `command + args` entry to their MCP
 * client config (no headers, no URL).
 *
 * On 401 from the relayer, we surface a clear error to the MCP client but
 * leave the local credentials file untouched. A naive `clearCreds()` here
 * was a creds-wipe DoS: anyone able to coerce a 401 response (transient WAF
 * rule, future http_proxy MITM, local malware racing the relayer port on
 * `--local`) would have wiped the user's saved seed without consent.
 * Re-auth requires an explicit `memwal-mcp login` from the user.
 */
import type { MemWalCredentials } from "./auth.js";
import { clearCreds, clearPendingLogin, credsPath, loadCreds } from "./auth.js";
import { TOOL_DEFINITIONS } from "./auth-required.js";
import {
    clientInfoHeaders,
    lastClientInfoHeaders,
    rememberInitializeClientInfo,
} from "./client-info.js";
import { randomUUID } from "node:crypto";
import { ensureCompatibleRelayer, resolveConnectTimeoutMs } from "./compatibility.js";
import {
    describeHealthProbe,
    probeRelayerHealth,
    resolveHealthProbeMs,
    type HealthProbe,
} from "./health-probe.js";
import { proactiveInstructions } from "./instructions.js";
import { startOrReuseLoginFlow, resolveLoginTimeoutMs, isLoginSuperseded } from "./login.js";
import { log, note } from "./logger.js";
import {
    loginPrompt,
    loginSuccessNotice,
    loginSuccessNotification,
    type LoginSuccessInfo,
} from "./messages.js";
import { openStreamableSession, resolveTransport } from "./streamable.js";
import { fetchMcp, ssePostUrl } from "./http-security.js";
import { MEMWAL_MCP_VERSION } from "./version.js";

/** Bridge mode runtime config — the URLs / label resolved at boot from
 * `--dev` / `--staging` / etc. Needed so `memwal_login` (re-auth) opens
 * the SAME dashboard the user originally signed in to, not the prod default. */
export interface BridgeConfig {
    relayerUrl: string;
    webUrl: string;
    label: string;
    /** Default memory namespace resolved at boot (`--namespace` /
     * `MEMWAL_NAMESPACE`). Injected into memory tool calls that omit a
     * namespace. Undefined → don't inject; the relayer applies its own
     * "default" namespace. */
    namespace?: string;
}

/** Memory tools that take a `namespace` argument. `memwal_remember`,
 * `memwal_remember_bulk`, `memwal_recall`, and `memwal_analyze` treat it as
 * optional; `memwal_restore` requires it (its upstream schema still lists
 * `namespace` as required, so agents normally pass one — but a configured
 * default is filled in if the agent calls it without). */
const NAMESPACE_TOOLS = new Set([
    "memwal_remember",
    "memwal_remember_bulk",
    "memwal_recall",
    "memwal_analyze",
    "memwal_restore",
]);

/**
 * Inject the configured default namespace into an outbound `tools/call`
 * message when the agent omitted one. Mutates `msg.params.arguments` in place
 * and returns `msg` (so it works inline before tracking/forwarding).
 *
 * No-op when:
 *   - no default namespace is configured (`namespace` falsy), or
 *   - the message is not a `tools/call` for a namespace-aware memory tool, or
 *   - the caller already supplied a non-empty `namespace` — an explicit
 *     per-call namespace always wins over the configured default.
 */
/**
 * Name the destination this process is bound to in a `memwal_health` result:
 * the relayer it dialled, and the account it signs for.
 *
 * The relayer-side text can only report an origin its deployment published, and
 * stays silent on a self-hosted or local one, where the sidecar knows nothing
 * but the loopback address it dials. This side always knows the URL it
 * connected to — it is exactly what `--prod` / `--relayer` / `MEMWAL_SERVER_URL`
 * selected — so a client bound to the wrong network sees that here instead of
 * by noticing its memories are missing.
 *
 * Rewrites an existing `relayer=` field rather than appending a second one: when
 * both sides know the origin they describe the same session, and two
 * conflicting fields would be worse than neither.
 *
 * `account=` rides along for the same reason (WALM-639). A project-local
 * credentials file can point this process at a different account than the one
 * the user signed in with, and "which account am I writing to" was otherwise
 * only visible in stderr the MCP host usually hides — so the half of the
 * destination that decides WHOSE memory this is now shows up beside the half
 * that decides where it is stored.
 */
export function annotateHealthResult(
    result: { content?: unknown; isError?: unknown },
    relayerUrl: string,
    accountId?: string,
): void {
    // A failed health call has no session to describe; naming a relayer beside
    // an error reads as though that relayer answered.
    if (result.isError) return;
    if (!Array.isArray(result.content)) return;
    const block = (result.content as { type?: string; text?: string }[]).find(
        (c) => c?.type === "text" && typeof c.text === "string",
    );
    if (!block || typeof block.text !== "string") return;
    const existing = /\brelayer=\S+/;
    block.text = existing.test(block.text)
        ? block.text.replace(existing, `relayer=${relayerUrl}`)
        : `${block.text} relayer=${relayerUrl}`;
    if (!accountId) return;
    const existingAccount = /\baccount=\S+/;
    block.text = existingAccount.test(block.text)
        ? block.text.replace(existingAccount, `account=${accountId}`)
        : `${block.text} account=${accountId}`;
}

/** Write tools whose replayed calls must carry an idempotency key so the
 * server can de-duplicate a reconnect replay that re-sends an already-accepted
 * request. The key is minted once per logical call and mutated into
 * `params.arguments` before the message is tracked in `inFlight`, so every
 * replay carries the same key the original POST used. */
const IDEMPOTENT_WRITE_TOOLS = new Set([
    "memwal_remember_bulk",
]);

/**
 * Inject a stable idempotency key into an outbound `tools/call` for a write
 * tool. Mutates `msg.params.arguments` in place — call BEFORE the message
 * is stored in `inFlight` so reconnect replays carry the same key.
 *
 * No-op when:
 *   - the message is not a `tools/call` for a write tool, or
 *   - the caller already supplied a `_idempotency_key`.
 */
export function applyIdempotencyKey(msg: RpcMessage): RpcMessage {
    if (msg.method !== "tools/call") return msg;
    const params = msg.params as
        | { name?: string; arguments?: Record<string, unknown> }
        | undefined;
    if (!params || typeof params.name !== "string" || !IDEMPOTENT_WRITE_TOOLS.has(params.name)) {
        return msg;
    }
    const args = (params.arguments ??= {});
    if (typeof args._idempotency_key === "string") return msg;
    args._idempotency_key = randomUUID();
    return msg;
}

export function applyDefaultNamespace(msg: RpcMessage, namespace?: string): RpcMessage {
    if (!namespace) return msg;
    if (msg.method !== "tools/call") return msg;
    const params = msg.params as
        | { name?: string; arguments?: Record<string, unknown> }
        | undefined;
    if (!params || typeof params.name !== "string" || !NAMESPACE_TOOLS.has(params.name)) {
        return msg;
    }
    const args = (params.arguments ??= {});
    const current = args.namespace;
    // Explicit, non-empty per-call namespace wins.
    if (typeof current === "string" && current.trim() !== "") return msg;
    args.namespace = namespace;
    return msg;
}

/** Tools we serve LOCALLY (not forwarded to the relayer) so the user can
 * re-auth or sign out without leaving the MCP client. The 4 memwal_*
 * tools registered on the relayer side still come from `tools/list`
 * upstream — we splice these in. */
const LOCAL_TOOL_DEFINITIONS = [
    {
        name: "memwal_login",
        description:
            "Sign in (or re-sign in) to Walrus Memory by opening a browser. Use to switch wallets, refresh credentials, or sign in for the first time. Returns a click-able URL — the user must approve in their browser.",
        inputSchema: {
            type: "object",
            properties: {
                freshKey: {
                    type: "boolean",
                    default: false,
                    description:
                        "Mint a new delegate key instead of reusing the one a previous unfinished sign-in left pending. Leave false for an ordinary login. Set it only after a normal sign-in has already failed on the pending key — it abandons that key, which must then be removed from the dashboard if it was approved on-chain, and the new one needs its own add_delegate_key transaction.",
                },
            },
            additionalProperties: false,
        },
    },
    {
        name: "memwal_logout",
        description:
            "Sign out of Walrus Memory: removes the saved credentials from this machine (~/.memwal/credentials.json) AND closes this connection's memory session, so memory tools stop working until you call memwal_login again. The on-chain delegate key registration is NOT revoked — visit the Walrus Memory dashboard to remove it from your account if needed.",
        inputSchema: {
            type: "object",
            properties: {},
            additionalProperties: false,
        },
    },
];

/** Protocol versions this local `initialize` responder can speak. We echo the
 * client's requested version when it's one of these, else fall back to our
 * baseline — the same negotiation shape a real MCP server does. */
const SUPPORTED_PROTOCOL_VERSIONS = new Set(["2024-11-05", "2025-03-26", "2025-06-18"]);
const FALLBACK_PROTOCOL_VERSION = "2024-11-05";

/** Build the `initialize` result we answer LOCALLY and instantly, before the
 * relayer session is up. Echoes the client's requested protocolVersion when we
 * support it (otherwise the baseline) instead of hard-coding one and ignoring
 * the request. `tools.listChanged: true` is a deliberate difference from
 * auth-required mode: the bridge serves a static `tools/list` at cold start and
 * then emits `notifications/tools/list_changed` once the background relayer
 * connect completes, so the client re-lists and picks up the real upstream tool
 * set. Advertising `listChanged: false` (as auth-required does, since it never
 * refreshes) would let a client ignore that notification. */
function buildLocalInitializeResult(params: unknown): {
    protocolVersion: string;
    capabilities: { tools: { listChanged: boolean } };
    serverInfo: { name: string; version: string };
    instructions: string;
} {
    const requested = (params as { protocolVersion?: unknown } | undefined)?.protocolVersion;
    const protocolVersion =
        typeof requested === "string" && SUPPORTED_PROTOCOL_VERSIONS.has(requested)
            ? requested
            : FALLBACK_PROTOCOL_VERSION;
    return {
        protocolVersion,
        capabilities: { tools: { listChanged: true } },
        serverInfo: { name: "memwal", version: MEMWAL_MCP_VERSION },
        // The relayer sets `instructions` too, but that reply never reaches the
        // client: this local answer wins and the upstream initialize reply is
        // suppressed. Omitting it here silently strips the proactive contract
        // from every stdio client, which is the WALM-324 regression itself.
        //
        // Resolved per handshake, not read from a module const: whether the
        // model is told to save unprompted depends on the user's automatic-save
        // opt-in, which lives on disk and can change between spawns (WALM-642).
        instructions: proactiveInstructions(),
    };
}

/** Names of the tools we serve locally, so we can de-dup them out of the
 * imported memory-tool list (which already carries its own `memwal_login`
 * entry) before appending our canonical definitions. */
const LOCAL_TOOL_NAMES = new Set(LOCAL_TOOL_DEFINITIONS.map((t) => t.name));

/** Reply for every memory tool call once `memwal_logout` has torn the session
 * down, and for anything still in flight at that moment. Names the way back in
 * so the client isn't left guessing why the tools stopped working. */
const SIGNED_OUT_TEXT =
    "❌ Signed out of Walrus Memory. Memory tools are unavailable on this connection until you call `memwal_login` again.";

/** `failRequest` options for every signed-out refusal, so a request refused at
 * logout time and one refused on arrival afterwards read identically. */
const SIGNED_OUT_FAILURE = {
    toolText: SIGNED_OUT_TEXT,
    errorMessage: SIGNED_OUT_TEXT,
} as const;

/** Reply for every request once the relayer has rejected the saved delegate
 * key. An empty recall and a rejected key used to be indistinguishable to the
 * agent — the queued call simply waited out the orphan sweeper and came back as
 * "connection dropped, please retry", which is advice that cannot work. Name
 * the cause and the way back in instead (GH #365 / WALM-602). */
const UNAUTHORIZED_TEXT =
    "❌ Walrus Memory rejected the saved credentials (HTTP 401). The delegate key may have been revoked or is no longer registered on this account. Call `memwal_login` to sign in again — saved credentials were NOT modified.";

/** Reply for a `tools/call` naming a tool the connected relayer does not
 * serve. Names what IS on offer, because the agent's next move is to pick one
 * of those — "unknown tool" alone leaves it guessing or retrying. */
export function unknownToolText(name: string, available: string[]): string {
    return (
        `❌ \`${name}\` is not a tool this Walrus Memory server offers. ` +
        `Available: ${available.join(", ")}. ` +
        `Your tool list is stale — re-read \`tools/list\` and use one of those instead. ` +
        `Nothing ran, so nothing was saved or changed.`
    );
}

/** `failRequest` options for every credentials-rejected refusal, so one refused
 * at handshake time and one refused on arrival afterwards read identically. */
const UNAUTHORIZED_FAILURE = {
    toolText: UNAUTHORIZED_TEXT,
    errorMessage: UNAUTHORIZED_TEXT,
} as const;

/** The `tools/list` we serve LOCALLY at cold start: the memory tools (from the
 * same source as auth-required mode) plus the locally-handled login/logout
 * tools. We strip any locally-served name from the imported list first —
 * `TOOL_DEFINITIONS` bundles its own `memwal_login`, and concatenating
 * `LOCAL_TOOL_DEFINITIONS` blindly would advertise `memwal_login` twice. This
 * yields the SAME shape as the post-connect spliced list (upstream memory tools
 * + login + logout, each once), so the static→refreshed transition doesn't
 * change the tool set out from under the client. OAuth-scoped sessions may
 * over-advertise write tools until `tools/list_changed` refreshes from the
 * relayer. Refreshed via
 * `tools/list_changed` once the relayer session is up. */
const LOCAL_TOOLS_LIST = {
    tools: [
        ...TOOL_DEFINITIONS.filter((t) => !LOCAL_TOOL_NAMES.has(t.name)),
        ...LOCAL_TOOL_DEFINITIONS,
    ],
};

/** Names advertised at cold start (baseline relayer + locally-served). A
 * `tools/call` for anything else is refused until an upstream `tools/list`
 * has been seen — fail-closed, not fail-open. */
const COLD_START_TOOL_NAMES = new Set(LOCAL_TOOLS_LIST.tools.map((t) => t.name));

const URL_READY_TIMEOUT_MS = 5_000;

/** Maximum silence we tolerate on the SSE stream before assuming the
 * relayer-side session has gone dead. The relayer sends keepalive events
 * roughly every 3s, so 30s ≈ 10 missed heartbeats — well past any plausible
 * network blip but quick enough that a stuck tool call recovers on its own.
 *
 * Override via `MEMWAL_MCP_SSE_IDLE_MS` (mostly for tests). Values below 500ms
 * are clamped — anything tighter races the heartbeat cadence and produces
 * spurious reconnects. */
function resolveSseIdleMs(): number {
    const raw = process.env.MEMWAL_MCP_SSE_IDLE_MS;
    if (!raw) return 30_000;
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 500) return 30_000;
    return n;
}

/** Longest deadline a server-side tool gives its own work (`analyze`). It
 * lives in a package this one cannot import from, so raise this whenever that
 * grows — otherwise the bridge declares healthy requests orphaned while the
 * relayer is still working. */
const SLOWEST_SERVER_TOOL_MS = 180_000;

/** 240s as the constants stand. The headroom absorbs the relayer's own
 * overhead, so expiry means the reply is lost rather than merely late. */
const DEFAULT_CALL_TIMEOUT_MS = SLOWEST_SERVER_TOOL_MS + 60_000;

/** An override below this is a mistake, not an intent. */
const MIN_CALL_TIMEOUT_MS = 1_000;

/** Longest a given tool can legitimately take server-side, keyed by tool name.
 *
 * `DEFAULT_CALL_TIMEOUT_MS` is sized for `memwal_analyze`, the slowest tool
 * there is. Applying that one number to every call means a request whose reply
 * is lost — the relayer answered, the stream dropped before it arrived — keeps
 * the agent blocked for 240s even when the tool could not still be working.
 * Users read that as a hang and reload the client.
 *
 * Each entry is the ceiling the matching tool enforces on itself in
 * `services/server/scripts/mcp/tools/`: `MAX_REMEMBER_WAIT_MS` for
 * `memwal_remember` (its default wait is 0 — it returns at accept — but an
 * operator can raise `MEMWAL_MCP_REMEMBER_WAIT_MS` up to that cap),
 * `MAX_STATUS_WAIT_MS` for `memwal_remember_status`, and the fixed `timeoutMs`
 * the bulk and analyze tools pass to the SDK. Keep them in lockstep: a value
 * below a tool's real ceiling abandons healthy work. Unlisted tools keep the
 * default.
 *
 * `memwal_recall` is the exception to lockstep: the SDK aborts the recall
 * request itself at 15s, but the checks it runs first (`/version`, `/config`)
 * carry their own deadlines, or none on older SDKs. 90s covers those. */
const TOOL_DEADLINE_MS: Readonly<Record<string, number>> = {
    memwal_recall: 90_000,
    memwal_remember: 90_000,
    memwal_remember_status: 60_000,
    memwal_remember_bulk: 120_000,
    memwal_analyze: SLOWEST_SERVER_TOOL_MS,
};

/** Absorbs relayer + transport overhead on top of a tool's own ceiling. The
 * sidecar answers at its deadline with a result or an error envelope rather
 * than going quiet, so the reply is one network hop behind it; 30s is many
 * times that. Cutting a merely-late reply off early is the expensive mistake —
 * the agent would retry a write that actually landed. */
const ORPHAN_HEADROOM_MS = 30_000;

/** Tool name for a `tools/call`, or null for any other JSON-RPC method. */
function toolNameOf(msg: RpcMessage): string | null {
    if (msg.method !== "tools/call") return null;
    const params = msg.params;
    if (params == null || typeof params !== "object") return null;
    const name = (params as { name?: unknown }).name;
    return typeof name === "string" ? name : null;
}

/** Deadline for one tracked request. A tool with a known ceiling gets that
 * plus headroom; everything else keeps the global default. An explicit
 * `MEMWAL_MCP_CALL_TIMEOUT_MS` pins every call, so tests still drive expiry
 * from one knob. */
function resolveDeadlineMs(msg: RpcMessage): number {
    const fallback = resolveCallTimeoutMs();
    if (process.env.MEMWAL_MCP_CALL_TIMEOUT_MS) return fallback;
    const tool = toolNameOf(msg);
    const ceiling = tool === null ? undefined : TOOL_DEADLINE_MS[tool];
    return ceiling === undefined ? fallback : ceiling + ORPHAN_HEADROOM_MS;
}

/** Without a cap, a long deadline drifts by a third of itself. */
const MAX_ORPHAN_SWEEP_MS = 5_000;

/** How long one request might sit unanswered. The idle watchdog above only sees
 * a silent *stream*, which the keepalive prevents, so a lost reply needs its
 * own deadline. Override via `MEMWAL_MCP_CALL_TIMEOUT_MS`, mostly for tests. */
function resolveCallTimeoutMs(): number {
    const raw = process.env.MEMWAL_MCP_CALL_TIMEOUT_MS;
    if (!raw) return DEFAULT_CALL_TIMEOUT_MS;
    const n = Number(raw);
    if (!Number.isFinite(n) || n < MIN_CALL_TIMEOUT_MS) return DEFAULT_CALL_TIMEOUT_MS;
    return n;
}

/** How long to wait before retrying a handshake the relayer refused with a 429
 * that carried NO `Retry-After`. That is the relayer's concurrent-session cap
 * (`ip_active_cap`), which deliberately sends no header because it clears when
 * some other session closes, not on a timer — so the ordinary sub-second
 * geometric retry is pure noise against it.
 *
 * Override via `MEMWAL_MCP_THROTTLE_FLOOR_MS` (mostly for tests). */
const DEFAULT_THROTTLE_FLOOR_MS = 5_000;

/** A relayer-supplied interval is a remote-controlled sleep, so cap it: a
 * misconfigured (or hostile) `Retry-After: 86400` must not park the bridge for
 * a day. Past this we retry anyway and take another 429 if we were wrong. */
const MAX_THROTTLE_WAIT_MS = 60_000;

function resolveThrottleFloorMs(): number {
    const raw = process.env.MEMWAL_MCP_THROTTLE_FLOOR_MS;
    if (!raw) return DEFAULT_THROTTLE_FLOOR_MS;
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 0) return DEFAULT_THROTTLE_FLOOR_MS;
    return Math.min(n, MAX_THROTTLE_WAIT_MS);
}

/** Parse a `Retry-After` value into ms. The header is legally either
 * delta-seconds or an HTTP-date (this relayer only ever emits the former, but
 * a proxy in the path may rewrite it). Returns null for absent / unparseable
 * values so the caller falls back to the floor — never NaN, which would poison
 * the backoff arithmetic and break the retry loop outright. */
function parseRetryAfterMs(raw: string | null): number | null {
    if (!raw) return null;
    const trimmed = raw.trim();
    if (trimmed === "") return null;
    if (/^\d+$/.test(trimmed)) {
        const seconds = Number(trimmed);
        // Non-positive is not advice. `Retry-After: 0` is a real thing to
        // receive (some intermediaries emit it for "unknown"), and taking it
        // literally puts us back on the ~500ms geometric backoff that
        // WALM-386 exists to stop — while still reporting `serverAdvised`,
        // which would also suppress the one hint the user can act on. Treat
        // it as no usable header and fall back to the floor.
        return Number.isFinite(seconds) && seconds > 0 ? seconds * 1000 : null;
    }
    const at = Date.parse(trimmed);
    if (!Number.isFinite(at)) return null;
    // Same for an HTTP-date already in the past — which a correct server can
    // produce simply by being a second behind the client's clock.
    const waitMs = at - Date.now();
    return waitMs > 0 ? waitMs : null;
}

/** The relayer refused the handshake with HTTP 429. Carried as a typed error so
 * the retry loops can honour the throttle interval instead of re-deriving it
 * from a message string — the whole point of WALM-386. `retryAfterMs` is
 * already resolved (header, else floor) and clamped, so callers just sleep it. */
class RelayerThrottledError extends Error {
    readonly status = 429;
    /** How long to wait before the next attempt, ms. Always a finite number. */
    readonly retryAfterMs: number;
    /** True when the relayer actually sent a usable `Retry-After`. False means
     * we applied the floor — the `ip_active_cap` shape, which has no ETA. */
    readonly serverAdvised: boolean;

    constructor(message: string, retryAfterHeader: string | null) {
        super(message);
        this.name = "RelayerThrottledError";
        const advised = parseRetryAfterMs(retryAfterHeader);
        this.serverAdvised = advised !== null;
        this.retryAfterMs = Math.min(
            MAX_THROTTLE_WAIT_MS,
            Math.max(0, advised ?? resolveThrottleFloorMs()),
        );
    }
}

/** Deadline for a request that is still buffered while the handshake has been
 * failing for at least this long — i.e. one we can prove never left this
 * process.
 *
 * It is much shorter than `callTimeoutMs` because the two cases carry
 * different risk, not because the wait is less important. A request that was
 * SENT might have been executed, so failing it early invites the agent to
 * retry a `remember` that already landed. A request that was never sent
 * cannot have executed: failing it is provably a no-op, and the agent's retry
 * costs one round trip.
 *
 * 90s is well past a relayer cold start and past six reconnect attempts at the
 * capped 15s backoff, so it does not fire on a slow-but-recovering relayer —
 * and it does not apply at all while the handshake is healthy (a request
 * buffered behind an in-progress flush keeps the full deadline). What it ends
 * is the case from WALM-618: no working connection, nothing sent, and four
 * minutes of silence before the user is told anything. */
const DEFAULT_STALLED_HANDSHAKE_MS = 90_000;

/** Same override shape as the call timeout, mostly for tests. Never longer
 * than the call timeout itself: this deadline exists to fire sooner. */
function resolveStalledHandshakeMs(callTimeoutMs: number): number {
    const raw = process.env.MEMWAL_MCP_STALLED_HANDSHAKE_MS;
    const n = raw ? Number(raw) : DEFAULT_STALLED_HANDSHAKE_MS;
    const resolved =
        Number.isFinite(n) && n >= MIN_CALL_TIMEOUT_MS ? n : DEFAULT_STALLED_HANDSHAKE_MS;
    return Math.min(resolved, callTimeoutMs);
}

interface RpcMessage {
    jsonrpc: "2.0";
    id?: number | string | null;
    method?: string;
    params?: unknown;
    result?: unknown;
    error?: unknown;
}

/** A request forwarded upstream and still awaiting its response. */
interface InFlightEntry {
    msg: RpcMessage;
    startedAt: number;
    /** Set once a POST has been issued for this request.
     *
     * This is what separates "cannot have executed" from "might have
     * executed", and it has to live on the entry: `pendingForward` only holds
     * requests buffered before the first successful connect, so in a
     * mid-session outage — the ordinary case — a request that never left the
     * process was indistinguishable from one already sent. */
    sent?: boolean;
    /** How long this call may go unanswered before the sweeper declares its
     * reply lost. Fixed when the request is first tracked, so a reconnect
     * replay keeps the original budget. */
    deadlineMs: number;
    /** Set while the sweeper asks the relayer's `/health` why this sent call
     * went unanswered, so the next sweep does not probe it again. */
    probing?: boolean;
    /** Set once the sweeper has decided this sent call's reply is lost and it
     * is being answered as failed. A replay would post it a second time — a
     * duplicate write for a tool with no idempotency key — while the agent is
     * told the call never ran, so `reconnect()` skips these. Never cleared,
     * unlike `probing`: the call is past its deadline whichever way the answer
     * goes. */
    orphaned?: boolean;
}

/** The relayer rejected the saved delegate key (HTTP 401 on the handshake).
 * Distinct from every other connect failure because retrying cannot fix it:
 * the caller must re-authenticate. Carrying it as a type keeps the background
 * connect loop from backing off forever on a key that will never be accepted,
 * which left tool calls parked until the orphan sweeper's deadline (WALM-602). */
class RelayerUnauthorizedError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "RelayerUnauthorizedError";
    }
}

interface SseHandshakeResult {
    /** Absolute URL the client must POST to for outbound JSON-RPC messages. */
    postUrl: string;
    /**
     * Forward one message, resolving with the HTTP status. Same shape as the
     * Streamable transport's `send`, so the forwarding path does not have to
     * know which transport is underneath.
     */
    send: (msg: RpcMessage, creds: MemWalCredentials, extra: Record<string, string>) => Promise<number>;
    /** Per-line iterator for incoming SSE messages (already-parsed JSON-RPC). */
    iter: AsyncIterator<RpcMessage>;
    /** Abort + close the SSE stream. */
    abort: () => void;
}

function mcpAuthHeaders(
    creds: MemWalCredentials,
    extra: Record<string, string> = {},
): Record<string, string> {
    return {
        authorization: `Bearer ${creds.delegatePrivateKey}`,
        "x-memwal-account-id": creds.accountId,
        ...extra,
    };
}

/**
 * Open a relayer session on the configured transport.
 *
 * `MEMWAL_MCP_TRANSPORT=http` dials the Streamable HTTP endpoint, which
 * answers a call on the same request instead of splitting POST from reply.
 * Default stays SSE until the new path has production mileage.
 */
async function openRelaySession(
    relayerUrl: string,
    creds: MemWalCredentials,
    extraHeaders: Record<string, string> = {},
): Promise<SseHandshakeResult> {
    if (resolveTransport(process.env.MEMWAL_MCP_TRANSPORT) === "http") {
        // `postUrl` is logging-only on this path; the session owns its
        // endpoint. A plain cast, not `as unknown as` — the two shapes must
        // stay structurally compatible, and a widening cast would hide it if
        // they ever stopped being.
        return (await openStreamableSession(relayerUrl, creds, extraHeaders)) as SseHandshakeResult;
    }
    return openSseStream(relayerUrl, creds, extraHeaders);
}

async function openSseStream(
    relayerUrl: string,
    creds: MemWalCredentials,
    extraHeaders: Record<string, string> = {},
): Promise<SseHandshakeResult> {
    const connectTimeoutMs = resolveConnectTimeoutMs();
    // One shared budget for the WHOLE attempt: the compatibility check (GET
    // /version + /health fallback) and the SSE connect below both honour this
    // single deadline, so an attempt is bounded by connectTimeoutMs in total
    // rather than each step getting its own (which could sum to 2–3×).
    const budgetSignal = AbortSignal.timeout(connectTimeoutMs);
    await ensureCompatibleRelayer(relayerUrl, budgetSignal);

    const url = `${relayerUrl.replace(/\/+$/, "")}/api/mcp/sse`;
    const controller = new AbortController();

    // Bound the INITIAL connect (headers + the wait-for-`endpoint`-event loop
    // below) on the SAME shared budget as the compat check above, so a hung
    // relayer aborts well before the MCP client's ~30s timeout and one attempt
    // never exceeds connectTimeoutMs total. This is distinct from the idle
    // watchdog, which only bounds silence AFTER the stream is up. When the
    // budget fires we abort `controller` (so the in-flight fetch/read unwinds);
    // we detach the listener the instant the endpoint resolves — past that
    // point the idle watchdog owns liveness and this must never fire, or it
    // would tear down a healthy stream.
    let connectTimedOut = false;
    const onBudgetExpired = (): void => {
        if (!controller.signal.aborted) {
            connectTimedOut = true;
            log.warn("bridge.connect_timeout", { url, timeoutMs: connectTimeoutMs });
            controller.abort();
        }
    };
    // If the compat check already burned the whole budget, `budgetSignal` is
    // already aborted — fire synchronously so we don't even attempt the SSE GET.
    if (budgetSignal.aborted) onBudgetExpired();
    else budgetSignal.addEventListener("abort", onBudgetExpired, { once: true });
    const clearConnectTimer = (): void =>
        budgetSignal.removeEventListener("abort", onBudgetExpired);

    let resp: Response;
    try {
        resp = await fetchMcp(url, {
            method: "GET",
            headers: {
                ...mcpAuthHeaders(creds, extraHeaders),
                accept: "text/event-stream",
                "cache-control": "no-cache",
            },
            signal: controller.signal,
        });
    } catch (err) {
        clearConnectTimer();
        if (connectTimedOut) {
            throw new Error(
                `Walrus Memory relayer SSE connect timed out after ${connectTimeoutMs}ms ` +
                    `(${url}). The relayer may be slow, cold-starting, or unreachable.`
            );
        }
        throw err;
    }

    // Every non-OK exit below DRAINS the body and deliberately does NOT abort
    // `controller`. Aborting a handshake response we have already read is what
    // produced the Windows libuv assertion in WALM-386
    // (`!(handle->flags & UV_HANDLE_CLOSING)`, src/win/async.c:76); 45b0ad87
    // removed those aborts on purpose ("the stdio bridge drains handshake error
    // bodies instead of aborting the socket", CHANGELOG 0.0.11). Draining to
    // completion lets undici return the socket to its pool normally. Do not
    // re-add `controller.abort()` here.
    if (resp.status === 401) {
        clearConnectTimer();
        if (resp.body) {
            await resp.text().catch(() => "");
        }
        log.warn("bridge.unauthorized", { url });
        // DO NOT wipe creds here. A 401 from the relayer is *evidence* of
        // a problem but not *proof* the saved seed is the cause. Possible
        // sources: revoked delegate key (genuine), transient WAF / rate
        // limit (false positive), http_proxy interposed somewhere on the
        // path, or — on `--local` — local malware racing the relayer port.
        // Auto-wiping the seed turns any one of those into a permanent
        // outage that forces re-login. Force-fail loud instead; the user
        // runs `memwal-mcp login` if they want to actually rotate.
        throw new RelayerUnauthorizedError(
            "Walrus Memory relayer rejected credentials (HTTP 401). " +
                "Delegate key may have been revoked, the relayer may be " +
                "rate-limiting, or a proxy may be interposed. Saved " +
                `credentials at ${credsPath()} were NOT modified. ` +
                "Run `memwal-mcp login` if you need to rotate the key."
        );
    }
    if (resp.status === 429) {
        clearConnectTimer();
        const retryAfter = resp.headers.get("retry-after");
        const body = resp.body ? await resp.text().catch(() => "") : "";
        // Throw a TYPED error: the interval has to survive as a number for the
        // retry loops to honour it. Stringifying it into the message (what this
        // used to do) left both loops guessing, so they retried a throttled
        // handshake after 500ms — WALM-386.
        throw new RelayerThrottledError(
            `Walrus Memory relayer SSE handshake rate-limited (HTTP 429` +
                `${retryAfter ? `, retry after ${retryAfter}s` : ""}). ${body.slice(0, 200)}`.trim(),
            retryAfter,
        );
    }
    if (!resp.ok || !resp.body) {
        clearConnectTimer();
        const body = resp.body ? await resp.text().catch(() => "") : "";
        throw new Error(
            `Walrus Memory relayer SSE handshake failed: HTTP ${resp.status} ${body.slice(0, 200)}`
        );
    }

    const ct = resp.headers.get("content-type") ?? "";
    if (!ct.includes("event-stream")) {
        clearConnectTimer();
        if (resp.body) {
            await resp.text().catch(() => "");
        }
        throw new Error(
            `Walrus Memory relayer returned unexpected content-type "${ct}" for SSE endpoint`
        );
    }

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    let endpointResolved = false;
    let endpointPath = "";
    let streamEnded = false;
    let streamError: string | null = null;
    const events: RpcMessage[] = [];
    type Waker = () => void;
    let queueResolver: Waker | null = null;
    function wake(): void {
        const r = queueResolver;
        if (r) {
            queueResolver = null;
            r();
        }
    }

    function pushEvent(ev: RpcMessage): void {
        events.push(ev);
        wake();
    }

    // Heartbeat watchdog: an alive SSE session emits keepalive events every
    // few seconds. If reader.read() stops yielding chunks entirely, the
    // server-side session has gone dead even though the TCP socket may still
    // be open (observed in the wild: relayer session state silently dropped
    // while the bridge waited forever for a response that never arrived,
    // because the next POST landed in the void). Abort the controller — the
    // catch block sets streamEnded=true and runBridge's serverPump triggers
    // reconnect("server-pump-eof"), which replays any in-flight requests on
    // the fresh session.
    const idleTimeoutMs = resolveSseIdleMs();
    const checkIntervalMs = Math.max(500, Math.floor(idleTimeoutMs / 3));
    let lastChunkAt = Date.now();
    const watchdog = setInterval(() => {
        const idleMs = Date.now() - lastChunkAt;
        if (idleMs > idleTimeoutMs && !controller.signal.aborted) {
            log.warn("bridge.sse_idle_watchdog_fired", { idleMs, idleTimeoutMs });
            controller.abort();
        }
    }, checkIntervalMs);
    // unref so the watchdog never holds the event loop open during shutdown.
    watchdog.unref?.();

    // Pump the SSE stream in the background.
    const pump = (async () => {
        try {
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                lastChunkAt = Date.now();
                buf += decoder.decode(value, { stream: true });
                let sep: number;
                while ((sep = buf.indexOf("\n\n")) >= 0) {
                    const chunk = buf.slice(0, sep);
                    buf = buf.slice(sep + 2);
                    const lines = chunk.split("\n");
                    const event = lines
                        .find((l) => l.startsWith("event:"))
                        ?.slice("event:".length)
                        .trim();
                    const data = lines
                        .filter((l) => l.startsWith("data:"))
                        .map((l) => l.slice("data:".length).replace(/^\s/, ""))
                        .join("\n");
                    if (event === "endpoint" && !endpointResolved) {
                        endpointPath = data.trim();
                        endpointResolved = true;
                        wake();
                        continue;
                    }
                    if (event === "message" || (!event && data)) {
                        try {
                            const parsed = JSON.parse(data) as RpcMessage;
                            pushEvent(parsed);
                        } catch {
                            log.warn("bridge.sse_parse_failed", { data: data.slice(0, 120) });
                        }
                    }
                }
            }
        } catch (err) {
            if (!controller.signal.aborted) {
                const msg = err instanceof Error ? err.message : String(err);
                streamError = msg;
                // `terminated` is undici's keep-alive idle drop — happens on
                // long-idle SSE in manual tests. The MCP client wrapping us
                // (Cursor / Claude Desktop) will re-spawn the process if it
                // needs the bridge again, so a clean exit is fine.
                if (msg === "terminated" || msg.includes("ECONNRESET")) {
                    log.warn("bridge.sse_idle_closed", { reason: msg });
                } else {
                    log.error("bridge.sse_pump_error", { err: msg });
                }
            }
        } finally {
            clearInterval(watchdog);
            streamEnded = true;
            // Wake any waiter so they see EOF.
            wake();
        }
    })();

    // Wait for the `endpoint` event (or first message) before returning.
    while (!endpointResolved) {
        if (streamEnded) {
            clearConnectTimer();
            controller.abort();
            if (connectTimedOut) {
                throw new Error(
                    `Walrus Memory relayer SSE connect timed out after ${connectTimeoutMs}ms ` +
                        `(${url}) waiting for the endpoint event. The relayer may be slow, ` +
                        `cold-starting, or unreachable.`
                );
            }
            throw new Error(
                `Walrus Memory relayer SSE handshake ended before endpoint event${streamError ? `: ${streamError}` : ""}`
            );
        }
        await new Promise<void>((r) => (queueResolver = r));
    }

    // Endpoint resolved — the stream is up. Hand liveness over to the idle
    // watchdog and disarm the connect timer so it can never abort a healthy
    // stream.
    clearConnectTimer();

    const iter: AsyncIterator<RpcMessage> = {
        async next(): Promise<IteratorResult<RpcMessage>> {
            while (events.length === 0) {
                if (controller.signal.aborted) return { value: undefined as never, done: true };
                if (streamEnded) return { value: undefined as never, done: true };
                await new Promise<void>((r) => (queueResolver = r));
            }
            return { value: events.shift()!, done: false };
        },
    };

    // `endpointPath` may be relative (`/api/mcp/messages?sessionId=...`) or
    // absolute. Make it absolute for `fetch()`.
    let postUrl: string;
    try {
        postUrl = ssePostUrl(relayerUrl, endpointPath);
    } catch (err) {
        controller.abort();
        throw err;
    }

    return {
        postUrl,
        send: (msg, sendCreds, extra) => postMessage(postUrl, msg, sendCreds, extra),
        iter,
        abort: () => {
            controller.abort();
            void pump; // suppress unused warning
        },
    };
}

async function postMessage(
    postUrl: string,
    msg: RpcMessage,
    creds: MemWalCredentials,
    extraHeaders: Record<string, string> = {},
): Promise<number> {
    const resp = await fetchMcp(postUrl, {
        method: "POST",
        headers: {
            ...mcpAuthHeaders(creds, extraHeaders),
            "content-type": "application/json",
        },
        body: JSON.stringify(msg),
    });
    if (!resp.ok && resp.status !== 202) {
        const body = await resp.text();
        log.warn("bridge.post_non_ok", { status: resp.status, body: body.slice(0, 200) });
    }
    return resp.status;
}

function readStdinLines(onLine: (line: string) => void): Promise<void> {
    return new Promise((resolve) => {
        let buf = "";
        process.stdin.setEncoding("utf8");
        process.stdin.on("data", (chunk: string) => {
            buf += chunk;
            let nl: number;
            while ((nl = buf.indexOf("\n")) >= 0) {
                const line = buf.slice(0, nl).replace(/\r$/, "");
                buf = buf.slice(nl + 1);
                if (line.length > 0) onLine(line);
            }
        });
        process.stdin.on("end", () => resolve());
        process.stdin.on("close", () => resolve());
        // Attaching a `data` listener only starts the flow on a stream that was
        // never explicitly paused. The auth-required stub hands off by calling
        // `process.stdin.pause()`, and a stream paused that way stays paused no
        // matter how many listeners attach — so after an in-session
        // `memwal_login` the bridge read NOTHING beyond the requests replayed
        // from `pendingLines`, and every later call hung unanswered. Harmless
        // on the cold path, where stdin is already flowing.
        process.stdin.resume();
    });
}

function writeStdoutMessage(msg: RpcMessage): void {
    process.stdout.write(JSON.stringify(msg) + "\n");
}

/** Run the browser-based login flow inline — same pattern as auth-required
 * mode, but available even when creds already exist (so user can re-login,
 * switch wallets, or refresh). Returns a click-able URL near-instantly;
 * listener stays alive in the background until callback or timeout. */
async function handleLocalLogin(
    config: BridgeConfig,
    onCredentials: (creds: MemWalCredentials) => Promise<void>,
    freshKey: boolean,
): Promise<{ text: string; isError: boolean }> {
    let discardedKey: { publicKey: string; address: string } | undefined;
    const session = startOrReuseLoginFlow(
        {
            relayerUrl: config.relayerUrl,
            webUrl: config.webUrl,
            label: config.label,
            timeoutMs: resolveLoginTimeoutMs(),
            openBrowser: false,
            freshKey,
            onDiscarded: (key) => {
                discardedKey = key;
            },
        },
        async (creds) => {
            await onCredentials(creds);
            log.info("memwal_login.bridge.success", {
                accountId: creds.accountId,
                delegateAddress: creds.delegateAddress,
            });
            // The tool call returned the URL long ago, so — exactly as on the
            // failure path below — this notification and the banner on the next
            // tool result are the only ways left to say the sign-in landed.
            writeStdoutMessage({
                jsonrpc: "2.0",
                method: "notifications/message",
                params: {
                    level: "info",
                    logger: "memwal-mcp",
                    data: loginSuccessNotification({
                        accountId: creds.accountId,
                        delegateAddress: creds.delegateAddress,
                        credentialsPath: credsPath(),
                    }),
                },
            });
        },
        // This tool call has already returned "here is your URL, go sign in",
        // so a later failure has no response left to ride home on. Without an
        // out-of-band notification the agent sits waiting on a flow that is
        // already dead. MCP logging notifications are fire-and-forget and safe
        // to emit at any point in the session.
        (err) => {
            const msg = err instanceof Error ? err.message : String(err);
            log.warn("memwal_login.bridge.failed", { msg });
            writeStdoutMessage({
                jsonrpc: "2.0",
                method: "notifications/message",
                params: {
                    level: "warning",
                    logger: "memwal-mcp",
                    // The reclaim is only possible because of the write-ahead
                    // record (WALM-332): a key the browser already paid to
                    // register is no longer lost with the process. A retry
                    // cannot help that key, since it reuses it and the
                    // dashboard cannot register it twice.
                    data:
                        `Walrus Memory sign-in did not complete: ${msg}. Existing credentials are ` +
                        `unchanged. The key is kept on disk and a later start reclaims it only if ` +
                        `the relayer can confirm it was registered, which it cannot always do. ` +
                        `Call memwal_login again to retry with that key, or with freshKey: true to ` +
                        `mint a new one and abandon it.`,
                },
            });
        },
    );

    const timeoutPromise = new Promise<string>((_, reject) =>
        setTimeout(
            () => reject(new Error("Listener never started")),
            URL_READY_TIMEOUT_MS,
        ).unref?.() as never,
    );

    let url: string;
    try {
        url = await Promise.race([session.url, timeoutPromise]);
    } catch (err) {
        if (isLoginSuperseded(err)) {
            return { isError: true, text: "This sign-in was replaced by a newer memwal_login. Open that result instead of starting another login." };
        }
        return {
            isError: true,
            text: `❌ Failed to start login: ${err instanceof Error ? err.message : String(err)}`,
        };
    }

    return {
        isError: false,
        // Read from disk, never assumed from the mode. The bridge usually runs
        // with credentials, but `memwal_logout` in this same session deletes
        // them and login is intercepted before the signed-out guard — claiming
        // "already signed in" there tells the user logout did not take.
        text: loginPrompt({
            url,
            credentialsPath: credsPath(),
            signedIn: loadCreds() !== null,
            discardedKey,
        }),
    };
}

/** Sign out by clearing the local credentials file. Does NOT revoke the
 * on-chain delegate key — that requires a separate dashboard action. */
function handleLocalLogout(): { text: string; isError: boolean } {
    try {
        const cleared = clearCreds();
        // Explicit sign-out discards the write-ahead record too. Without this
        // an interrupted re-login leaves `login-pending.json` behind, and the
        // next start's `recoverPendingLogin` signs the user straight back in.
        //
        // Kept out of `clearCreds()` so only a deliberate sign-out discards a
        // key that may still be reclaimable. `clearCreds` is exported, and a
        // 401 deliberately does NOT wipe credentials (see the relayer-401
        // handling above), so the two are not the same decision.
        clearPendingLogin();
        log.info("memwal_logout.bridge.success", {
            removedPath: cleared.removedPath ?? null,
            fallbackPath: cleared.fallbackPath ?? null,
        });
        if (!cleared.removedPath) {
            return {
                isError: false,
                // The bridge only runs with credentials loaded, so a missing
                // file here still means a live in-memory session to tear down —
                // exactly the GH #616 case. Say so rather than implying nothing
                // happened.
                text:
                    `✅ Already signed out. No credentials at \`${credsPath()}\`, and this ` +
                    `connection's memory session has been closed — memory tools will refuse ` +
                    `to run until you sign in again.`,
            };
        }
        return {
            isError: false,
            text: [
                `✅ Signed out. Credentials removed from \`${cleared.removedPath}\`, and this connection's memory session has been closed — memory tools will refuse to run until you sign in again.`,
                ...(cleared.fallbackPath
                    ? [
                          ``,
                          `**Still signed in elsewhere:** \`${cleared.fallbackPath}\` remains and is ` +
                              `what the next run loads, under a possibly different account. Remove ` +
                              `that file too to sign out everywhere.`,
                      ]
                    : []),
                ``,
                `**Note:** the on-chain delegate key for this client is still registered on your Walrus Memory account. To fully revoke access, visit the Walrus Memory dashboard and remove the matching public key from the "Delegate Keys" section.`,
                ``,
                `Call \`memwal_login\` to sign in again with the same or a different wallet.`,
            ].join("\n"),
        };
    } catch (err) {
        return {
            isError: true,
            text: `❌ Logout failed: ${err instanceof Error ? err.message : String(err)}`,
        };
    }
}

/**
 * A completed sign-in waiting to be reported to the client.
 *
 * Set when credentials are adopted — either mid-session via `adoptCredentials`
 * or on the cold hand-off from the auth-required stub, which is why this is
 * module state with a setter rather than a local inside `runBridge`: on the
 * cold path the sign-in happens before the bridge exists.
 *
 * Consumed by {@link takePendingLoginSuccess}, so it can only ever be reported
 * once.
 */
let pendingLoginSuccess: LoginSuccessInfo | null = null;

/** Record a completed sign-in for the next tool result to carry. */
export function notePendingLoginSuccess(info: LoginSuccessInfo): void {
    pendingLoginSuccess = info;
}

/** Read the pending sign-in AND clear it — the read is the consumption. */
function takePendingLoginSuccess(): LoginSuccessInfo | null {
    const pending = pendingLoginSuccess;
    pendingLoginSuccess = null;
    return pending;
}

/**
 * Prefix the sign-in banner onto a tool result, if one is pending.
 *
 * Only ever called for a `tools/call` reply. A `tools/list` or `ping` response
 * would consume the banner into somewhere the user never reads it, so the
 * caller checks which request is being answered first.
 */
function applyPendingLoginSuccess(value: RpcMessage): void {
    const result = value.result as { content?: unknown } | undefined;
    if (!result || typeof result !== "object" || !Array.isArray(result.content)) return;

    const first = result.content[0] as { type?: string; text?: string } | undefined;
    if (!first || first.type !== "text" || typeof first.text !== "string") return;

    const pending = takePendingLoginSuccess();
    if (!pending) return;

    first.text = `${loginSuccessNotice(pending)}${first.text}`;
    log.info("bridge.login_success_notice_attached", { accountId: pending.accountId });
}

/**
 * Open the SSE bridge and forward stdio ↔ relayer until stdin closes.
 *
 * On SSE drop (idle timeout in the Rust proxy / undici keep-alive / network
 * blip), we transparently reopen the stream — the relayer issues a fresh
 * sessionId, we route subsequent POSTs there. stdin stays open the whole
 * time, so the MCP client (Cursor / Claude Desktop / etc.) never sees the
 * reconnection.
 *
 * Two tools (`memwal_login`, `memwal_logout`) are intercepted LOCALLY and
 * never forwarded to the relayer — they manipulate the local credentials
 * file directly. They appear in `tools/list` by splicing them into the
 * relayer's response on the way back to the client.
 */
export async function runBridge(
    initialCreds: MemWalCredentials,
    config: BridgeConfig,
    /** Requests the auth-required server already read off stdin before it
     * detected fresh credentials and handed control here (e.g. the
     * `memwal_recall` that triggered the hot-handoff). Replayed once the SSE
     * stream is up so they're served for real instead of being lost in the
     * mode switch — this is what removes the historical "second restart". */
    pendingLines: string[] = [],
): Promise<void> {
    note(`Connecting to ${initialCreds.relayerUrl}...`);
    log.info("bridge.connecting", {
        relayer: initialCreds.relayerUrl,
        accountId: initialCreds.accountId,
        delegate: initialCreds.delegateAddress,
    });

    // Live handle to the current SSE stream — replaced whenever we reconnect.
    // Starts null: we answer `initialize` / `tools/list` LOCALLY and wire stdin
    // BEFORE the relayer session exists, so the MCP client's handshake never
    // waits on a (possibly slow / cold) relayer round-trip. The connect runs in
    // the background; anything that must reach the relayer (`tools/call`) is
    // buffered in `pendingForward` until `sse` is live, then flushed.
    let sse: SseHandshakeResult | null = null;

    /** The delegate key this bridge is currently authorized to act with.
     * Nulled by `invalidateSession()` so signing out drops the key itself
     * rather than only setting a flag that every forwarding path has to
     * remember to check — after logout there is simply nothing left to sign
     * with. `adoptCredentials` republishes it on the next login. */
    let creds: MemWalCredentials | null = initialCreds;
    /**
     * Best-effort `x-memwal-client` / `x-memwal-client-version` forwarded to
     * the sidecar. Seeded from `lastClientInfoHeaders()`, which is only
     * populated after the auth-required → bridge handoff (that path does not
     * replay `initialize`). On a normal already-signed-in start this object
     * is empty at first SSE connect: `connectInBackground` opens the stream
     * before stdin is wired. Headers are filled when we see `initialize` and
     * then land on reconnects / later POSTs. The sidecar treats the MCP
     * handshake (`initialize.clientInfo`) as the authoritative source.
     */
    const extraHeaders: Record<string, string> = { ...lastClientInfoHeaders() };

    let stdinClosed = false;
    /** Set by `memwal_logout`. Unlike `stdinClosed` the process stays up and
     * the client keeps talking to us — `memwal_login` must still work — but the
     * relayer session is torn down and must never be re-established with the
     * credentials the user just deleted. Every connect/reconnect path therefore
     * checks this alongside `stdinClosed`; `adoptCredentials` clears it when a
     * new login lands. */
    let loggedOut = false;
    /** Set when the relayer 401s the handshake, cleared on the next successful
     * connect. While set, requests fail fast with `UNAUTHORIZED_FAILURE` rather
     * than parking in `pendingForward` behind a connect that cannot succeed. */
    let credentialsRejected = false;
    /** Resolves once a post-logout `memwal_login` has published a fresh session
     * (or stdin closed). The server pump parks on this instead of exiting, so
     * signing back in resumes streaming without the user restarting their MCP
     * client. Recreated on every logout; null while signed in. */
    let logoutPark: Promise<void> | null = null;
    let releaseLogoutPark: (() => void) | null = null;
    let reconnectAttempt = 0;
    let reconnectPromise: Promise<void> | null = null;
    let firstConnectDone = false;
    /** Wall-clock instant before which the relayer told us (HTTP 429) not to
     * open another session. Both retry loops floor their backoff at this, so a
     * throttle survives across the separate `reconnect()` calls that would
     * otherwise each start from a fresh 500ms. 0 = not throttled. */
    let throttledUntilMs = 0;
    /** One "we are being throttled" note per throttle episode. A sustained cap
     * would otherwise print a line per retry cycle for as long as it lasts. */
    let throttleNoticed = false;
    /** Why the last handshake attempt failed, and when the run of failures
     * started. Kept so a request that ages out while buffered can say what
     * it was actually waiting on instead of a generic "unavailable" — the
     * user-visible half of WALM-618, where the bridge retried in silence and
     * a `remember` looked like it was just slow. Cleared on every success. */
    let lastHandshakeError: string | null = null;
    let handshakeFailingSince: number | null = null;
    /** Identifies one "I need a session" episode, and stays the same across
     * every retry inside it. Sent on each handshake as `x-memwal-connect-id`.
     *
     * Without it the relayer sees N unrelated sub-second requests and cannot
     * tell they were one user waiting: its per-request id is minted fresh each
     * time, so a four-minute wait leaves no four-minute anything in its logs,
     * only a scatter of fast 401s and 429s. With it, one grep returns the
     * whole episode and the span between first and last line IS the wait.
     * Cleared on success, so the next outage starts a new episode. */
    let connectEpisodeId: string | null = null;
    const connectHeaders = (): Record<string, string> => {
        connectEpisodeId ??= randomUUID();
        return {
            // `x-memwal-client` is only known after `initialize`, and a first
            // connect happens before stdin is even wired — so on the attempt
            // that matters most the relayer has no idea who is calling. The
            // bridge's own version it always knows, and "which build is
            // looping" is the actionable half anyway.
            "x-memwal-bridge-version": MEMWAL_MCP_VERSION,
            ...extraHeaders,
            "x-memwal-connect-id": connectEpisodeId,
        };
    };
    const endConnectEpisode = (): void => {
        connectEpisodeId = null;
    };
    const noteHandshakeFailure = (reason: string): void => {
        lastHandshakeError = reason;
        handshakeFailingSince ??= Date.now();
    };
    const clearHandshakeFailure = (): void => {
        lastHandshakeError = null;
        handshakeFailingSince = null;
    };
    /** Bumped when the live SSE session is aborted or replaced so queued
     * POSTs captured against a stale URL are skipped (reconnect replays). */
    let sessionEpoch = 0;
    /** One in-flight POST per SSE session — overlapping POSTs drop the stream. */
    let postChain: Promise<unknown> = Promise.resolve();
    function enqueuePost<T>(fn: () => Promise<T>): Promise<T> {
        const run = postChain.then(fn, fn);
        postChain = run.then(
            () => undefined,
            () => undefined,
        );
        return run;
    }
    function postIfCurrent(
        epoch: number,
        send: SseHandshakeResult["send"],
        msg: RpcMessage,
        postCreds: MemWalCredentials,
    ): Promise<number> {
        if (epoch !== sessionEpoch) return Promise.resolve(0);
        // Marked before the await, not after. Once the POST is issued we can
        // no longer prove the call did not run, so it must keep the full call
        // timeout even if the socket then fails — failing it early is what
        // invites a duplicate `remember`.
        if (msg.id !== undefined && msg.id !== null) {
            const tracked = inFlight.get(msg.id);
            if (tracked) tracked.sent = true;
        }
        return send(msg, postCreds, extraHeaders).then((status) => {
            // 404 is the relayer saying that session does not exist, so the
            // message was discarded rather than routed: it provably did not
            // run, and the request goes back to being never-sent.
            //
            // This is not a corner case. `sse` is not cleared when the server
            // pump hits EOF — it keeps pointing at the dead session until a
            // reconnect succeeds — so a call arriving during a mid-session
            // outage takes the POST path, posts to the stale URL, and gets
            // exactly this. Without the reset it would be marked sent and
            // wait out the full call timeout, which is the WALM-618 symptom
            // the stalled deadline exists to remove.
            if (status === 404 && msg.id !== undefined && msg.id !== null) {
                const tracked = inFlight.get(msg.id);
                if (tracked) tracked.sent = false;
            }
            return status;
        });
    }
    let credentialGeneration = 0;
    let activeCredentialGeneration = 0;

    /** Callbacks to run once, the moment stdin closes — used to wake anything
     * parked on a timer (e.g. the connect-retry backoff) so shutdown is prompt
     * instead of waiting out the timer. `markStdinClosed` is the single writer
     * of `stdinClosed`; call it instead of assigning the flag directly. */
    const stdinCloseListeners = new Set<() => void>();
    /** Register a shutdown callback. Returns an unregister fn so a caller that
     * only cares about shutdown *while it's parked* (e.g. one backoff sleep) can
     * detach when it wakes normally — otherwise the set would grow one stale
     * closure per retry for the whole session. Fires immediately if already
     * closed (unregister is then a no-op). */
    function onStdinClose(fn: () => void): () => void {
        if (stdinClosed) {
            fn();
            return () => {};
        }
        stdinCloseListeners.add(fn);
        return () => stdinCloseListeners.delete(fn);
    }
    function markStdinClosed(): void {
        if (stdinClosed) return;
        stdinClosed = true;
        // Wake a pump parked on logout, or shutdown would block on a login
        // that is never coming.
        releaseLogoutPark?.();
        releaseLogoutPark = null;
        for (const fn of stdinCloseListeners) {
            try {
                fn();
            } catch {
                /* listener failure must not block shutdown */
            }
        }
        stdinCloseListeners.clear();
    }

    /** Requests that arrived before the relayer session came up. Held here and
     * flushed in order once `sse` is live. `tools/call` (and any other request
     * that must reach the relayer) lands here; `tools/list` and
     * `memwal_login|logout` are answered locally and never buffered. `initialize`
     * IS buffered (to forward upstream for capability negotiation) but is never
     * failed back — `failRequest` skips `method === "initialize"`. */
    const pendingForward: RpcMessage[] = [];

    /** True while `flushPendingForward` is draining the buffer after the first
     * connect. New stdin requests that arrive mid-drain must keep buffering
     * rather than posting directly, or they'd overtake still-queued items and
     * break arrival order. */
    let flushing = false;

    /** Resolves the first time the SSE stream is up (or when stdin closes before
     * that ever happens). `serverPump` waits on this before reading from
     * `sse.iter`; after it resolves, `sse` is either a live handle or null
     * (stdin closed) — the pump loop guards on both. Idempotent. */
    let signalFirstConnect: () => void = () => {};
    let firstConnectSignaled = false;
    const firstConnect = new Promise<void>((r) => {
        signalFirstConnect = () => {
            if (firstConnectSignaled) return;
            firstConnectSignaled = true;
            r();
        };
    });

    /** Expected-suppression COUNT per id, for requests we answered locally but
     * still forwarded upstream (currently just `initialize`, so the relayer
     * session negotiates capabilities). The upstream reply must be dropped in
     * the pump — the client already has our local reply, and a second response
     * for the same id corrupts its JSON-RPC state.
     *
     * A count (not a bare Set) so suppression is EXACT and self-limiting: we
     * expect exactly one upstream reply per forward, so we increment on each
     * forward (initial + every reconnect replay) and decrement on each dropped
     * reply, removing the id at zero. Once the initialize replies are all
     * consumed, the id stops suppressing — so a client that later REUSES the
     * initialize id for a real request gets that request's genuine reply
     * (result OR error) through, instead of it being swallowed forever. */
    const suppressUpstreamReplies = new Map<string | number, number>();

    /** IDs we've already answered with a shutdown "unavailable" envelope
     * (`failRequest`). If a late upstream reply for one of these still arrives —
     * e.g. a flush-404 reconnect re-posted the request onto a live session that
     * answers just as we were closing out at shutdown — the pump must DROP it,
     * or the client would get two responses for one id. */
    const closedOutIds = new Set<string | number>();

    const expectSuppressedReply = (id: string | number): void => {
        suppressUpstreamReplies.set(id, (suppressUpstreamReplies.get(id) ?? 0) + 1);
    };
    /** Consume one expected suppression for `id`. Returns true if the reply
     * should be dropped (an outstanding local-answer suppression existed). */
    const consumeSuppressedReply = (id: string | number): boolean => {
        const n = suppressUpstreamReplies.get(id);
        if (!n) return false;
        if (n <= 1) suppressUpstreamReplies.delete(id);
        else suppressUpstreamReplies.set(id, n - 1);
        return true;
    };

    // In-flight requests pending a response. We replay them after a forced
    // reconnect so a server-side session swap doesn't strand a tool call
    // forever waiting for a reply that will never come. Notifications
    // (no id) and responses (no method) are not tracked.
    // `startedAt` is never refreshed, not even by a replay: a reconnect loop
    // would otherwise keep pushing the deadline out.
    const inFlight = new Map<string | number, InFlightEntry>();
    const callTimeoutMs = resolveCallTimeoutMs();
    const stalledHandshakeMs = resolveStalledHandshakeMs(callTimeoutMs);
    const healthProbeMs = resolveHealthProbeMs();

    /** IDs of `tools/list` requests we've forwarded to the relayer. When
     * the response comes back through the SSE pump, we splice in the
     * locally-served `memwal_login` + `memwal_logout` tools so the MCP
     * client surfaces them in its tool palette. */
    const pendingListIds = new Set<string | number>();

    /** Tool names the CONNECTED relayer advertised on its last `tools/list`,
     * minus the ones we serve locally. Empty until the client has listed tools
     * at least once over the *current* session. `reconnect()` clears it: a
     * stale allow would re-forward a tool the new relayer does not serve
     * (GH #928), and a stale deny would refuse a tool it does. Until the
     * next upstream list, the gate allows only the cold-start floor. */
    const upstreamToolNames = new Set<string>();

    /** IDs of forwarded `memwal_health` calls, each against the destination the
     * call went out on — relayer URL and account. Captured at send time rather
     * than read at reply time so a reconnect that swapped credentials mid-flight
     * cannot label the answer with a destination it did not come from. */
    const pendingHealthIds = new Map<
        string | number,
        { relayerUrl: string; accountId?: string }
    >();

    /** Record a 429 and tell the user ONCE that this is a rate limit rather
     * than a broken config — the distinction the MCP host cannot make for
     * itself, and the reason a throttled bridge reads as "memwal is down". */
    function noteThrottled(err: RelayerThrottledError): void {
        throttledUntilMs = Math.max(throttledUntilMs, Date.now() + err.retryAfterMs);
        log.warn("bridge.relayer_throttled", {
            retryAfterMs: err.retryAfterMs,
            serverAdvised: err.serverAdvised,
            err: err.message,
        });
        if (throttleNoticed) return;
        throttleNoticed = true;
        const seconds = Math.max(1, Math.round(err.retryAfterMs / 1000));
        note(
            `Relayer is rate-limiting new MCP sessions (HTTP 429). This is a ` +
                `throttle, not a bad config or bad credentials — retrying in ` +
                `${seconds}s. Memory tools start working once a session opens.` +
                (err.serverAdvised
                    ? ""
                    : " The cap counts concurrent sessions, so closing another " +
                      "MCP client using this account clears it sooner."),
        );
    }

    /** Reopen the SSE stream and replay outstanding `inFlight` requests against
     * the fresh session. All callers await the SAME reconnect via
     * `reconnectPromise` — returning immediately while one is active would let
     * the server pump spin on the aborted stream and let client messages race
     * the stale POST URL. Any reconnect replays the WHOLE `inFlight` map, so
     * callers must treat every id-bearing request as reconnect-owned and never
     * re-post it themselves. `immediate` skips the backoff (used right after a
     * login credential swap). Credential-generation checks discard a session
     * whose key rotated mid-handshake. */
    async function reconnect(reason: string, immediate = false): Promise<void> {
        if (stdinClosed || loggedOut) return;
        if (reconnectPromise) return reconnectPromise;

        reconnectPromise = (async () => {
            sessionEpoch += 1;
            try {
                sse?.abort();
            } catch {
                /* already dead */
            }
            // `immediate` (a login credential swap) still bypasses everything,
            // throttle included: that path trades a possible extra 429 for a
            // re-login that doesn't stall behind a multi-second floor.
            const backoff = immediate
                ? 0
                : Math.max(
                      Math.min(15_000, 500 * Math.pow(2, reconnectAttempt)),
                      throttledUntilMs - Date.now(),
                  );
            reconnectAttempt += 1;
            log.warn("bridge.reconnecting", {
                reason,
                backoffMs: backoff,
                attempt: reconnectAttempt,
            });
            // Sleep, but wake immediately on stdin close so shutdown isn't held
            // up for the whole backoff; unref'd so the timer never keeps the
            // event loop alive on its own (mirrors the connect-retry backoff).
            if (backoff > 0) {
                await new Promise<void>((resolve) => {
                    const timer = setTimeout(() => {
                        unregister();
                        resolve();
                    }, backoff);
                    timer.unref?.();
                    const unregister = onStdinClose(() => {
                        clearTimeout(timer);
                        resolve();
                    });
                });
            }
            // Hoisted so the catch below can ask whether the credentials moved
            // since the handshake that threw was opened — a 401 for a key a
            // login has already replaced says nothing about the new one.
            let openingGeneration = credentialGeneration;
            try {
                while (!stdinClosed && !loggedOut) {
                    openingGeneration = credentialGeneration;
                    const openingCreds = creds;
                    // Signed out between the guard above and here: the key is
                    // gone, so there is nothing to authorize a new session
                    // with. Belt-and-braces against `loggedOut` alone.
                    if (!openingCreds) break;
                    const candidate = await openRelaySession(
                        openingCreds.relayerUrl,
                        openingCreds,
                        connectHeaders(),
                    );

                    // Logout can also land mid-handshake. Same reasoning as the
                    // stale-credentials case below, except there is no new key
                    // to reconnect with — drop the session and stop.
                    if (loggedOut) {
                        candidate.abort();
                        log.info("bridge.reconnect_discarded_signed_out", {});
                        break;
                    }

                    // Login can finish while an older handshake is awaiting its
                    // endpoint event. Never publish that stale session: its GET
                    // used the old key, while subsequent POSTs would use the new
                    // key and fail session authentication.
                    if (openingGeneration !== credentialGeneration) {
                        candidate.abort();
                        log.info("bridge.reconnect_discarded_stale_credentials", {
                            openingGeneration,
                            credentialGeneration,
                        });
                        continue;
                    }

                    sessionEpoch += 1;
                    sse = candidate;
                    firstConnectDone = true;
                    activeCredentialGeneration = openingGeneration;
                    reconnectAttempt = 0;
                    throttledUntilMs = 0;
                    throttleNoticed = false;
                    clearHandshakeFailure();
                    endConnectEpisode();
                    // This session has not advertised anything yet. Keep the
                    // previous set and a login that swapped relayerUrl would
                    // re-forward a tool the new one does not serve, or refuse
                    // one it does, until the client happened to re-list.
                    upstreamToolNames.clear();
                    writeStdoutMessage({
                        jsonrpc: "2.0",
                        method: "notifications/tools/list_changed",
                    });
                    // An accepted handshake retires any earlier rejection —
                    // `memwal_login` re-registers a key and lands here, not on
                    // the background connect's publish path, so clearing only
                    // there would leave every later request refused (WALM-602).
                    credentialsRejected = false;
                    // Usually a no-op: the pump is past `firstConnect` by the
                    // time anything reconnects. It is NOT a no-op when this is
                    // the first session to exist at all — a login after the
                    // saved key was rejected — and without it the pump would
                    // stay parked until the background connect's backoff
                    // happened to expire, with nothing draining this stream.
                    signalFirstConnect();
                    log.info("bridge.reconnected", {
                        relayer: openingCreds.relayerUrl,
                        replayCount: inFlight.size,
                        // The count alone cannot tell "nothing was pending"
                        // from "the entry was dropped early" — the ambiguity
                        // behind WALM-328's unexplained `replayCount: 0`.
                        inFlight: Array.from(inFlight.entries()).map(([id, entry]) => ({
                            id,
                            method: entry.msg.method ?? null,
                        })),
                    });
                    // Replay any requests that haven't been answered yet against the
                    // fresh session. Iterate over a snapshot — postMessage is async
                    // and the SSE pump may delete entries concurrently as replies
                    // start arriving on the new session.
                    for (const [id, entry] of Array.from(inFlight.entries())) {
                        // Replay awaits a POST per entry, so a logout can land
                        // partway through this loop. The snapshot and
                        // `openingCreds` both predate it, so without this the
                        // remaining entries would still go out under the key the
                        // user just deleted — `invalidateSession` clearing
                        // `inFlight` cannot stop a snapshot already taken.
                        if (loggedOut || openingGeneration !== credentialGeneration) {
                            log.info("bridge.replay_halted_signed_out", { id });
                            break;
                        }
                        // The sweeper already declared this call's reply lost
                        // and is answering it as failed. Posting it again would
                        // run it a second time — a duplicate write for a tool
                        // with no idempotency key — and the reply would be
                        // dropped anyway, as a late answer for a closed-out id.
                        if (entry.orphaned) {
                            log.info("bridge.replay_skipped_orphaned", { id });
                            continue;
                        }
                        const msg = entry.msg;
                        try {
                            // A replayed `initialize` produces a fresh upstream
                            // reply on the NEW session that must also be dropped.
                            // REPLACE (not stack) any pending suppression for this
                            // id: the old session was aborted, so its initialize
                            // reply will never arrive to consume its own arm.
                            // Re-arming without clearing would leave that orphaned
                            // arm forever, and a later reused id would have its
                            // real reply wrongly dropped. Reset to exactly one —
                            // the single reply the new session will send.
                            if (msg.method === "initialize" && msg.id != null) {
                                suppressUpstreamReplies.delete(msg.id);
                                expectSuppressedReply(msg.id);
                            }
                            const epoch = sessionEpoch;
                            const send = sse.send;
                            const status = await enqueuePost(() =>
                                postIfCurrent(epoch, send, msg, openingCreds),
                            );
                            log.info("bridge.replayed", { id, status });
                        } catch (err) {
                            log.error("bridge.replay_failed", {
                                id,
                                err: err instanceof Error ? err.message : String(err),
                            });
                        }
                    }
                    // Credentials can also rotate while replay awaits POSTs.
                    // In that case this candidate is already stale even though
                    // it passed the first generation check.
                    if (openingGeneration !== credentialGeneration) {
                        candidate.abort();
                        // The replay above armed one initialize suppression for
                        // THIS (now-discarded) candidate; its reply will never
                        // arrive to consume it. Clear those arms so the count
                        // doesn't leak if the loop exits before another replay
                        // re-arms (a leaked arm would swallow a later reused-id
                        // reply). A surviving candidate re-arms fresh next pass.
                        for (const [, entry] of inFlight) {
                            if (entry.msg.method === "initialize" && entry.msg.id != null) {
                                suppressUpstreamReplies.delete(entry.msg.id);
                            }
                        }
                        continue;
                    }
                    break;
                }
            } catch (err) {
                const reason = err instanceof Error ? err.message : String(err);
                // A 429 must outlive this call: reconnect() gives up after one
                // failure, so without recording the deadline the next caller
                // would compute a fresh sub-second backoff and hammer the cap.
                if (err instanceof RelayerThrottledError) noteThrottled(err);
                noteHandshakeFailure(reason);
                log.error("bridge.reconnect_failed", { err: reason });
                // A key revoked mid-session lands here rather than on the
                // background connect, and retrying cannot fix it either. Answer
                // the replay set now instead of letting the orphan sweeper hand
                // back "connection dropped, please retry" four minutes later —
                // the same WALM-602 symptom, one path over.
                //
                // This does not strand the transient case: the server pump is
                // still looping on the dead stream, so it keeps driving
                // `reconnect()` on its own growing backoff, and the publish
                // above clears the flag the moment a handshake is accepted.
                //
                // It also takes precedence over the stalled-handshake deadline
                // added here: a 401 is terminal until the user logs in again,
                // so there is nothing to gain by waiting out even the short
                // deadline for it.
                if (
                    err instanceof RelayerUnauthorizedError &&
                    openingGeneration === credentialGeneration
                ) {
                    credentialsRejected = true;
                    failInFlightRequests("credentials rejected", UNAUTHORIZED_FAILURE);
                }
                // Try again on the next stdin message rather than spinning.
            }
        })();

        try {
            await reconnectPromise;
        } finally {
            reconnectPromise = null;
        }
    }

    async function adoptCredentials(nextCreds: MemWalCredentials): Promise<void> {
        // `null` after a logout — treated as an account change, which is the
        // safe direction: it purges rather than replays. (`invalidateSession`
        // already emptied both queues, so the purge is a no-op there.)
        const previousAccountId = creds?.accountId ?? null;
        const accountChanged = previousAccountId !== nextCreds.accountId;

        // Never replay an operation authorized for account A against account B.
        // Return explicit retryable errors instead; the caller can decide which
        // operations belong in the newly-selected account.
        if (accountChanged) {
            try {
                sse?.abort();
            } catch {
                /* already dead */
            }
            // Purge EVERY structure that holds an account-A request. `inFlight`
            // (tracked requests) AND `pendingForward` (cold-start / mid-flush
            // buffered requests) — the latter is unique to the cold-start path
            // and would otherwise be flushed to account B's session (a
            // cross-account replay) since the flush posts with the current
            // `creds`. For each, reply once with a retryable error and stop
            // tracking; never write a second reply for a locally-answered
            // `initialize`. Keep its one-shot suppress arm so a queued
            // upstream initialize reply is consumed. Do not put initialize in
            // closedOutIds — a later reused id must still get a real reply.
            const purge = (msg: RpcMessage): void => {
                if (msg.id == null) return; // notification — nothing to reply to
                pendingListIds.delete(msg.id);
                pendingHealthIds.delete(msg.id);
                if (msg.method === "initialize") {
                    return;
                }
                suppressUpstreamReplies.delete(msg.id);
                // A request can be in BOTH inFlight and pendingForward (cold-start
                // dual-tracking), so guard against answering the same id twice.
                if (closedOutIds.has(msg.id)) return;
                // Record the id so a late reply for it (e.g. one already
                // in-flight on the aborted session, or a racing replay) is
                // dropped by the pump rather than becoming a second response.
                closedOutIds.add(msg.id);
                writeStdoutMessage({
                    jsonrpc: "2.0",
                    id: msg.id,
                    error: {
                        code: -32001,
                        message:
                            "Walrus Memory account changed during login; retry this request for the new account",
                    },
                });
            };
            for (const [, entry] of Array.from(inFlight.entries())) purge(entry.msg);
            inFlight.clear();
            for (const msg of pendingForward.splice(0, pendingForward.length)) purge(msg);
        } else {
            // Same account: reconnect() owns inFlight. Drop id-bearing
            // pendingForward so a login mid-flush cannot POST the same
            // remember/recall again after replay.
            const leftover = pendingForward.filter((m) => m.id == null);
            pendingForward.length = 0;
            pendingForward.push(...leftover);
        }

        creds = nextCreds;
        credentialGeneration += 1;
        reconnectAttempt = 0;
        // Lift the logout halt BEFORE reconnecting — reconnect() refuses to run
        // while it is set. The parked pump is released further down, once the
        // new session actually exists.
        loggedOut = false;
        log.info("bridge.credentials_updated", {
            previousAccountId,
            accountId: creds.accountId,
            delegate: creds.delegateAddress,
        });
        await reconnect("login-credentials-updated", true);
        // Covers the narrow case where this update joined a reconnect just as
        // its promise was resolving, after its final generation check.
        if (activeCredentialGeneration !== credentialGeneration) {
            await reconnect("login-credentials-generation-mismatch", true);
        }
        // Session is live again: wake a pump parked by a previous logout.
        releaseLogoutPark?.();
        releaseLogoutPark = null;
        logoutPark = null;

        // Queue the confirmation only once the session is actually live, so
        // the banner cannot claim an authenticated connection before there is
        // one. It rides out on the next `tools/call` result.
        notePendingLoginSuccess({
            accountId: creds.accountId,
            delegateAddress: creds.delegateAddress,
            credentialsPath: credsPath(),
        });
    }

    /**
     * Tear the relayer session down after a successful `memwal_logout`.
     *
     * Deleting the credentials file is not revocation on its own: the bridge
     * holds the delegate key in memory and owns a live SSE session, so without
     * this every later memory tool call would still be forwarded and executed
     * under the key the user just removed (GH #616).
     *
     * `loggedOut` is set FIRST so the abort below cannot race the pump into
     * `reconnect("server-pump-eof")` and immediately re-authorize a new session
     * with those same in-memory credentials.
     */
    function invalidateSession(): void {
        if (loggedOut) return;
        loggedOut = true;
        logoutPark = new Promise<void>((resolve) => {
            releaseLogoutPark = resolve;
        });
        try {
            sse?.abort();
        } catch {
            /* already dead */
        }
        sse = null;
        // Drop the delegate key itself, not just the flag. Revocation that
        // rests only on `loggedOut` is one missed check away from forwarding
        // under the key the user deleted; with `creds` null there is nothing
        // left to sign with and every forwarding path fails closed instead.
        creds = null;
        // Bump the generation so any handshake or replay that captured the old
        // key before this point discards its work on its next check, exactly as
        // it would for a mid-flight key rotation.
        credentialGeneration += 1;
        // Answer everything still outstanding rather than stranding it: these
        // were authorized under the old key and must not be replayed later.
        for (const [, entry] of Array.from(inFlight.entries())) {
            failRequest(entry.msg, "signed out", SIGNED_OUT_FAILURE);
        }
        inFlight.clear();
        for (const msg of pendingForward.splice(0, pendingForward.length)) {
            failRequest(msg, "signed out", SIGNED_OUT_FAILURE);
        }
        log.info("bridge.session_invalidated", { reason: "logout" });
    }

    // Server → client: stream SSE messages to stdout. Loop forever, restart
    // pump on stream end (which means SSE got cut → we already reconnected).
    const serverPump = (async () => {
        // Nothing to pump until the first relayer session is up. `firstConnect`
        // resolves only on a SUCCESSFUL connect (the background connector
        // retries failures with backoff), unless stdin closed first — in which
        // case `sse` stays null and we exit the loop immediately.
        await firstConnect;
        while (!stdinClosed) {
            try {
                // Snapshot the current stream. `sse` is non-null here: set before
                // signalFirstConnect(), and reconnect() only ever replaces it with
                // another live handle. Reading through a local keeps us on one
                // stream for the duration of this drain; a reconnect swaps `sse`
                // and we pick up the new handle on the next outer iteration.
                // Cast: TS control-flow narrows `sse` to `null` in the outer
                // scope because every non-null assignment happens inside a
                // sibling closure (connectInBackground / reconnect) that TS
                // analyzes independently. At runtime `sse` is a live handle here.
                const stream = sse as SseHandshakeResult | null;
                if (!stream) {
                    // Signed out: park rather than exit. Exiting would end the
                    // pump for good, so a later `memwal_login` would reconnect a
                    // session with nothing draining it — the client would hang
                    // instead of recovering. `logoutPark` resolves once the new
                    // session is published (or stdin closes).
                    // Cast for the same reason as `stream` above: every
                    // assignment to `logoutPark` happens in a sibling closure,
                    // so TS narrows it to `null` here. No `!stdinClosed` guard:
                    // the `while` above already established it and nothing is
                    // awaited in between, so it cannot have changed.
                    if (loggedOut) {
                        await (logoutPark as Promise<void> | null);
                        continue;
                    }
                    break; // stdin closed before we ever connected
                }
                while (true) {
                    const { value, done } = await stream.iter.next();
                    if (done) break;
                    // Drop the upstream reply to a request we already answered
                    // locally (e.g. `initialize`). Writing it would be a second
                    // response for the same id. We consume exactly ONE expected
                    // suppression per id (see suppressUpstreamReplies), so once
                    // the initialize reply(s) are drained the id stops
                    // suppressing — a client that later reuses that id for a real
                    // request still gets THAT request's reply (result or error).
                    if (
                        value &&
                        value.id !== undefined &&
                        value.id !== null &&
                        (value.result !== undefined || value.error !== undefined) &&
                        consumeSuppressedReply(value.id)
                    ) {
                        inFlight.delete(value.id);
                        continue;
                    }
                    // Drop a late reply for an id we already closed out at
                    // shutdown — writing it would be a second response for that
                    // id (see closedOutIds / failRequest).
                    if (
                        value &&
                        value.id !== undefined &&
                        value.id !== null &&
                        (value.result !== undefined || value.error !== undefined) &&
                        closedOutIds.has(value.id)
                    ) {
                        inFlight.delete(value.id);
                        continue;
                    }
                    // Which request this reply answers. Captured BEFORE the
                    // `inFlight.delete` below drops the entry, so the sign-in
                    // banner can tell a `tools/call` result from a `tools/list`
                    // or a `ping` and avoid being consumed by a response the
                    // user never reads.
                    const answeredMethod =
                        value && value.id !== undefined && value.id !== null
                            ? inFlight.get(value.id)?.msg.method
                            : undefined;

                    // Clear in-flight tracking once the response lands.
                    if (
                        value &&
                        (value.result !== undefined || value.error !== undefined) &&
                        value.id !== undefined &&
                        value.id !== null
                    ) {
                        inFlight.delete(value.id);
                    }
                    // Splice local tools into `tools/list` responses so
                    // memwal_login + memwal_logout appear in the client's
                    // tool palette alongside the relayer-side tools.
                    if (
                        value &&
                        value.id !== undefined &&
                        value.id !== null &&
                        pendingListIds.has(value.id) &&
                        value.result &&
                        typeof value.result === "object"
                    ) {
                        pendingListIds.delete(value.id);
                        const result = value.result as { tools?: unknown };
                        if (Array.isArray(result.tools)) {
                            // Strip any locally-served name from the upstream set
                            // before appending ours, so a relayer that ever
                            // advertises login/logout itself can't produce a
                            // duplicate tool name. Mirrors LOCAL_TOOLS_LIST.
                            const upstream = (result.tools as { name?: string }[]).filter(
                                (t) => !LOCAL_TOOL_NAMES.has(t.name ?? ""),
                            );
                            result.tools = [...upstream, ...LOCAL_TOOL_DEFINITIONS];
                            // Record what this relayer actually serves. A
                            // later call for a name absent here is answered
                            // locally instead of being forwarded into a wait
                            // no reply will ever end.
                            upstreamToolNames.clear();
                            for (const t of upstream) {
                                if (typeof t.name === "string" && t.name !== "") {
                                    upstreamToolNames.add(t.name);
                                }
                            }
                        }
                    }
                    if (
                        value &&
                        value.id !== undefined &&
                        value.id !== null &&
                        pendingHealthIds.has(value.id) &&
                        value.result &&
                        typeof value.result === "object"
                    ) {
                        const dialled = pendingHealthIds.get(value.id);
                        pendingHealthIds.delete(value.id);
                        if (dialled !== undefined) {
                            annotateHealthResult(
                                value.result as { content?: unknown; isError?: unknown },
                                dialled.relayerUrl,
                                dialled.accountId,
                            );
                        }
                    }
                    // Health annotation runs BEFORE the sign-in banner. Both
                    // rewrite the same first text block, and annotateHealthResult
                    // replaces the first `relayer=` it finds — so a banner
                    // prefixed first would be the thing it rewrote if that text
                    // ever names a relayer.
                    if (answeredMethod === "tools/call") {
                        applyPendingLoginSuccess(value);
                    }
                    writeStdoutMessage(value);
                }
            } catch (err) {
                log.error("bridge.server_pump_error", {
                    err: err instanceof Error ? err.message : String(err),
                });
            }
            // Deliberately NOT short-circuited on `loggedOut`: breaking here
            // would end the pump for good and strand a later re-login. Fall
            // through instead — `reconnect()` no-ops while signed out, and the
            // next iteration parks on `logoutPark` at the top of the loop.
            if (stdinClosed) break;
            // Stream ended. If a reconnect is ALREADY in progress (e.g. the
            // flush hit a 404), await THAT one rather than hammering reconnect()
            // — otherwise this loop would spin on the dead stream's immediate
            // `done`. reconnect() itself returns the shared reconnectPromise when
            // one is active, so awaiting it here is enough; on the next
            // iteration `sse` has been swapped to the fresh session and we
            // resume reading. If no reconnect is in progress, this starts one.
            await reconnect("server-pump-eof");
        }
    })();

    // Client → server: forward stdin lines as POST messages. On 404 (the
    // relayer doesn't know our sessionId — happens right after a reconnect
    // if the message races the new handshake), trigger another reconnect.
    const handleClientLine = (line: string): void => {
        void (async () => {
            try {
                const msg = JSON.parse(line) as RpcMessage;

                // Answer `initialize` LOCALLY and instantly so the MCP client's
                // handshake never waits on the relayer connect (the cold-start
                // bug). We STILL forward it upstream (below) so the relayer
                // session negotiates capabilities — but suppress that upstream
                // reply, since the client already has this one.
                if (msg.method === "initialize" && msg.id != null) {
                    const clientInfo = rememberInitializeClientInfo(msg.params);
                    if (clientInfo) {
                        Object.assign(extraHeaders, clientInfoHeaders(clientInfo));
                        log.info("bridge.agent_client", {
                            clientName: clientInfo.name,
                            clientVersion: clientInfo.version,
                        });
                    }
                    writeStdoutMessage({
                        jsonrpc: "2.0",
                        id: msg.id,
                        result: buildLocalInitializeResult(msg.params),
                    });
                    // Signed out, or the key was rejected: the local reply is the
                    // whole answer. Both refuse further down instead of
                    // forwarding, so do not arm a suppression that no reply can
                    // ever consume — a leaked arm would swallow the real reply
                    // if the client later reuses this id.
                    if (loggedOut || credentialsRejected) return;
                    // Expect exactly one upstream reply to drop for this forward.
                    expectSuppressedReply(msg.id);
                    // Fall through: forward/buffer the initialize upstream too.
                }

                // Answer `tools/list` LOCALLY at cold start (before the relayer
                // session exists) so tool discovery unblocks immediately. Once
                // connected we emit `notifications/tools/list_changed` and the
                // client re-lists — that re-list is forwarded upstream and gets
                // the real tool set spliced (handled further down + in the pump).
                if (msg.method === "tools/list" && msg.id != null && sse === null) {
                    writeStdoutMessage({
                        jsonrpc: "2.0",
                        id: msg.id,
                        result: LOCAL_TOOLS_LIST,
                    });
                    return;
                }

                // Local interception: `memwal_login` and `memwal_logout`
                // are handled here, never sent to the relayer. The user
                // can call them any time to re-auth or sign out without
                // having to remove + re-add the MCP server.
                if (msg.method === "tools/call" && msg.id != null) {
                    const params = (msg.params ?? {}) as {
                        name?: string;
                        arguments?: { freshKey?: unknown };
                    };
                    // Tool NAME only, never `arguments` — memory text is the
                    // user's private data and must not reach a log file.
                    // Without this the only trace of a call is the host's own
                    // `method="tools/call" id=N` line, which cannot say WHICH
                    // tool ran. Scoring the WALM-368 T1-T3 cases needs exactly
                    // that: "remember never fired" and "remember fired and
                    // failed" are different bugs that looked identical.
                    log.info("bridge.tool_call", {
                        tool: params.name ?? null,
                        id: msg.id,
                    });
                    if (params.name === "memwal_login") {
                        const result = await handleLocalLogin(
                            config,
                            adoptCredentials,
                            params.arguments?.freshKey === true,
                        );
                        writeStdoutMessage({
                            jsonrpc: "2.0",
                            id: msg.id,
                            result: {
                                content: [{ type: "text", text: result.text }],
                                isError: result.isError,
                            },
                        });
                        return;
                    }
                    if (params.name === "memwal_logout") {
                        const result = handleLocalLogout();
                        // Tear the session down before replying, so by the time
                        // the client is told it is signed out that is actually
                        // true. Only on success: if the credentials file could
                        // not be removed the user is still signed in.
                        if (!result.isError) invalidateSession();
                        writeStdoutMessage({
                            jsonrpc: "2.0",
                            id: msg.id,
                            result: {
                                content: [{ type: "text", text: result.text }],
                                isError: result.isError,
                            },
                        });
                        return;
                    }
                }

                // Signed out: refuse EVERY remaining request locally, not just
                // memory tool calls. `login`/`logout` returned above, and
                // `initialize`/`tools/list` are answered locally further up, so
                // anything still here would need the delegate key the user
                // deleted. Falling through instead would park it in
                // `pendingForward` — `sse` is null and `reconnect()` no-ops
                // while signed out — where it would either hang the client until
                // a login that may never come, or be flushed afterwards under a
                // NEW key the client never authorized it against. `failRequest`
                // picks the right shape per method: tool-result text for
                // `tools/call`, a JSON-RPC error for `ping` and friends, and
                // nothing at all for notifications.
                if (loggedOut) {
                    failRequest(msg, "signed out", SIGNED_OUT_FAILURE);
                    return;
                }

                // Credentials rejected: same reasoning as `loggedOut` above.
                // `memwal_login` returned locally already, so refusing here
                // still leaves the user a way back in. Falling through would
                // park the request in `pendingForward` behind a connect loop
                // that keeps 401ing, and the client would learn nothing until
                // the orphan sweeper's deadline — the WALM-602 symptom.
                if (credentialsRejected) {
                    failRequest(msg, "credentials rejected", UNAUTHORIZED_FAILURE);
                    return;
                }

                // Version skew: this bridge ships on npm and updates itself,
                // while a relayer ships per environment and does not, so the
                // bridge is routinely newer than the server it dials. A tool
                // named in initialize instructions or a cached list can be
                // missing from the session that actually came up —
                // `memwal_remember_status` against a prod relayer, which is
                // GH #928. Forwarding that call parks it in `inFlight` until
                // the orphan sweeper's deadline (60s + 30s headroom for that
                // tool), and the user reads the 90s as a hang.
                //
                // Fail closed. Before any upstream `tools/list`, only the
                // cold-start floor is callable. After one, only what that
                // relayer advertised (plus locally-served tools). A stale
                // tool list is not a transport fault: say so now, while the
                // agent can still act on it.
                if (msg.method === "tools/call" && msg.id != null) {
                    const called = (msg.params as { name?: string } | undefined)?.name;
                    if (typeof called === "string" && !LOCAL_TOOL_NAMES.has(called)) {
                        const known =
                            upstreamToolNames.size > 0
                                ? upstreamToolNames
                                : COLD_START_TOOL_NAMES;
                        if (!known.has(called)) {
                            const available = [
                                ...(upstreamToolNames.size > 0
                                    ? [...upstreamToolNames, ...LOCAL_TOOL_NAMES]
                                    : COLD_START_TOOL_NAMES),
                            ].sort();
                            log.warn("bridge.tool_not_served", {
                                tool: called,
                                window:
                                    upstreamToolNames.size > 0 ? "upstream" : "cold-start",
                            });
                            failRequest(msg, "tool not served", {
                                toolText: unknownToolText(called, available),
                                errorMessage: `${called} is not served by this Walrus Memory relayer`,
                            });
                            return;
                        }
                    }
                }

                // Fill in the configured default namespace for memory tool
                // calls that didn't pass one. Mutates msg in place so the
                // forwarded — and any replayed-on-reconnect — copy carries it.
                applyDefaultNamespace(msg, config.namespace);

                // Stamp write tools with a stable idempotency key, once per
                // logical call, so a reconnect replay carries the same key as
                // the original (issue #1045). The MCP server sends it to the
                // relayer as `idempotency_key` on `/api/remember/bulk`, and the
                // relayer answers a replayed key with the jobs it already
                // queued instead of registering a second paid Walrus blob.
                applyIdempotencyKey(msg);

                // Track `tools/list` requests so the SSE pump can splice
                // our local tools into the upstream response.
                if (msg.method === "tools/list" && msg.id != null) {
                    pendingListIds.add(msg.id);
                }

                // Same idea for `memwal_health`: record the relayer this
                // session is bound to so the pump can name it on the reply.
                if (
                    msg.method === "tools/call" &&
                    msg.id != null &&
                    (msg.params as { name?: string } | undefined)?.name === "memwal_health"
                ) {
                    pendingHealthIds.set(msg.id, {
                        relayerUrl: creds?.relayerUrl ?? config.relayerUrl,
                        accountId: creds?.accountId,
                    });
                }

                // Track requests (have both method and id) so we can replay
                // them on reconnect. Notifications and responses are not
                // tracked.
                if (
                    msg.method !== undefined &&
                    msg.id !== undefined &&
                    msg.id !== null
                ) {
                    inFlight.set(msg.id, {
                        msg,
                        startedAt: Date.now(),
                        deadlineMs: resolveDeadlineMs(msg),
                    });
                }
                // Relayer session not up yet, OR the post-connect flush is still
                // draining — buffer so this request stays behind everything that
                // arrived before it (posting directly here would let it overtake
                // a still-queued buffered item). The flush (or the next connect)
                // forwards it in order. Dropping it would strand the request.
                if (flushing || (sse === null && !firstConnectDone)) {
                    pendingForward.push(msg);
                    log.info("bridge.buffered_pre_connect", {
                        method: msg.method,
                        id: msg.id ?? null,
                    });
                    return;
                }
                // After the first connect, do not buffer: nothing flushes
                // pendingForward once connectInBackground has returned.
                if (sse === null) {
                    await reconnect("sse-missing");
                    return;
                }

                // A successful background login swaps credentials and SSE
                // sessions asynchronously. Wait for that swap before sending a
                // new request so it cannot race the stale session URL/key.
                if (reconnectPromise) await reconnectPromise;
                if (activeCredentialGeneration !== credentialGeneration) {
                    await reconnect("post-credential-generation-mismatch", true);
                }
                // A logout can land while the two awaits above are parked. The
                // key is gone by then, so answer locally instead of posting.
                if (loggedOut || !creds) {
                    failRequest(msg, "signed out", SIGNED_OUT_FAILURE);
                    return;
                }
                if (!sse) {
                    await reconnect("sse-missing");
                    return;
                }
                const epoch = sessionEpoch;
                const send = sse.send;
                const postCreds = creds;
                const status = await enqueuePost(() =>
                    postIfCurrent(epoch, send, msg, postCreds),
                );
                if (status === 404) {
                    log.warn("bridge.session_stale", { sessionUrl: sse.postUrl });
                    // reconnect() itself replays in-flight against the fresh
                    // session, so no explicit per-message retry is needed.
                    await reconnect("post-404");
                }
            } catch {
                log.warn("bridge.stdin_parse_failed", { line: line.slice(0, 120) });
            }
        })();
    };

    /** Flush everything buffered before the session came up, in arrival order,
     * then announce the real tool set. Called once, right after the first
     * successful connect. `flushing` keeps concurrently-arriving stdin requests
     * buffering (rather than posting directly and overtaking the queue); we
     * drain until the buffer is empty so those late arrivals are forwarded too. */
    async function flushPendingForward(): Promise<void> {
        flushing = true;
        try {
            if (pendingForward.length > 0) {
                log.info("bridge.flushing_pre_connect", { count: pendingForward.length });
            }
            while (pendingForward.length > 0) {
                if (stdinClosed) {
                    // Shutting down mid-flush: don't post to a torn-down session.
                    // Everything still buffered (plus what we've already shifted
                    // into inFlight but not delivered) is closed out below.
                    break;
                }
                // `invalidateSession` nulls both; either one means this queue
                // must not be drained onto the relayer.
                if (!sse || !creds) break; // lost the session; reconnect replays inFlight
                const msg = pendingForward.shift()!;
                try {
                    const epoch = sessionEpoch;
                    const send = sse.send;
                    const postCreds = creds;
                    const status = await enqueuePost(() =>
                        postIfCurrent(epoch, send, msg, postCreds),
                    );
                    if (status === 404) {
                        // Stale session right after connect. EVERY id-bearing
                        // request is in `inFlight`, and ANY reconnect — this
                        // flush's own, or a concurrent `server-pump-eof` one that
                        // shares the same `reconnectPromise` — replays the whole
                        // `inFlight` map against the fresh session. So id-bearing
                        // items are owned by reconnect, period; re-posting them
                        // from the flush would duplicate them (double write +
                        // two replies for one id). We therefore drop ALL
                        // id-bearing items from the queue after reconnect and
                        // keep only id-less notifications (never in `inFlight`,
                        // so no reconnect carries them) to re-drain. `await
                        // reconnect()` resolves the shared reconnectPromise, so
                        // `inFlight` has been fully replayed by the time we
                        // decide what's left to send — no matter which caller
                        // owns the reconnect.
                        log.warn("bridge.session_stale", { sessionUrl: sse.postUrl });
                        if (msg.id == null) pendingForward.unshift(msg);
                        await reconnect("post-404");
                        const notifications = pendingForward.filter((m) => m.id == null);
                        pendingForward.length = 0;
                        pendingForward.push(...notifications);
                        continue;
                    }
                } catch (err) {
                    log.error("bridge.flush_failed", {
                        id: msg.id ?? null,
                        err: err instanceof Error ? err.message : String(err),
                    });
                }
            }
        } finally {
            flushing = false;
        }
        // If stdin closed while we were draining, close out anything still open
        // (buffered + already-in-inFlight-but-undelivered) so those calls get an
        // error envelope instead of hanging until the client's own timeout.
        if (stdinClosed) {
            failPendingForward("connection lost during shutdown");
            failInFlightRequests("connection lost during shutdown");
            return;
        }
        // The client discovered tools from our static `tools/list`. Now that the
        // real relayer session is up, tell it to re-list so it picks up the
        // authoritative upstream set (spliced with login/logout in the pump).
        writeStdoutMessage({
            jsonrpc: "2.0",
            method: "notifications/tools/list_changed",
        });
    }

    /** Write a failure reply for one open request, stop tracking it, and never
     * double-answer a locally-answered request. Shared by the buffered
     * (`failPendingForward`) and in-flight (`failInFlightRequests`) close-outs,
     * and by the orphan sweeper — which passes `opts` because "relayer
     * unavailable" would be a lie there: the relayer is fine, one reply just
     * never arrived. Skips:
     *   - notifications (no id → nothing to reply to; also unforwardable now).
     *   - `initialize` (we already answered it locally; a second response for
     *     that id would corrupt the client's JSON-RPC state — just untrack).
     * Only `tools/call` shaped requests get the tool-result error envelope; any
     * other id-bearing request gets a JSON-RPC error object (the correct shape
     * for a non-tool request). */
    /** `opts` overrides the default "relayer unavailable" wording for callers
     * whose failure is not an outage — logout, for one, where blaming the
     * relayer would be actively misleading. */
    function failRequest(
        msg: RpcMessage,
        reason: string,
        opts: { toolText?: string; errorMessage?: string } = {},
    ): void {
        if (msg.id == null) return; // notification — nothing to answer
        if (msg.method === "initialize") {
            // Locally answered already. Never write a second reply for this id.
            // Keep any suppress arm so a late upstream initialize result is
            // consumed; do not closedOut the id (clients may reuse it later).
            inFlight.delete(msg.id);
            return;
        }
        inFlight.delete(msg.id);
        // Remember we answered this id, so a late genuine reply (e.g. from a
        // flush-404 reconnect that re-posted onto a live session) is dropped by
        // the pump instead of becoming a second response for the same id.
        closedOutIds.add(msg.id);
        if (msg.method === "tools/call") {
            writeStdoutMessage({
                jsonrpc: "2.0",
                id: msg.id,
                result: {
                    content: [
                        {
                            type: "text",
                            text:
                                opts.toolText ??
                                `❌ Walrus Memory relayer unavailable: ${reason}. The memory tool could not run. Please retry shortly.`,
                        },
                    ],
                    isError: true,
                },
            });
        } else {
            writeStdoutMessage({
                jsonrpc: "2.0",
                id: msg.id,
                error: {
                    code: -32000,
                    message:
                        opts.errorMessage ??
                        `Walrus Memory relayer unavailable: ${reason}`,
                },
            });
        }
    }

    function failPendingForward(
        reason: string,
        opts: { toolText?: string; errorMessage?: string } = {},
    ): void {
        const queued = pendingForward.splice(0, pendingForward.length);
        for (const msg of queued) failRequest(msg, reason, opts);
    }

    /** Close out requests that reached `inFlight` but were never delivered a
     * reply — the shutdown counterpart of `failPendingForward`. Used when stdin
     * closes mid-flush: items already shifted out of `pendingForward` and posted
     * to a torn-down session would otherwise hang, since no upstream reply is
     * coming. Idempotent w.r.t. ids already closed out (delete-then-skip). */
    function failInFlightRequests(
        reason: string,
        opts: { toolText?: string; errorMessage?: string } = {},
    ): void {
        for (const entry of Array.from(inFlight.values())) failRequest(entry.msg, reason, opts);
    }

    /** How long the current run of handshake failures has lasted, or `null`
     * when the last attempt succeeded. */
    function handshakeStalledForMs(now: number): number | null {
        return handshakeFailingSince === null ? null : now - handshakeFailingSince;
    }

    /** How a request that just hit its deadline should be explained.
     *
     * Three cases, where the old wording only described one. A request for
     * which no POST was ever issued never left this process: no session ever
     * carried it. Telling the user the connection "dropped before the result
     * came back" points them at the relayer, or at a half-written memory, when
     * the truth is that nothing was attempted (WALM-618 — the bridge retried
     * in silence, so a `remember` looked like it was merely slow for minutes).
     * And a buffered request is only evidence of a *failing* connection when
     * one is actually failing: post-connect, `handleClientLine` also buffers
     * behind an in-progress flush, on a perfectly healthy session.
     *
     * Pure: the caller is responsible for dropping a `neverSent` message from
     * the buffer, which it must, or a later flush would run the call we just
     * said never ran. */
    /** Tools whose call, once POSTed, may have written to Walrus.
     *
     * The relayer answers these with HTTP 202 and finishes the work in a
     * durable queue, so a client-side deadline cancels nothing: the write can
     * still land minutes after we have given up waiting for the reply. And a
     * retry the agent issues of `memwal_remember_bulk` is a NEW call with a
     * NEW bridge idempotency key (only a transport replay reuses the key,
     * unlike the content-derived key on the single path), so a blind retry
     * mints a second paid blob that `recall` will then hide behind the first. Telling the user to "please retry" here is how a
     * lost reply turns into duplicate paid storage. */
    const MUTATING_TOOLS = new Set([
        "memwal_remember",
        "memwal_remember_bulk",
        "memwal_analyze",
    ]);

    function expiredRequestReport(
        neverSent: boolean,
        now: number,
        tool: string | null,
        health?: { probe: HealthProbe; relayerUrl: string },
    ): {
        reason: string;
        opts: { toolText: string; errorMessage: string };
    } {
        if (!neverSent) {
            // What the relayer's `/health` said just now: tells a dead
            // relayer from a wrong URL from one stuck call.
            const described = health ? describeHealthProbe(health.probe, health.relayerUrl) : null;
            // The request reached the relayer. What is missing is the reply,
            // and for a write that distinction is the whole message: the work
            // may have completed, may still be running, and cannot be assumed
            // undone. "Please retry" is only safe advice for a read.
            if (tool !== null && MUTATING_TOOLS.has(tool)) {
                const healthNote = described
                    ? `\nRelayer health: ${described.health}. ${described.verdict}`
                    : "";
                return {
                    reason: "no response to a sent write",
                    opts: {
                        toolText:
                            `⚠️ Walrus Memory accepted this ${tool} call but did not return a ` +
                            "result in time. The write was sent, so it may have completed or may " +
                            "still be finishing in the background — a timeout here does not cancel " +
                            "it and does not mean nothing was stored. Do NOT simply repeat the " +
                            "call: run `memwal_recall` for this content first, and only re-save " +
                            "what is genuinely missing. Repeating a bulk save that already " +
                            "landed stores a second paid copy." +
                            healthNote,
                        errorMessage:
                            `Walrus Memory ${tool} was sent but its reply never arrived. The write ` +
                            "may have completed; verify with recall before retrying." +
                            healthNote,
                    },
                };
            }
            // Not "this call only reads": `memwal_restore` re-indexes. What
            // makes a retry safe is that none of these can store a duplicate.
            const nextStep =
                described === null || described.reachable
                    ? "Repeating this call cannot store a duplicate, so it is safe to retry " +
                      "once. If it keeps happening, report it with the time of the call."
                    : "Repeating this call cannot store a duplicate, so it is safe to retry " +
                      "after the relayer is reachable again — wait a minute if the problem " +
                      "is on the relayer's side.";
            const healthValue = described?.health ?? "not checked";
            return {
                reason: "no response",
                opts: {
                    toolText: [
                        "❌ Walrus Memory did not answer this call.",
                        "Cause: the request reached the relayer but no reply came back." +
                            (described ? ` ${described.verdict}` : ""),
                        `Relayer health: ${healthValue}`,
                        `Next step: ${nextStep}`,
                    ].join("\n"),
                    errorMessage:
                        "Walrus Memory call reached the relayer but never received a " +
                        `response (relayer health: ${healthValue}). Safe to retry: it cannot ` +
                        "store a duplicate.",
                },
            };
        }

        const stalledForMs = handshakeStalledForMs(now);
        if (stalledForMs === null) {
            // Buffered on a live session (a flush was draining) and still
            // unsent at the deadline. Nothing ran, but nothing is failing
            // either — do not invent an outage.
            return {
                reason: "never left the queue",
                opts: {
                    toolText:
                        "❌ Walrus Memory never sent this call — it was still queued when " +
                        "the call timed out, so nothing was stored. Please retry.",
                    errorMessage:
                        "Walrus Memory call was still queued when it timed out and was " +
                        "never sent. Please retry.",
                },
            };
        }

        const waited = `for ${Math.round(stalledForMs / 1000)}s`;
        const detail = lastHandshakeError ? ` Last handshake error: ${lastHandshakeError}` : "";
        return {
            reason: "never reached the relayer",
            opts: {
                toolText:
                    `❌ Walrus Memory could not reach the relayer — the MCP connection has ` +
                    `been failing ${waited}, so this call never ran and nothing was stored.` +
                    `${detail} Check the relayer, or run \`memwal-mcp login\` if the delegate ` +
                    `key was revoked, then retry.`,
                errorMessage:
                    `Walrus Memory call never reached the relayer: the MCP connection has ` +
                    `been failing ${waited}.${detail}`,
            },
        };
    }

    /** Close out requests whose deadline has passed. Without this a reply lost
     * on a still-healthy stream leaves its request tracked forever. */
    // Same shape as the SSE watchdog's check interval, but capped.
    const sweepIntervalMs = Math.min(
        MAX_ORPHAN_SWEEP_MS,
        Math.max(500, Math.floor(callTimeoutMs / 3)),
    );
    const orphanSweeper = setInterval(() => {
        const now = Date.now();
        const handshakeStalledMs = handshakeStalledForMs(now);
        // One `/health` request per sweep, however many calls expired in it.
        let sweepProbe: Promise<HealthProbe | null> | null = null;
        for (const [id, entry] of Array.from(inFlight.entries())) {
            const elapsedMs = now - entry.startedAt;
            // Never sent = no POST was ever issued for it. Read from the entry
            // rather than from `pendingForward` membership, which only ever
            // covered the cold-start window.
            const neverSent = entry.sent !== true;
            // A call we can prove never left this process, while no working
            // connection has existed for `stalledHandshakeMs`, does not need
            // the full `callTimeoutMs`: it cannot have executed, so answering
            // it early is a no-op the agent can safely retry. Anything that
            // was actually sent — or that is queued on a healthy session —
            // keeps the full deadline, because there a premature failure
            // invites a duplicate write.
            const handshakeIsStalled =
                handshakeStalledMs !== null && handshakeStalledMs > stalledHandshakeMs;
            // `entry.deadlineMs` is this tool's own ceiling plus headroom, not
            // the global one sized for the slowest tool — so a `memwal_remember`
            // whose reply is lost is answered at 120s instead of 240s. The
            // stalled-handshake shortcut still wins when it is tighter, but can
            // never extend a tool past its own deadline.
            const deadlineMs =
                neverSent && handshakeIsStalled
                    ? Math.min(stalledHandshakeMs, entry.deadlineMs)
                    : entry.deadlineMs;
            if (elapsedMs <= deadlineMs) continue;
            // `initialize` is answered locally and gets no reply here, so
            // there is nothing to explain and nothing to probe for.
            if (!neverSent && entry.msg.method !== "initialize") {
                // A sent call: ask the relayer's `/health` before answering,
                // so the message can say whether it is down, unreachable, or
                // up with this one call stuck. Only the answer waits on the
                // probe; the bookkeeping stays synchronous.
                if (entry.probing) continue;
                entry.probing = true;
                // From here the call is the sweeper's to answer: a reconnect
                // must not replay it behind the probe's back.
                entry.orphaned = true;
                const relayerUrl = creds?.relayerUrl ?? config.relayerUrl;
                // `probeRelayerHealth` does not reject, but a call left with
                // `probing` set and no answer is the one outcome this path
                // must never have, so a rejection still answers it.
                sweepProbe ??= probeRelayerHealth(relayerUrl, healthProbeMs).catch(() => null);
                void sweepProbe
                    .then((probe) => {
                        // A late reply, a logout or a shutdown may have answered
                        // it while the probe ran. Answering again would be a
                        // second response for the same id — and after stdin has
                        // closed there is nobody left to answer.
                        if (stdinClosed || inFlight.get(id) !== entry) return;
                        const settledAt = Date.now();
                        const { reason, opts } = expiredRequestReport(
                            false,
                            settledAt,
                            toolNameOf(entry.msg),
                            probe ? { probe, relayerUrl } : undefined,
                        );
                        log.warn("bridge.call_orphaned", {
                            id,
                            method: entry.msg.method ?? null,
                            elapsedMs: settledAt - entry.startedAt,
                            deadlineMs,
                            reason,
                            health: probe?.kind ?? null,
                            healthMs: probe?.ms ?? null,
                            handshakeStalledMs: handshakeStalledForMs(settledAt),
                            lastHandshakeError,
                        });
                        failRequest(entry.msg, reason, opts);
                    })
                    .catch((err: unknown) => {
                        // Never leave a call marked `probing` with no answer:
                        // clearing it lets the next sweep answer it.
                        entry.probing = false;
                        log.warn("bridge.call_orphaned_answer_failed", {
                            id,
                            error: err instanceof Error ? err.message : String(err),
                        });
                    });
                continue;
            }
            // Built only for what actually expired: this walks `pendingForward`
            // and interpolates two user-facing strings, and the branch it
            // serves fires roughly never.
            const { reason, opts } = expiredRequestReport(
                neverSent,
                now,
                toolNameOf(entry.msg),
            );
            // Drop it from the buffer before answering: a later successful
            // connect would otherwise flush and actually run the call we are
            // about to report as never having run.
            //
            // `initialize` is the exception, as everywhere else here: it was
            // answered locally and is only buffered so the relayer session can
            // still negotiate capabilities, and `failRequest` writes it no
            // reply. Removing it would silently cost that negotiation on the
            // first connect after a long outage.
            if (neverSent && entry.msg.method !== "initialize") {
                // Only buffered requests are in there at all now, so the miss
                // is ordinary — `splice(-1, 1)` would drop the last entry.
                const queuedAt = pendingForward.indexOf(entry.msg);
                if (queuedAt >= 0) pendingForward.splice(queuedAt, 1);
            }
            log.warn("bridge.call_orphaned", {
                id,
                method: entry.msg.method ?? null,
                elapsedMs,
                deadlineMs,
                reason,
                handshakeStalledMs,
                lastHandshakeError,
            });
            failRequest(entry.msg, reason, opts);
        }
    }, sweepIntervalMs);
    // unref so the sweeper never holds the event loop open during shutdown.
    orphanSweeper.unref?.();

    // Kick off the relayer connect in the BACKGROUND — do NOT await it before
    // wiring stdin below. This is the whole fix: `initialize` / `tools/list` are
    // answered locally the moment they arrive, while the (possibly slow / cold)
    // relayer round-trip proceeds off the handshake's critical path.
    //
    // Retry with backoff so a cold-starting relayer eventually connects. We do
    // NOT fail buffered requests between attempts: a request that the next
    // attempt would serve must not get a spurious "unavailable" error (that
    // would also drop the auth-required hot-handoff request). Buffered tool
    // calls stay queued and are flushed on the first SUCCESS. They are no
    // longer left to the client's own per-tool timeout, though: once no
    // connection has existed for `stalledHandshakeMs` the orphan sweeper
    // answers them (see `DEFAULT_STALLED_HANDSHAKE_MS`), because a call that
    // was never sent cannot have executed and silence helps nobody. On
    // shutdown `failPendingForward` closes out anything still open. `initialize`
    // is answered locally, so it never blocks and is only forwarded, not failed.
    // First connect stays on `openSseStream` + `flushPendingForward` so a
    // flush-time 404 still goes through the existing reconnect/replay path.
    // It must NOT publish if login already owns `sse`, or if the handshake
    // finished after `credentialGeneration` moved — that was the double-flush.
    const connectInBackground = (async () => {
        let attempt = 0;
        while (!stdinClosed && !loggedOut) {
            if (reconnectPromise) {
                await reconnectPromise;
                continue;
            }
            if (sse) {
                signalFirstConnect();
                const notifications = pendingForward.filter((m) => m.id == null);
                pendingForward.length = 0;
                pendingForward.push(...notifications);
                await flushPendingForward();
                return;
            }
            const openingGeneration = credentialGeneration;
            try {
                const candidate = await openRelaySession(creds.relayerUrl, creds, connectHeaders());
                if (stdinClosed) {
                    candidate.abort();
                    break;
                }
                // Signed out while this handshake was in flight. The loop guard
                // above only runs between iterations, so without this the
                // session would be published — an open, authenticated stream
                // holding the delegate key the user just deleted.
                if (loggedOut) {
                    candidate.abort();
                    break;
                }
                if (openingGeneration !== credentialGeneration || sse) {
                    candidate.abort();
                    continue;
                }
                sessionEpoch += 1;
                sse = candidate;
                firstConnectDone = true;
                throttledUntilMs = 0;
                throttleNoticed = false;
                clearHandshakeFailure();
                endConnectEpisode();
                // A key that was rejected earlier is evidently accepted now
                // (re-registered, or the 401 was a transient WAF/rate-limit
                // false positive), so stop failing requests fast.
                credentialsRejected = false;
                note(`Connected. Bridging stdio MCP ↔ ${creds.relayerUrl}`);
                log.info("bridge.connected", { relayer: creds.relayerUrl });
                signalFirstConnect();
                await flushPendingForward();
                return;
            } catch (err) {
                const reason = err instanceof Error ? err.message : String(err);
                noteHandshakeFailure(reason);
                attempt += 1;
                if (err instanceof RelayerThrottledError) noteThrottled(err);
                log.error("bridge.initial_connect_failed", { err: reason, attempt });
                // A rejected key will not start working on the next attempt, so
                // answer everything queued instead of leaving it to the orphan
                // sweeper. Keep looping: `memwal_login` re-registers a key on
                // this same relayer, and whichever path publishes the next
                // session clears the flag and resumes normal buffering.
                //
                // Do NOT signal `firstConnect` here. It means "a session
                // exists", and none does — the pump would fall straight through
                // its `break; // stdin closed before we ever connected`, win the
                // shutdown race in `runBridge`, and `markStdinClosed()` would
                // disable the very `reconnect()` the error text tells the user
                // to reach via `memwal_login`. `failPendingForward` writes to
                // stdout directly and needs no pump.
                //
                // Same staleness test as the publish path above: a 401 for the
                // key a login already replaced says nothing about the new one,
                // and latching the flag on it would refuse every request against
                // a session that is live and fine.
                if (
                    err instanceof RelayerUnauthorizedError &&
                    !sse &&
                    openingGeneration === credentialGeneration
                ) {
                    credentialsRejected = true;
                    // Everything still queued never left the process, so no
                    // upstream initialize reply will arrive to consume its arm.
                    // `failRequest` keeps initialize arms for replies that CAN
                    // still arrive; a leaked one here would swallow the reply to
                    // a reused id after `memwal_login`.
                    for (const msg of pendingForward) {
                        if (msg.method === "initialize" && msg.id != null) {
                            suppressUpstreamReplies.delete(msg.id);
                        }
                    }
                    failPendingForward("credentials rejected", UNAUTHORIZED_FAILURE);
                }
                if (stdinClosed) break;
                // Floor the geometric backoff at whatever throttle window is
                // still open. Without this the first retry after a 429 lands
                // 500ms later, well inside the interval the relayer asked for.
                const backoff = Math.max(
                    Math.min(15_000, 500 * Math.pow(2, attempt - 1)),
                    throttledUntilMs - Date.now(),
                );
                await new Promise<void>((resolve) => {
                    const timer = setTimeout(() => {
                        unregister();
                        resolve();
                    }, backoff);
                    timer.unref?.();
                    const unregister = onStdinClose(() => {
                        clearTimeout(timer);
                        resolve();
                    });
                });
            }
        }
        signalFirstConnect();
        failPendingForward("connection not established before shutdown");
    })();

    // Replay anything the auth-required server handed off (the tool call that
    // triggered the hot-handoff, plus anything buffered behind it). These run
    // through handleClientLine, which buffers them into pendingForward until the
    // background connect lands — so the triggering request is served for real
    // instead of being dropped in the mode switch.
    if (pendingLines.length > 0) {
        log.info("bridge.replaying_handoff", { count: pendingLines.length });
        for (const line of pendingLines) handleClientLine(line);
    }

    const clientPump = readStdinLines(handleClientLine).then(() => {
        markStdinClosed();
        sse?.abort();
    });

    try {
        await Promise.race([serverPump, clientPump]);
    } finally {
        clearInterval(orphanSweeper);
    }
    markStdinClosed();
    const finalStream = sse as SseHandshakeResult | null;
    finalStream?.abort();
    await connectInBackground.catch(() => {});
    log.info("bridge.closed", {});
}
