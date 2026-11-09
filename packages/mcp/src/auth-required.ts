/**
 * "Auth-required" stdio MCP server — run when ~/.memwal/credentials.json is
 * missing but the package was spawned by an MCP client (Cursor / Claude
 * Desktop / etc.).
 *
 * Instead of exiting (which makes the MCP client show a cryptic
 * "Failed to start server" error that the user can't act on), we boot a
 * minimal MCP server that:
 *
 *   - Responds to `initialize` so the client sees a healthy server.
 *   - Advertises the 4 real Walrus Memory tools + a 5th `memwal_login` tool in
 *     `tools/list` so the agent knows what's available.
 *   - On `tools/call memwal_login`: invokes the browser-based wallet login
 *     flow inline so the user never has to leave their MCP client. Eliminates
 *     the previous "run a separate `npx ... login` command then restart" UX.
 *   - On any other `tools/call`: returns `isError: true` with a friendly
 *     instruction telling the agent to call `memwal_login` first (or run
 *     the CLI command as a fallback).
 *
 * Note: HTTP transport (`/api/mcp`) gets a separate native OAuth flow per
 * MCP spec 2025-06 — see ENG-1750. The two paths cover different surfaces
 * and coexist.
 */
import { credsPath, loadCreds, type MemWalCredentials } from "./auth.js";
import { rememberInitializeClientInfo } from "./client-info.js";
import { loginFailureNotice, loginPrompt, loginSuccessNotification } from "./messages.js";
import { log } from "./logger.js";
import { startOrReuseLoginFlow, resolveLoginTimeoutMs, isLoginSuperseded } from "./login.js";
import { localPromptReply } from "./consent-instruction.js";
import { AUTH_REQUIRED_INSTRUCTIONS } from "./instructions.js";
import {
    SECRET_EXCLUSION_RULES,
    SECRET_EXCLUSION_SUMMARY,
    AUTO_SAVE_OPT_IN_RULE,
} from "./memory-policy.js";
import { MEMWAL_MCP_VERSION } from "./version.js";

interface RpcMessage {
    jsonrpc: "2.0";
    id?: number | string | null;
    method?: string;
    params?: unknown;
    result?: unknown;
    error?: unknown;
}

/**
 * WALM-642: every write-tool description below ends with the shared policy
 * block, the same text the `instructions` field and the plugin hooks carry, so
 * an agent that only ever sees one of the three still gets the same rules.
 * The signed-out variants get the one-line summary — they exist to keep a
 * credential-less model from spamming writes, and the full block would be the
 * longest thing in a list of tools that cannot run yet.
 */
const SIGNED_OUT_REMEMBER =
    "Save a fact to the user's Walrus Memory personal memory. Call ONLY when the user explicitly asks to remember/save something. Pass the full, detailed text — never summarize. " +
    SECRET_EXCLUSION_SUMMARY;
const SIGNED_IN_REMEMBER =
    "Save a durable fact about the user or project to their Walrus Memory. Call this PROACTIVELY whenever the user states a preference, decision, constraint, correction, identity detail, or recurring workflow — even if they did not say 'remember this' — provided they have turned automatic memory on. Skip one-off tasks, the current file or bug, and small talk. Pass the full statement; do not summarize. To save several facts at once, use memwal_remember_bulk instead. By default this returns in ~1s once the relayer has accepted the job (job_id) — the Walrus write is still in flight and the fact is NOT stored yet. Do not claim it is saved. Settle it with the job-status tool this server advertises (re-list tools if you do not see one). A blob_id in the same reply means it already stored (optional wait budget). " +
    AUTO_SAVE_OPT_IN_RULE +
    " " +
    SECRET_EXCLUSION_RULES;
const SIGNED_OUT_RECALL =
    "Search the user's Walrus Memory for facts relevant to a query. Returns matching memories ranked by relevance.";
const SIGNED_IN_RECALL =
    "Search the user's Walrus Memory for relevant facts before responding. Call this PROACTIVELY at the start of a task, or whenever the user references past work, prior decisions, their preferences, or anything you may have stored earlier — don't wait to be asked. A single focused query is usually enough — recall is a real retrieval over encrypted storage, so do NOT fire multiple redundant searches for the same question. Returns matching memories ranked by relevance.";

/** Build the static memory-tool list. `proactive` is true for the signed-in
 * cold-start path (bridge: credentials exist, relayer not yet up) and false
 * for auth-required (no credentials). Same tool names/order as the sidecar. */
function buildToolDefinitions(proactive: boolean) {
    return [
    {
        name: "memwal_remember",
        title: "Remember a Fact",
        annotations: { readOnlyHint: false, destructiveHint: false },
        description: proactive ? SIGNED_IN_REMEMBER : SIGNED_OUT_REMEMBER,
        inputSchema: {
            type: "object",
            properties: {
                text: { type: "string", minLength: 1 },
                namespace: { type: "string" },
            },
            required: ["text"],
            additionalProperties: false,
        },
    },
    {
        name: "memwal_remember_bulk",
        title: "Remember Multiple Facts",
        annotations: { readOnlyHint: false, destructiveHint: false },
        description:
            "Save multiple durable facts in one call. Use when you learned several distinct facts at once (onboarding details, a list of preferences, decisions from a discussion). Pass an array of complete fact statements (max 20) — do not summarize. Prefer this over repeated memwal_remember calls. By default this returns in ~1s once the relayer has accepted the batch (job_ids) — the Walrus writes are still in flight and the facts are NOT stored yet. Do not claim they are saved. Settle them with the job-status tool this server advertises (re-list tools if you do not see one). A blob_id in the same reply means that fact already stored (optional wait budget). " +
            (proactive ? AUTO_SAVE_OPT_IN_RULE + " " + SECRET_EXCLUSION_RULES : SECRET_EXCLUSION_SUMMARY),
        inputSchema: {
            type: "object",
            properties: {
                facts: {
                    type: "array",
                    items: { type: "string", minLength: 1 },
                    minItems: 1,
                    maxItems: 20,
                },
                namespace: { type: "string" },
            },
            required: ["facts"],
            additionalProperties: false,
        },
    },
    {
        name: "memwal_remember_status",
        title: "Check a Remember Job",
        annotations: { readOnlyHint: true, destructiveHint: false },
        description:
            "Check whether in-flight Walrus Memory writes have landed. Call this with the job_id memwal_remember returned, or job_ids from memwal_remember_bulk, when the write was reported NOT saved yet. Returns the blob_id once stored, reports that it is still uploading (call again with the ids still listed), or reports that it failed \u2014 in which case the fact was never stored and you should send it again. A batch can come back mixed, so read every line before telling the user anything is saved.",
        inputSchema: {
            type: "object",
            properties: {
                job_id: { type: "string", minLength: 1 },
                // The sidecar takes either one id or a whole batch, and the
                // pending body `memwal_remember_bulk` returns tells the agent
                // to come back with `job_ids`. Advertising only `job_id` —
                // required, under `additionalProperties: false` — made that
                // instruction unfollowable for the whole cold-start window.
                job_ids: {
                    type: "array",
                    items: { type: "string", minLength: 1 },
                    minItems: 1,
                    maxItems: 20,
                },
                waitMs: { type: "integer", minimum: 0, maximum: 45000, default: 10000 },
            },
            // Neither is required on its own; the sidecar rejects passing both
            // and rejects passing neither, which JSON Schema cannot express
            // here without a `oneOf` that some clients mishandle.
            additionalProperties: false,
        },
    },
    {
        name: "memwal_recall",
        title: "Recall Memories",
        annotations: { readOnlyHint: true, destructiveHint: false },
        description: proactive ? SIGNED_IN_RECALL : SIGNED_OUT_RECALL,
        inputSchema: {
            type: "object",
            properties: {
                query: { type: "string", minLength: 1 },
                limit: { type: "integer", minimum: 1, maximum: 100, default: 10 },
                namespace: { type: "string" },
                maxDistance: {
                    type: "number",
                    minimum: 0,
                    description:
                        "Optional cosine-distance cutoff (low = similar; 0 = identical). Hits with distance >= maxDistance are dropped. Omit to apply no cutoff. Displayed score is 1 - distance (high = similar); do not treat score as the cutoff.",
                },
            },
            required: ["query"],
            additionalProperties: false,
        },
    },
    {
        name: "memwal_analyze",
        title: "Analyze and Remember",
        annotations: { readOnlyHint: false, destructiveHint: true },
        description:
            "Extract memorable facts from a longer passage of text (preferences, habits, biographical info, constraints) and save each as a separate Walrus Memory memory. Use this when you want MemWal's LLM to split the facts out of a transcript or notes for you; if you already know the exact facts, use memwal_remember or memwal_remember_bulk instead. " +
            (proactive ? AUTO_SAVE_OPT_IN_RULE + " " + SECRET_EXCLUSION_RULES : SECRET_EXCLUSION_SUMMARY),
        inputSchema: {
            type: "object",
            properties: {
                text: { type: "string", minLength: 1 },
                namespace: { type: "string" },
            },
            required: ["text"],
            additionalProperties: false,
        },
    },
    {
        name: "memwal_restore",
        title: "Restore Memory Index",
        annotations: { readOnlyHint: false, destructiveHint: false },
        description:
            "Recovery tool. Re-index a namespace from Walrus blobs back into the relayer's search index \u2014 use when memwal_recall unexpectedly returns nothing even though facts were saved before (e.g. on a new machine, a fresh relayer, or after switching servers). Returns restored/skipped/failed/total plus truncated \u2014 does not return memory texts. truncated=true is known-retryable-incomplete: retry the same limit on a download/embed blip; raising limit expands the sidecar cap only while limit < 20; after the cap saturates, truncation follows this call's missing-blob page. truncated=false is not completeness; WALM-451 will add sourceCapped. Call memwal_recall afterwards to query the rebuilt index.",
        inputSchema: {
            type: "object",
            properties: {
                namespace: { type: "string", minLength: 1 },
                limit: { type: "integer", minimum: 1, maximum: 100, default: 10 },
            },
            required: ["namespace"],
            additionalProperties: false,
        },
    },
    {
        name: "memwal_health",
        title: "Check Walrus Memory Health",
        annotations: { readOnlyHint: true, destructiveHint: false },
        description:
            "Quick connectivity check for Walrus Memory. Calls the relayer's lightweight health endpoint (no search, no decryption) and returns its status and version. Use this to confirm the server is reachable — do NOT use memwal_recall for health checks, which is a full and slow retrieval.",
        inputSchema: {
            type: "object",
            properties: {},
            additionalProperties: false,
        },
    },
    {
        name: "memwal_login",
        title: "Sign In to Walrus Memory",
        annotations: { readOnlyHint: false, destructiveHint: false },
        description:
            "Sign this MCP client into your Walrus Memory account by opening a browser. Run once when the agent reports Walrus Memory is not signed in. Opens the dashboard in the default browser, waits for wallet approval, then writes credentials to ~/.memwal/credentials.json. Other memwal_* tools become usable on the next call after a successful login.",
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
    ];
}

/** Tool names the OLDEST relayer this bridge still talks to serves.
 *
 * The bridge ships on npm and updates itself; a relayer ships per environment
 * and does not, so the bridge is routinely NEWER than the relayer it dials —
 * 0.0.14-dev.0 against prod and staging on 0.0.13, which is GH #928. The
 * cold-start list is served before any relayer capability is known, so every
 * name in it that the dialled relayer does not serve is a tool the agent can
 * be told about and then cannot call.
 *
 * Cold start is therefore a FLOOR, not a forecast: add a name here only once
 * the tool has shipped to prod, never when it lands on dev. Newer tools reach
 * the client a beat later anyway — the relayer's own `tools/list` replaces
 * this one and `notifications/tools/list_changed` tells the client to re-read
 * it. `memwal_remember_status` is the worked example: it exists on dev, not on
 * prod/staging, and belongs here only after a prod release carries it. */
export const BASELINE_RELAYER_TOOLS: ReadonlySet<string> = new Set([
    "memwal_remember",
    "memwal_remember_bulk",
    "memwal_recall",
    "memwal_analyze",
    "memwal_restore",
    "memwal_health",
]);

/** Served by this process, so no relayer has to know about it. Advertising it
 * at cold start is always safe. */
const LOCALLY_SERVED_TOOLS: ReadonlySet<string> = new Set(["memwal_login"]);

/** Every tool this bridge can describe, baseline or not. Only the baseline
 * subset is advertised at cold start; this is what the schema tests pin, so a
 * newer tool's shape stays reviewed while it waits for a prod release. */
export const ALL_TOOL_DEFINITIONS = buildToolDefinitions(true);

/** Drop anything the oldest supported relayer would not serve. */
function coldStartTools(proactive: boolean) {
    return buildToolDefinitions(proactive).filter(
        (t) => BASELINE_RELAYER_TOOLS.has(t.name) || LOCALLY_SERVED_TOOLS.has(t.name),
    );
}

/** Signed-in cold-start list (bridge). Credentials exist; the relayer session
 * is not up yet. Proactive wording so clients that keep the first tools/list
 * still save/recall without being asked. */
export const TOOL_DEFINITIONS = coldStartTools(true);

/** Signed-out list (auth-required). No credentials, so every memory call
 * fails: keep conservative wording or the model will spam remember and get
 * a stream of auth errors. */
export const SIGNED_OUT_TOOL_DEFINITIONS = coldStartTools(false);

/** How long to wait for the local listener to bind + emit its URL before we
 * give up and return an error. Should be near-instant; 5s is paranoia. */
const URL_READY_TIMEOUT_MS = 5_000;

const LOGIN_INSTRUCTION = [
    "❌ Walrus Memory isn't signed in yet.",
    "",
    "**Easiest fix — call the `memwal_login` tool from this client.** It opens a browser,",
    "you approve the wallet sign-in, and on the next tool call this server picks up the",
    "credentials automatically. No terminal command, no client restart.",
    "",
    "Fallback (if your client cannot call `memwal_login`, or you prefer a CLI):",
    "",
    "    npx -y @mysten-incubation/memwal-mcp login",
    "",
    "(or `npx -y @mysten-incubation/memwal-mcp login --local` / `--dev` for a non-prod env)",
    "",
    "Either path opens a browser tab — click **Connect Sui Wallet** and approve the on-chain",
    "`add_delegate_key` transaction. Credentials land at `~/.memwal/credentials.json`.",
].join("\n");

/** Replaces {@link LOGIN_INSTRUCTION} after a failed attempt, which
 * {@link loginFailureNotice} has just described. The generic copy promises "no
 * client restart" and leads with `memwal_login`; for a key the user already
 * approved, a restart is the only thing that recovers it and a plain retry
 * reuses it rather than registering a second one. So the retry names
 * `freshKey` for the case the plain one cannot fix. */
const LOGIN_RETRY_INSTRUCTION = [
    "Start a new sign-in: call the `memwal_login` tool from this client, or run",
    "`npx -y @mysten-incubation/memwal-mcp login`. Open the new link straight away and",
    "leave this client running through the wallet prompt.",
    "",
    "If that keeps failing on the same key, call `memwal_login` with `freshKey: true` to",
    "mint a new one. That abandons the pending key: if you already approved it on-chain,",
    "remove it from the dashboard afterwards.",
].join("\n");

/** Set when a background `memwal_login` ends without credentials. The tool call
 * already returned the URL by then, so this is the only place left to say so. */
let lastLoginFailure: string | null = null;

function writeStdoutMessage(msg: RpcMessage): void {
    process.stdout.write(JSON.stringify(msg) + "\n");
}

/** Config passed in by the entry point (`index.ts`) so the login flow uses
 * the same web/relayer URLs as the rest of the CLI (e.g. `--dev` →
 * dashboard at `https://dev.memwal.ai`, not the prod default at
 * `https://memory.walrus.xyz`). */
export interface AuthRequiredConfig {
    relayerUrl: string;
    webUrl: string;
    label: string;
    /** Default memory namespace resolved at boot. Accepted here so the entry
     * point can pass one config shape to both server modes — but auth-required
     * mode never forwards a memory tool call (every non-login tool returns the
     * login instruction), so there is nothing to namespace yet. It takes
     * effect once credentials exist and the bridge runs. */
    namespace?: string;
}

/** Send a `notifications/message` (MCP logging notification). Some clients
 * surface these inline (Cursor); others swallow them (Claude Code as of
 * 2026-05). We rely primarily on the tool result for the URL — this is a
 * secondary surface for clients that show it. */
function sendLogMessage(level: "info" | "warning" | "error", text: string): void {
    writeStdoutMessage({
        jsonrpc: "2.0",
        method: "notifications/message",
        params: {
            level,
            logger: "memwal-mcp",
            data: text,
        },
    });
}

/**
 * Start the browser-based login flow and return the click-able URL
 * IMMEDIATELY in the tool result (do NOT block waiting for the user to
 * approve). Reasons:
 *
 *   - MCP clients enforce a tool-call timeout (~60s in Claude Code/Codex).
 *     The user's wallet flow can easily exceed it (hardware wallet review,
 *     Enoki sponsor lag, browser tab not focused).
 *   - The agent paraphrases timeout errors and may strip the URL when
 *     reporting to the user, leaving them stuck.
 *   - `notifications/message` is filtered out by some clients.
 *
 * The login HTTP listener stays alive for resolveLoginTimeoutMs() in the
 * background. Once the user clicks the link and approves the wallet, the
 * callback writes credentials to ~/.memwal/credentials.json. The user then
 * issues any other memwal_* tool to verify — which now succeeds because
 * the bridge picks up the saved creds on its next call.
 */
async function handleLoginToolCall(
    config: AuthRequiredConfig,
    _progressToken: unknown,
    freshKey: boolean,
): Promise<{ text: string; isError: boolean }> {
    // Fire login but DO NOT await the wallet callback — it runs in the
    // background. openBrowser: false because (a) child-process spawning a
    // browser is unreliable across MCP clients, and (b) macOS `open <url>`
    // often foregrounds an existing memory.walrus.xyz tab instead of
    // navigating to the full /connect/mcp?... URL. The agent surfaces the
    // clickable URL from the tool result instead.
    //
    // Concurrent memwal_login calls join this in-flight flow instead of
    // opening a second listener (that race hung later recall/remember).
    lastLoginFailure = null;
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
            onUrl: (url) => {
                sendLogMessage("info", `Walrus Memory MCP login URL: ${url}`);
            },
        },
        (creds) => {
            lastLoginFailure = null;
            log.info("memwal_login.bg.success", {
                accountId: creds.accountId,
                delegateAddress: creds.delegateAddress,
            });
            // Symmetric with the failure branch below: the tool call returned
            // the URL immediately, so nothing is left to carry the outcome
            // except this notification and the banner the bridge prefixes onto
            // the next tool result.
            sendLogMessage(
                "info",
                loginSuccessNotification({
                    accountId: creds.accountId,
                    delegateAddress: creds.delegateAddress,
                    credentialsPath: credsPath(),
                }),
            );
        },
        (err) => {
            const msg = err instanceof Error ? err.message : String(err);
            lastLoginFailure = msg;
            log.warn("memwal_login.bg.failed", { msg });
            sendLogMessage("warning", `Walrus Memory sign-in did not complete: ${msg}`);
        },
    );

    // Race the URL-ready against a short timeout. The listener bind is
    // synchronous-ish (single port allocation); 5s is a hard cap for a
    // pathologically slow machine or unrelated bug.
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
        const msg = err instanceof Error ? err.message : String(err);
        log.error("memwal_login.tool.url_not_ready", { msg });
        return {
            isError: true,
            text: [
                `❌ Failed to start Walrus Memory login: ${msg}`,
                "",
                "Try the CLI fallback:",
                "",
                "    npx -y @mysten-incubation/memwal-mcp login",
            ].join("\n"),
        };
    }

    log.info("memwal_login.tool.url_ready", { url });
    return {
        isError: false,
        // Read from disk rather than assuming the stub only runs signed out: a
        // completed callback writes credentials before the hand-off, so a
        // second `memwal_login` in that window really would replace a stored
        // key and must say so.
        text: loginPrompt({
            url,
            credentialsPath: credsPath(),
            signedIn: loadCreds() !== null,
            discardedKey,
        }),
    };
}

/** Returned by {@link runAuthRequiredServer} when the user signs in mid-session
 * (via `memwal_login`) and the request should now be served by the real bridge
 * instead — WITHOUT a client restart. */
export interface AuthHandoff {
    creds: MemWalCredentials;
    /** Lines the auth-required reader already pulled off stdin that the bridge
     * must process first: the tool call that triggered the handoff, plus
     * anything buffered behind it. */
    pendingLines: string[];
}

/**
 * Dispatch one JSON-RPC line in auth-required mode.
 *
 * Returns the freshly-loaded credentials when `memwal_login` has written them
 * since spawn and the request should be handed to the bridge for real
 * servicing. Returns null when the line was fully handled locally (initialize,
 * stub tools/list, login tool call, or the not-signed-in nudge).
 */
function handleAuthLine(
    line: string,
    config: AuthRequiredConfig,
): { creds: MemWalCredentials } | null {
    let req: RpcMessage;
    try {
        req = JSON.parse(line) as RpcMessage;
    } catch {
        return null;
    }

    // Notifications don't need a response.
    if (req.id == null && typeof req.method === "string") {
        return null;
    }

    const id = req.id ?? null;
    const method = req.method;

    if (method === "initialize") {
        const clientInfo = rememberInitializeClientInfo(req.params);
        if (clientInfo) {
            log.info("bridge.agent_client", {
                clientName: clientInfo.name,
                clientVersion: clientInfo.version,
                mode: "auth-required",
            });
        }
        writeStdoutMessage({
            jsonrpc: "2.0",
            id,
            result: {
                protocolVersion: "2024-11-05",
                // listChanged:true because the tool set DOES change after a
                // mid-session login: the hot-handoff to the bridge emits
                // `notifications/tools/list_changed`, and a client told
                // `false` here would be entitled to ignore it and never pick up
                // the real upstream tools (or `memwal_logout`). Advertise the
                // capability the handoff depends on.
                capabilities: { tools: { listChanged: true }, prompts: {} },
                serverInfo: { name: "memwal", version: MEMWAL_MCP_VERSION },
                instructions: AUTH_REQUIRED_INSTRUCTIONS,
            },
        });
        return null;
    }

    const promptReply = localPromptReply(method, req.params);
    if (promptReply && id != null) {
        if (promptReply.error) {
            writeStdoutMessage({
                jsonrpc: "2.0",
                id,
                error: promptReply.error,
            });
        } else {
            writeStdoutMessage({
                jsonrpc: "2.0",
                id,
                result: promptReply.result,
            });
        }
        return null;
    }

    if (method === "tools/list") {
        // Signed in since spawn? Hand off so the client gets the real upstream
        // tool list (with memwal_login/memwal_logout spliced in) from the bridge.
        const creds = loadCreds();
        if (creds) return { creds };
        writeStdoutMessage({
            jsonrpc: "2.0",
            id,
            result: { tools: SIGNED_OUT_TOOL_DEFINITIONS },
        });
        return null;
    }

    if (method === "tools/call") {
        const params = (req.params ?? {}) as {
            name?: string;
            arguments?: { freshKey?: unknown };
            _meta?: { progressToken?: unknown };
        };
        const toolName = params.name;
        const progressToken = params._meta?.progressToken;

        if (toolName === "memwal_login") {
            // Returns near-instantly with the click-able URL. The listener
            // stays alive in the background — see handleLoginToolCall for the
            // rationale on not blocking.
            void handleLoginToolCall(
                config,
                progressToken,
                params.arguments?.freshKey === true,
            ).then((result) => {
                writeStdoutMessage({
                    jsonrpc: "2.0",
                    id,
                    result: {
                        content: [{ type: "text", text: result.text }],
                        isError: result.isError,
                    },
                });
            });
            return null;
        }

        // Any other memory tool. If `memwal_login` has since written
        // credentials, hand off to the bridge so THIS call is served for real —
        // no client restart (the historical "second reboot"). Otherwise nudge
        // the agent to sign in first.
        const creds = loadCreds();
        if (creds) {
            lastLoginFailure = null;
            return { creds };
        }

        writeStdoutMessage({
            jsonrpc: "2.0",
            id,
            result: {
                content: [
                    {
                        type: "text",
                        text: lastLoginFailure
                            ? `${loginFailureNotice(lastLoginFailure)}${LOGIN_RETRY_INSTRUCTION}`
                            : LOGIN_INSTRUCTION,
                    },
                ],
                isError: true,
            },
        });
        return null;
    }

    // Anything else — return Method not found per JSON-RPC.
    writeStdoutMessage({
        jsonrpc: "2.0",
        id,
        error: {
            code: -32601,
            message: `Method not found: ${method ?? "(missing)"}`,
        },
    });
    return null;
}

/**
 * Run the auth-required stdio MCP server.
 *
 * Resolves with an {@link AuthHandoff} the moment `memwal_login` completes and
 * the next memory tool call (or tools/list) arrives — so the caller can pick up
 * the real bridge IN THE SAME PROCESS, eliminating the second client restart.
 * Resolves with `undefined` if stdin closes before any sign-in.
 *
 * We manage the stdin listeners directly (rather than via the shared
 * `readStdinLines`) so we can DETACH cleanly at handoff: the bridge attaches its
 * own reader next, and two concurrent `data` listeners would double-process
 * every line. `pause()` keeps any bytes that arrive during the switch buffered
 * until the bridge's reader resumes the stream.
 *
 * The `config` parameter carries the same `relayerUrl` / `webUrl` / `label`
 * that the rest of the CLI resolved (e.g. `--dev` → dev URLs). Without it,
 * `memwal_login` would fall back to prod defaults and open the wrong dashboard.
 */
export async function runAuthRequiredServer(
    config: AuthRequiredConfig,
): Promise<AuthHandoff | void> {
    log.info("auth_required_server.started", {
        webUrl: config.webUrl,
        relayerUrl: config.relayerUrl,
    });

    return await new Promise<AuthHandoff | void>((resolve) => {
        let buf = "";
        let settled = false;

        const detach = (): void => {
            process.stdin.removeListener("data", onData);
            process.stdin.removeListener("end", onEnd);
            process.stdin.removeListener("close", onEnd);
        };

        const onData = (chunk: string): void => {
            buf += chunk;
            let nl: number;
            while ((nl = buf.indexOf("\n")) >= 0) {
                const rawLine = buf.slice(0, nl).replace(/\r$/, "");
                buf = buf.slice(nl + 1);
                if (rawLine.length === 0) continue;

                const handoff = handleAuthLine(rawLine, config);
                if (!handoff) continue;

                // Fresh credentials detected mid-session. Stop consuming stdin
                // and hand the bridge everything we've read but not forwarded:
                // the triggering line first, then anything buffered behind it.
                settled = true;
                detach();
                process.stdin.pause();

                const pendingLines: string[] = [rawLine];
                let n2: number;
                while ((n2 = buf.indexOf("\n")) >= 0) {
                    const l = buf.slice(0, n2).replace(/\r$/, "");
                    buf = buf.slice(n2 + 1);
                    if (l.length > 0) pendingLines.push(l);
                }

                log.info("auth_required_server.handoff_to_bridge", {
                    accountId: handoff.creds.accountId,
                    pendingLines: pendingLines.length,
                });
                resolve({ creds: handoff.creds, pendingLines });
                return;
            }
        };

        const onEnd = (): void => {
            if (settled) return;
            settled = true;
            detach();
            log.info("auth_required_server.closed", {});
            resolve(undefined);
        };

        process.stdin.setEncoding("utf8");
        process.stdin.on("data", onData);
        process.stdin.on("end", onEnd);
        process.stdin.on("close", onEnd);
    });
}
