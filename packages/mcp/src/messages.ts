/**
 * User-facing copy for the sign-in lifecycle.
 *
 * The same events are reported from two places — the auth-required stub
 * (signed out) and the bridge (signed in) — and the wording had already
 * drifted between them. Keeping the strings here means one voice regardless
 * of which mode the user happens to be in.
 */

/** What a completed sign-in produced, as the user needs it described. */
export interface LoginSuccessInfo {
    accountId: string;
    delegateAddress: string;
    /** The file `saveCreds` actually wrote — project-local or global. Never a
     * hardcoded `~/.memwal/credentials.json`: which one it lands in is exactly
     * the confusion behind GH #628, so the copy states the resolved path. */
    credentialsPath: string;
}

/** What a sign-in prompt needs to describe the flow accurately. */
export interface LoginPromptInfo {
    /** The connect URL the user must open. */
    url: string;
    /** Where credentials will land — resolved, never assumed to be global. */
    credentialsPath: string;
    /** True when credentials already exist, so signing in REPLACES them. */
    signedIn: boolean;
    /** Set when `freshKey` dropped a pending delegate key. The write-ahead
     * file no longer has it, so the prompt is the place that names it. */
    discardedKey?: { publicKey: string; address: string };
    /** Configured relayer URL for the active MCP session. */
    relayerUrl?: string;
    /** Configured dashboard web URL for the active MCP session. */
    webUrl?: string;
    /** Optional environment name or explicit CLI flag (e.g. 'dev', 'local', 'staging'). */
    environment?: string;
}

const PROD_RELAYER_URL = "https://relayer.memory.walrus.xyz";
const PROD_WEB_URL = "https://memory.walrus.xyz";
const DEV_RELAYER_URL = "https://relayer.dev.memwal.ai";
const DEV_WEB_URL = "https://dev.memwal.ai";
const LOCAL_RELAYER_URL = "http://127.0.0.1:8000";
const LOCAL_WEB_URL = "http://localhost:5173";

function normalizeCliUrl(raw: string | undefined | null): string | null {
    if (!raw) return null;
    const trimmed = raw.trim();
    if (!trimmed || /[\s\u0000-\u001f\u007f;|&$`\\"'<>(){}[\]*?~#!]/.test(trimmed)) {
        return null;
    }
    try {
        const parsed = new URL(trimmed);
        if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
        if (parsed.username || parsed.password || parsed.search || parsed.hash) return null;
        const path = parsed.pathname.replace(/\/+$/, "");
        return `${parsed.origin}${path}`;
    } catch {
        return null;
    }
}

function shellQuote(value: string): string {
    return `'${value.replace(/'/g, "'\\''")}'`;
}

/** Resolves the CLI login command for remote or headless login fallback,
 * preserving exact environment presets (`--dev`, `--local`) only when both
 * relayer and web URLs match the preset pair, and otherwise emitting
 * shell-quoted `--relayer` and `--web-url` overrides. */
export function remoteLoginCommand(
    info:
        | LoginPromptInfo
        | { url?: string; relayerUrl?: string; webUrl?: string; environment?: string },
): string {
    const base = "npx -y @mysten-incubation/memwal-mcp login";
    if (info.environment && !info.relayerUrl && !info.webUrl) {
        const env = info.environment.trim().toLowerCase().replace(/^--/, "");
        if (env === "dev" || env === "staging" || env === "local") {
            return `${base} --${env}`;
        }
        if (env === "prod" || env === "production") {
            return base;
        }
    }

    let urlRelayer: string | null = null;
    let urlWeb: string | null = null;
    if (info.url) {
        try {
            const parsed = new URL(info.url);
            urlRelayer = normalizeCliUrl(parsed.searchParams.get("relayer"));
            const basePath = parsed.pathname.replace(/\/connect\/mcp\/?$/, "").replace(/\/+$/, "");
            urlWeb = normalizeCliUrl(`${parsed.origin}${basePath}`);
        } catch {}
    }

    const explicitRelayer = normalizeCliUrl(info.relayerUrl) ?? urlRelayer;
    const explicitWeb = normalizeCliUrl(info.webUrl) ?? urlWeb;

    const relayer = explicitRelayer ?? PROD_RELAYER_URL;
    const defaultWebForRelayer =
        !explicitWeb && relayer.toLowerCase() === DEV_RELAYER_URL
            ? DEV_WEB_URL
            : !explicitWeb && relayer.toLowerCase() === LOCAL_RELAYER_URL
              ? LOCAL_WEB_URL
              : PROD_WEB_URL;
    const web = explicitWeb ?? defaultWebForRelayer;

    const normRelayer = relayer.toLowerCase();
    const normWeb = web.toLowerCase();

    if (normRelayer === PROD_RELAYER_URL && normWeb === PROD_WEB_URL) {
        return base;
    }
    if (normRelayer === DEV_RELAYER_URL && normWeb === DEV_WEB_URL) {
        return `${base} --dev`;
    }
    if (normRelayer === LOCAL_RELAYER_URL && normWeb === LOCAL_WEB_URL) {
        return `${base} --local`;
    }

    const args = [base];
    if (normRelayer !== PROD_RELAYER_URL) {
        args.push(`--relayer ${shellQuote(relayer)}`);
    }
    if (normWeb !== PROD_WEB_URL) {
        args.push(`--web-url ${shellQuote(web)}`);
    }
    return args.join(" ");
}

/**
 * The `memwal_login` tool result, for both modes.
 *
 * The URL appears three times — plain, fenced, and as a link — on purpose.
 * Some clients paraphrase tool output aggressively, and repeating it in three
 * forms means at least one survives into what the user actually sees. Without
 * the URL the user cannot proceed at all, so this is the one place where
 * redundancy beats tidiness.
 */
export function loginPrompt(info: LoginPromptInfo): string {
    return [
        `## ⚠️ ACTION REQUIRED: User must click this URL to sign in`,
        ``,
        `**URL:** ${info.url}`,
        ``,
        "```",
        info.url,
        "```",
        ``,
        `[Click here to open Walrus Memory sign-in](${info.url})`,
        ``,
        `**IMPORTANT for the assistant**: do NOT summarize or omit the URL above.`,
        `The user CANNOT proceed without seeing the exact URL. Surface it verbatim`,
        `in your reply, then explain the steps:`,
        ``,
        `1. Open the URL in a browser on the same machine running this MCP server (it may have already opened automatically)`,
        `2. Click **Connect Sui Wallet** and approve the on-chain \`add_delegate_key\` transaction`,
        `3. Once "Connected" appears in the browser, retry the original request — the other memwal_* tools will then have credentials at \`${info.credentialsPath}\``,
        ...(info.signedIn
            ? [
                  ``,
                  `**Note:** you are already signed in. Completing this replaces the stored delegate key at \`${info.credentialsPath}\` with the new wallet's.`,
              ]
            : []),
        ...(info.discardedKey
            ? [
                  ``,
                  `**Abandoned key:** this sign-in replaced an unfinished delegate key.`,
                  `Public key: \`${info.discardedKey.publicKey}\``,
                  `Address: \`${info.discardedKey.address}\``,
                  `If you already approved that key on-chain, remove it from the dashboard.`,
              ]
            : []),
        ``,
        `_The login link stays valid for 5 minutes and talks to localhost on the machine running this MCP server. If it expires, call \`memwal_login\` again to get a fresh URL. If this MCP server runs on a remote host or bot without a local browser, run \`${remoteLoginCommand(info)}\` on the machine with your browser and copy the resulting credentials file to \`${info.credentialsPath}\` (mode \`0600\`) on the remote host._`,
    ].join("\n");
}

/** Sui ids are 66 characters; showing one whole swamps the message. */
function shortId(id: string): string {
    return id.length > 20 ? `${id.slice(0, 10)}…${id.slice(-6)}` : id;
}

/**
 * Banner prefixed onto the first tool result after a sign-in completes.
 *
 * Deliberately a ONE-SHOT, unlike {@link loginFailureNotice}, which repeats
 * until the user fixes it: a failed sign-in is a state that persists until
 * they act, but a successful one is an event. Repeating it on every recall
 * would be noise on top of every result the user asked for.
 */
export function loginSuccessNotice(info: LoginSuccessInfo): string {
    return [
        "✅ Signed in to Walrus Memory.",
        "",
        `Account:  ${shortId(info.accountId)}`,
        `Delegate: ${shortId(info.delegateAddress)}`,
        `Saved to: ${info.credentialsPath}`,
        "",
        "This connection is now authenticated — no client restart needed.",
        "",
        "---",
        "",
    ].join("\n");
}

/**
 * The `notifications/message` twin of the banner, mirroring the warning the
 * failure path already sends. Clients differ in which surface they show —
 * some render notifications inline, others drop them — so the confirmation
 * goes out on both and neither depends on the other.
 */
export function loginSuccessNotification(info: LoginSuccessInfo): string {
    return (
        `Walrus Memory sign-in complete — account ${shortId(info.accountId)}, ` +
        `credentials saved to ${info.credentialsPath}.`
    );
}

/**
 * Prefix explaining that a sign-in was attempted and did not complete.
 *
 * Repeats on every refused tool call, unlike {@link loginSuccessNotice}: this
 * describes a state the user is still in, and the tool call that started the
 * sign-in returned its URL long before the failure was known, so there is no
 * earlier surface left to report it on.
 *
 * `reason` null — no attempt on record — yields the empty string, so callers
 * can prefix unconditionally.
 *
 * The advice splits on whether the user approved the wallet step. If they did,
 * the key is on-chain and in the write-ahead record (WALM-332). A restart
 * retries that same key. `freshKey: true` mints a new one and closes the
 * sign-in that is already open. A key already approved on-chain has to be
 * removed from the dashboard; nothing else will use it.
 */
export function loginFailureNotice(reason: string | null): string {
    if (!reason) return "";
    return [
        "⚠️ A sign-in was started but never completed, so there are still no credentials.",
        "",
        `Reason: ${reason}`,
        "",
        "If you approved the wallet step, that key is registered and saved on this machine.",
        "A restart retries the same key. Call",
        "`memwal_login` with `freshKey: true` to mint a new one, and remove it from the",
        "dashboard if you already approved the old key on-chain.",
        "",
        "If you did not approve it, sign in again and open the new link straight away. A",
        "retry only helps once the MCP client is left running through the wallet prompt.",
        "",
        "---",
        "",
    ].join("\n");
}
