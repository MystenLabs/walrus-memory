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
    /** Optional environment name or explicit CLI flag (e.g. 'dev', 'local', 'staging'). */
    environment?: string;
}

/** Resolves the CLI login command for remote or headless login fallback,
 * preserving explicit environment presets (`--dev`, `--local`, `--staging`)
 * and custom `--relayer` overrides. */
export function remoteLoginCommand(info: LoginPromptInfo | { url: string; environment?: string }): string {
    const base = "npx -y @mysten-incubation/memwal-mcp login";
    if (info.environment) {
        const env = info.environment.trim().toLowerCase().replace(/^--/, "");
        if (env === "dev" || env === "staging" || env === "local") {
            return `${base} --${env}`;
        }
        if (env === "prod" || env === "production") {
            return base;
        }
        return `${base} ${info.environment.startsWith("--") ? info.environment : `--${info.environment}`}`;
    }
    try {
        const u = new URL(info.url);
        const relayerParam = u.searchParams.get("relayer");
        const relayer = (relayerParam ?? "").trim().toLowerCase().replace(/\/+$/, "");
        const host = u.hostname.toLowerCase();
        if (relayer.includes("dev.memwal.ai") || host.includes("dev.memwal.ai")) {
            return `${base} --dev`;
        }
        if (
            relayer.includes("127.0.0.1:8000") ||
            relayer.includes("localhost:8000") ||
            host === "localhost" ||
            host === "127.0.0.1"
        ) {
            return `${base} --local`;
        }
        if (relayer.includes("staging")) {
            return `${base} --staging`;
        }
        if (relayerParam && !relayer.includes("relayer.memory.walrus.xyz")) {
            return `${base} --relayer ${relayerParam}`;
        }
    } catch {}
    return base;
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
