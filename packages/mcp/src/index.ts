/**
 * Walrus Memory MCP — orchestrator.
 *
 * Boot sequence:
 *   1. If `--logout` flag → wipe credentials.json and exit.
 *   2. Load credentials from `~/.memwal/credentials.json`.
 *   3. If missing → run `loginFlow()` (browser-based wallet sign-in).
 *   4. Bridge stdio MCP ↔ remote SSE relayer using the loaded credentials.
 *   5. On 401 (revoked key), the bridge wipes credentials before throwing
 *      — the next process spawn will re-trigger login.
 */
import {
    approveProjectCreds,
    clearCreds,
    clearPendingLogin,
    credsPath,
    formatProjectCredsNotice,
    formatProjectCredsStorageWarning,
    loadCreds,
    resolveCreds,
    revokeProjectCredsApproval,
} from "./auth.js";
import { recoverPendingLogin, formatStrandedLoginNotice } from "./recovery.js";
import { runAuthRequiredServer } from "./auth-required.js";
import { notePendingLoginSuccess, runBridge } from "./bridge.js";
import { loginFlow } from "./login.js";
import {
    autoSaveStatus,
    autoSaveSummary,
    markConsentPending,
    pendingConsentNotice,
    publishHookState,
    setAutoSave,
    AUTO_SAVE_ENV,
} from "./auto-save.js";
import { askAutoSaveConsent, consentOutcomeNotice } from "./consent.js";
import { log, note } from "./logger.js";

/**
 * Parsed CLI flags. All optional — env vars cover the same surface.
 * CLI takes precedence over env so per-config overrides work even when the
 * user shares the same shell across MCP clients.
 */
interface ParsedArgs {
    help: boolean;
    logout: boolean;
    forceLogin: boolean;
    /** Approve the project-local credentials found from the working directory
     * (WALM-639). A repo file is inert until this has been run for it. */
    approveProject: boolean;
    /** Withdraw that approval again. */
    revokeProject: boolean;
    relayerUrl?: string;
    webUrl?: string;
    label?: string;
    namespace?: string;
    /** `auto-save on|off|status` — the automatic-memory opt-in (WALM-642). */
    autoSave?: "on" | "off" | "status";
    /** `status` / `whoami` — print current credential info and exit. */
    status: boolean;
    /** Args parseArgs did not recognise, in the order seen. For a flag
     *  written `--key=value`, only `--key` is recorded — see parseArgs. */
    unknown: string[];
}

/** Per-environment URL shortcuts. `--dev`/`--staging`/`--local` set both
 *  relayer + web in one flag. Explicit `--relayer` / `--web-url` override. */
const ENV_PRESETS: Record<string, { relayer: string; web: string }> = {
    prod: { relayer: "https://relayer.memory.walrus.xyz", web: "https://memory.walrus.xyz" },
    dev: { relayer: "https://relayer.dev.memwal.ai", web: "https://dev.memwal.ai" },
    staging: { relayer: "https://relayer.dev.memwal.ai", web: "https://dev.memwal.ai" },
    local: { relayer: "http://127.0.0.1:8000", web: "http://localhost:5173" },
};

/** Bare words that are commands rather than values. An unknown flag must not
 *  swallow one as its argument. */
const POSITIONALS = new Set(["login", "approve-project", "revoke-project", "auto-save", "on", "off", "status", "whoami"]);

export function parseArgs(argv: string[]): ParsedArgs {
    const out: ParsedArgs = {
        help: false,
        logout: false,
        forceLogin: false,
        approveProject: false,
        revokeProject: false,
        status: false,
        unknown: [],
    };
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        const next = () => argv[++i];
        switch (a) {
            case "--help":
            case "-h":
                out.help = true;
                break;
            case "--logout":
                out.logout = true;
                break;
            case "--login":
            case "login":
                out.forceLogin = true;
                break;
            case "--approve-project":
            case "approve-project":
                out.approveProject = true;
                break;
            case "--revoke-project":
            case "revoke-project":
                out.revokeProject = true;
                break;
            case "--status":
            case "status":
            case "--whoami":
            case "whoami":
                out.status = true;
                break;
            case "auto-save":
            case "--auto-save": {
                // `auto-save` on its own reports the state rather than
                // changing it — a bare subcommand must never be read as
                // consent to turn automatic saving on.
                const value = argv[i + 1]?.toLowerCase();
                if (value === "on" || value === "off" || value === "status") {
                    out.autoSave = value;
                    i++;
                } else {
                    out.autoSave = "status";
                }
                break;
            }
            case "--prod":
            case "--dev":
            case "--staging":
            case "--local": {
                const preset = ENV_PRESETS[a.slice(2)];
                if (preset) {
                    out.relayerUrl ??= preset.relayer;
                    out.webUrl ??= preset.web;
                }
                break;
            }
            case "--relayer":
            case "--relayer-url":
                out.relayerUrl = next();
                break;
            case "--web-url":
            case "--web":
                out.webUrl = next();
                break;
            case "--label":
                out.label = next();
                break;
            case "--namespace":
            case "--ns":
                out.namespace = next();
                break;
            default:
                // Allow `--relayer=URL` and `--web-url=URL` forms too.
                if (a?.startsWith("--relayer=")) out.relayerUrl = a.split("=", 2)[1];
                else if (a?.startsWith("--web-url=")) out.webUrl = a.split("=", 2)[1];
                else if (a?.startsWith("--label=")) out.label = a.split("=", 2)[1];
                else if (a?.startsWith("--namespace=")) out.namespace = a.split("=", 2)[1];
                else if (a?.startsWith("--ns=")) out.namespace = a.split("=", 2)[1];
                // Anything still unmatched is a typo, or a flag from a newer
                // build. Values of KNOWN value-taking flags never reach this
                // branch — `next()` already consumed them.
                else if (a !== undefined) {
                    // Record the key only. A mistyped value-taking flag written
                    // `--tokenn=hunter2` would otherwise put the user's secret
                    // on stderr, which is the one place this warning must not
                    // put it.
                    const eq = a.indexOf("=");
                    out.unknown.push(eq === -1 ? a : a.slice(0, eq));
                    // An unknown flag may take its value as the next token, so
                    // consume one — `--namesapce work` should warn once about
                    // `--namesapce`, not a second time naming the user's data.
                    // POSITIONALS are exempt: they are commands, not values, and
                    // swallowing one would turn `memwal-mcp --typo login` into a
                    // run that never logs in.
                    const value = argv[i + 1];
                    if (
                        a.startsWith("-") &&
                        eq === -1 &&
                        value !== undefined &&
                        !value.startsWith("-") &&
                        !POSITIONALS.has(value)
                    ) {
                        i++;
                    }
                }
                break;
        }
    }
    return out;
}

export async function main(argv: string[] = process.argv.slice(2)): Promise<void> {
    const args = parseArgs(argv);

    // Runs before the --help branch so `memwal-mcp --typo --help` still calls
    // the typo out. Warn, never exit: an unknown flag from a newer config must
    // not brick the server.
    for (const flag of args.unknown) {
        log.warn("cli.unrecognised_arg", { arg: flag });
        note(
            `Unrecognised option \`${flag}\` — ignored. ` +
                `Run \`memwal-mcp --help\` for the supported options.`
        );
    }

    if (args.help) {
        printHelp();
        return;
    }

    // Republish the resolved opt-in for the plugin hooks before anything else
    // runs. The hooks do no resolution of their own — they read this file or
    // they fail safe to "off" (WALM-642) — so every start-up refreshes it,
    // including the ones that return early below. Best effort by design: a
    // read-only home must not stop the server, and a hook that finds nothing
    // already behaves as off.
    publishHookState();

    // Runs before the credential paths below: reading or flipping the opt-in
    // does not need an account, and a user deciding whether to enable
    // automatic memory should not be pushed through a browser login first.
    if (args.autoSave) {
        if (args.autoSave === "status") {
            note(autoSaveSummary());
            return;
        }
        const enabled = args.autoSave === "on";
        const { path } = setAutoSave(enabled);
        note(
            enabled
                ? `Automatic memory is ON. The agent may now save durable facts without being asked; ` +
                      `credentials are still excluded and stripped before any write. Saved to ${path}.`
                : `Automatic memory is OFF. Facts are saved only when you ask for them. Saved to ${path}.`,
        );
        const status = autoSaveStatus();
        if (status.source === "env" && status.enabled !== enabled) {
            // The file was written, but this process would still answer the
            // other way — say so rather than let the setting look ignored.
            note(
                `Note: ${AUTO_SAVE_ENV}=${process.env[AUTO_SAVE_ENV]} is set in this environment ` +
                    `and overrides the file. Unset it for the saved choice to take effect.`,
            );
        }
        return;
    }

    if (args.logout) {
        const cleared = clearCreds();
        // Explicit sign-out discards the write-ahead record too. Without this
        // an interrupted re-login leaves `login-pending.json` behind, and the
        // next start's `recoverPendingLogin` signs the user straight back in.
        //
        // Kept out of `clearCreds()` so only a deliberate sign-out discards a
        // key that may still be reclaimable. `clearCreds` is exported, and a
        // relayer 401 deliberately does NOT wipe credentials, so the two are
        // not the same decision.
        clearPendingLogin();
        if (!cleared.removedPath) {
            note(`No credentials to remove (${credsPath()}).`);
            return;
        }
        note(`Credentials removed (${cleared.removedPath}).`);
        if (cleared.fallbackPath) {
            note(
                `Still signed in elsewhere: ${cleared.fallbackPath} remains and is what ` +
                    `the next run loads, under a possibly different account. Remove it too ` +
                    `to sign out everywhere.`,
            );
        }
        return;
    }

    // `memwal-mcp status` / `memwal-mcp whoami` — print credential info and exit.
    // Works without a TTY so scripts and CI can query the active account.
    if (args.status) {
        const resolution = resolveCreds();
        const projectNotice = formatProjectCredsNotice(resolution);
        if (projectNotice) {
            note(projectNotice);
        }
        const creds = loadCreds();
        if (!creds) {
            note("Not logged in. Run `memwal-mcp login` to authenticate.");
            process.exitCode = 1;
            return;
        }
        const effectiveRelayerUrl = args.relayerUrl ?? creds.relayerUrl;
        const envRelayerUrl = process.env.MEMWAL_SERVER_URL;
        const relayerNote =
            args.relayerUrl && args.relayerUrl !== creds.relayerUrl
                ? `${effectiveRelayerUrl} (overrides saved ${creds.relayerUrl} via --relayer)`
                : !args.relayerUrl && envRelayerUrl && envRelayerUrl !== creds.relayerUrl
                  ? `${effectiveRelayerUrl} (saved; MEMWAL_SERVER_URL=${envRelayerUrl} is ignored when signed in — pass --relayer to override)`
                  : effectiveRelayerUrl;
        const effectiveLabel =
            args.label || process.env.MEMWAL_CLIENT_LABEL || creds.label || "MCP Client";
        const effectiveNamespace = args.namespace
            ? `${args.namespace} (via --namespace)`
            : process.env.MEMWAL_NAMESPACE
              ? `${process.env.MEMWAL_NAMESPACE} (via MEMWAL_NAMESPACE)`
              : "default (relayer default)";
        note(`Logged in as ${creds.walletAddress}`);
        note(`  Account:   ${creds.accountId}`);
        note(`  Delegate:  ${creds.delegateAddress}`);
        note(`  Wallet:    ${creds.walletAddress}`);
        note(`  Label:     ${effectiveLabel}`);
        note(`  Relayer:   ${relayerNote}`);
        note(`  Namespace: ${effectiveNamespace}`);
        note(`  Creds:     ${resolution.path} (${resolution.source})`);
        note(autoSaveSummary());
        return;
    }

    // A project-local `.memwal/credentials.json` decides the account and the
    // relayer every memory from that directory goes to, and it lives inside a
    // repository — so it stays inert until the user approves it here
    // (WALM-639). The approval is a decision about where memory goes, so it
    // wants a real terminal for the same reason `login` does: a non-interactive
    // spawn is a script or an MCP client, and neither of those is the user
    // saying yes.
    if (args.approveProject || args.revokeProject) {
        if (!process.stdin.isTTY) {
            log.error("creds.project_approval.requires_tty", { cwd: process.cwd() });
            note(
                "error: `approve-project` / `revoke-project` require an interactive terminal " +
                    "(stdin is not a TTY).",
            );
            note("       Run it in a terminal, from the project directory.");
            process.exitCode = 1;
            return;
        }
        if (args.revokeProject) {
            const revoked = revokeProjectCredsApproval();
            log.info("creds.project_approval.revoked", {
                outcome: revoked.outcome,
                projectPath: revoked.projectPath,
            });
            if (revoked.outcome === "none") {
                note(`No approval on record for ${revoked.projectPath}.`);
            } else {
                note(`Approval withdrawn for ${revoked.projectPath}.`);
                note(`Memory from this project goes to ${credsPath()} again.`);
            }
            return;
        }
        const approved = approveProjectCreds();
        log.info("creds.project_approval", {
            outcome: approved.outcome,
            projectPath: approved.projectPath,
            accountId: approved.accountId,
            relayerUrl: approved.relayerUrl,
        });
        switch (approved.outcome) {
            case "overridden":
                note(
                    `MEMWAL_CREDS_DIR is set (${process.env.MEMWAL_CREDS_DIR}), so project ` +
                        `credentials are never used. Nothing to approve.`,
                );
                break;
            case "none":
                note(
                    `No project credentials found at or above ${process.cwd()} ` +
                        `(.memwal/credentials.json). Nothing to approve.`,
                );
                break;
            case "unreadable":
                note(
                    `${approved.projectPath} is not a valid Walrus Memory credentials file. ` +
                        `Nothing to approve.`,
                );
                process.exitCode = 1;
                break;
            case "already-approved":
                note(
                    `Already approved: ${approved.projectPath} → account ${approved.accountId} ` +
                        `on ${approved.relayerUrl}.`,
                );
                // Repeated on a no-op approve too: someone re-running this is
                // checking what the state is, and "a private key gets written
                // into your repo" is part of that state.
                if (approved.projectPath) {
                    note(formatProjectCredsStorageWarning(approved.projectPath));
                }
                break;
            default:
                if (approved.outcome === "reapproved") {
                    note(
                        `The approved destination changed — was account ` +
                            `${approved.previousAccountId} on ${approved.previousRelayerUrl}.`,
                    );
                }
                note(`Approved ${approved.projectPath}.`);
                note(
                    `Memory written from this project now goes to account ${approved.accountId} ` +
                        `on ${approved.relayerUrl}.`,
                );
                note(
                    `Recorded in ${approved.approvalsPath}. Approval is required again if the ` +
                        `account, delegate key or relayer changes.`,
                );
                // Approving picks the WRITE target as well as the read one, and
                // that target is inside the repository. Saying only where memory
                // now goes would leave the user to discover the delegate key in
                // their working tree — at best in a diff, at worst in a push.
                if (approved.projectPath) {
                    note(formatProjectCredsStorageWarning(approved.projectPath));
                }
        }
        return;
    }

    // Resolve URLs: CLI > env > default.
    const relayerUrl =
        args.relayerUrl ?? process.env.MEMWAL_SERVER_URL ?? "https://relayer.memory.walrus.xyz";
    const webUrl =
        args.webUrl ?? process.env.MEMWAL_WEB_URL ?? "https://memory.walrus.xyz";
    // On-chain delegate-key display name; users can rename it in the dashboard.
    const label = args.label ?? process.env.MEMWAL_CLIENT_LABEL ?? "MCP Client";
    // Default memory namespace applied to memory tool calls when the agent
    // omits one. CLI > env, then UNSET — we deliberately do NOT hardcode a
    // fallback here: if neither is set, the namespace argument is left off
    // the forwarded call and the relayer applies its own "default" namespace.
    // An explicit per-call `namespace` from the agent always wins (see
    // applyDefaultNamespace in bridge.ts).
    const namespace = args.namespace ?? process.env.MEMWAL_NAMESPACE;

    // Explicit `login` is a human command. When stdin is not a TTY the
    // process was spawned by a script or MCP client — booting the
    // auth-required stub here would exit 0 without ever opening a browser.
    if (args.forceLogin && !process.stdin.isTTY) {
        log.error("login.requires_tty", { credsPath: credsPath() });
        note("error: `login` requires an interactive terminal (stdin is not a TTY).");
        note("       Run it in a terminal, or call `memwal_login` from an MCP client.");
        process.exitCode = 1;
        return;
    }

    // `login` forces a fresh sign-in by IGNORING what is on disk, not by
    // deleting it. Deleting up front meant an abandoned or failed login left
    // the user with no credentials at all and nothing to recover from — and it
    // also destroyed the file `saveCreds` needs in order to notice that the new
    // sign-in belongs to a different account (GH #628). The old file is now
    // replaced only on success, and backed up when the account changes.
    // Report a project-local credentials file that resolution refused to use,
    // once, before anything else reads credentials. Staying silent would be the
    // mirror of the silent redirect the gate exists to stop: the user put that
    // file there expecting it to be used, and nothing else would tell them it
    // was skipped or how to approve it (WALM-639).
    const resolution = resolveCreds();
    const projectNotice = formatProjectCredsNotice(resolution);
    if (projectNotice) {
        log.warn("creds.project_ignored", {
            projectPath: resolution.project?.path,
            decision: resolution.project?.decision,
            // Destination it would have redirected to — never anything from
            // the file's key material.
            projectAccountId: resolution.project?.accountId,
            projectRelayerUrl: resolution.project?.relayerUrl,
            using: resolution.path,
        });
        note(projectNotice);
    }

    let creds = args.forceLogin ? null : loadCreds();
    // A previous sign-in may have died after the browser registered our
    // delegate key on-chain but before the callback saved it (WALM-332). The
    // key was write-ahead-persisted, so try to reclaim it rather than making
    // the user register — and pay for — a replacement. Cheap no-op when there
    // is no pending record, which is the overwhelmingly common case: it hits
    // the network only when there is genuinely something stranded.
    if (!args.forceLogin) {
        const recovery = await recoverPendingLogin();
        if (recovery.outcome === "recovered" && recovery.credentials) {
            creds = recovery.credentials;
            note(
                `Recovered credentials from an interrupted sign-in ` +
                    `(delegate ${recovery.credentials.delegateAddress}).`,
            );
            if (recovery.replacementNotice) note(recovery.replacementNotice);
        } else {
            const notice = formatStrandedLoginNotice(recovery);
            if (notice) note(notice);
        }
    }
    if (creds && args.relayerUrl && creds.relayerUrl !== args.relayerUrl) {
        // Caller wants a different relayer than what's saved. NEVER silently
        // mutate the saved relayerUrl — a malicious config snippet (e.g.
        // copy-pasted from a forum) carrying `--relayer https://attacker`
        // would otherwise rewrite the saved creds so even subsequent runs
        // without the flag ship the seed to the attacker (audit H4).
        //
        // In-memory override is fine for THIS process — the saved file is
        // left untouched, so the next spawn falls back to the saved URL.
        log.warn("creds.relayer_override.transient_only", {
            saved: creds.relayerUrl,
            override: args.relayerUrl,
        });
        note(
            `--relayer flag (${args.relayerUrl}) overrides saved relayer ` +
                `(${creds.relayerUrl}) for THIS process only. The saved file ` +
                `is not modified. To rotate the saved relayer, run ` +
                `\`memwal-mcp login --logout\` then a fresh login.`
        );
        creds = { ...creds, relayerUrl: args.relayerUrl };
    }
    const wasLoggedIn = !!creds;
    if (!creds) {
        if (!process.stdin.isTTY) {
            // Spawned by an MCP client (Cursor / Claude Desktop / etc.).
            // Instead of exiting — which makes the client UI show "Failed to
            // start" with no actionable next step — boot a minimal stdio MCP
            // server that responds to `initialize` and `tools/list` but
            // returns an `isError: true` envelope on every `tools/call` with
            // a friendly login instruction. The user sees the message
            // INLINE in their chat, not buried in stderr logs.
            //
            // Phase B.5 (see plans/memwal-mcp-package-with-login.md) will
            // replace this with the MCP OAuth flow so the client's host
            // drives the browser dance and retries the tool call
            // automatically — no client restart required.
            log.warn("creds.missing_at_spawn.serving_auth_required", {
                credsPath: credsPath(),
                relayerUrl,
                webUrl,
            });
            // Pass the resolved URLs through so `memwal_login` (called as a
            // tool from the MCP client) opens the correct dashboard. Before
            // this fix `--dev` was silently dropped here and the flow always
            // routed to prod (https://memory.walrus.xyz).
            // No credentials and no terminal: a brand-new install being set up
            // through an MCP client. Stamp it now, while we can still tell it
            // apart from a long-standing user — otherwise a sign-in through the
            // `memwal_login` tool would later be indistinguishable from one,
            // and automatic saving would switch itself on with nobody having
            // been asked (WALM-642).
            markConsentPending();
            const handoff = await runAuthRequiredServer({ relayerUrl, webUrl, label, namespace });
            if (handoff) {
                // The user completed `memwal_login` in this SAME session: the
                // auth-required server detected the freshly-written credentials
                // and handed off here without a client restart. Pick up the
                // bridge and replay the request(s) it already read off stdin.
                // This is what removes the historical "second reboot".
                log.info("creds.hot_handoff_to_bridge", {
                    accountId: handoff.creds.accountId,
                });
                // Reaching here IS a completed sign-in: the auth-required
                // server only hands off once `memwal_login` has written
                // credentials mid-session. `adoptCredentials` covers the
                // re-login case; this covers signing in from signed-out, where
                // the bridge does not yet exist when the callback lands.
                notePendingLoginSuccess({
                    accountId: handoff.creds.accountId,
                    delegateAddress: handoff.creds.delegateAddress,
                    credentialsPath: credsPath(),
                });
                const pendingAfterLogin = pendingConsentNotice();
                if (pendingAfterLogin) note(pendingAfterLogin);
                await runBridge(
                    handoff.creds,
                    { relayerUrl, webUrl, label, namespace },
                    handoff.pendingLines,
                );
            }
            return;
        }
        // TTY = manual invocation. Block on the browser flow as before.
        note(
            "Walrus Memory MCP is not authorized yet — opening browser to connect your Sui wallet."
        );
        creds = await loginFlow({ relayerUrl, webUrl, label, freshKey: args.forceLogin });
        note(`Authorized as ${creds.walletAddress.slice(0, 10)}...`);
        // Before the question is put, not after: if the user abandons the
        // prompt, the install must still read as "never answered" rather than
        // fall through to the pre-existing-user rule and start saving.
        markConsentPending();
    } else {
        log.info("creds.loaded", {
            accountId: creds.accountId,
            delegateAddress: creds.delegateAddress,
            label: creds.label,
            relayerUrl: creds.relayerUrl,
            // Which file won, and how. "Where is this sending my memory" is
            // otherwise only answerable by re-deriving the resolution by hand.
            credentialsPath: resolution.path,
            credentialsSource: resolution.source,
        });
    }

    // Manual invocation from a real terminal: print status and exit.
    // Bridge mode only makes sense when an MCP client is attached on the
    // other end of stdin (Cursor / Claude Desktop / ...). A TTY means the
    // user is the one looking at stdout — there's no MCP client to bridge
    // with, so hanging the process is the wrong default.
    if (process.stdin.isTTY) {
        // The one moment there is demonstrably a human here. Consent is asked
        // on a terminal and nowhere else — never as an MCP tool, a tool
        // description or an instruction, because a model answering this is not
        // the user answering it (WALM-642).
        await askForConsentIfOwed();

        note(``);
        if (wasLoggedIn) {
            note(`✅ Already authorized as ${creds.walletAddress.slice(0, 10)}...${creds.walletAddress.slice(-6)}`);
            note(`   Account:  ${creds.accountId}`);
            note(`   Relayer:  ${creds.relayerUrl}`);
            note(`   Creds:    ${resolution.path} (${resolution.source})`);
        } else {
            note(`✅ Login complete. Credentials saved to ${credsPath()}`);
        }
        note(``);
        // The one moment a human is guaranteed to be looking at this output —
        // so it is where the automatic-save choice gets surfaced (WALM-642).
        note(autoSaveSummary());
        note(``);
        note(`Next: add this package to your MCP client config (Cursor / Claude Desktop / etc).`);
        note(`See \`memwal-mcp --help\` for ready-to-paste snippets.`);
        return;
    }

    // Non-interactive from here on. Say the state once on stderr — there is no
    // one to ask, and a prompt on this stdin would hang the server forever.
    const pending = pendingConsentNotice();
    if (pending) note(pending);

    await runBridge(creds, { relayerUrl, webUrl, label, namespace });
}

/**
 * Put the consent question to the user, if it is still owed one.
 *
 * Silent when the question has been answered, when `MEMWAL_AUTO_SAVE` has
 * settled it, or when the input stream ends without an answer — in that last
 * case the state stays unset and the question comes back next time, rather than
 * a choice being recorded that nobody made. A declined answer is written once
 * and never asked about again.
 */
async function askForConsentIfOwed(): Promise<void> {
    if (!autoSaveStatus().pendingConsent) return;

    const answer = await askAutoSaveConsent({
        input: process.stdin,
        output: process.stderr,
        isTTY: process.stdin.isTTY === true,
    });
    if (answer === null) {
        note(
            "No answer recorded — automatic memory is unchanged and you will be " +
                "asked again next time. Set it directly with `memwal-mcp auto-save on|off`.",
        );
        return;
    }
    const { path } = setAutoSave(answer);
    note(consentOutcomeNotice(answer, path));
}

function printHelp(): void {
    process.stderr.write(helpText() + "\n");
}

/** The `--help` body. Exported so tests can assert it stays in step with the
 *  flags parseArgs actually accepts. */
export function helpText(): string {
    // Rendered from ENV_PRESETS rather than retyped, so a new preset cannot
    // ship undocumented.
    const presetLines = Object.entries(ENV_PRESETS).flatMap(([name, urls]) => [
        `  ${`--${name}`.padEnd(33)}relayer: ${urls.relayer}`,
        `  ${"".padEnd(33)}web:     ${urls.web}`,
    ]);
    const help = [
        "memwal-mcp — Walrus Memory Model Context Protocol client",
        "",
        "Usage:",
        "  memwal-mcp                       Run the MCP stdio server (default).",
        "                                   Triggers a one-time browser login",
        "                                   if ~/.memwal/credentials.json is",
        "                                   missing.",
        "  memwal-mcp login                 Force re-authentication (wipes",
        "                                   existing credentials and opens",
        "                                   browser).",
        "  memwal-mcp --logout              Delete saved credentials without",
        "                                   re-running login.",
        "  memwal-mcp approve-project       Approve the project-local",
        "                                   .memwal/credentials.json found from",
        "                                   the current directory, so memory",
        "                                   written here goes to ITS account and",
        "                                   relayer. Until approved the file is",
        "                                   ignored and the global credentials",
        "                                   are used. Approval is per machine,",
        "                                   stored outside the repository, and",
        "                                   required again if the account,",
        "                                   delegate key or relayer changes.",
        "  memwal-mcp revoke-project        Withdraw that approval.",
        "  memwal-mcp auto-save on|off      Turn automatic memory on or off.",
        "                                   ON once you agree to it: `login` asks",
        "                                   in the terminal the first time, and",
        "                                   nothing is saved unprompted until you",
        "                                   answer. Saved memories are permanent",
        "                                   — Walrus is immutable storage — so",
        "                                   you can stop saving new ones but",
        "                                   cannot delete one already saved.",
        "                                   Credentials (passwords, API keys,",
        "                                   tokens, private keys, seed phrases,",
        "                                   auth headers, URLs with an embedded",
        "                                   user:password) are stripped before",
        "                                   any write either way — a safety net,",
        "                                   not a guarantee. Stored in",
        "                                   settings.json next to",
        "                                   credentials.json.",
        "  memwal-mcp auto-save             Report the current setting.",
        "  memwal-mcp status                Print current account, relayer URL,",
        "                                   and credential path. Alias: whoami.",
        "                                   Exits 1 when not logged in.",
        "  memwal-mcp --help                Show this help.",
        "",
        "Options:",
        "  --relayer <url>                  Override the relayer base URL.",
        "                                   Default: https://relayer.memory.walrus.xyz",
        "                                   (or saved value from credentials).",
        "  --web-url <url>                  Override the dashboard URL the",
        "                                   browser opens during login.",
        "                                   Default: https://memory.walrus.xyz",
        "  --label <text>                   Friendly delegate-key label",
        "                                   registered on-chain. Default:",
        '                                   "MCP Client"',
        "  --namespace <name>               Default memory namespace applied",
        "                                   to memwal_remember / recall /",
        "                                   analyze / restore when the agent",
        "                                   omits one. An explicit per-call",
        "                                   namespace always wins. Unset →",
        '                                   relayer uses its "default".',
        "                                   Alias: --ns",
        "",
        "Network presets (set --relayer and --web-url together):",
        ...presetLines,
        "",
        "                                   An explicit --relayer or --web-url",
        "                                   wins over a preset, whichever",
        "                                   order they are written in.",
        "",
        "Environment (equivalent to options):",
        "  MEMWAL_SERVER_URL                same as --relayer",
        "  MEMWAL_WEB_URL                   same as --web-url",
        "  MEMWAL_CLIENT_LABEL              same as --label",
        "  MEMWAL_CREDS_DIR                 Use this directory for credentials",
        "                                   and approvals, overriding both the",
        "                                   project-local and global files.",
        "                                   Must be an ABSOLUTE path outside the",
        "                                   project; anything else is refused.",
        "  MEMWAL_NAMESPACE                 same as --namespace",
        "  MEMWAL_AUTO_SAVE=0               Turn automatic memory off for this",
        "                                   server process only. Turning it on",
        "                                   requires `memwal-mcp auto-save on`",
        "                                   or the `login` prompt.",
        "  MEMWAL_MCP_DEBUG=1               Verbose stderr logging.",
        "",
        "Minimal MCP client config (Cursor, Claude Desktop, etc.):",
        "  {",
        '    "mcpServers": {',
        '      "memwal": {',
        '        "command": "npx",',
        '        "args": ["-y", "@mysten-incubation/memwal-mcp"]',
        "      }",
        "    }",
        "  }",
        "",
        "With explicit relayer override (e.g. dev environment):",
        "  {",
        '    "mcpServers": {',
        '      "memwal": {',
        '        "command": "npx",',
        '        "args": [',
        '          "-y", "@mysten-incubation/memwal-mcp",',
        '          "--relayer", "https://relayer.dev.memwal.ai"',
        "        ]",
        "      }",
        "    }",
        "  }",
        "",
        "Pinned to a memory namespace (set once, no per-call namespace needed):",
        "  {",
        '    "mcpServers": {',
        '      "memwal": {',
        '        "command": "npx",',
        '        "args": [',
        '          "-y", "@mysten-incubation/memwal-mcp",',
        '          "--namespace", "work"',
        "        ]",
        "      }",
        "    }",
        "  }",
        "",
    ].join("\n");
    return help;
}

// Re-exports — handy if someone wants to embed this in another tool.
export {
    loadCreds,
    saveCreds,
    clearCreds,
    credsPath,
    resolveCreds,
    approveProjectCreds,
    revokeProjectCredsApproval,
    formatProjectCredsNotice,
    formatProjectCredsStorageWarning,
} from "./auth.js";
export {
    isAutoSaveEnabled,
    isConsentPending,
    autoSaveStatus,
    setAutoSave,
    markConsentPending,
    publishHookState,
    settingsPath,
    hookStatePath,
} from "./auto-save.js";
export { askAutoSaveConsent, interpretConsentAnswer, CONSENT_PROMPT } from "./consent.js";
export { loginFlow } from "./login.js";
export { runBridge } from "./bridge.js";
export type { MemWalCredentials, CredsResolution, ProjectCredsDecision } from "./auth.js";
