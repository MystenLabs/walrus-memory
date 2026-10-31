/**
 * Connect MCP — browser-based wallet sign-in flow for the `@mysten-incubation/memwal-mcp`
 * stdio bridge.
 *
 * The MCP package opens this page in the user's browser with a query string:
 *
 *   /connect/mcp?port=17463
 *               &publicKey=<64-hex Ed25519 pub>
 *               &label=<URL-encoded label>
 *               &relayer=<URL-encoded relayer base URL>
 *               &connectState=<64-hex CSRF token>  (legacy bridges: `state`)
 *
 * Flow:
 *   1. Verify the exact state/public-key tuple against the localhost MCP
 *      bridge. A copied/emailed URL has no matching bridge and fails closed.
 *   2. Render consent screen — show requested permissions + the full delegate
 *      public key/address returned by the verified bridge. A wallet that is
 *      already connected does not skip this screen.
 *   3. User clicks through consent → standard dApp Kit wallet popup if needed.
 *   4. Re-check the local bridge, then sign `add_delegate_key`
 *      via useSponsoredTransaction (matches SetupWizard pattern).
 *   5. POST result {accountId, walletAddress, packageId, txDigest, label}
 *      to http://localhost:<port>/callback — the MCP package's listener.
 *   6. Show success screen — user can close the tab.
 *
 * Error paths:
 *   - Wallet not connected → wallet picker.
 *   - User has no Walrus Memory account yet → link to /setup.
 *   - Wallet rejects tx → retry button.
 *   - localhost callback unreachable or refused → on-chain key stands but never
 *     reaches the client; send the user back through sign-in.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
    ConnectModal,
    useCurrentAccount,
    useSuiClient,
} from '@mysten/dapp-kit'
import { Transaction } from '@mysten/sui/transactions'
import { Ed25519PublicKey } from '@mysten/sui/keypairs/ed25519'
import { Link, useSearchParams } from 'react-router-dom'
import { useSponsoredTransaction } from '../hooks/useSponsoredTransaction'
import { config } from '../config'
import { getAnalyticsErrorType, trackEvent } from '../utils/analytics'
import { fetchAccountIdForOwner } from '../utils/suiClientCompat'



/**
 * One-time standing instruction handed to the user on the success screen.
 * Claude Desktop does not inject initialize.instructions, and write tools start
 * at Ask. Keep in sync with packages/mcp/src/consent-instruction.ts.
 */
const CONSENT_INSTRUCTION = `Save durable facts to the user's Walrus Memory proactively, without asking for confirmation. Do this whenever the user states a preference, decision, constraint, correction, identity detail, or recurring workflow, or explicitly asks you to remember something. Pass the user's complete statement verbatim, never a summary. Skip one-off tasks, the current file or bug, and small talk.

Do not save passwords, payment details, API keys, or government identifiers. After saving, briefly confirm what you stored.

Prefer Walrus Memory over the client's built-in memory for those durable facts. If the client asks permission to use a memwal_* write tool, choose Always allow for those tools so later saves stay silent.`

type Step =
    | 'verifying'
    | 'consent'
    | 'signing'
    | 'callback'
    | 'success'
    | 'no-account'
    | 'error'

/** Hand-off result; the two failures have different causes, so not one boolean. */
type CallbackOutcome = 'delivered' | 'unreachable' | 'rejected'

function hexToBytes(hex: string): number[] {
    const clean = hex.startsWith('0x') ? hex.slice(2) : hex
    const out: number[] = []
    for (let i = 0; i < clean.length; i += 2) {
        out.push(parseInt(clean.slice(i, i + 2), 16))
    }
    return out
}

async function resolveAccountId(
    suiClient: ReturnType<typeof useSuiClient>,
    ownerAddress: string,
): Promise<string | null> {
    try {
        return await fetchAccountIdForOwner(suiClient, config.memwalRegistryId, ownerAddress)
    } catch {
        return null
    }
}

interface McpCallbackPayload {
    accountId: string
    walletAddress: string
    packageId: string
    txDigest: string
    label: string
    /** Echoes the state token the bridge issued in the query string. */
    state: string
}

interface VerifiedBridge {
    publicKey: string
    label: string
    relayer: string
}

function isVerifiedBridge(
    value: unknown,
    expectedPublicKey: string,
    expectedRelayer: string,
): value is VerifiedBridge & { ok: true } {
    if (!value || typeof value !== 'object') return false
    const candidate = value as Record<string, unknown>
    return (
        candidate.ok === true &&
        typeof candidate.publicKey === 'string' &&
        candidate.publicKey.toLowerCase() === expectedPublicKey.toLowerCase() &&
        typeof candidate.label === 'string' &&
        candidate.label.length > 0 &&
        typeof candidate.relayer === 'string' &&
        candidate.relayer.replace(/\/+$/, '') === expectedRelayer.replace(/\/+$/, '')
    )
}

function sameRelayer(a: string, b: string): boolean {
    const norm = (value: string) => value.trim().replace(/\/+$/, '').toLowerCase()
    return norm(a) === norm(b)
}

/** Ask the local bridge again. Network and abort errors propagate to the caller. */
async function confirmLocalBridge(
    port: string,
    state: string,
    publicKey: string,
    relayer: string,
    signal?: AbortSignal,
): Promise<VerifiedBridge | null> {
    const response = await fetch(`http://127.0.0.1:${port}/preflight`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ state, publicKey, relayer }),
        signal,
    })
    const body: unknown = await response.json().catch(() => null)
    if (!response.ok || !isVerifiedBridge(body, publicKey, relayer)) return null
    return {
        publicKey: body.publicKey,
        label: body.label,
        relayer: body.relayer,
    }
}

export default function ConnectMcp() {
    const [params] = useSearchParams()
    const currentAccount = useCurrentAccount()
    const suiClient = useSuiClient()
    const { mutateAsync: signAndExecute } = useSponsoredTransaction()

    const port = params.get('port') ?? ''
    const publicKey = params.get('publicKey') ?? ''
    const relayer = params.get('relayer') ?? config.memwalServerUrl
    /**
     * Cryptographic state token from the MCP bridge. Must be echoed verbatim
     * in the callback POST — the bridge constant-time compares it to defeat
     * cross-origin CSRF (audit C2). Empty string if absent (older bridge);
     * the bridge will then reject our callback with 400.
     *
     * Read from `connectState` (current bridge) with a fallback to the legacy
     * `state` param. The bridge renamed this param away from `state` because
     * `state` is a reserved OAuth 2.0 response parameter: when this page starts
     * Enoki/Google sign-in it reuses the current URL as the OAuth redirect_uri,
     * and Google rejects any redirect_uri carrying a reserved param (WALM-86:
     * "Access blocked: invalid_request — Invalid redirect_uri contains reserved
     * response param state"). We still echo it back in the POST body as `state`.
     */
    const state = params.get('connectState') ?? params.get('state') ?? ''
    // Local preview only. Production builds drop this, and it never talks to a bridge or the chain.
    const devMock = import.meta.env.DEV && params.get('mock') === '1'

    const [step, setStep] = useState<Step>('verifying')
    const [errorMsg, setErrorMsg] = useState('')
    const [walletPickerOpen, setWalletPickerOpen] = useState(false)
    const [callbackPayload, setCallbackPayload] = useState<McpCallbackPayload | null>(null)
    const [callbackOutcome, setCallbackOutcome] = useState<CallbackOutcome | null>(null)
    const [verifiedBridge, setVerifiedBridge] = useState<VerifiedBridge | null>(null)
    const [preflightAttempt, setPreflightAttempt] = useState(0)
    const invalidRequestTrackedRef = useRef(false)
    // Set only after the user clicks consent. A wallet that hydrates on its
    // own must not start add_delegate_key (#368).
    const initiatedRef = useRef(false)

    // Validate query string up-front.
    const paramsValid = useMemo(() => {
        const portNum = Number(port)
        return (
            Number.isFinite(portNum) &&
            portNum > 1024 &&
            portNum < 65536 &&
            /^[0-9a-fA-F]{64}$/.test(publicKey) &&
            // delegateAddress is derived on-chain (v1_new) and no longer sent
            // in the tx, so it is not required for a valid request.
            // State token is a 32-byte hex string emitted by the MCP bridge.
            // Old bridges without state will fail this check — by design;
            // forces a bridge upgrade so we never accept stateless callbacks.
            /^[0-9a-f]{64}$/.test(state)
        )
    }, [port, publicKey, state])

    // Never trust/display the legacy delegateAddress query parameter. The
    // contract derives this same Sui address from the Ed25519 public key.
    const delegateAddress = useMemo(() => {
        if (!/^[0-9a-fA-F]{64}$/.test(publicKey)) return ''
        return new Ed25519PublicKey(Uint8Array.from(hexToBytes(publicKey))).toSuiAddress()
    }, [publicKey])

    useEffect(() => {
        if (devMock || !paramsValid) {
            if (!devMock) setVerifiedBridge(null)
            return
        }
        const controller = new AbortController()
        setStep('verifying')
        setErrorMsg('')
        setVerifiedBridge(null)

        void (async () => {
            try {
                const confirmed = await confirmLocalBridge(
                    port,
                    state,
                    publicKey,
                    relayer,
                    controller.signal,
                )
                if (!confirmed) {
                    throw new Error('The local MCP bridge did not verify this connection request.')
                }
                setVerifiedBridge(confirmed)
                setStep('consent')
            } catch (error) {
                if (controller.signal.aborted) return
                setVerifiedBridge(null)
                const openedTooLate = error instanceof TypeError
                setErrorMsg(
                    openedTooLate
                        ? 'Nothing answered on your computer. Sign-in links stop working after five minutes, so most often the link was simply opened too late.'
                        : error instanceof Error
                          ? error.message
                          : 'Could not verify the local MCP bridge.',
                )
                setStep('error')
                trackEvent('mcp_connect_failed', { error_type: 'bridge_preflight_failed' })
            }
        })()

        return () => controller.abort()
    }, [devMock, paramsValid, port, preflightAttempt, publicKey, relayer, state])

    const postCallback = useCallback(
        async (payload: McpCallbackPayload): Promise<boolean> => {
            try {
                const res = await fetch(`http://127.0.0.1:${port}/callback`, {
                    method: 'POST',
                    headers: { 'content-type': 'application/json' },
                    body: JSON.stringify(payload),
                })
                setCallbackOutcome(res.ok ? 'delivered' : 'rejected')
                return res.ok
            } catch {
                setCallbackOutcome('unreachable')
                return false
            }
        },
        [port],
    )

    const handleConnect = useCallback(async () => {
        initiatedRef.current = true
        if (!paramsValid || !verifiedBridge) {
            trackEvent('mcp_connect_failed', { error_type: 'invalid_request' })
            setErrorMsg('This request was not verified by the local MCP client.')
            setStep('error')
            return
        }
        if (!currentAccount) {
            trackEvent('mcp_connect_start', { wallet_connected: false })
            setWalletPickerOpen(true)
            return
        }

        trackEvent('mcp_connect_start', { wallet_connected: true })
        let bridge: VerifiedBridge
        try {
            const confirmed = await confirmLocalBridge(port, state, publicKey, relayer)
            if (!confirmed) {
                throw new Error('The local MCP bridge did not verify this connection request.')
            }
            bridge = confirmed
        } catch (error) {
            if (error instanceof DOMException && error.name === 'AbortError') return
            trackEvent('mcp_connect_failed', { error_type: 'bridge_preflight_failed' })
            setVerifiedBridge(null)
            setErrorMsg(
                error instanceof TypeError
                    ? 'Nothing answered on your computer. Sign-in links stop working after five minutes, so most often the link was simply opened too late.'
                    : error instanceof Error
                      ? error.message
                      : 'Could not verify the local MCP bridge.',
            )
            setStep('error')
            return
        }
        setVerifiedBridge(bridge)
        setStep('signing')
        try {
            // Resolve the user's Walrus Memory account object.
            const accountId = await resolveAccountId(suiClient, currentAccount.address)
            if (!accountId) {
                trackEvent('mcp_connect_failed', { error_type: 'no_account' })
                setStep('no-account')
                return
            }

            // Build + sign add_delegate_key tx.
            const tx = new Transaction()
            tx.moveCall({
                target: `${config.memwalPackageId}::account::add_delegate_key`,
                arguments: [
                    tx.object(accountId),
                    tx.object(config.memwalRegistryId),
                    tx.pure('vector<u8>', hexToBytes(bridge.publicKey)),
                    // v1_new derives the Sui address on-chain — no address arg.
                    tx.pure('string', bridge.label),
                    tx.object('0x6'),
                ],
            })
            let result
            try {
                result = await signAndExecute({ transaction: tx })
            } catch (txErr: unknown) {
                const m = txErr instanceof Error ? txErr.message : String(txErr)
                // Friendly mapping for common contract aborts.
                if (m.includes('abort code: 0') && m.includes('add_delegate_key')) {
                    setErrorMsg(
                        `This wallet (${currentAccount.address.slice(0, 10)}…${currentAccount.address.slice(-6)}) is not the owner of Walrus Memory account ${accountId.slice(0, 10)}…${accountId.slice(-6)}. ` +
                        `Switch your wallet to the account that originally created this Walrus Memory account, OR run /setup to create a new Walrus Memory account for the current wallet.`
                    )
                    trackEvent('mcp_connect_failed', { error_type: 'owner_mismatch' })
                    setStep('error')
                    return
                }
                if (m.includes('abort code: 2') && m.includes('add_delegate_key')) {
                    setErrorMsg(
                        `This Walrus Memory account already has the maximum number of delegate keys (20). Go to /dashboard and revoke an unused key, then try again.`
                    )
                    trackEvent('mcp_connect_failed', { error_type: 'max_delegate_keys' })
                    setStep('error')
                    return
                }
                throw txErr
            }
            await suiClient.waitForTransaction({ digest: result.digest })

            const payload: McpCallbackPayload = {
                accountId,
                walletAddress: currentAccount.address,
                packageId: config.memwalPackageId,
                txDigest: result.digest,
                label: bridge.label,
                state,
            }
            setCallbackPayload(payload)
            setStep('callback')
            const delivered = await postCallback(payload)
            // Flow done — drop the OAuth-resume breadcrumb so a later visit to
            // `/` goes to the dashboard instead of looping back here.
            sessionStorage.removeItem('memwal_mcp_connect')
            setStep('success')
            trackEvent('mcp_connect_complete', { callback_delivered: delivered })
        } catch (err) {
            setErrorMsg(err instanceof Error ? err.message : String(err))
            setStep('error')
            trackEvent('mcp_connect_failed', { error_type: getAnalyticsErrorType(err) })
        }
    }, [
        paramsValid,
        currentAccount,
        suiClient,
        signAndExecute,
        verifiedBridge,
        port,
        publicKey,
        relayer,
        state,
        postCallback,
    ])

    useEffect(() => {
        if (devMock || paramsValid || invalidRequestTrackedRef.current) return
        invalidRequestTrackedRef.current = true
        trackEvent('mcp_connect_failed', { error_type: 'invalid_request' })
    }, [devMock, paramsValid])

    // Persist the connect request so it survives the Google OAuth redirect.
    // Enoki's redirect_uri is pinned to the app root (App.tsx), so signing in
    // with Google leaves this page and returns to `/` — losing the query
    // string. App's PostAuthRedirect reads this back and re-opens
    // /connect/mcp with the params restored. Keyed identically to the URL
    // params (note `connectState`, not `state`). Cleared on success below.
    useEffect(() => {
        if (devMock || !paramsValid) return
        sessionStorage.setItem(
            'memwal_mcp_connect',
            JSON.stringify({ port, publicKey, delegateAddress, relayer, connectState: state }),
        )
    }, [devMock, paramsValid, port, publicKey, delegateAddress, relayer, state])

    // If the wallet popup completes after the user clicked consent, continue.
    // A wallet that was already connected, or that hydrates on its own, must
    // not skip the disclosure (#368).
    useEffect(() => {
        if (devMock) return
        // A wallet that was already connected, or that hydrates on its own,
        // must not skip the disclosure (#368).
        if (initiatedRef.current && !walletPickerOpen && currentAccount && step === 'consent') {
            void handleConnect()
        }
        // we only want this to fire on wallet→connected transition.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [walletPickerOpen, currentAccount])

    return (
        <div className="dash-page mcp-connect">
            <nav className="nav playground-nav dashboard-nav">
                <div className="nav-inner">
                    <Link to="/" className="nav-brand">
                        <img className="nav-brand-logo" src="/walrus-memory-logo.svg?v=3" alt="Walrus Memory" />
                    </Link>
                </div>
            </nav>

            <main className="dash-shell">
                <div className="mcp-connect-panel">
                    {devMock ? (
                        <ConsentCard
                            label="Claude Code"
                            publicKey={'11'.repeat(32)}
                            delegateAddress="0x7c30e2a1b4c89f01d2e3a4b5c6d7e8f90123456789abcdef0123456789abcd"
                            relayer={config.memwalServerUrl}
                            relayerIsDefault
                            wallet={currentAccount?.address ?? null}
                            onConnect={() => undefined}
                        />
                    ) : !paramsValid && (
                        <div className="setup-classic-intro">
                            <h2 className="setup-classic-title">Invalid request</h2>
                            <p className="setup-classic-description">
                                This page must be opened by the{' '}
                                <code className="mcp-code">@mysten-incubation/memwal-mcp</code> package during its login flow.
                            </p>
                            <div className="card setup-classic-feature-card">
                                <div className="mcp-detail">
                                    <span className="mcp-detail-label">Got</span>
                                    <span className="mcp-detail-value">
                                        port={port || '(none)'} · publicKey={publicKey ? publicKey.slice(0, 12) + '…' : '(none)'}
                                    </span>
                                </div>
                            </div>
                        </div>
                    )}

                    {paramsValid && step === 'verifying' && (
                        <div className="setup-classic-intro">
                            <h2 className="setup-classic-title">Verifying local MCP client…</h2>
                            <p className="setup-classic-description">
                                Checking that this request came from an MCP login listener running on this device.
                            </p>
                        </div>
                    )}

                    {paramsValid && step === 'consent' && verifiedBridge && (
                        <ConsentCard
                            label={verifiedBridge.label}
                            publicKey={verifiedBridge.publicKey}
                            delegateAddress={delegateAddress}
                            relayer={verifiedBridge.relayer}
                            relayerIsDefault={sameRelayer(verifiedBridge.relayer, config.memwalServerUrl)}
                            wallet={currentAccount?.address ?? null}
                            onConnect={handleConnect}
                        />
                    )}

                    {paramsValid && step === 'signing' && (
                        <div className="setup-classic-intro">
                            <h2 className="setup-classic-title">Confirm in your wallet…</h2>
                            <p className="setup-classic-description">
                                A wallet popup is registering this delegate key on chain. Approve the transaction to continue.
                            </p>
                        </div>
                    )}

                    {paramsValid && step === 'callback' && (
                        <div className="setup-classic-intro">
                            <h2 className="setup-classic-title">Wrapping up…</h2>
                            <p className="setup-classic-description">Sending credentials back to your MCP client.</p>
                        </div>
                    )}

                    {paramsValid && step === 'success' && callbackPayload && (
                        <SuccessCard
                            payload={callbackPayload}
                            callbackOutcome={callbackOutcome}
                            port={port}
                        />
                    )}

                    {paramsValid && step === 'no-account' && (
                        <div className="setup-classic-intro">
                            <h2 className="setup-classic-title">Create a Walrus Memory account first</h2>
                            <p className="setup-classic-description">
                                This wallet doesn't have a Walrus Memory account yet. Run through the one-time setup, then we'll bring you back here to finish connecting.
                            </p>
                            <div className="setup-classic-actions">
                                <Link
                                    to="/setup"
                                    className="mcp-btn"
                                    onClick={() => trackEvent('cta_click', { cta: 'mcp_create_account', location: 'connect_mcp' })}
                                >
                                    Create account and continue
                                </Link>
                            </div>
                        </div>
                    )}

                    {paramsValid && step === 'error' && (
                        <div className="setup-classic-intro">
                            <h2 className="setup-classic-title">Something went wrong</h2>
                            <p className="setup-classic-description mcp-error">{errorMsg}</p>
                            <div className="setup-classic-actions">
                                <button
                                    className="mcp-btn"
                                    onClick={() => {
                                        trackEvent('cta_click', { cta: 'mcp_retry', location: 'connect_mcp' })
                                        setErrorMsg('')
                                        if (verifiedBridge) {
                                            setStep('consent')
                                        } else {
                                            setPreflightAttempt(attempt => attempt + 1)
                                        }
                                    }}
                                >
                                    Try again
                                </button>
                            </div>
                        </div>
                    )}
                </div>
            </main>

            <ConnectModal
                trigger={<></>}
                open={walletPickerOpen}
                onOpenChange={setWalletPickerOpen}
            />
        </div>
    )
}

function ConsentCard({
    label,
    publicKey,
    delegateAddress,
    relayer,
    relayerIsDefault,
    wallet,
    onConnect,
}: {
    label: string
    publicKey: string
    delegateAddress: string
    relayer: string
    relayerIsDefault: boolean
    wallet: string | null
    onConnect: () => void
}) {
    return (
        <div className="setup-classic-intro">
            <h2 className="setup-classic-title">
                A local MCP client is requesting access
            </h2>
            <p className="setup-classic-description">
                This local app calls itself <span className="mcp-client-name">{label}</span>. This name is not verified.
                Approving grants persistent access until you revoke the delegate key on-chain.
            </p>

            <div className="card setup-classic-feature-card">
                <p className="mcp-kicker">Permissions requested</p>
                <ul className="mcp-perms">
                    <li>✓ Read and decrypt all your memories (<code className="mcp-code">memwal_recall</code>)</li>
                    <li>✓ Write new memories (<code className="mcp-code">memwal_remember</code>)</li>
                    <li>✓ Extract facts from text (<code className="mcp-code">memwal_analyze</code>)</li>
                    <li>✓ Re-index from Walrus (<code className="mcp-code">memwal_restore</code>)</li>
                </ul>

                <div className="mcp-rule" />

                <details className="mcp-details">
                    <summary className="mcp-kicker">Details</summary>
                    <div className="mcp-details-body">
                        <div className="mcp-detail">
                            <span className="mcp-detail-label">Relayer</span>
                            <span className="mcp-detail-value">{relayer}</span>
                            {!relayerIsDefault && (
                                <span className="mcp-error">
                                    Non-default relayer. Memories would be served through this host. Continue only if you chose it.
                                </span>
                            )}
                        </div>
                        <div className="mcp-detail">
                            <span className="mcp-detail-label">Delegate public key</span>
                            <span className="mcp-detail-value">{publicKey}</span>
                        </div>
                        <div className="mcp-detail">
                            <span className="mcp-detail-label">Delegate address</span>
                            <span className="mcp-detail-value">{delegateAddress}</span>
                        </div>
                        <div className="mcp-detail">
                            <span className="mcp-detail-label">Connected wallet</span>
                            <span className="mcp-detail-value">
                                {wallet ? `${wallet.slice(0, 12)}…${wallet.slice(-6)}` : '(not connected yet)'}
                            </span>
                        </div>
                    </div>
                </details>
            </div>

            <div className="setup-classic-actions">
                <button onClick={onConnect} className="mcp-btn">
                    {wallet ? 'Approve in wallet' : 'Connect Sui wallet'}
                </button>
            </div>
        </div>
    )
}

function SuccessCard({
    payload,
    callbackOutcome,
    port,
}: {
    payload: McpCallbackPayload
    callbackOutcome: CallbackOutcome | null
    port: string
}) {
    const delivered = callbackOutcome === 'delivered'
    return (
        <div className="setup-classic-intro">
            <h2 className="setup-classic-title">
                {delivered ? (
                    <>
                        <span className="mcp-ok">✓</span> MCP client connected
                    </>
                ) : (
                    <>
                        <span className="mcp-warn">!</span> Almost there — one step
                        left
                    </>
                )}
            </h2>
            {delivered && (
                <p className="setup-classic-description">
                    Credentials were handed off to your MCP client. You can close this tab safely.
                </p>
            )}
            {!delivered && callbackOutcome !== null && (
                <>
                    <p className="setup-classic-description">
                        The first half of sign-in succeeded: your key was created and registered
                        to your account. What did not work is the last step: this page could not
                        pass the key back to the Walrus Memory app running on your computer, so
                        your MCP client cannot use it yet.
                    </p>
                    <p className="setup-classic-description">
                        {callbackOutcome === 'unreachable'
                            ? 'Nothing answered on your computer. The app stopped waiting after this tab was already open, which usually means the wallet prompt sat through the deadline, the MCP client restarted, or the login command was cancelled.'
                            : 'The app on your computer rejected this hand-off. That usually means this tab is leftover from a sign-in that already finished, or the request did not match what the app expected.'}
                    </p>
                    <p className="setup-classic-description">
                        <strong>Restart your MCP client within 24 hours.</strong> On start it
                        finds the key from this attempt and signs you in, with no second wallet
                        prompt. Do not sign in again first: this key is already registered to
                        your account, and it cannot be registered twice. Remove it from the
                        dashboard only if you mean to abandon it.{' '}
                        {config.docsUrl && (
                            <a
                                href={`${config.docsUrl}/troubleshooting/overview#sign-in-succeeds-but-credentials-are-not-saved`}
                                target="_blank"
                                rel="noopener noreferrer"
                                onClick={() =>
                                    trackEvent('outbound_link_click', {
                                        link: 'docs',
                                        location: 'connect_mcp_callback_failed',
                                    })
                                }
                            >
                                If it keeps failing, see troubleshooting.
                            </a>
                        )}
                    </p>
                </>
            )}
            <div className="card setup-classic-feature-card">
                <div className="mcp-detail">
                    <span className="mcp-detail-label">Account</span>
                    <span className="mcp-detail-value">{payload.accountId}</span>
                </div>
                {!delivered && callbackOutcome !== null && (
                    <div className="mcp-detail">
                        <span className="mcp-detail-label">Hand-off address</span>
                        <span className="mcp-detail-value mcp-code">
                            http://127.0.0.1:{port}/callback
                        </span>
                    </div>
                )}
            </div>
            {delivered && <ConsentSetupCard />}

            <div className="setup-classic-actions">
                <Link
                    to="/dashboard"
                    className="mcp-btn"
                    onClick={() => trackEvent('cta_click', { cta: 'mcp_success_dashboard', location: 'connect_mcp' })}
                >
                    Go to dashboard
                </Link>
            </div>
        </div>
    )
}

/**
 * Required one-time setup after credentials are delivered: native-memory
 * choice, paste the standing instruction, Always allow after the first save,
 * and a view/delete pointer.
 */
function ConsentSetupCard() {
    const [copied, setCopied] = useState(false)

    const handleCopy = useCallback(() => {
        void navigator.clipboard
            .writeText(CONSENT_INSTRUCTION)
            .then(() => {
                setCopied(true)
                trackEvent('cta_click', {
                    cta: 'mcp_success_copy_prompt',
                    location: 'connect_mcp',
                })
                window.setTimeout(() => setCopied(false), 2000)
            })
            .catch(() => undefined)
    }, [])

    return (
        <div className="card setup-classic-feature-card">
            <p className="mcp-kicker">Required: one-time setup</p>
            <ol className="mcp-prompt-intro" style={{ paddingLeft: 18 }}>
                <li>
                    Native memory: for portable memory across apps, turn off the client's
                    built-in memory. That is reversible and does not delete existing native
                    memories. If you keep it on, Walrus Memory is explicit-only: name memwal
                    when you want a save.
                </li>
                <li>
                    Paste this standing instruction, then start a new chat. Claude: Settings →
                    Profile (or General) → Instructions for Claude / Personal Preferences.
                    Claude Code: <code className="mcp-code">~/.claude/CLAUDE.md</code>. Codex:{' '}
                    <code className="mcp-code">AGENTS.md</code>. Cursor: a rule file under{' '}
                    <code className="mcp-code">.cursor/rules</code>.
                </li>
            </ol>
            <pre className="mcp-prompt">{CONSENT_INSTRUCTION}</pre>
            <div className="mcp-prompt-actions">
                <button type="button" onClick={handleCopy} className="mcp-btn">
                    {copied ? 'Copied' : 'Copy instruction'}
                </button>
                {config.docsUrl && (
                    <a
                        href={`${config.docsUrl}/mcp/claude-desktop`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="mcp-link"
                        onClick={() =>
                            trackEvent('outbound_link_click', {
                                link: 'docs',
                                location: 'connect_mcp_one_time_setup',
                            })
                        }
                    >
                        Full one-time setup
                    </a>
                )}
            </div>
            <p className="mcp-prompt-intro" style={{ marginTop: 8 }}>
                The Desktop guide is the long walkthrough. Other clients use the same three
                steps with the paste paths above.
            </p>
            <ol start={3} className="mcp-prompt-intro" style={{ paddingLeft: 18, marginTop: 16 }}>
                <li>
                    After you save the first fact, choose Always allow for{' '}
                    <code className="mcp-code">memwal_remember</code> and{' '}
                    <code className="mcp-code">memwal_remember_bulk</code>. Keep recall allowed.
                </li>
                <li>
                    View or delete memories at{' '}
                    <a
                        href="https://memory.walrus.xyz"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="mcp-link"
                        onClick={() =>
                            trackEvent('outbound_link_click', {
                                link: 'dashboard',
                                location: 'connect_mcp_view_delete',
                            })
                        }
                    >
                        memory.walrus.xyz
                    </a>
                    .
                </li>
            </ol>
        </div>
    )
}
