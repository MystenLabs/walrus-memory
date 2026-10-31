/**
 * Connect Claude — consent screen for the MCP OAuth 2.1 flow
 * (`services/server/src/routes/oauth.rs`), used by Claude's native
 * custom-connector "Add" flow and any other OAuth-speaking MCP client.
 *
 * Unlike `ConnectMcp.tsx` (which drives itself entirely from query-string
 * params supplied by a local CLI process), this page takes a single opaque
 * `session` id and fetches everything it displays from the server
 * (`GET /api/oauth/session/{id}`). That's deliberate: WALM-288 found that
 * `/connect/mcp` trusted attacker-controlled query params for the consent
 * text, enabling a phishing link that granted a stranger persistent
 * account access. Nothing here is rendered from `useSearchParams()` except
 * the session id itself, which is meaningless without a valid, unexpired
 * server-side session row behind it.
 *
 * Flow:
 *   1. GET /api/oauth/session/{id} → client name (untrusted, labeled as
 *      such), the *server-validated* redirect host, scopes, delegate
 *      pubkey/address.
 *   2. User connects a Sui wallet.
 *   3. POST .../account {accountId, ownerAddress} → server checks whether
 *      this account already has an active OAuth delegate from a previous
 *      grant; if so, no on-chain tx is needed.
 *   4. If needed: sign `add_delegate_key` (identical tx shape to
 *      ConnectMcp.tsx), same sponsored-transaction path.
 *   5. POST .../complete {accountId, ownerAddress, txDigest} → server
 *      verifies on-chain, mints a one-time code, returns `redirect_url`.
 *   6. `window.location.replace(redirect_url)` — hands control back to
 *      Claude (or whatever OAuth client started the flow).
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
    ConnectModal,
    useCurrentAccount,
    useSignPersonalMessage,
    useSuiClient,
} from '@mysten/dapp-kit'
import { Transaction } from '@mysten/sui/transactions'
import { Link, useSearchParams } from 'react-router-dom'
import { useSponsoredTransaction } from '../hooks/useSponsoredTransaction'
import { config } from '../config'
import { getAnalyticsErrorType, trackEvent } from '../utils/analytics'
import {
    fetchDelegateKeyCount,
    isMaxDelegateKeysError,
    MAX_DELEGATE_KEYS,
    MAX_DELEGATE_KEYS_CONNECT_MESSAGE,
} from '../utils/delegateKeys'
import { fetchAccountIdForOwner } from '../utils/suiClientCompat'



/** The `POST /complete` body, plus the analytics flag that goes with it. */
type CompletePayload = {
    account_id: string
    owner_address: string
    owner_signature: string
    tx_digest: string
    reused_delegate: boolean
}

/** Where the in-flight `POST /complete` payload survives a reload. */
const PENDING_COMPLETE_KEY = 'memwal_claude_pending_complete'

/**
 * The saved `POST /complete` payload for this session, if any.
 *
 * Session-scoped on purpose: one authorization's wallet signature must never be
 * replayed against another.
 */
function loadStoredComplete(sessionId: string): CompletePayload | null {
    try {
        const raw = sessionStorage.getItem(PENDING_COMPLETE_KEY)
        if (!raw) return null
        const saved = JSON.parse(raw) as { session?: string; payload?: CompletePayload }
        if (saved.session !== sessionId || !saved.payload?.owner_signature) return null
        return saved.payload
    } catch {
        return null
    }
}

function hasStoredComplete(sessionId: string): boolean {
    return loadStoredComplete(sessionId) !== null
}

type Step =
    | 'loading'
    | 'consent'
    | 'signing'
    | 'finishing'
    | 'retry-complete'
    | 'redirecting'
    | 'no-account'
    | 'error'

interface SessionView {
    client_name: string
    redirect_host: string
    scopes: string[]
    delegate_public_key: string
    delegate_sui_address: string
    expires_at: string
}

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

type OAuthRequestError = Error & { status: number; oauthError?: string }

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
    const res = await fetch(url, {
        ...init,
        headers: { 'content-type': 'application/json', ...(init?.headers ?? {}) },
    })
    const body = await res.json().catch(() => null)
    if (!res.ok) {
        const envelope = body && typeof body === 'object' ? (body as Record<string, unknown>) : null
        const description =
            envelope && 'error_description' in envelope
                ? String(envelope.error_description)
                : `request failed (${res.status})`
        const err = new Error(description) as OAuthRequestError
        err.status = res.status
        if (envelope && typeof envelope.error === 'string') err.oauthError = envelope.error
        throw err
    }
    return body as T
}

/**
 * The relayer could not reach Sui, so it left the authorization session
 * `pending` instead of burning it (WALM-605). Re-POSTing `/complete` alone is
 * the recovery: the wallet signature and the on-chain registration from the
 * first attempt are both still good, so restarting `handleConnect` would only
 * re-ask the wallet and re-submit a transaction the chain has already taken.
 */
function isRetryableComplete(err: unknown): boolean {
    const e = err as Partial<OAuthRequestError> | null
    return e?.oauthError === 'temporarily_unavailable' || e?.status === 503
}

export default function ConnectClaude() {
    const [params] = useSearchParams()
    const sessionId = params.get('session') ?? ''
    const currentAccount = useCurrentAccount()
    const suiClient = useSuiClient()
    const { mutateAsync: signAndExecute } = useSponsoredTransaction()
    const { mutateAsync: signPersonalMessage } = useSignPersonalMessage()

    const apiBase = config.memwalServerUrl.replace(/\/$/, '')

    const [step, setStep] = useState<Step>('loading')
    const [errorMsg, setErrorMsg] = useState('')
    const [walletPickerOpen, setWalletPickerOpen] = useState(false)
    const [session, setSession] = useState<SessionView | null>(null)

    const sessionValid = useMemo(() => /^mws_[A-Za-z0-9_-]{20,}$/.test(sessionId), [sessionId])

    useEffect(() => {
        if (!sessionValid) {
            setStep('error')
            setErrorMsg('This link is missing or malformed — ask the connecting app to start over.')
            return
        }
        let cancelled = false
        fetchJson<SessionView>(`${apiBase}/api/oauth/session/${sessionId}`)
            .then((view) => {
                if (cancelled) return
                setSession(view)
                // A reload mid-recovery resumes at the retry step. Landing on
                // consent would re-run handleConnect, which re-asks the wallet
                // to sign and re-sends a transaction the chain already took.
                setStep(hasStoredComplete(sessionId) ? 'retry-complete' : 'consent')
            })
            .catch((err) => {
                if (cancelled) return
                setErrorMsg(err instanceof Error ? err.message : String(err))
                setStep('error')
            })
        return () => {
            cancelled = true
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [sessionValid, sessionId])

    // Persist the resume breadcrumb across the Enoki/Google OAuth redirect,
    // same mechanism `ConnectMcp.tsx` uses for `memwal_mcp_connect`.
    useEffect(() => {
        if (!sessionValid) return
        sessionStorage.setItem('memwal_claude_connect', JSON.stringify({ session: sessionId }))
    }, [sessionValid, sessionId])


    // Everything `POST /complete` needs, kept so a retry re-sends exactly this
    // request instead of re-running `handleConnect`, which would re-ask the
    // wallet for a signature and re-submit `add_delegate_key` for a key that
    // is already on chain.
    //
    // A ref does not survive a reload, and a reload is the obvious thing to try
    // when the relayer says "retry", so the payload also goes to sessionStorage.
    // It gets its own key rather than joining `memwal_claude_connect`, which
    // the mount effect rewrites to `{ session }` on every load and would drop
    // the payload.
    const pendingComplete = useRef<CompletePayload | null>(null)

    const forgetPendingComplete = useCallback(() => {
        pendingComplete.current = null
        try {
            sessionStorage.removeItem(PENDING_COMPLETE_KEY)
        } catch {
            // Nothing to clean up if storage is unavailable.
        }
    }, [])

    const rememberPendingComplete = useCallback(
        (payload: CompletePayload) => {
            pendingComplete.current = payload
            try {
                sessionStorage.setItem(
                    PENDING_COMPLETE_KEY,
                    JSON.stringify({ session: sessionId, payload }),
                )
            } catch {
                // Private mode or a full quota: the in-page button still works.
            }
        },
        [sessionId],
    )

    const readPendingComplete = useCallback((): CompletePayload | null => {
        if (pendingComplete.current) return pendingComplete.current
        const saved = loadStoredComplete(sessionId)
        if (saved) pendingComplete.current = saved
        return saved
    }, [sessionId])

    const completeSession = useCallback(async (payload: CompletePayload) => {
        // Durable before the request, not after it fails. A reload while
        // /complete is still in flight is the gap a ref cannot cover, and on
        // the first-time path it is the expensive one: without the crumb the
        // page lands on consent, re-runs handleConnect, and re-submits
        // add_delegate_key for a key the tx above already put on chain. That
        // no longer dead-ends now that /account detects it, but it still costs
        // a wallet round-trip and a sponsored transaction.
        //
        // Writing early is safe because every terminal exit clears it: success
        // below, and a definitive 400 in the catch. A spent session therefore
        // cannot leave a crumb that loops the user on "Sui is busy".
        rememberPendingComplete(payload)
        setStep('finishing')
        try {
            const { redirect_url } = await fetchJson<{ redirect_url: string }>(
                `${apiBase}/api/oauth/session/${sessionId}/complete`,
                {
                    method: 'POST',
                    body: JSON.stringify({
                        account_id: payload.account_id,
                        owner_address: payload.owner_address,
                        owner_signature: payload.owner_signature,
                        tx_digest: payload.tx_digest,
                    }),
                },
            )
            sessionStorage.removeItem('memwal_claude_connect')
            sessionStorage.removeItem(PENDING_COMPLETE_KEY)
            setStep('redirecting')
            trackEvent('claude_connect_complete', { reused_delegate: payload.reused_delegate })
            window.location.replace(redirect_url)
        } catch (err) {
            if (!isRetryableComplete(err)) {
                // Definitive: the session is spent. Clear the crumb so a reload
                // lands on the error rather than looping on "Sui is busy".
                forgetPendingComplete()
                throw err
            }
            // The session is still pending, so offer this one request again
            // rather than dropping into the terminal error state. The crumb
            // written above is what the retry step and a reload both read.
            setErrorMsg(err instanceof Error ? err.message : String(err))
            setStep('retry-complete')
            trackEvent('claude_connect_failed', { error_type: 'sui_unavailable' })
        }
    }, [apiBase, sessionId, rememberPendingComplete, forgetPendingComplete])

    const handleRetryComplete = useCallback(async () => {
        const payload = readPendingComplete()
        if (!payload) return
        try {
            await completeSession(payload)
        } catch (err) {
            setErrorMsg(err instanceof Error ? err.message : String(err))
            setStep('error')
            trackEvent('claude_connect_failed', { error_type: getAnalyticsErrorType(err) })
        }
    }, [completeSession, readPendingComplete])
    const handleConnect = useCallback(async () => {
        if (!session) return
        if (!currentAccount) {
            trackEvent('claude_connect_start', { wallet_connected: false })
            setWalletPickerOpen(true)
            return
        }

        trackEvent('claude_connect_start', { wallet_connected: true })
        setStep('signing')
        try {
            const accountId = await resolveAccountId(suiClient, currentAccount.address)
            if (!accountId) {
                trackEvent('claude_connect_failed', { error_type: 'no_account' })
                setStep('no-account')
                return
            }

            const preflight = await fetchJson<{
                needs_onchain_registration: boolean
                delegate_public_key: string
                delegate_sui_address: string
                // Absent on a relayer older than WALM-605, which is the
                // pre-existing behaviour: no resume, just the first-time path.
                resume_pending_registration?: boolean
            }>(`${apiBase}/api/oauth/session/${sessionId}/account`, {
                method: 'POST',
                body: JSON.stringify({ account_id: accountId, owner_address: currentAccount.address }),
            })

            let txDigest = ''
            if (preflight.needs_onchain_registration) {
                const delegateKeyCount = await fetchDelegateKeyCount(suiClient, accountId)
                if (delegateKeyCount !== null && delegateKeyCount >= MAX_DELEGATE_KEYS) {
                    setErrorMsg(MAX_DELEGATE_KEYS_CONNECT_MESSAGE)
                    setStep('error')
                    trackEvent('claude_connect_failed', { error_type: 'max_delegate_keys' })
                    return
                }

                const tx = new Transaction()
                tx.moveCall({
                    target: `${config.memwalPackageId}::account::add_delegate_key`,
                    arguments: [
                        tx.object(accountId),
                        tx.object(config.memwalRegistryId),
                        tx.pure('vector<u8>', hexToBytes(preflight.delegate_public_key)),
                        // v1_new derives the Sui address on-chain — no address arg.
                        tx.pure('string', `Claude (${new Date().toISOString().slice(0, 10)})`),
                        tx.object('0x6'),
                    ],
                })
                // Deliberately no `EDelegateKeyAlreadyExists` (0) or `ENotOwner` (4)
                // abort-code branches here. Duplicate keys are settled before this
                // point by `/account`'s on-chain check (`resume_pending_registration`),
                // and `ETooManyDelegateKeys` (2) is preflighted above and classified
                // as `max_delegate_keys` (409) by `/sponsor`. Unclassified 502s remain
                // terminal errors rather than being guessed as already-registered.
                const result = await signAndExecute({ transaction: tx })
                await suiClient.waitForTransaction({ digest: result.digest })
                txDigest = result.digest
            }

            setStep('finishing')
            const proofMessage = new TextEncoder().encode(
                `Walrus Memory OAuth authorization\nsession:${sessionId}\naccount:${accountId.toLowerCase()}\nowner:${currentAccount.address.toLowerCase()}`,
            )
            const { signature: ownerSignature } = await signPersonalMessage({ message: proofMessage })
            const resuming = preflight.resume_pending_registration === true
            await completeSession({
                account_id: accountId,
                owner_address: currentAccount.address,
                owner_signature: ownerSignature,
                // `/complete` requires a non-empty digest. When no tx was sent
                // this call names why, rather than claiming a reused delegate
                // for a key this session registered on an earlier attempt.
                tx_digest: txDigest || (resuming ? 'already-on-chain' : 'reused-delegate'),
                reused_delegate: !preflight.needs_onchain_registration && !resuming,
            })
        } catch (err) {
            setErrorMsg(err instanceof Error ? err.message : String(err))
            if (isRetryableComplete(err)) {
                // The session is still pending. The terminal error has no
                // button back, so return to consent and let the user start
                // this request again.
                setStep('consent')
                trackEvent('claude_connect_failed', { error_type: 'sui_unavailable' })
                return
            }
            setStep('error')
            trackEvent('claude_connect_failed', { error_type: getAnalyticsErrorType(err) })
        }
    }, [session, currentAccount, suiClient, signAndExecute, signPersonalMessage, completeSession])

    const handleCancel = useCallback(async () => {
        try {
            const { redirect_url } = await fetchJson<{ redirect_url: string }>(
                `${apiBase}/api/oauth/session/${sessionId}/cancel`,
                { method: 'POST', body: JSON.stringify({ error: 'access_denied' }) },
            )
            trackEvent('cta_click', { cta: 'claude_connect_deny', location: 'connect_claude' })
            window.location.replace(redirect_url)
        } catch {
            // Session already consumed/expired — nothing sensible to redirect
            // to. Leave the user on this page rather than guessing a URL.
        }
    }, [apiBase, sessionId])

    // Auto-proceed once the wallet popup resolves.
    useEffect(() => {
        if (!walletPickerOpen && currentAccount && step === 'consent') {
            if (hasStoredComplete(sessionId)) return
            void handleConnect()
        }
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
                    {step === 'loading' && (
                        <div className="setup-classic-intro">
                            <h2 className="setup-classic-title">Loading…</h2>
                        </div>
                    )}

                    {step === 'consent' && session && (
                        <ConsentCard session={session} wallet={currentAccount?.address ?? null} error={errorMsg} onConnect={handleConnect} onCancel={handleCancel} />
                    )}

                    {step === 'signing' && (
                        <div className="setup-classic-intro">
                            <h2 className="setup-classic-title">Confirm in your wallet…</h2>
                            <p className="setup-classic-description">
                                A wallet popup is registering this delegate key on chain. Approve the transaction to continue.
                            </p>
                        </div>
                    )}

                    {step === 'finishing' && (
                        <div className="setup-classic-intro">
                            <h2 className="setup-classic-title">Finishing up…</h2>
                            <p className="setup-classic-description">Verifying on-chain and handing back to the connecting app.</p>
                        </div>
                    )}

                    {step === 'redirecting' && (
                        <div className="setup-classic-intro">
                            <h2 className="setup-classic-title"><span className="mcp-ok">✓</span> Connected</h2>
                            <p className="setup-classic-description">Redirecting you back…</p>
                        </div>
                    )}

                    {step === 'no-account' && (
                        <div className="setup-classic-intro">
                            <h2 className="setup-classic-title">Create a Walrus Memory account first</h2>
                            <p className="setup-classic-description">
                                This wallet doesn't have a Walrus Memory account yet. Run through the one-time setup, then we'll bring you back here to finish connecting.
                            </p>
                            <div className="setup-classic-actions">
                                <Link to="/setup" className="mcp-btn">Create account and continue</Link>
                            </div>
                        </div>
                    )}

                    {step === 'retry-complete' && (
                        <div className="setup-classic-intro">
                            <h2 className="setup-classic-title">Sui is busy — try again</h2>
                            <p className="setup-classic-description">
                                We couldn't reach Sui to verify your delegate key, so this authorization is
                                still pending rather than spent. Nothing needs redoing — press the button to
                                finish.
                            </p>
                            <p className="setup-classic-description mcp-error">{errorMsg}</p>
                            <div className="setup-classic-actions">
                                <button type="button" className="mcp-btn" onClick={handleRetryComplete}>
                                    Finish connecting
                                </button>
                            </div>
                        </div>
                    )}

                    {step === 'error' && (
                        <div className="setup-classic-intro">
                            <h2 className="setup-classic-title">Something went wrong</h2>
                            <p className="setup-classic-description mcp-error">{errorMsg}</p>
                            {isMaxDelegateKeysError(errorMsg) && (
                                <div className="setup-classic-actions">
                                    <Link
                                        to="/dashboard"
                                        className="mcp-btn"
                                        onClick={() => trackEvent('cta_click', { cta: 'claude_error_dashboard', location: 'connect_claude' })}
                                    >
                                        Go to dashboard
                                    </Link>
                                </div>
                            )}
                        </div>
                    )}
                </div>
            </main>

            <ConnectModal trigger={<></>} open={walletPickerOpen} onOpenChange={setWalletPickerOpen} />
        </div>
    )
}

function ConsentCard({
    session,
    wallet,
    error,
    onConnect,
    onCancel,
}: {
    session: SessionView
    wallet: string | null
    error?: string
    onConnect: () => void
    onCancel: () => void
}) {
    return (
        <div className="setup-classic-intro">
            <h2 className="setup-classic-title">Connect to Walrus Memory</h2>
            <p className="setup-classic-description">
                <strong className="mcp-client-name">{session.client_name}</strong>{' '}
                <span className="mcp-unverified">(name supplied by the connecting app — not verified by Walrus Memory)</span>{' '}
                wants access to your Walrus Memory account.
            </p>

            <div className="card setup-classic-feature-card">
                <p className="mcp-kicker">This grants persistent access, until you revoke it</p>
                <ul className="mcp-perms">
                    {session.scopes.includes('memwal:read') && <li>✓ Read your memories</li>}
                    {session.scopes.includes('memwal:write') && <li>✓ Save new memories</li>}
                    <li>✓ Walrus Memory will hold an encrypted key on your behalf to authorize these actions — it never leaves our servers, and you can revoke it from the dashboard at any time</li>
                </ul>

                <div className="mcp-rule" />

                <p className="mcp-kicker">Verified redirect destination</p>
                <div className="mcp-detail">
                    <span className="mcp-detail-value">{session.redirect_host}</span>
                </div>

                <div className="mcp-rule" />

                <p className="mcp-kicker">Connected wallet</p>
                <div className="mcp-detail">
                    <span className="mcp-detail-value">
                        {wallet ? `${wallet.slice(0, 12)}…${wallet.slice(-6)}` : '(not connected yet)'}
                    </span>
                </div>
            </div>

            {error ? <p className="setup-classic-description mcp-error">{error}</p> : null}
            <div className="setup-classic-actions">
                <button onClick={onConnect} className="mcp-btn">
                    {wallet ? 'Approve' : 'Connect Sui wallet'}
                </button>
                <button onClick={onCancel} className="mcp-btn mcp-btn--ghost">
                    Deny
                </button>
            </div>
        </div>
    )
}
