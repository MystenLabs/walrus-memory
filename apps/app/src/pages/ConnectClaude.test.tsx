/**
 * WALM-605 recovery path.
 *
 * A Sui outage during `POST /complete` leaves the authorization session
 * `pending` instead of burning it. That only helps if the consent UI can
 * re-send *that one request*: re-running the whole flow re-asks the wallet to
 * sign and re-submits `add_delegate_key` for a key already on chain.
 *
 * The duplicate submission is decided server-side, by `/account`'s on-chain
 * check. It cannot be decided here: this page signs through the sponsor proxy,
 * and `sponsor::mask_upstream` replaces every upstream 5xx with a bare 502 that
 * carries no Move abort, so the consent UI never sees which abort fired.
 */
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
    address: '0xowner',
    accountId: '0xaccount',
    accountObjectJson: null as Record<string, unknown> | null,
    signAndExecute: vi.fn(),
    signPersonalMessage: vi.fn(),
}))

vi.mock('../config', () => ({
    config: {
        memwalServerUrl: 'https://relayer.test',
        memwalPackageId: '0xpkg',
        memwalRegistryId: '0xreg',
        suiNetwork: 'testnet',
        docsUrl: 'https://docs.test',
    },
}))
vi.mock('@mysten/dapp-kit', () => ({
    ConnectModal: () => null,
    useCurrentAccount: () => ({ address: mocks.address }),
    useSuiClient: () => ({ waitForTransaction: vi.fn().mockResolvedValue({}) }),
    useSignPersonalMessage: () => ({ mutateAsync: mocks.signPersonalMessage }),
}))
vi.mock('../hooks/useSponsoredTransaction', () => ({
    useSponsoredTransaction: () => ({ mutateAsync: mocks.signAndExecute }),
}))
vi.mock('../utils/suiClientCompat', () => ({
    fetchAccountIdForOwner: vi.fn().mockResolvedValue(mocks.accountId),
    fetchObjectJson: vi.fn(async () => mocks.accountObjectJson),
}))
vi.mock('../utils/analytics', () => ({
    trackEvent: vi.fn(),
    getAnalyticsErrorType: () => 'unknown',
}))

import ConnectClaude from './ConnectClaude'

const SESSION = `mws_${'a'.repeat(24)}`

function json(body: unknown, status = 200) {
    return new Response(JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json' },
    })
}

const SESSION_VIEW = {
    client_name: 'Claude',
    redirect_host: 'claude.ai',
    scopes: ['memory.read'],
    delegate_public_key: 'ab'.repeat(32),
    delegate_sui_address: '0xdelegate',
    expires_at: new Date(Date.now() + 600_000).toISOString(),
}

/**
 * Serves the session GET and the `/account` preflight, and hands each
 * `/complete` POST to the next entry of `completeResponses`. Returns a counter
 * of how many times each endpoint was called.
 */
function stubRelayer(
    completeResponses: (() => Response | Promise<Response>)[],
    {
        needsOnchainRegistration = false,
        resumePendingRegistration = false,
        accountResponse,
    }: {
        needsOnchainRegistration?: boolean
        resumePendingRegistration?: boolean
        accountResponse?: () => Response
    } = {},
) {
    const calls = { account: 0, complete: 0, completeBodies: [] as string[] }
    vi.stubGlobal(
        'fetch',
        vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input)
            if (url.endsWith(`/session/${SESSION}`)) return json(SESSION_VIEW)
            if (url.endsWith('/account')) {
                calls.account += 1
                if (accountResponse) return accountResponse()
                // Default: reused delegate, so no add_delegate_key transaction
                // is needed and the test isolates the /complete round-trip.
                return json({
                    needs_onchain_registration: needsOnchainRegistration,
                    delegate_public_key: SESSION_VIEW.delegate_public_key,
                    delegate_sui_address: SESSION_VIEW.delegate_sui_address,
                    resume_pending_registration: resumePendingRegistration,
                })
            }
            if (url.endsWith('/complete')) {
                const next = completeResponses[calls.complete] ?? completeResponses.at(-1)
                calls.complete += 1
                calls.completeBodies.push(String(init?.body ?? ''))
                return next!()
            }
            throw new Error(`unexpected fetch: ${url}`)
        }),
    )
    return calls
}

async function approve() {
    render(
        <MemoryRouter initialEntries={[`/connect/claude?session=${SESSION}`]}>
            <ConnectClaude />
        </MemoryRouter>,
    )
    await userEvent.click(await screen.findByRole('button', { name: 'Approve' }))
}

beforeEach(() => {
    vi.clearAllMocks()
    sessionStorage.clear()
    mocks.accountObjectJson = null
    mocks.signPersonalMessage.mockResolvedValue({ signature: 'sig' })
    // jsdom refuses a real navigation; the page only needs the call to not throw.
    vi.stubGlobal('location', { ...window.location, replace: vi.fn() })
})

describe('ConnectClaude /complete recovery', () => {
    it('offers a retry of /complete alone when Sui is unavailable', async () => {
        const calls = stubRelayer([
            () =>
                json(
                    {
                        error: 'temporarily_unavailable',
                        error_description: 'could not verify the delegate key on-chain right now',
                    },
                    503,
                ),
            () => json({ redirect_url: 'https://claude.ai/callback?code=abc' }),
        ])

        await approve()

        // Not the terminal error state: the session is still pending.
        const retry = await screen.findByRole('button', { name: /finish connecting/i })
        expect(screen.queryByText('Something went wrong')).toBeNull()

        await userEvent.click(retry)

        await waitFor(() => expect(calls.complete).toBe(2))
        // The retry re-sent /complete only — no second preflight, so no second
        // add_delegate_key submission.
        expect(calls.account).toBe(1)
        expect(mocks.signAndExecute).not.toHaveBeenCalled()
        await screen.findByText(/Redirecting you back/)
    })

    it('a reload mid-recovery resumes at the retry step, not at consent', async () => {
        // The ref does not survive a remount. Without the sessionStorage copy
        // the user lands back on consent, and a first-time connect re-asks the
        // wallet and re-submits add_delegate_key for a key already on chain.
        const calls = stubRelayer([
            () => json({ error: 'temporarily_unavailable', error_description: 'sui unavailable' }, 503),
            () => json({ redirect_url: 'https://claude.ai/callback?code=abc' }),
        ])

        await approve()
        await screen.findByRole('button', { name: /finish connecting/i })
        expect(calls.account).toBe(1)

        // Remount, as a browser reload would.
        cleanup()
        render(
            <MemoryRouter initialEntries={[`/connect/claude?session=${SESSION}`]}>
                <ConnectClaude />
            </MemoryRouter>,
        )

        const retry = await screen.findByRole('button', { name: /finish connecting/i })
        await userEvent.click(retry)

        await waitFor(() => expect(calls.complete).toBe(2))
        // Still no second preflight and no second transaction after the reload.
        expect(calls.account).toBe(1)
        expect(mocks.signAndExecute).not.toHaveBeenCalled()
    })

    it('a definitive rejection leaves nothing to resume after a reload', async () => {
        // The session is spent on a 400, so a reload must land on the error and
        // not loop on the "Sui is busy" retry screen.
        stubRelayer([
            () => json({ error: 'invalid_request', error_description: 'delegate key is not registered on-chain' }, 400),
        ])

        await approve()
        await screen.findByText('Something went wrong')

        cleanup()
        render(
            <MemoryRouter initialEntries={[`/connect/claude?session=${SESSION}`]}>
                <ConnectClaude />
            </MemoryRouter>,
        )

        await screen.findByRole('button', { name: 'Approve' })
        expect(screen.queryByRole('button', { name: /finish connecting/i })).toBeNull()
    })

    it('does not replay a stored payload against a different session', async () => {
        sessionStorage.setItem(
            'memwal_claude_pending_complete',
            JSON.stringify({
                session: 'mws_' + 'z'.repeat(24),
                payload: { account_id: '0xa', owner_address: '0xb', owner_signature: 'sig', tx_digest: 'd', reused_delegate: true },
            }),
        )
        stubRelayer([() => json({ redirect_url: 'https://claude.ai/callback?code=abc' })])

        render(
            <MemoryRouter initialEntries={[`/connect/claude?session=${SESSION}`]}>
                <ConnectClaude />
            </MemoryRouter>,
        )

        // Lands on consent, not on someone else's half-finished authorization.
        await screen.findByRole('button', { name: 'Approve' })
        expect(screen.queryByRole('button', { name: /finish connecting/i })).toBeNull()
    })

    it('a reload while /complete is in flight resumes at the retry step', async () => {
        // The gap a ref cannot cover, and the reason the crumb is written
        // before the request rather than after it fails: /complete never
        // answered, so there is no 503 to react to, yet the transaction above
        // has already landed and the wallet has already signed.
        // Never settles: a reload destroys the context that issued it, so this
        // response is never processed by anyone. Resolving it here instead
        // would let the dead page run its success path and clear the crumb,
        // which no real reload can do.
        const inFlight = new Promise<Response>(() => {})
        const calls = stubRelayer(
            [() => inFlight, () => json({ redirect_url: 'https://claude.ai/callback?code=abc' })],
            { needsOnchainRegistration: true },
        )
        mocks.signAndExecute.mockResolvedValue({ digest: '0xdigest' })

        await approve()
        await waitFor(() => expect(calls.complete).toBe(1))
        expect(mocks.signAndExecute).toHaveBeenCalledTimes(1)

        // Reload before the relayer answers.
        cleanup()
        render(
            <MemoryRouter initialEntries={[`/connect/claude?session=${SESSION}`]}>
                <ConnectClaude />
            </MemoryRouter>,
        )

        const retry = await screen.findByRole('button', { name: /finish connecting/i })
        await userEvent.click(retry)

        await waitFor(() => expect(calls.complete).toBe(2))
        // No second preflight, and above all no second wallet signature or
        // second add_delegate_key for a key the chain already took.
        expect(calls.account).toBe(1)
        expect(mocks.signAndExecute).toHaveBeenCalledTimes(1)
    })

    it('skips add_delegate_key when /account says this session key is already on chain', async () => {
        // The WALM-605 journey: an earlier attempt landed the transaction and
        // then hit a 429 during verify. The chain, not a transaction error, is
        // what tells us there is nothing left to submit.
        const calls = stubRelayer([() => json({ redirect_url: 'https://claude.ai/callback?code=abc' })], {
            needsOnchainRegistration: false,
            resumePendingRegistration: true,
        })

        await approve()

        await screen.findByText(/Redirecting you back/)
        expect(mocks.signAndExecute).not.toHaveBeenCalled()
        expect(calls.complete).toBe(1)
        // Named honestly: this is not a delegate reused from an earlier grant.
        expect(JSON.parse(calls.completeBodies[0]!).tx_digest).toBe('already-on-chain')
    })

    it('does not read a duplicate-key abort out of the masked sponsor 502', async () => {
        // Built from the real exports, so the fixture cannot drift from the
        // wrapper the way a hand-written 'MoveAbort ... abort code: 0' string
        // did: that string is not what production throws, so a test using it
        // passes while the user dead-ends.
        const { SponsorHttpError, sponsorFailureMessage } = await vi.importActual<
            typeof import('../hooks/useSponsoredTransaction')
        >('../hooks/useSponsoredTransaction')
        const masked = sponsorFailureMessage(
            new SponsorHttpError(
                'sponsor',
                502,
                JSON.stringify({
                    error: 'Sponsor service error',
                    code: 'sponsor_upstream_error',
                    traceId: 'tr_1',
                }),
            ),
        )
        // The premise: an Enoki dry-run abort reaches the SPA with no Move text.
        expect(masked).not.toMatch(/abort code/)
        expect(masked).not.toMatch(/add_delegate_key/)

        const calls = stubRelayer([() => json({ redirect_url: 'https://claude.ai/callback?code=abc' })], {
            needsOnchainRegistration: true,
        })
        mocks.signAndExecute.mockRejectedValue(new Error(masked))

        await approve()

        await screen.findByText('Something went wrong')
        // The load-bearing assertion: a sponsor 502 must not be treated as
        // "already registered" and POSTed to /complete. ENotOwner,
        // ETooManyDelegateKeys and EDelegateKeyAlreadyExists are
        // indistinguishable here, and guessing the last one burns the session
        // as Unregistered for the other two.
        expect(calls.complete).toBe(0)
    })

    it('returns to consent when the /account preflight cannot reach Sui', async () => {
        const calls = stubRelayer([() => json({ redirect_url: 'https://claude.ai/callback?code=abc' })], {
            accountResponse: () =>
                json(
                    { error: 'temporarily_unavailable', error_description: 'sui unavailable' },
                    503,
                ),
        })

        await approve()

        // The session is still pending. The terminal error has no way back,
        // so the user must be able to start this request again.
        expect(screen.queryByText('Something went wrong')).toBeNull()
        expect(await screen.findByText('sui unavailable')).toBeTruthy()
        expect(screen.getByRole('button', { name: 'Approve' })).toBeTruthy()
        expect(mocks.signAndExecute).not.toHaveBeenCalled()
        expect(calls.complete).toBe(0)
    })

    it('still fails terminally on a definitive rejection', async () => {
        stubRelayer([
            () =>
                json(
                    {
                        error: 'invalid_request',
                        error_description: 'delegate key is not registered on-chain',
                    },
                    400,
                ),
        ])

        await approve()

        await screen.findByText('Something went wrong')
        expect(screen.queryByRole('button', { name: /finish connecting/i })).toBeNull()
    })

    it('fails fast on preflight when registration is needed and the account has 20 delegate keys', async () => {
        const calls = stubRelayer([() => json({ redirect_url: 'https://claude.ai/callback?code=abc' })], {
            needsOnchainRegistration: true,
        })
        mocks.accountObjectJson = {
            delegate_keys: Array.from({ length: 20 }, (_, idx) => ({ public_key: `key_${idx}` })),
        }

        await approve()

        expect(
            await screen.findByText(
                /already has the maximum number of delegate keys \(20\)\. Go to \/dashboard and revoke an unused key/i,
            ),
        ).toBeInTheDocument()
        expect(screen.getByRole('link', { name: /go to dashboard/i })).toHaveAttribute('href', '/dashboard')
        expect(mocks.signAndExecute).not.toHaveBeenCalled()
        expect(calls.complete).toBe(0)
    })

    it('still allows reusing an existing OAuth delegate when the account is at 20 delegate keys', async () => {
        const calls = stubRelayer([() => json({ redirect_url: 'https://claude.ai/callback?code=abc' })], {
            needsOnchainRegistration: false,
        })
        mocks.accountObjectJson = {
            delegate_keys: Array.from({ length: 20 }, (_, idx) => ({ public_key: `key_${idx}` })),
        }

        await approve()

        await screen.findByText(/Redirecting you back/)
        expect(mocks.signAndExecute).not.toHaveBeenCalled()
        expect(calls.complete).toBe(1)
    })
})
