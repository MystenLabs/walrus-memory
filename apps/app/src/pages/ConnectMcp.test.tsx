import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
    address: '0xowner',
    accountId: '0xaccount',
    accountObjectJson: null as Record<string, unknown> | null,
    signAndExecute: vi.fn(),
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

import ConnectMcp from './ConnectMcp'

const PORT = '38291'
const PUBLIC_KEY = 'a'.repeat(64)
const STATE = 'b'.repeat(64)
const RELAYER = 'https://relayer.test'

/** Answers the page's `/preflight` so it reaches consent, then applies
 * `callback` to the `/callback` POST that decides the outcome under test. */
function stubListener(callback: () => Promise<Response>) {
    vi.stubGlobal(
        'fetch',
        vi.fn(async (input: RequestInfo | URL) => {
            const url = String(input)
            if (url.endsWith('/preflight')) {
                return new Response(
                    JSON.stringify({ ok: true, publicKey: PUBLIC_KEY, label: 'Claude Code', relayer: RELAYER }),
                    { status: 200, headers: { 'content-type': 'application/json' } },
                )
            }
            if (url.endsWith('/callback')) return callback()
            throw new Error(`unexpected fetch: ${url}`)
        }),
    )
}

async function signIn() {
    const query = `?port=${PORT}&publicKey=${PUBLIC_KEY}&relayer=${encodeURIComponent(RELAYER)}&connectState=${STATE}`
    render(
        <MemoryRouter initialEntries={[`/connect/mcp${query}`]}>
            <ConnectMcp />
        </MemoryRouter>,
    )
    const approve = await screen.findByRole('button', { name: /approve in wallet/i })
    await userEvent.click(approve)
}

beforeEach(() => {
    vi.clearAllMocks()
    mocks.accountObjectJson = null
    mocks.signAndExecute.mockResolvedValue({ digest: '0xdigest' })
})

describe('MCP sign-in hand-off', () => {
    it('does not sign until the user approves, even when a wallet is already connected', async () => {
        stubListener(async () => new Response('{}', { status: 200 }))
        const query = `?port=${PORT}&publicKey=${PUBLIC_KEY}&relayer=${encodeURIComponent(RELAYER)}&connectState=${STATE}`
        render(
            <MemoryRouter initialEntries={[`/connect/mcp${query}`]}>
                <ConnectMcp />
            </MemoryRouter>,
        )

        const approve = await screen.findByRole('button', { name: /approve in wallet/i })
        expect(mocks.signAndExecute).not.toHaveBeenCalled()
        await userEvent.click(approve)
        expect(await screen.findByText(/MCP client connected/i)).toBeInTheDocument()
        expect(mocks.signAndExecute).toHaveBeenCalledTimes(1)
    })

    it('confirms the connection when the listener accepts the callback', async () => {
        stubListener(async () => new Response('{}', { status: 200 }))
        await signIn()

        expect(await screen.findByText(/MCP client connected/i)).toBeInTheDocument()
        expect(screen.getByText(/handed off to your MCP client/i)).toBeInTheDocument()
    })

    it('offers the starter system prompt once the client is connected', async () => {
        stubListener(async () => new Response('{}', { status: 200 }))
        await signIn()

        expect(await screen.findByText(/MCP client connected/i)).toBeInTheDocument()
        expect(screen.getByText(/most agents only write when told to/i)).toBeInTheDocument()
        expect(screen.getByText(/call memwal_remember in that same turn/i)).toBeInTheDocument()
        expect(screen.getByRole('button', { name: /copy prompt/i })).toBeInTheDocument()
    })

    it('withholds the starter prompt when the hand-off never landed', async () => {
        stubListener(async () => {
            throw new TypeError('Failed to fetch')
        })
        await signIn()

        expect(await screen.findByText(/Almost there/i)).toBeInTheDocument()
        expect(screen.queryByRole('button', { name: /copy prompt/i })).not.toBeInTheDocument()
    })

    it('does not claim success when nothing answers on localhost', async () => {
        stubListener(async () => {
            throw new TypeError('Failed to fetch')
        })
        await signIn()

        expect(await screen.findByText(/Almost there/i)).toBeInTheDocument()
        expect(screen.queryByText(/MCP client connected/i)).not.toBeInTheDocument()
        expect(screen.getByText(/Nothing answered on your computer/i)).toBeInTheDocument()
        expect(screen.getByText(/stopped waiting after this tab was already open/i)).toBeInTheDocument()
        expect(screen.queryByText(/opened too late/i)).not.toBeInTheDocument()
        expect(screen.queryByText(/usually works/i)).not.toBeInTheDocument()
        // The key is registered and saved by the client that started this
        // sign-in, so a restart reclaims it. Signing in again cannot register
        // it twice, and removing it from the dashboard throws it away.
        expect(screen.getByText(/Restart your MCP client within 24 hours/i)).toBeInTheDocument()
        expect(screen.getByText(/only if you mean to abandon it/i)).toBeInTheDocument()
        expect(
            screen.queryByText(/Remove it from the dashboard if you are not using it/i),
        ).not.toBeInTheDocument()
        expect(screen.queryByText(/Sign in again and open the new link straight away/i)).not.toBeInTheDocument()
    })

    it('explains an expired link when preflight cannot reach the listener', async () => {
        vi.stubGlobal(
            'fetch',
            vi.fn(async (input: RequestInfo | URL) => {
                const url = String(input)
                if (url.endsWith('/preflight')) throw new TypeError('Failed to fetch')
                throw new Error(`unexpected fetch: ${url}`)
            }),
        )
        const query = `?port=${PORT}&publicKey=${PUBLIC_KEY}&relayer=${encodeURIComponent(RELAYER)}&connectState=${STATE}`
        render(
            <MemoryRouter initialEntries={[`/connect/mcp${query}`]}>
                <ConnectMcp />
            </MemoryRouter>,
        )

        expect(await screen.findByText(/opened too late/i)).toBeInTheDocument()
        expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument()
        expect(screen.queryByText(/Almost there/i)).not.toBeInTheDocument()
    })

    it('tells a refused hand-off apart from an absent one', async () => {
        stubListener(async () => new Response('nope', { status: 409 }))
        await signIn()

        expect(await screen.findByText(/Almost there/i)).toBeInTheDocument()
        expect(screen.queryByText(/MCP client connected/i)).not.toBeInTheDocument()
        expect(await screen.findByText(/rejected this hand-off/i)).toBeInTheDocument()
        expect(screen.queryByText(/Nothing answered on your computer/i)).not.toBeInTheDocument()
    })

    it('keeps the key reassuring and links troubleshooting on failure', async () => {
        stubListener(async () => {
            throw new TypeError('Failed to fetch')
        })
        await signIn()

        expect(await screen.findByText(/first half of sign-in succeeded/i)).toBeInTheDocument()
        expect(screen.getByRole('link', { name: /troubleshooting/i })).toHaveAttribute(
            'href',
            'https://docs.test/troubleshooting/overview#sign-in-succeeds-but-credentials-are-not-saved',
        )
    })

    it('fails fast on preflight when the account already holds 20 delegate keys', async () => {
        stubListener(async () => new Response('{}', { status: 200 }))
        mocks.accountObjectJson = {
            delegate_keys: Array.from({ length: 20 }, (_, idx) => ({ public_key: `key_${idx}` })),
        }
        await signIn()

        expect(
            await screen.findByText(
                /already has the maximum number of delegate keys \(20\)\. Go to \/dashboard and revoke an unused key/i,
            ),
        ).toBeInTheDocument()
        expect(screen.getByRole('link', { name: /go to dashboard/i })).toHaveAttribute('href', '/dashboard')
        expect(mocks.signAndExecute).not.toHaveBeenCalled()
    })

    it('surfaces the 20 delegate-key limit when sponsor rejects with max_delegate_keys', async () => {
        const { SponsorHttpError, sponsorFailureMessage } = await vi.importActual<
            typeof import('../hooks/useSponsoredTransaction')
        >('../hooks/useSponsoredTransaction')
        stubListener(async () => new Response('{}', { status: 200 }))
        mocks.signAndExecute.mockRejectedValue(
            new Error(
                sponsorFailureMessage(
                    new SponsorHttpError(
                        'sponsor',
                        409,
                        JSON.stringify({
                            error: 'This Walrus Memory account already has the maximum number of delegate keys (20). Go to /dashboard and revoke an unused key, then try again.',
                            code: 'max_delegate_keys',
                            traceId: 'tr_limit_1',
                        }),
                    ),
                ),
            ),
        )
        await signIn()

        expect(
            await screen.findByText(/already has the maximum number of delegate keys \(20\)/i),
        ).toBeInTheDocument()
        expect(screen.getByText(/traceId: tr_limit_1/i)).toBeInTheDocument()
        expect(screen.getByRole('link', { name: /go to dashboard/i })).toHaveAttribute('href', '/dashboard')
    })
})
