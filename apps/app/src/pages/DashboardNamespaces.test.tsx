/**
 * Namespaces card pagination (WALM-607).
 *
 * The relayer list endpoint is cursor-paginated: it clamps `limit` and reports
 * `has_more` + `next_cursor`. These tests pin the card to that contract rather
 * than to page length, and check that Refresh drops the cursor trail.
 */
import { render, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

// Hook return values must keep a stable identity across renders: Dashboard
// memoizes callbacks on `suiClient` / `currentAccount`, so fresh objects each
// render would re-fire their effects forever.
const mocks = vi.hoisted(() => ({
    address: '0xOwnerAddress',
    apiGet: vi.fn(),
    currentAccount: { address: '0xOwnerAddress' },
    suiClient: { waitForTransaction: () => Promise.resolve({}) },
    disconnect: { mutateAsync: () => Promise.resolve() },
    signPersonalMessage: { mutateAsync: () => Promise.resolve() },
    sponsoredTransaction: { mutateAsync: () => Promise.resolve() },
    delegateKeyCtx: {
        delegateKey: '0xdelegate',
        delegatePublicKey: '0xpub',
        accountObjectId: '0xaccount',
        setDelegateKeys: () => {},
        clearDelegateKeys: () => {},
    },
}))

vi.mock('../config', () => ({
    config: {
        memwalServerUrl: 'https://relayer.test',
        memwalPackageId: '0xpkg',
        memwalRegistryId: '0xreg',
        legacyMemwalRegistryId: '0xreg',
        suiNetwork: 'testnet',
        docsUrl: 'https://docs.test',
        enableMemoryDeletion: false,
        securityDeleteEnabled: false,
    },
}))
vi.mock('@mysten/dapp-kit', () => ({
    ConnectModal: () => null,
    useCurrentAccount: () => mocks.currentAccount,
    useDisconnectWallet: () => mocks.disconnect,
    useSignPersonalMessage: () => mocks.signPersonalMessage,
    useSuiClient: () => mocks.suiClient,
}))
vi.mock('../hooks/useSponsoredTransaction', () => ({
    useSponsoredTransaction: () => mocks.sponsoredTransaction,
}))
vi.mock('../App', () => ({
    useDelegateKey: () => mocks.delegateKeyCtx,
}))
vi.mock('@mysten-incubation/memwal/account', () => ({
    generateDelegateKey: vi.fn(),
}))
vi.mock('../utils/api', () => ({ apiGet: mocks.apiGet }))
vi.mock('../utils/suiClientCompat', () => ({
    fetchAccountIdForOwner: vi.fn().mockResolvedValue('0xaccount'),
    fetchObjectJson: vi.fn().mockResolvedValue(null),
    publicKeyToHex: (v: unknown) => String(v),
}))
vi.mock('../utils/analytics', () => ({
    trackEvent: vi.fn(),
    getAnalyticsErrorType: () => 'unknown',
}))
vi.mock('../components/SecurityDeleteSection', () => ({ default: () => null }))

import Dashboard from './Dashboard'
import { fetchObjectJson } from '../utils/suiClientCompat'

/** One relayer page of `count` namespaces, named `<prefix>-<n>`. */
function page(prefix: string, count: number, hasMore: boolean, nextCursor: string | null = null) {
    return {
        namespaces: Array.from({ length: count }, (_, i) => ({
            name: `${prefix}-${i}`,
            memory_count: i + 1,
        })),
        has_more: hasMore,
        next_cursor: nextCursor,
    }
}

/** The namespaces list request URL for the Nth apiGet call, or '' if absent. */
function nsCalls(): string[] {
    return mocks.apiGet.mock.calls
        .map((c) => String(c[2] ?? ''))
        .filter((p) => p.includes('/namespaces'))
}

function renderDashboard() {
    return render(
        <MemoryRouter>
            <Dashboard />
        </MemoryRouter>,
    )
}

/** Render the dashboard and return its Namespaces card once mounted. */
async function namespacesCard(): Promise<HTMLElement> {
    const { container } = renderDashboard()
    let card: Element | null = null
    await waitFor(() => {
        card = container.querySelector('#namespaces')
        expect(card).not.toBeNull()
    })
    if (!(card instanceof HTMLElement)) throw new Error('namespaces card not found')
    return card
}

beforeEach(() => {
    mocks.apiGet.mockReset()
    // Non-namespace calls (delegate keys etc.) get a harmless empty payload.
    mocks.apiGet.mockResolvedValue({})
    vi.mocked(fetchObjectJson).mockReset()
    vi.mocked(fetchObjectJson).mockResolvedValue(null)
    // Incident status uses global fetch. A clean miss keeps the banner off
    // and never dials the relayer.
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
            account_id: null,
            affected: false,
            quarantined: false,
            active: false,
        }),
    }))
})

describe('Dashboard namespaces pagination', () => {
    it('advances on has_more and sends the relayer cursor as updated_after', async () => {
        const user = userEvent.setup()
        mocks.apiGet.mockImplementation(async (_k: string, _u: string, path: string) => {
            if (!path.includes('/namespaces')) return {}
            if (path.includes('updated_after=cursor-1')) return page('b', 2, false)
            return page('a', 15, true, 'cursor-1')
        })

        const card = await namespacesCard()
        await within(card).findByText('a-0')
        expect(nsCalls()[0]).toContain('limit=15')
        expect(nsCalls()[0]).not.toContain('updated_after')

        await user.click(within(card).getByRole('button', { name: 'Next page' }))

        await within(card).findByText('b-0')
        expect(within(card).queryByText('a-0')).toBeNull()
        expect(nsCalls().at(-1)).toContain('updated_after=cursor-1')
        // Last page: no further cursor to follow.
        expect(within(card).getByRole('button', { name: 'Next page' })).toBeDisabled()
        expect(within(card).getByRole('button', { name: 'Previous page' })).toBeEnabled()
    })

    it('stops at has_more=false even when the page came back full', async () => {
        // The relayer clamps `limit`, so a full page is not proof of more data.
        mocks.apiGet.mockImplementation(async (_k: string, _u: string, path: string) =>
            path.includes('/namespaces') ? page('a', 15, false, 'ignored-cursor') : {},
        )

        const card = await namespacesCard()
        await within(card).findByText('a-0')
        // Nothing to paginate: the footer stays out of the way entirely.
        expect(within(card).queryByRole('button', { name: 'Next page' })).toBeNull()
        expect(within(card).getByText('120 memories across 15 namespaces')).toBeTruthy()
    })

    it('goes back to the previous page without refetching from scratch', async () => {
        const user = userEvent.setup()
        mocks.apiGet.mockImplementation(async (_k: string, _u: string, path: string) => {
            if (!path.includes('/namespaces')) return {}
            if (path.includes('updated_after=cursor-1')) return page('b', 3, false)
            return page('a', 15, true, 'cursor-1')
        })

        const card = await namespacesCard()
        await within(card).findByText('a-0')
        await user.click(within(card).getByRole('button', { name: 'Next page' }))
        await within(card).findByText('b-0')
        expect(within(card).getByText('16–18')).toBeTruthy()

        await user.click(within(card).getByRole('button', { name: 'Previous page' }))

        await within(card).findByText('a-0')
        expect(within(card).getByText('1–15')).toBeTruthy()
        expect(nsCalls().at(-1)).not.toContain('updated_after')
        expect(within(card).getByRole('button', { name: 'Previous page' })).toBeDisabled()
    })

    it('Refresh restarts the walk with no leftover cursor', async () => {
        const user = userEvent.setup()
        mocks.apiGet.mockImplementation(async (_k: string, _u: string, path: string) => {
            if (!path.includes('/namespaces')) return {}
            if (path.includes('updated_after=cursor-1')) return page('b', 3, false)
            return page('a', 15, true, 'cursor-1')
        })

        const card = await namespacesCard()
        await within(card).findByText('a-0')
        await user.click(within(card).getByRole('button', { name: 'Next page' }))
        await within(card).findByText('b-0')

        await user.click(within(card).getByRole('button', { name: /Refresh/ }))

        await within(card).findByText('a-0')
        expect(nsCalls().at(-1)).not.toContain('updated_after')
        expect(within(card).getByRole('button', { name: 'Previous page' })).toBeDisabled()
    })

    it('changing page size restarts from the first page', async () => {
        const user = userEvent.setup()
        mocks.apiGet.mockImplementation(async (_k: string, _u: string, path: string) => {
            if (!path.includes('/namespaces')) return {}
            if (path.includes('updated_after=cursor-1')) return page('b', 3, false)
            return page('a', 15, true, 'cursor-1')
        })

        const card = await namespacesCard()
        await within(card).findByText('a-0')
        await user.click(within(card).getByRole('button', { name: 'Next page' }))
        await within(card).findByText('b-0')

        await user.selectOptions(within(card).getByLabelText('Items per page'), '50')

        await waitFor(() => expect(nsCalls().at(-1)).toContain('limit=50'))
        expect(nsCalls().at(-1)).not.toContain('updated_after')
    })

    it('keeps the page-size selector reachable after the list fits one page', async () => {
        const user = userEvent.setup()
        // 25 namespaces: two pages at 15, a single page at 50.
        mocks.apiGet.mockImplementation(async (_k: string, _u: string, path: string) => {
            if (!path.includes('/namespaces')) return {}
            if (path.includes('limit=50')) return page('all', 25, false)
            if (path.includes('updated_after=cursor-1')) return page('b', 5, false)
            return page('a', 15, true, 'cursor-1')
        })

        const card = await namespacesCard()
        await within(card).findByText('a-0')
        await user.selectOptions(within(card).getByLabelText('Items per page'), '50')

        await within(card).findByText('all-24')
        // Everything now fits, but the selector must survive so 15 is reachable.
        const select = within(card).getByLabelText('Items per page')
        expect(select).toBeTruthy()
        await user.selectOptions(select, '15')
        await waitFor(() => expect(nsCalls().at(-1)).toContain('limit=15'))
    })

    it('keeps the empty state', async () => {
        mocks.apiGet.mockImplementation(async (_k: string, _u: string, path: string) =>
            path.includes('/namespaces') ? page('a', 0, false) : {},
        )
        const card = await namespacesCard()
        await within(card).findByText(/No indexed namespaces yet/)
        expect(within(card).queryByRole('button', { name: 'Next page' })).toBeNull()
    })

    it('steps back when a continuation page comes back empty', async () => {
        const user = userEvent.setup()
        // The namespaces behind cursor-1 raced past the relayer snapshot, so the
        // second page is empty. That is not a fresh empty account.
        mocks.apiGet.mockImplementation(async (_k: string, _u: string, path: string) => {
            if (!path.includes('/namespaces')) return {}
            if (path.includes('updated_after=cursor-1')) return page('b', 0, false)
            return page('a', 15, true, 'cursor-1')
        })

        const card = await namespacesCard()
        await within(card).findByText('a-0')
        await user.click(within(card).getByRole('button', { name: 'Next page' }))

        // Back on page 1, with its rows — not the first-load empty copy.
        await waitFor(() => expect(nsCalls().at(-1)).not.toContain('updated_after'))
        await within(card).findByText('a-0')
        expect(within(card).queryByText(/No indexed namespaces yet/)).toBeNull()
        expect(within(card).getByRole('button', { name: 'Previous page' })).toBeDisabled()
    })

    it('keeps the error state and hides the pagination footer', async () => {
        mocks.apiGet.mockImplementation(async (_k: string, _u: string, path: string) => {
            if (path.includes('/namespaces')) throw new Error('relayer down')
            return {}
        })
        const card = await namespacesCard()
        // Shown twice by design: card subtitle and the inline error paragraph.
        await within(card).findAllByText('Could not load namespace counts from the relayer.')
        expect(within(card).queryByRole('button', { name: 'Next page' })).toBeNull()
    })

    it('links each namespace row into the playground', async () => {
        mocks.apiGet.mockImplementation(async (_k: string, _u: string, path: string) =>
            path.includes('/namespaces')
                ? { namespaces: [{ name: 'my ns', memory_count: 4 }], has_more: false, next_cursor: null }
                : {},
        )
        const card = await namespacesCard()
        const link = await within(card).findByTitle('Open this namespace in the playground')
        expect(link.getAttribute('href')).toBe('/playground?namespace=my%20ns')
    })
})

describe('Dashboard incident banner', () => {
    it('asks a locked account with no highlighted keys to reactivate', async () => {
        mocks.apiGet.mockResolvedValue({})
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
            ok: true,
            json: async () => ({
                account_id: '0xaccount',
                affected: true,
                quarantined: true,
                active: false,
                affected_public_keys: [],
            }),
        }))
        const { findByRole, queryByRole } = renderDashboard()
        const button = await findByRole('button', { name: 'Reactivate the account' })
        expect(button.closest('p')?.textContent).toContain('Your account is ready to restore.')
        expect(queryByRole('button', { name: 'Remove highlighted keys' })).toBeNull()
        expect(document.body.textContent).not.toContain('delete the highlighted delegate keys below')
    })

    it('highlights affected keys and removes them in one confirmation', async () => {
        const user = userEvent.setup()
        const leaked = 'ab'.repeat(32)
        const other = 'cd'.repeat(32)
        vi.mocked(fetchObjectJson).mockResolvedValue({
            delegate_keys: [
                { public_key: `0x${leaked.toUpperCase()}`, label: 'Leaked', created_at: '1' },
                { public_key: other, label: 'Safe', created_at: '2' },
            ],
        })
        mocks.apiGet.mockResolvedValue({})
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
            ok: true,
            json: async () => ({
                account_id: '0xaccount',
                affected: true,
                quarantined: true,
                active: false,
                affected_public_keys: [leaked],
            }),
        }))
        const { findByRole, findByText, queryByText } = renderDashboard()
        const leakedRow = (await findByText('Leaked')).closest('tr')
        expect(queryByText('Safe')).toBeNull()
        expect(leakedRow?.classList.contains('dashboard-key-row--affected')).toBe(true)
        expect(leakedRow?.querySelector('input[type="checkbox"]')).toBeChecked()
        expect(leakedRow?.textContent).not.toContain('Affected')
        const banner = await findByRole('button', { name: 'Remove highlighted keys' })
        expect(banner.closest('p')).toBeNull()
        const status = document.querySelector('.dash-alert--info p')
        expect(status?.textContent).toBe('Your account has been temporarily locked following a security disclosure by Railway, our third-party hosting provider. To restore your account, delete the highlighted delegate keys below.')
        expect(document.body.textContent).not.toContain('request an unblock')
        await user.click(banner)
        expect(await findByRole('heading', { name: 'Remove delegate key?' })).toBeTruthy()
    })

    it('keeps the locked banner until the highlighted keys are gone', async () => {
        const leaked = 'ab'.repeat(32)
        vi.mocked(fetchObjectJson).mockResolvedValue({
            delegate_keys: [{ public_key: leaked, label: 'Leaked', created_at: '1' }],
        })
        mocks.apiGet.mockResolvedValue({})
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
            ok: true,
            json: async () => ({
                account_id: '0xaccount',
                affected: true,
                quarantined: false,
                active: false,
                affected_public_keys: [leaked],
            }),
        }))
        const { findByRole, findByText, queryByRole } = renderDashboard()
        expect((await findByText('Leaked')).closest('tr')?.querySelector('input[type="checkbox"]')).toBeChecked()
        expect(await findByRole('button', { name: 'Remove highlighted keys' })).toBeTruthy()
        expect(queryByRole('button', { name: 'Reactivate the account' })).toBeNull()
        expect(document.body.textContent).toContain('delete the highlighted delegate keys below')
    })

    it('asks a cleared account to reactivate', async () => {
        mocks.apiGet.mockResolvedValue({})
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
            ok: true,
            json: async () => ({
                account_id: '0xaccount',
                affected: true,
                quarantined: false,
                active: false,
            }),
        }))
        const { findByRole } = renderDashboard()
        const button = await findByRole('button', { name: 'Reactivate the account' })
        expect(button.closest('p')?.textContent).toContain('Your account is ready to restore.')
    })
})
