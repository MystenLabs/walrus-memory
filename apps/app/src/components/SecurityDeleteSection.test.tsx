import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
    address: '0x1',
    securityDeleteEnabled: true,
    phase: { kind: 'idle' } as { kind: string; batch?: number; totalBatches?: number | null; deletedBlobs?: number },
    lastDigest: null as string | null,
    scope: 'current' as string | undefined,
    onStateChanged: () => {},
    listBlobs: vi.fn(),
    deleteSelection: vi.fn(),
    deleteAll: vi.fn(),
    cancelActive: vi.fn(),
    fetchPreview: vi.fn(),
    clearSealSession: vi.fn(),
}))
vi.mock('../config', () => ({ config: {
    get securityDeleteEnabled() { return mocks.securityDeleteEnabled },
    memwalServerUrl: 'http://test',
    suiNetwork: 'testnet',
    memwalPackageId: '0x1',
    sealKeyServers: [],
    migrationCompletedDate: 'July 30, 2026',
    securityGuideUrl: 'https://docs.wal.app/walrus-memory/guides/delete-old-memories',
} }))
vi.mock('@mysten/dapp-kit', () => ({
    useCurrentAccount: () => ({ address: mocks.address }),
    useSuiClient: () => ({}),
    useSignPersonalMessage: () => ({ mutateAsync: vi.fn() }),
}))
vi.mock('../hooks/useSecurityDeletion', () => ({ useSecurityDeletion: ({ onStateChanged, scope }: { onStateChanged: () => void; scope?: string }) => {
    mocks.onStateChanged = onStateChanged
    mocks.scope = scope
    return {
        phase: mocks.phase,
        lastDigest: mocks.lastDigest,
        deleteSelection: mocks.deleteSelection,
        deleteAll: mocks.deleteAll,
        cancelActive: mocks.cancelActive,
    }
} }))
vi.mock('../utils/securityDeleteAuth', () => ({
    withAuth: (_address: string, _sign: unknown, call: (token: string) => unknown) => call('token'),
    clearToken: vi.fn(),
}))
vi.mock('../utils/securityDeleteApi', async importOriginal => ({
    ...await importOriginal<typeof import('../utils/securityDeleteApi')>(), listBlobs: mocks.listBlobs,
}))
vi.mock('../utils/blobPreview', () => ({ clearSealSession: mocks.clearSealSession, fetchAndDecryptBlob: mocks.fetchPreview }))

import SecurityDeleteSection from './SecurityDeleteSection'

const counts = { total: 2, deletable: 2, deleting: 0, deleted: 0, deletedExternal: 0, notOwner: 0, expired: 0 }
const risk = [
    { blobId: 'blob-one-long-identifier', objectId: '0x111', createdAt: '2026-01-01T00:00:00Z', state: 'deletable' },
    { blobId: 'blob-two-long-identifier', objectId: null, createdAt: '2026-01-02T00:00:00Z', state: 'deletable' },
]

const loadMemories = (user: ReturnType<typeof userEvent.setup>) => user.click(screen.getByRole('button', { name: 'Load my memories' }))

beforeEach(() => {
    vi.clearAllMocks()
    mocks.address = '0x1'
    mocks.securityDeleteEnabled = true
    mocks.phase = { kind: 'idle' }
    mocks.lastDigest = null
    mocks.scope = 'current'
    mocks.listBlobs.mockResolvedValue({ items: risk, counts, limits: { deleteBatchMax: 900 }, nextCursor: null })
    mocks.fetchPreview.mockResolvedValue('owner secret')
})

it('defaults to post-migration scope and switches cleanly to pre-migration notice', async () => {
    const user = userEvent.setup()
    render(<SecurityDeleteSection accountObjectId="0xlegacy" currentAccountObjectId="0xcurrent" />)
    expect(screen.getByText('Delete memories')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Post-migration' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByRole('button', { name: 'Pre-migration' })).toHaveAttribute('aria-pressed', 'false')
    expect(screen.getByText(/Select one or more post-migration memory blobs below/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'here' })).toHaveAttribute(
        'href',
        'https://docs.wal.app/walrus-memory/guides/delete-old-memories',
    )

    await user.click(screen.getByRole('button', { name: 'Pre-migration' }))
    expect(screen.getByRole('button', { name: 'Pre-migration' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByText(/On July 30, 2026 all existing memories were migrated/)).toBeInTheDocument()
})

it('uses scope-matched account objects for preview and shows single-blob confirmation copy', async () => {
    const user = userEvent.setup()
    render(<SecurityDeleteSection accountObjectId={null} currentAccountObjectId="0xcurrent99" />)
    await loadMemories(user)
    expect(mocks.listBlobs).toHaveBeenCalledWith('token', expect.objectContaining({ scope: 'current', state: 'deletable' }))

    await user.click(await screen.findByRole('button', { name: 'Preview blob-one-long-identifier' }))
    expect(mocks.fetchPreview).toHaveBeenCalledWith(expect.objectContaining({
        blobId: 'blob-one-long-identifier',
        accountObjectId: '0xcurrent99',
        scope: 'current',
    }))
    await user.click(screen.getByRole('button', { name: 'Close' }))

    await user.click(screen.getByLabelText('Select blob-one-long-identifier'))
    await user.click(screen.getByRole('button', { name: /Delete selected/ }))
    expect(screen.getByText(/blob-one-long-identifier/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Delete forever' }))
    expect(mocks.deleteSelection).toHaveBeenCalledWith(['blob-one-long-identifier'], 900)
})

it('waits for explicit user intent before loading affected rows', async () => {
    const user = userEvent.setup()
    render(<SecurityDeleteSection accountObjectId="0x99" />)
    expect(mocks.listBlobs).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: 'Load my memories' }).closest('.card-header')).toBeNull()
    await loadMemories(user)
    expect(await screen.findByRole('tab', { name: 'Stored' })).toBeInTheDocument()
    await waitFor(() => expect(mocks.listBlobs).toHaveBeenCalledWith('token', expect.objectContaining({ state: 'deletable' })))
    expect(screen.getByTitle('blob-one-long-identifier')).toBeInTheDocument()
    expect(screen.getByText('resolving…')).toBeInTheDocument()
})

it('loads the read-only progress state set after tab switch', async () => {
    const user = userEvent.setup()
    render(<SecurityDeleteSection accountObjectId="0x99" />)
    await loadMemories(user)
    await screen.findByTitle('blob-one-long-identifier')
    const storedTab = screen.getByRole('tab', { name: 'Stored' })
    const deletedTab = screen.getByRole('tab', { name: 'Deleted' })
    expect(storedTab).toHaveAttribute('aria-selected', 'true')
    expect(deletedTab).toHaveAttribute('aria-selected', 'false')
    await user.click(deletedTab)
    expect(storedTab).toHaveAttribute('aria-selected', 'false')
    expect(deletedTab).toHaveAttribute('aria-selected', 'true')
    await waitFor(() => expect(mocks.listBlobs).toHaveBeenLastCalledWith('token', expect.objectContaining({ state: 'deleting,deleted,deleted_external,not_owner,expired' })))
})

it('keeps the activated list when the account object resolves for the same owner', async () => {
    const user = userEvent.setup()
    const { rerender } = render(<SecurityDeleteSection accountObjectId={null} />)
    await loadMemories(user)
    await screen.findByTitle('blob-one-long-identifier')

    rerender(<SecurityDeleteSection accountObjectId="0x99" />)
    expect(screen.getByRole('button', { name: 'Refresh' })).toBeInTheDocument()
    expect(screen.getByTitle('blob-one-long-identifier')).toBeInTheDocument()
    expect(mocks.listBlobs).toHaveBeenCalledOnce()
})

it('ignores a stale deletion refresh after the wallet changes', async () => {
    const user = userEvent.setup()
    const { rerender } = render(<SecurityDeleteSection accountObjectId="0x99" />)
    await loadMemories(user)
    await screen.findByTitle('blob-one-long-identifier')
    const staleRefresh = mocks.onStateChanged

    mocks.address = '0x2'
    rerender(<SecurityDeleteSection accountObjectId="0x99" />)
    staleRefresh()

    expect(screen.getByRole('button', { name: 'Load my memories' })).toBeInTheDocument()
    expect(mocks.listBlobs).toHaveBeenCalledOnce()
})

it('ignores a stale deletion refresh after switching tabs', async () => {
    const user = userEvent.setup()
    render(<SecurityDeleteSection accountObjectId="0x99" />)
    await loadMemories(user)
    await screen.findByTitle('blob-one-long-identifier')
    const staleRefresh = mocks.onStateChanged

    await user.click(screen.getByRole('tab', { name: 'Deleted' }))
    await waitFor(() => expect(mocks.listBlobs).toHaveBeenCalledTimes(2))
    staleRefresh()

    expect(mocks.listBlobs).toHaveBeenCalledTimes(2)
    expect(screen.getByRole('tab', { name: 'Deleted' })).toHaveAttribute('aria-selected', 'true')
})

it('prevents tab changes while deletion is in progress', async () => {
    const user = userEvent.setup()
    const { rerender } = render(<SecurityDeleteSection accountObjectId="0x99" />)
    await loadMemories(user)
    await screen.findByTitle('blob-one-long-identifier')

    mocks.phase = { kind: 'executing', batch: 1 }
    rerender(<SecurityDeleteSection accountObjectId="0x99" />)

    expect(screen.getByRole('tab', { name: 'Stored' })).toBeDisabled()
    expect(screen.getByRole('tab', { name: 'Deleted' })).toBeDisabled()
})

it('passes the exact selected IDs after confirmation', async () => {
    const user = userEvent.setup()
    render(<SecurityDeleteSection accountObjectId="0x99" />)
    await loadMemories(user)
    await user.click(await screen.findByLabelText('Select blob-one-long-identifier'))
    await user.click(screen.getByRole('button', { name: /Delete selected/ }))
    await user.click(screen.getByRole('button', { name: 'Delete forever' }))
    expect(mocks.deleteSelection).toHaveBeenCalledWith(['blob-one-long-identifier'], 900)
})

it('is hidden when the security-delete selector is off', () => {
    mocks.securityDeleteEnabled = false
    const { container } = render(<SecurityDeleteSection accountObjectId="0x99" />)
    expect(container).toBeEmptyDOMElement()
})

it('ignores an old owner response that resolves after address switch', async () => {
    let releaseOld!: (value: unknown) => void
    const oldResponse = new Promise(resolve => { releaseOld = resolve })
    const nextResponse = {
        items: [{ blobId: 'new-owner-blob', objectId: '0x2', createdAt: '2026-01-03T00:00:00Z', state: 'deletable' }],
        counts: { ...counts, total: 1, deletable: 1 }, limits: { deleteBatchMax: 900 }, nextCursor: null,
    }
    mocks.listBlobs.mockReset().mockReturnValueOnce(oldResponse).mockResolvedValue(nextResponse)
    const user = userEvent.setup()
    const { rerender } = render(<SecurityDeleteSection accountObjectId="0x99" />)
    await loadMemories(user)
    await waitFor(() => expect(mocks.listBlobs).toHaveBeenCalledTimes(1))
    mocks.address = '0x2'
    rerender(<SecurityDeleteSection accountObjectId="0x99" />)
    expect(screen.getByRole('button', { name: 'Load my memories' })).toBeInTheDocument()
    expect(mocks.listBlobs).toHaveBeenCalledTimes(1)
    await loadMemories(user)
    expect(await screen.findByTitle('new-owner-blob')).toBeInTheDocument()
    releaseOld({ items: risk, counts, limits: { deleteBatchMax: 900 }, nextCursor: null })
    await Promise.resolve()
    expect(screen.queryByTitle('blob-one-long-identifier')).not.toBeInTheDocument()
})

it('clears rows and ignores an old tab response during a tab switch', async () => {
    let releaseRisk!: (value: unknown) => void
    const oldRiskResponse = new Promise(resolve => { releaseRisk = resolve })
    const progressResponse = {
        items: [{ blobId: 'progress-blob', objectId: '0x2', createdAt: '2026-01-03T00:00:00Z', state: 'deleting' }],
        counts: { ...counts, deletable: 0, deleting: 1 }, limits: { deleteBatchMax: 900 }, nextCursor: null,
    }
    mocks.listBlobs.mockReset().mockReturnValueOnce(oldRiskResponse).mockResolvedValue(progressResponse)
    const user = userEvent.setup()
    render(<SecurityDeleteSection accountObjectId="0x99" />)
    await loadMemories(user)
    await waitFor(() => expect(mocks.listBlobs).toHaveBeenCalledOnce())
    await user.click(screen.getByRole('tab', { name: 'Deleted' }))
    expect(await screen.findByTitle('progress-blob')).toBeInTheDocument()
    releaseRisk({ items: risk, counts, limits: { deleteBatchMax: 900 }, nextCursor: null })
    await Promise.resolve()
    expect(screen.queryByTitle('blob-one-long-identifier')).not.toBeInTheDocument()
})

it('removes owner-scoped plaintext immediately on an address switch', async () => {
    const user = userEvent.setup()
    const { rerender } = render(<SecurityDeleteSection accountObjectId="0x99" />)
    await loadMemories(user)
    await user.click(await screen.findByRole('button', { name: 'Preview blob-one-long-identifier' }))
    expect(await screen.findByText('owner secret')).toBeInTheDocument()
    expect(mocks.fetchPreview).toHaveBeenCalledOnce()

    mocks.address = '0x2'
    rerender(<SecurityDeleteSection accountObjectId="0x99" />)
    expect(screen.queryByText('owner secret')).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: 'Memory preview' })).not.toBeInTheDocument()
    expect(mocks.fetchPreview).toHaveBeenCalledOnce()
})

it('wires an explicit cancel action while awaiting the wallet signature', async () => {
    mocks.phase = { kind: 'signing', batch: 1, totalBatches: 1 }
    const user = userEvent.setup()
    render(<SecurityDeleteSection accountObjectId="0x99" />)
    await user.click(screen.getByRole('button', { name: 'Cancel batch' }))
    expect(mocks.cancelActive).toHaveBeenCalledOnce()
})

it('shows a dismissible toast when a deletion operation completes', async () => {
    mocks.phase = { kind: 'done', deletedBlobs: 42 } as typeof mocks.phase
    const user = userEvent.setup()
    render(<SecurityDeleteSection accountObjectId="0x99" />)
    expect(await screen.findByText('Deleted 42 memories.')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Dismiss notification' }))
    expect(screen.queryByText('Deleted 42 memories.')).not.toBeInTheDocument()
})

it('keeps the loaded rows when the active tab is clicked again', async () => {
    const user = userEvent.setup()
    render(<SecurityDeleteSection accountObjectId="0x99" />)
    await loadMemories(user)
    await screen.findByTitle('blob-one-long-identifier')
    await user.click(screen.getByRole('tab', { name: 'Stored' }))
    expect(screen.getByTitle('blob-one-long-identifier')).toBeInTheDocument()
    expect(screen.getByTitle('blob-two-long-identifier')).toBeInTheDocument()
})

it('jumps to an unvisited page by walking cursors and shows pager state', async () => {
    const user = userEvent.setup()
    const bigCounts = { ...counts, total: 250, deletable: 250 }
    const pageRows = (prefix: string) => [{ blobId: `${prefix}-row`, objectId: '0x1', createdAt: '2026-01-01T00:00:00Z', state: 'deletable' }]
    mocks.listBlobs.mockImplementation(async (_token: string, opts: { cursor?: string }) => {
        if (!opts.cursor) return { items: pageRows('p1'), counts: bigCounts, limits: { deleteBatchMax: 900 }, nextCursor: 'c1' }
        if (opts.cursor === 'c1') return { items: pageRows('p2'), counts: bigCounts, limits: { deleteBatchMax: 900 }, nextCursor: 'c2' }
        return { items: pageRows('p3'), counts: bigCounts, limits: { deleteBatchMax: 900 }, nextCursor: null }
    })
    render(<SecurityDeleteSection accountObjectId="0x99" />)
    await loadMemories(user)
    await screen.findByTitle('p1-row')
    expect(screen.getByText('Page 1 of 3')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '‹ Prev' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '3' }))
    await screen.findByTitle('p3-row')
    expect(screen.queryByTitle('p1-row')).not.toBeInTheDocument()
    expect(screen.getByText('Page 3 of 3')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Next ›' })).toBeDisabled()
    // Walk: page 1 was cached at mount, so the jump fetched pages 2 and 3.
    expect(mocks.listBlobs).toHaveBeenCalledTimes(3)
    expect(mocks.listBlobs).toHaveBeenLastCalledWith('token', expect.objectContaining({ cursor: 'c2' }))
})

it('steps back when the current page empties out after deletions', async () => {
    const user = userEvent.setup()
    const bigCounts = { ...counts, total: 150, deletable: 150 }
    let page2Deleted = false
    mocks.listBlobs.mockImplementation(async (_token: string, opts: { cursor?: string }) => {
        const liveCounts = page2Deleted ? { ...bigCounts, deletable: 100 } : bigCounts
        if (!opts.cursor) return { items: [{ blobId: 'p1-row', objectId: '0x1', createdAt: '2026-01-01T00:00:00Z', state: 'deletable' }], counts: liveCounts, limits: { deleteBatchMax: 900 }, nextCursor: page2Deleted ? null : 'c1' }
        if (page2Deleted) return { items: [], counts: liveCounts, limits: { deleteBatchMax: 900 }, nextCursor: null }
        return { items: [{ blobId: 'p2-row', objectId: '0x2', createdAt: '2026-01-02T00:00:00Z', state: 'deletable' }], counts: liveCounts, limits: { deleteBatchMax: 900 }, nextCursor: null }
    })
    render(<SecurityDeleteSection accountObjectId="0x99" />)
    await loadMemories(user)
    await screen.findByTitle('p1-row')
    await user.click(screen.getByRole('button', { name: 'Next ›' }))
    await screen.findByTitle('p2-row')
    page2Deleted = true
    await user.click(screen.getByRole('button', { name: /Refresh/ }))
    await screen.findByTitle('p1-row')
    // Back on page 1 with a single remaining page — the pager hides entirely.
    expect(screen.queryByText(/Page \d+ of \d+/)).not.toBeInTheDocument()
})

it('select page toggles to unselect page and clears the page selection', async () => {
    const user = userEvent.setup()
    render(<SecurityDeleteSection accountObjectId="0x99" />)
    await loadMemories(user)
    await screen.findByTitle('blob-one-long-identifier')
    await user.click(screen.getByRole('button', { name: 'Select page' }))
    expect(screen.getByLabelText('Select blob-one-long-identifier')).toBeChecked()
    expect(screen.getByLabelText('Select blob-two-long-identifier')).toBeChecked()
    await user.click(screen.getByRole('button', { name: 'Unselect page' }))
    expect(screen.getByLabelText('Select blob-one-long-identifier')).not.toBeChecked()
    expect(screen.getByLabelText('Select blob-two-long-identifier')).not.toBeChecked()
})
