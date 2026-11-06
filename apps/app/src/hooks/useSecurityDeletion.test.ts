import { act, renderHook, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const wallet = vi.hoisted(() => ({ address: '0x1', signTransaction: vi.fn(), signPersonal: vi.fn() }))
const api = vi.hoisted(() => ({ prepareDeletion: vi.fn(), submitDeletion: vi.fn(), cancelDeletion: vi.fn(), getDeletionStatus: vi.fn() }))
vi.mock('@mysten/dapp-kit', () => ({
    useCurrentAccount: () => ({ address: wallet.address }),
    useSignPersonalMessage: () => ({ mutateAsync: wallet.signPersonal }),
    useSignTransaction: () => ({ mutateAsync: wallet.signTransaction }),
}))
vi.mock('@mysten/sui/transactions', () => ({ Transaction: { from: vi.fn(value => ({ value })) } }))
vi.mock('../utils/securityDeleteAuth', () => ({ withAuth: (_address: string, _sign: unknown, call: (token: string) => unknown) => call('tok') }))
vi.mock('../utils/analytics', () => ({ trackEvent: vi.fn(), getAnalyticsErrorType: () => 'test' }))
vi.mock('../utils/securityDeleteApi', async importOriginal => ({
    ...await importOriginal<typeof import('../utils/securityDeleteApi')>(),
    ...api,
}))

import { SdApiError } from '../utils/securityDeleteApi'
import { useSecurityDeletion } from './useSecurityDeletion'

const batch = { batchId: 'batch-1', txBytes: 'AA==', included: 2, excluded: [], expiresAt: null }
const nothing = { batchId: null, txBytes: null, included: 0, excluded: [], expiresAt: null }

beforeEach(() => {
    vi.clearAllMocks()
    wallet.address = '0x1'
    wallet.signPersonal.mockResolvedValue({ signature: 'personal' })
    wallet.signTransaction.mockResolvedValue({ signature: 'tx-signature' })
    api.cancelDeletion.mockResolvedValue({ state: 'rolled_back', blobCount: 2, digest: null, resolvedAt: 'now' })
})

describe('useSecurityDeletion', () => {
    it('recovers a dropped submit response through status without resigning', async () => {
        api.prepareDeletion.mockResolvedValueOnce(batch).mockResolvedValueOnce(nothing)
        api.submitDeletion.mockRejectedValueOnce(new SdApiError('NETWORK_ERROR', 'RETRY_AFTER', true, 0, 'offline', { retryAfterSecs: 0 }))
        api.getDeletionStatus.mockResolvedValue({ state: 'completed', blobCount: 2, digest: 'digest', resolvedAt: 'now' })
        const changed = vi.fn()
        const { result } = renderHook(() => useSecurityDeletion({ onStateChanged: changed }))
        await act(() => result.current.deleteAll(2, 900))
        expect(result.current.phase).toEqual({ kind: 'done', deletedBlobs: 2 })
        expect(wallet.signTransaction).toHaveBeenCalledTimes(1)
        expect(api.submitDeletion).toHaveBeenCalledTimes(1)
        expect(api.getDeletionStatus).toHaveBeenCalledTimes(1)
    })

    it('refreshes Progress instead of re-preparing when submit status is unknown', async () => {
        api.prepareDeletion.mockResolvedValue(batch)
        api.submitDeletion.mockRejectedValue(new SdApiError('NETWORK_ERROR', 'RETRY_AFTER', true, 0, 'offline', { retryAfterSecs: 0 }))
        api.getDeletionStatus.mockRejectedValue(new SdApiError('NETWORK_ERROR', 'RETRY_AFTER', true, 0, 'offline'))
        const changed = vi.fn()
        const { result } = renderHook(() => useSecurityDeletion({ onStateChanged: changed }))
        await act(() => result.current.deleteSelection(['b1'], 900))
        expect(result.current.phase).toMatchObject({ kind: 'error', code: 'BATCH_STATUS_UNAVAILABLE' })
        expect(wallet.signTransaction).toHaveBeenCalledOnce()
        expect(api.prepareDeletion).toHaveBeenCalledOnce()
        expect(changed).toHaveBeenCalledOnce()
    })

    it('best-effort cancels an awaiting batch when wallet signing fails', async () => {
        api.prepareDeletion.mockResolvedValue(batch)
        wallet.signTransaction.mockRejectedValue(new Error('User rejected'))
        const { result } = renderHook(() => useSecurityDeletion({ onStateChanged: vi.fn() }))
        await act(() => result.current.deleteSelection(['b1'], 900))
        await waitFor(() => expect(result.current.phase.kind).toBe('error'))
        expect(api.cancelDeletion).toHaveBeenCalledWith('tok', 'batch-1')
        expect((result.current.phase as { message: string }).message).toContain('User rejected')
    })

    it('does not mask wallet rejection when cancellation also fails', async () => {
        api.prepareDeletion.mockResolvedValue(batch)
        wallet.signTransaction.mockRejectedValue(new Error('User rejected original request'))
        api.cancelDeletion.mockRejectedValue(new Error('Cancel endpoint unavailable'))
        const { result } = renderHook(() => useSecurityDeletion({ onStateChanged: vi.fn() }))
        await act(() => result.current.deleteSelection(['b1'], 900))
        expect(result.current.phase).toMatchObject({ kind: 'error', message: 'User rejected original request' })
    })

    it('bounds re-prepare cycles at three', async () => {
        api.prepareDeletion.mockResolvedValue(batch)
        api.submitDeletion.mockRejectedValue(new SdApiError('TX_EXECUTION_FAILED', 'RE_PREPARE', true, 502, 'retry'))
        const { result } = renderHook(() => useSecurityDeletion({ onStateChanged: vi.fn() }))
        await act(() => result.current.deleteSelection(['b1'], 900))
        expect(api.prepareDeletion).toHaveBeenCalledTimes(3)
        expect(wallet.signTransaction).toHaveBeenCalledTimes(3)
        expect(result.current.phase.kind).toBe('error')
    })

    it('does not re-prepare a failed batch when the sponsor cannot fund gas', async () => {
        api.prepareDeletion.mockResolvedValue(batch)
        api.submitDeletion.mockRejectedValue(new SdApiError(
            'SPONSOR_FUNDS_UNAVAILABLE',
            'RETRY_AFTER',
            true,
            503,
            'Deletion sponsorship is temporarily unavailable',
            { retryAfterSecs: 0 },
        ))
        api.getDeletionStatus.mockResolvedValue({ state: 'failed', blobCount: 2, digest: null, resolvedAt: 'now' })
        const { result } = renderHook(() => useSecurityDeletion({ onStateChanged: vi.fn() }))
        await act(() => result.current.deleteSelection(['b1'], 900))
        expect(api.prepareDeletion).toHaveBeenCalledOnce()
        expect(wallet.signTransaction).toHaveBeenCalledOnce()
        expect(api.submitDeletion).toHaveBeenCalledOnce()
        expect(result.current.phase).toMatchObject({ kind: 'error', code: 'SPONSOR_FUNDS_UNAVAILABLE' })
    })

    it('never creates selection chunks larger than the tested 900-blob ceiling', async () => {
        api.prepareDeletion.mockResolvedValue(nothing)
        const ids = Array.from({ length: 901 }, (_, index) => `b${index}`)
        const { result } = renderHook(() => useSecurityDeletion({ onStateChanged: vi.fn() }))
        await act(() => result.current.deleteSelection(ids, 10_000))
        expect(api.prepareDeletion).toHaveBeenNthCalledWith(1, 'tok', { mode: 'selection', blobIds: ids.slice(0, 900) })
        expect(api.prepareDeletion).toHaveBeenNthCalledWith(2, 'tok', { mode: 'selection', blobIds: ids.slice(900) })
    })

    it('cancels and never submits an old awaiting batch after address switch', async () => {
        api.prepareDeletion.mockResolvedValue(batch)
        let release!: (value: { signature: string }) => void
        wallet.signTransaction.mockReturnValue(new Promise(resolve => { release = resolve }))
        const { result, rerender } = renderHook(() => useSecurityDeletion({ onStateChanged: vi.fn() }))
        let operation!: Promise<void>
        act(() => { operation = result.current.deleteSelection(['b1'], 900) })
        await waitFor(() => expect(wallet.signTransaction).toHaveBeenCalledOnce())
        act(() => { wallet.address = '0x2'; rerender() })
        await act(async () => { release({ signature: 'old-signature' }); await operation })
        expect(api.cancelDeletion).toHaveBeenCalledWith('tok', 'batch-1')
        expect(api.submitDeletion).not.toHaveBeenCalled()
        expect(result.current.phase.kind).toBe('idle')
    })

    it('forwards post-migration scope and records lastDigest on single-blob deletion', async () => {
        api.prepareDeletion.mockResolvedValueOnce({ ...batch, included: 1 })
        api.submitDeletion.mockResolvedValueOnce({ state: 'completed', deleted: 1, digest: '5xDigest123' })
        const changed = vi.fn()
        const { result } = renderHook(() => useSecurityDeletion({ onStateChanged: changed, scope: 'current' }))
        await act(() => result.current.deleteSelection(['post-blob-1'], 900))
        expect(api.prepareDeletion).toHaveBeenCalledWith('tok', {
            mode: 'selection',
            blobIds: ['post-blob-1'],
            scope: 'current',
        })
        expect(result.current.phase).toEqual({ kind: 'done', deletedBlobs: 1 })
        expect(result.current.lastDigest).toBe('5xDigest123')
    })
})
