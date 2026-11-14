import { useCallback, useEffect, useRef, useState } from 'react'
import { useCurrentAccount, useSignPersonalMessage, useSignTransaction } from '@mysten/dapp-kit'
import { Transaction } from '@mysten/sui/transactions'
import { getAnalyticsErrorType, trackEvent } from '../utils/analytics'
import { withAuth, type SignPersonalMessage } from '../utils/securityDeleteAuth'
import {
    cancelDeletion,
    getDeletionStatus,
    prepareDeletion,
    SdApiError,
    submitDeletion,
    type DeletionScope,
    type PrepareResponse,
} from '../utils/securityDeleteApi'

export type DeletionPhase =
    | { kind: 'idle' }
    | { kind: 'preparing'; batch: number }
    | { kind: 'signing'; batch: number; totalBatches: number | null }
    | { kind: 'executing'; batch: number }
    | { kind: 'done'; deletedBlobs: number }
    | { kind: 'error'; message: string; code: string }

const sleep = (ms: number) => new Promise<void>(resolve => window.setTimeout(resolve, ms))
const retryDelayMs = (value: unknown, fallbackSeconds: number) => {
    const seconds = typeof value === 'number' && Number.isFinite(value) ? value : fallbackSeconds
    return Math.min(60, Math.max(0, seconds)) * 1000
}
const errorInfo = (error: unknown) => ({
    message: error instanceof Error ? error.message : 'Deletion failed.',
    code: error instanceof SdApiError ? error.code : 'UNKNOWN',
})
class DeletionCancelledError extends Error {}

export function useSecurityDeletion({ onStateChanged, scope }: { onStateChanged: () => void; scope?: DeletionScope }) {
    const account = useCurrentAccount()
    const { mutateAsync: signPersonal } = useSignPersonalMessage()
    const { mutateAsync: signTransaction } = useSignTransaction()
    const [phase, setPhase] = useState<DeletionPhase>({ kind: 'idle' })
    const [lastDigest, setLastDigest] = useState<string | null>(null)
    const running = useRef(false)
    const mounted = useRef(true)
    const generation = useRef(0)
    const activeBatch = useRef<string | null>(null)
    const cancellationGeneration = useRef(0)
    const address = account?.address ?? ''
    const personalSigner: SignPersonalMessage = useCallback(
        message => signPersonal({ message }),
        [signPersonal],
    )

    useEffect(() => {
        mounted.current = true
        return () => {
            mounted.current = false
        }
    }, [])
    useEffect(() => {
        generation.current++
        cancellationGeneration.current++
        running.current = false
        activeBatch.current = null
        setLastDigest(null)
        setPhase({ kind: 'idle' })
    }, [address])

    const safePhase = useCallback((next: DeletionPhase, run: number) => {
        if (mounted.current && generation.current === run) setPhase(next)
    }, [])

    const authed = useCallback(<T,>(call: (token: string) => Promise<T>) => {
        if (!address) return Promise.reject(new Error('Connect a wallet to delete memories.'))
        return withAuth(address, personalSigner, call)
    }, [address, personalSigner])

    const cancelActive = useCallback(async () => {
        cancellationGeneration.current++
        const batchId = activeBatch.current
        if (!batchId || !address) return
        const run = generation.current
        try {
            await authed(token => cancelDeletion(token, batchId))
            safePhase({ kind: 'idle' }, run)
        } catch (error) {
            safePhase({ kind: 'error', ...errorInfo(error) }, run)
        } finally {
            if (activeBatch.current === batchId) activeBatch.current = null
            onStateChanged()
        }
    }, [address, authed, onStateChanged, safePhase])

    const prepareWithRetry = useCallback(async (body: { mode: 'all' } | { mode: 'selection'; blobIds: string[] }) => {
        const requestBody = scope ? { ...body, scope } : body
        let delayed = false
        for (;;) {
            try { return await authed(token => prepareDeletion(token, requestBody)) } catch (error) {
                if (error instanceof SdApiError && error.action === 'RETRY_AFTER' && !delayed) {
                    delayed = true
                    await sleep(retryDelayMs(error.details.retryAfterSecs, 5))
                    continue
                }
                throw error
            }
        }
    }, [authed, scope])

    const submitWithRecovery = useCallback(async (prepared: PrepareResponse, signature: string) => {
        const batchId = prepared.batchId!
        try {
            return await authed(token => submitDeletion(token, batchId, signature))
        } catch (error) {
            if (!(error instanceof SdApiError) || error.action !== 'RETRY_AFTER') throw error
            const retryError = error
            await sleep(retryDelayMs(error.details.retryAfterSecs, 2))
            let status: Awaited<ReturnType<typeof getDeletionStatus>>
            try {
                status = await authed(token => getDeletionStatus(token, batchId))
            } catch (statusError) {
                // Submission may already have reached the server. Make the UI
                // refresh Progress instead of implying that preparing/signing
                // another transaction is safe while status is unknown.
                throw new SdApiError(
                    'BATCH_STATUS_UNAVAILABLE',
                    'REFETCH',
                    true,
                    statusError instanceof SdApiError ? statusError.status : 0,
                    'Submission status is temporarily unavailable. Check the Deleted tab.',
                )
            }
            if (status.state === 'completed') return { state: 'completed' as const, deleted: status.blobCount, digest: status.digest ?? '' }
            if (status.state === 'awaiting_signature') return authed(token => submitDeletion(token, batchId, signature))
            if (status.state === 'failed' || status.state === 'rolled_back') {
                // Sponsor underfunding cannot converge by rebuilding the same
                // transaction against an unchanged blob pool. Preserve the
                // operational error instead of entering the RE_PREPARE loop.
                if (retryError.code === 'SPONSOR_FUNDS_UNAVAILABLE') throw retryError
                throw new SdApiError('BATCH_RECOVERED_FAILED', 'RE_PREPARE', true, 409, 'The batch must be prepared again.')
            }
            throw new SdApiError('BATCH_EXECUTING', 'REFETCH', true, 409, 'Deletion is still executing. Check the Deleted tab.')
        }
    }, [authed])

    const runChunk = useCallback(async (
        body: { mode: 'all' } | { mode: 'selection'; blobIds: string[] },
        batchNumber: number,
        totalBatches: number | null,
        run: number,
    ): Promise<number | null> => {
        for (let cycle = 0; cycle < 3; cycle++) {
            safePhase({ kind: 'preparing', batch: batchNumber }, run)
            let prepared: PrepareResponse
            try { prepared = await prepareWithRetry(body) } catch (error) {
                if (error instanceof SdApiError && error.action === 'RE_PREPARE' && cycle < 2) continue
                throw error
            }
            if (!prepared.batchId) return null
            if (!prepared.txBytes) throw new SdApiError('UNKNOWN', 'NONE', false, 0, 'The server omitted transaction bytes.')
            activeBatch.current = prepared.batchId
            if (!mounted.current || generation.current !== run) {
                try { await authed(token => cancelDeletion(token, prepared.batchId!)) } catch { /* best effort */ }
                if (activeBatch.current === prepared.batchId) activeBatch.current = null
                throw new DeletionCancelledError('Deletion was cancelled before signing.')
            }
            const preparedCancellation = cancellationGeneration.current
            safePhase({ kind: 'signing', batch: batchNumber, totalBatches }, run)
            let signature: string
            try {
                signature = (await signTransaction({ transaction: Transaction.from(prepared.txBytes) })).signature
            } catch (error) {
                try { await cancelActive() } catch { /* preserve wallet error */ }
                throw error
            }
            if (!mounted.current || generation.current !== run || cancellationGeneration.current !== preparedCancellation) {
                try { await authed(token => cancelDeletion(token, prepared.batchId!)) } catch { /* best effort */ }
                if (activeBatch.current === prepared.batchId) activeBatch.current = null
                throw new DeletionCancelledError('Deletion was cancelled before submission.')
            }
            safePhase({ kind: 'executing', batch: batchNumber }, run)
            try {
                const result = await submitWithRecovery(prepared, signature)
                activeBatch.current = null
                if (result.digest && mounted.current && generation.current === run) {
                    setLastDigest(result.digest)
                }
                onStateChanged()
                return result.deleted
            } catch (error) {
                activeBatch.current = null
                if (error instanceof SdApiError && error.action === 'RE_PREPARE' && cycle < 2) continue
                throw error
            }
        }
        throw new SdApiError('RE_PREPARE_EXHAUSTED', 'NONE', false, 0, 'Deletion could not converge after three attempts.')
    }, [authed, cancelActive, onStateChanged, prepareWithRetry, safePhase, signTransaction, submitWithRecovery])

    const execute = useCallback(async (
        expectedCount: number,
        chunks: Array<{ mode: 'selection'; blobIds: string[] }> | null,
    ) => {
        if (running.current || !address) return
        running.current = true
        const run = generation.current
        if (mounted.current) setLastDigest(null)
        let deleted = 0
        trackEvent('memory_delete_start', { blobs: expectedCount })
        try {
            if (chunks) {
                for (let i = 0; i < chunks.length; i++) deleted += await runChunk(chunks[i], i + 1, chunks.length, run) ?? 0
            } else {
                for (let i = 1; ; i++) {
                    const result = await runChunk({ mode: 'all' }, i, null, run)
                    if (result === null) break
                    deleted += result
                }
            }
            safePhase({ kind: 'done', deletedBlobs: deleted }, run)
            onStateChanged()
            trackEvent('memory_delete_complete', { blobs: deleted })
        } catch (error) {
            if (error instanceof DeletionCancelledError) {
                safePhase({ kind: 'idle' }, run)
                return
            }
            const info = errorInfo(error)
            safePhase({ kind: 'error', ...info }, run)
            if (error instanceof SdApiError && error.action === 'REFETCH') onStateChanged()
            trackEvent('memory_delete_failed', { error_type: getAnalyticsErrorType(error) })
        } finally {
            if (generation.current === run) running.current = false
        }
    }, [address, onStateChanged, runChunk, safePhase])

    const deleteAll = useCallback((expectedCount: number, deleteBatchMax: number) => {
        void deleteBatchMax
        return execute(expectedCount, null)
    }, [execute])
    const deleteSelection = useCallback((blobIds: string[], deleteBatchMax: number) => {
        const unique = [...new Set(blobIds)]
        // The API client rejects advertised limits above the empirically tested
        // ceiling, but keep this destructive boundary safe if another caller
        // invokes the hook directly with an invalid value.
        const requestedSize = Number.isFinite(deleteBatchMax) ? Math.floor(deleteBatchMax) : 1
        const size = Math.min(900, Math.max(1, requestedSize))
        const chunks: Array<{ mode: 'selection'; blobIds: string[] }> = []
        for (let i = 0; i < unique.length; i += size) chunks.push({ mode: 'selection', blobIds: unique.slice(i, i + size) })
        return execute(unique.length, chunks)
    }, [execute])

    return { phase, lastDigest, deleteAll, deleteSelection, cancelActive }
}
