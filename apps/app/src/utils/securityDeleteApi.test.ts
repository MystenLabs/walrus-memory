import { afterEach, describe, expect, it, vi } from 'vitest'
import {
    cancelDeletion, getDeletionStatus, listBlobs, prepareDeletion, requestChallenge,
    SdApiError, submitDeletion, verifyChallenge,
} from './securityDeleteApi'

const counts = { total: 0, deletable: 0, deleting: 0, deleted: 0, deletedExternal: 0, notOwner: 0, expired: 0 }
const ok = (body: unknown) => Promise.resolve(new Response(JSON.stringify(body), { status: 200 }))

afterEach(() => vi.unstubAllGlobals())

describe('securityDeleteApi', () => {
    it('sends bearer and encoded list query', async () => {
        const fetchMock = vi.fn().mockReturnValue(ok({ items: [], counts, limits: { deleteBatchMax: 900 }, nextCursor: null }))
        vi.stubGlobal('fetch', fetchMock)
        await listBlobs('tok', { state: 'deletable', cursor: 'a+b/c=', limit: 50, scope: 'current' })
        const [url, init] = fetchMock.mock.calls[0]
        expect(String(url)).toContain('state=deletable&cursor=a%2Bb%2Fc%3D&limit=50&scope=current')
        expect(new Headers(init.headers).get('Authorization')).toBe('Bearer tok')
    })

    it('forwards scope in prepareDeletion when specified', async () => {
        const fetchMock = vi.fn().mockReturnValue(ok({ batchId: null, txBytes: null, included: 0, excluded: [], expiresAt: null }))
        vi.stubGlobal('fetch', fetchMock)
        await prepareDeletion('tok', { mode: 'selection', blobIds: ['blob-1'], scope: 'current' })
        expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ mode: 'selection', blobIds: ['blob-1'], scope: 'current' })
    })

    it('propagates the opaque challengeId exactly', async () => {
        const fetchMock = vi.fn()
            .mockReturnValueOnce(ok({ challengeId: 'opaque/+==', challenge: 'sign me', expiresInSecs: 300 }))
            .mockReturnValueOnce(ok({ token: 'token', expiresInSecs: 2700 }))
        vi.stubGlobal('fetch', fetchMock)
        const challenge = await requestChallenge('0x1')
        await verifyChallenge(challenge.challengeId, '0x1', 'sig')
        expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual({ challengeId: 'opaque/+==', address: '0x1', signature: 'sig' })
    })

    it('uses the exact prepare, submit, status, and cancel wire contracts', async () => {
        const fetchMock = vi.fn()
            .mockReturnValueOnce(ok({ batchId: null, txBytes: null, included: 0, excluded: [], expiresAt: null }))
            .mockReturnValueOnce(ok({ state: 'completed', deleted: 2, digest: 'digest' }))
            .mockReturnValueOnce(ok({ state: 'executing', blobCount: 2, digest: 'digest', resolvedAt: null }))
            .mockReturnValueOnce(ok({ state: 'rolled_back', blobCount: 2, digest: 'digest', resolvedAt: '2026-07-11T08:15:30Z' }))
        vi.stubGlobal('fetch', fetchMock)

        await prepareDeletion('tok', { mode: 'selection', blobIds: ['b1', 'b2'] })
        await submitDeletion('tok', 'batch/id', 'base64-signature')
        await getDeletionStatus('tok', 'batch/id')
        await cancelDeletion('tok', 'batch/id')

        expect(fetchMock.mock.calls.map(call => [String(call[0]), call[1].method ?? 'GET'])).toEqual([
            [expect.stringContaining('/api/security-deletions'), 'POST'],
            [expect.stringContaining('/api/security-deletions/batch%2Fid/submit'), 'POST'],
            [expect.stringContaining('/api/security-deletions/batch%2Fid'), 'GET'],
            [expect.stringContaining('/api/security-deletions/batch%2Fid'), 'DELETE'],
        ])
        expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ mode: 'selection', blobIds: ['b1', 'b2'] })
        expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual({ signature: 'base64-signature' })
    })

    it('turns a valid error envelope into SdApiError', async () => {
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { code: 'BATCH_CONFLICT', action: 'REFETCH', retriable: false, message: 'conflict', details: { conflictingBlobIds: ['b1'] } } }), { status: 409 })))
        const error = await prepareDeletion('tok', { mode: 'selection', blobIds: ['b1'] }).catch(value => value) as SdApiError
        expect(error).toMatchObject({ code: 'BATCH_CONFLICT', action: 'REFETCH', status: 409 })
    })

    it('accepts the sponsor-funding retry contract', async () => {
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { code: 'SPONSOR_FUNDS_UNAVAILABLE', action: 'RETRY_AFTER', retriable: true, message: 'temporarily unavailable', details: { retryAfterSecs: 30 } } }), { status: 503 })))
        const error = await prepareDeletion('tok', { mode: 'all' }).catch(value => value) as SdApiError
        expect(error).toMatchObject({ code: 'SPONSOR_FUNDS_UNAVAILABLE', action: 'RETRY_AFTER', retriable: true, status: 503 })
    })

    it('sanitizes unknown error actions', async () => {
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { code: 'X', action: 'DO_BAD_THING' } }), { status: 500 })))
        await expect(listBlobs('tok', {})).rejects.toMatchObject({ code: 'UNKNOWN', action: 'NONE', status: 500 })
    })

    it.each([
        ['unknown code', 409, { code: 'FUTURE_CODE', action: 'REFETCH', retriable: false }],
        ['wrong status', 500, { code: 'BATCH_CONFLICT', action: 'REFETCH', retriable: false }],
        ['wrong action', 409, { code: 'BATCH_CONFLICT', action: 'RE_PREPARE', retriable: false }],
        ['wrong retriable flag', 409, { code: 'BATCH_CONFLICT', action: 'REFETCH', retriable: true }],
    ])('sanitizes an error envelope with %s', async (_label, status, contract) => {
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
            error: { ...contract, message: 'bad contract', details: {} },
        }), { status })))
        await expect(listBlobs('tok', {})).rejects.toMatchObject({ code: 'UNKNOWN', action: 'NONE', status })
    })

    it('rejects malformed successful payloads', async () => {
        vi.stubGlobal('fetch', vi.fn().mockReturnValue(ok({ items: [], counts, nextCursor: null })))
        await expect(listBlobs('tok', {})).rejects.toMatchObject({ code: 'UNKNOWN', action: 'NONE' })
    })

    it('rejects negative counts, non-integer limits, and limits above the empirical maximum', async () => {
        vi.stubGlobal('fetch', vi.fn()
            .mockReturnValueOnce(ok({ items: [], counts: { ...counts, total: -1 }, limits: { deleteBatchMax: 900 }, nextCursor: null }))
            .mockReturnValueOnce(ok({ items: [], counts, limits: { deleteBatchMax: 1.5 }, nextCursor: null }))
            .mockReturnValueOnce(ok({ items: [], counts, limits: { deleteBatchMax: 901 }, nextCursor: null })))
        await expect(listBlobs('tok', {})).rejects.toMatchObject({ code: 'UNKNOWN' })
        await expect(listBlobs('tok', {})).rejects.toMatchObject({ code: 'UNKNOWN' })
        await expect(listBlobs('tok', {})).rejects.toMatchObject({ code: 'UNKNOWN' })
    })

    it('rejects list pages above 200 even when the remaining shape is valid', async () => {
        const item = { blobId: 'b1', objectId: null, createdAt: '2026-07-11T08:15:30Z', state: 'deletable' }
        vi.stubGlobal('fetch', vi.fn().mockReturnValue(ok({
            items: Array.from({ length: 201 }, () => item), counts,
            limits: { deleteBatchMax: 900 }, nextCursor: null,
        })))
        await expect(listBlobs('tok', {})).rejects.toMatchObject({ code: 'UNKNOWN', action: 'NONE' })
    })

    it('accepts backend standard-base64 tx bytes and the exact nothing shape', async () => {
        vi.stubGlobal('fetch', vi.fn()
            .mockReturnValueOnce(ok({ batchId: 'batch', txBytes: 'AA==', included: 1, excluded: [], expiresAt: 'epoch:931' }))
            .mockReturnValueOnce(ok({ batchId: null, txBytes: null, included: 0, excluded: [], expiresAt: null })))
        await expect(prepareDeletion('tok', { mode: 'all' })).resolves.toMatchObject({ batchId: 'batch', txBytes: 'AA==' })
        await expect(prepareDeletion('tok', { mode: 'all' })).resolves.toMatchObject({ batchId: null, txBytes: null })
    })

    it.each([
        { batchId: 'batch', txBytes: 'not-base64', included: 1, excluded: [], expiresAt: 'epoch:931' },
        { batchId: 'batch', txBytes: '', included: 1, excluded: [], expiresAt: 'epoch:931' },
        { batchId: 'batch', txBytes: 'AA==', included: 1, excluded: [], expiresAt: null },
        { batchId: null, txBytes: null, included: 0, excluded: [], expiresAt: 'epoch:931' },
        { batchId: null, txBytes: null, included: 0, excluded: [{ blobId: '', reason: 'expired' }], expiresAt: null },
    ])('rejects a malformed prepare response %#', async response => {
        vi.stubGlobal('fetch', vi.fn().mockReturnValue(ok(response)))
        await expect(prepareDeletion('tok', { mode: 'all' })).rejects.toMatchObject({ code: 'UNKNOWN', action: 'NONE' })
    })

    it('maps fetch rejection to bounded recovery action', async () => {
        vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('offline')))
        await expect(listBlobs('tok', {})).rejects.toMatchObject({ code: 'NETWORK_ERROR', action: 'RETRY_AFTER', status: 0 })
    })
})
