import { config } from '../config'

export type SdAction = 'REAUTH' | 'REFETCH' | 'RE_PREPARE' | 'RETRY_AFTER' | 'NONE'
export type BlobState = 'deletable' | 'deleting' | 'deleted' | 'deleted_external' | 'not_owner' | 'expired'
export type BatchState = 'awaiting_signature' | 'executing' | 'completed' | 'failed' | 'rolled_back'
export type DeletionScope = 'legacy' | 'current'

export class SdApiError extends Error {
    code: string
    action: SdAction
    retriable: boolean
    status: number
    details: Record<string, unknown>
    constructor(
        code: string,
        action: SdAction,
        retriable: boolean,
        status: number,
        message: string,
        details: Record<string, unknown> = {},
    ) {
        super(message)
        this.name = 'SdApiError'
        this.code = code
        this.action = action
        this.retriable = retriable
        this.status = status
        this.details = details
    }
}

export interface BlobItem { blobId: string; objectId: string | null; createdAt: string; state: BlobState }
export interface BlobCounts { total: number; deletable: number; deleting: number; deleted: number; deletedExternal: number; notOwner: number; expired: number }
export interface ListResponse { items: BlobItem[]; counts: BlobCounts; limits: { deleteBatchMax: number }; nextCursor: string | null }
export interface PrepareResponse { batchId: string | null; txBytes: string | null; included: number; excluded: { blobId: string; reason: 'already_deleted' | 'expired' | 'not_owner' }[]; expiresAt: string | null }
export interface SubmitResponse { state: 'completed'; deleted: number; digest: string }
export interface BatchStatus { state: BatchState; blobCount: number; digest: string | null; resolvedAt: string | null }
export interface ChallengeResponse { challengeId: string; challenge: string; expiresInSecs: number }

const ACTIONS = new Set<SdAction>(['REAUTH', 'REFETCH', 'RE_PREPARE', 'RETRY_AFTER', 'NONE'])
const ERROR_CONTRACT: Record<string, { status: number; action: SdAction; retriable: boolean }> = {
    AUTH_CHALLENGE_EXPIRED: { status: 401, action: 'REAUTH', retriable: false },
    AUTH_INVALID_SIGNATURE: { status: 401, action: 'NONE', retriable: false },
    AUTH_TOKEN_EXPIRED: { status: 401, action: 'REAUTH', retriable: false },
    INVALID_REQUEST: { status: 400, action: 'NONE', retriable: false },
    ACTIVE_BATCH_LIMIT: { status: 409, action: 'REFETCH', retriable: false },
    BATCH_CONFLICT: { status: 409, action: 'REFETCH', retriable: false },
    BATCH_NOT_FOUND: { status: 404, action: 'REFETCH', retriable: false },
    BATCH_ALREADY_RESOLVED: { status: 409, action: 'REFETCH', retriable: false },
    BATCH_EXPIRED: { status: 410, action: 'RE_PREPARE', retriable: false },
    TX_EXECUTION_FAILED: { status: 502, action: 'RE_PREPARE', retriable: false },
    SPONSOR_FUNDS_UNAVAILABLE: { status: 503, action: 'RETRY_AFTER', retriable: true },
    INVALID_SIGNATURE: { status: 400, action: 'NONE', retriable: false },
    RATE_LIMITED: { status: 429, action: 'RETRY_AFTER', retriable: true },
    RPC_UNAVAILABLE: { status: 503, action: 'RETRY_AFTER', retriable: true },
    INTERNAL_ERROR: { status: 500, action: 'RETRY_AFTER', retriable: true },
    FEATURE_DISABLED: { status: 404, action: 'NONE', retriable: false },
}
const STATES = new Set<BlobState>(['deletable', 'deleting', 'deleted', 'deleted_external', 'not_owner', 'expired'])
const BATCH_STATES = new Set<BatchState>(['awaiting_signature', 'executing', 'completed', 'failed', 'rolled_back'])
const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)
const isString = (v: unknown): v is string => typeof v === 'string'
const isNullableString = (v: unknown): v is string | null => v === null || isString(v)
const isFiniteNumber = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v)
const isNonnegativeInt = (v: unknown): v is number => isFiniteNumber(v) && Number.isInteger(v) && v >= 0
const isPositiveInt = (v: unknown): v is number => isNonnegativeInt(v) && v > 0
const isStandardBase64 = (v: unknown): v is string => {
    if (!isString(v) || !v || v.length % 4 !== 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(v)) return false
    try { return atob(v).length > 0 } catch { return false }
}

function malformed(): never {
    throw new SdApiError('UNKNOWN', 'NONE', false, 0, 'The server returned an invalid response.')
}

async function sdFetch(path: string, init: RequestInit = {}, token?: string, timeoutMs = 15_000): Promise<unknown> {
    const controller = new AbortController()
    const timeout = window.setTimeout(() => controller.abort(), timeoutMs)
    try {
        const headers = new Headers(init.headers)
        headers.set('Accept', 'application/json')
        if (init.body) headers.set('Content-Type', 'application/json')
        if (token) headers.set('Authorization', `Bearer ${token}`)
        const response = await fetch(`${config.memwalServerUrl.replace(/\/$/, '')}${path}`, { ...init, headers, signal: controller.signal })
        let body: unknown
        try { body = await response.json() } catch { body = null }
        if (!response.ok) {
            const envelope = isRecord(body) && isRecord(body.error) ? body.error : null
            if (!envelope || !isString(envelope.code) || !isString(envelope.action) || !ACTIONS.has(envelope.action as SdAction) || typeof envelope.retriable !== 'boolean' || !isString(envelope.message) || !isRecord(envelope.details)) {
                throw new SdApiError('UNKNOWN', 'NONE', false, response.status, 'Request failed.')
            }
            const expected = ERROR_CONTRACT[envelope.code]
            if (!expected || expected.status !== response.status || expected.action !== envelope.action || expected.retriable !== envelope.retriable) {
                throw new SdApiError('UNKNOWN', 'NONE', false, response.status, 'Request failed.')
            }
            throw new SdApiError(
                envelope.code,
                envelope.action as SdAction,
                envelope.retriable,
                response.status,
                envelope.message,
                envelope.details,
            )
        }
        return body
    } catch (error) {
        if (error instanceof SdApiError) throw error
        throw new SdApiError('NETWORK_ERROR', 'RETRY_AFTER', true, 0, 'Unable to reach the deletion service.')
    } finally {
        window.clearTimeout(timeout)
    }
}

export async function requestChallenge(address: string): Promise<ChallengeResponse> {
    const v = await sdFetch('/api/security-delete-auth/challenge', { method: 'POST', body: JSON.stringify({ address }) })
    if (!isRecord(v) || !isString(v.challengeId) || !v.challengeId || !isString(v.challenge) || !v.challenge || !isPositiveInt(v.expiresInSecs)) malformed()
    return v as unknown as ChallengeResponse
}

export async function verifyChallenge(challengeId: string, address: string, signature: string): Promise<{ token: string; expiresInSecs: number }> {
    const v = await sdFetch('/api/security-delete-auth/verify', { method: 'POST', body: JSON.stringify({ challengeId, address, signature }) })
    if (!isRecord(v) || !isString(v.token) || !v.token || !isPositiveInt(v.expiresInSecs)) malformed()
    return v as unknown as { token: string; expiresInSecs: number }
}

export async function listBlobs(token: string, opts: { state?: string; cursor?: string; limit?: number; scope?: DeletionScope }): Promise<ListResponse> {
    const query = new URLSearchParams()
    if (opts.state) query.set('state', opts.state)
    if (opts.cursor) query.set('cursor', opts.cursor)
    if (opts.limit !== undefined) query.set('limit', String(opts.limit))
    if (opts.scope) query.set('scope', opts.scope)
    const v = await sdFetch(`/api/security-deletable-blobs${query.size ? `?${query}` : ''}`, {}, token)
    if (!isRecord(v) || !Array.isArray(v.items) || v.items.length > 200 || !isRecord(v.counts) || !isRecord(v.limits) || !isPositiveInt(v.limits.deleteBatchMax) || v.limits.deleteBatchMax > 900 || !isNullableString(v.nextCursor)) malformed()
    const counts = v.counts
    const countKeys = ['total', 'deletable', 'deleting', 'deleted', 'deletedExternal', 'notOwner', 'expired']
    if (!countKeys.every(k => isNonnegativeInt(counts[k]))) malformed()
    for (const item of v.items) {
        if (!isRecord(item) || !isString(item.blobId) || !item.blobId || !isNullableString(item.objectId) || !isString(item.createdAt) || !Number.isFinite(Date.parse(item.createdAt)) || !isString(item.state) || !STATES.has(item.state as BlobState)) malformed()
    }
    return v as unknown as ListResponse
}

export async function prepareDeletion(
    token: string,
    body: ({ mode: 'all' } | { mode: 'selection'; blobIds: string[] }) & { scope?: DeletionScope },
): Promise<PrepareResponse> {
    const v = await sdFetch('/api/security-deletions', { method: 'POST', body: JSON.stringify(body) }, token)
    if (!isRecord(v) || !isNullableString(v.batchId) || !isNullableString(v.txBytes) || !isNonnegativeInt(v.included) || !Array.isArray(v.excluded) || !isNullableString(v.expiresAt)) malformed()
    if ((v.batchId === null) !== (v.txBytes === null)) malformed()
    if (v.batchId === null
        ? v.included !== 0 || v.expiresAt !== null
        : v.included === 0 || !v.batchId || !isStandardBase64(v.txBytes) || !isString(v.expiresAt) || !v.expiresAt) malformed()
    for (const e of v.excluded) if (!isRecord(e) || !isString(e.blobId) || !e.blobId || !['already_deleted', 'expired', 'not_owner'].includes(String(e.reason))) malformed()
    return v as unknown as PrepareResponse
}

export async function submitDeletion(token: string, batchId: string, signature: string): Promise<SubmitResponse> {
    const v = await sdFetch(`/api/security-deletions/${encodeURIComponent(batchId)}/submit`, { method: 'POST', body: JSON.stringify({ signature }) }, token, 120_000)
    if (!isRecord(v) || v.state !== 'completed' || !isNonnegativeInt(v.deleted) || !isString(v.digest) || !v.digest) malformed()
    return v as unknown as SubmitResponse
}

function parseStatus(v: unknown): BatchStatus {
    if (!isRecord(v) || !isString(v.state) || !BATCH_STATES.has(v.state as BatchState) || !isNonnegativeInt(v.blobCount) || !isNullableString(v.digest) || !isNullableString(v.resolvedAt)) malformed()
    return v as unknown as BatchStatus
}

export async function cancelDeletion(token: string, batchId: string): Promise<BatchStatus> {
    return parseStatus(await sdFetch(`/api/security-deletions/${encodeURIComponent(batchId)}`, { method: 'DELETE' }, token))
}

export async function getDeletionStatus(token: string, batchId: string): Promise<BatchStatus> {
    return parseStatus(await sdFetch(`/api/security-deletions/${encodeURIComponent(batchId)}`, {}, token))
}
