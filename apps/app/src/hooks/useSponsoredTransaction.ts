/**
 * useSponsoredTransaction — Enoki-sponsored transaction hook
 *
 * Drop-in replacement for useSignAndExecuteTransaction from @mysten/dapp-kit.
 * ALL transactions are gaslessly sponsored via Enoki (through the sidecar
 * server) for BOTH zkLogin and regular-wallet users — nobody is ever asked to
 * pay their own gas.
 *
 * There is intentionally NO self-pay fallback. The old fallback re-signed the
 * transaction with the user's own wallet, which for a gasless zkLogin wallet
 * (0 SUI) always aborted in the Sui SDK gas resolver with the misleading
 * "No valid gas coins found for the transaction." — masking the real cause
 * (network blip, relayer 429/5xx, sponsor dry-run rejection). Instead we retry
 * the sponsor flow on transient failures and, if it ultimately fails, surface
 * the real reason.
 *
 * Flow (per attempt):
 *   1. Build Transaction as TransactionKind bytes (no gas data)
 *   2. POST /sponsor → { bytes, digest }
 *   3. Sign sponsored bytes with the user's wallet
 *   4. POST /sponsor/execute → { digest }
 */

import { useCurrentAccount, useSignPersonalMessage, useSignTransaction, useSuiClient } from '@mysten/dapp-kit'
import { createSponsorAuthorization } from '@mysten-incubation/memwal'
import { Transaction } from '@mysten/sui/transactions'
import { config } from '../config'
import { MAX_DELEGATE_KEYS_CONNECT_MESSAGE } from '../utils/delegateKeys'

const MAX_ATTEMPTS = 3
const BASE_DELAY_MS = 500

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms))

/**
 * Transient statuses worth retrying:
 *   429 rate limit, 500 proxy/transport error (sidecar unreachable),
 *   503 overloaded, 504 gateway timeout, 408 request timeout.
 * NOT retried: 502 — the sidecar/Enoki dry-run rejected the transaction
 * (e.g. a duplicate delegate key or an otherwise invalid tx). Retrying that
 * just fails again, so we surface it immediately.
 */
function isRetryableStatus(status: number): boolean {
    return status === 408 || status === 429 || status === 500 || status === 503 || status === 504
}

/** fetch() rejects with a TypeError on network failure / offline / CORS. */
function isNetworkError(err: unknown): boolean {
    return err instanceof TypeError
}

/**
 * The relayer's error envelope. `code` is present only when the relayer masked
 * an upstream failure; a rejection the relayer decided itself arrives as a
 * plain `error` message naming the actual reason.
 */
type SponsorErrorBody = { error?: string; code?: string; traceId?: string }

function parseErrorBody(body: string): SponsorErrorBody {
    try {
        const parsed: unknown = JSON.parse(body)
        return typeof parsed === 'object' && parsed !== null ? (parsed as SponsorErrorBody) : {}
    } catch {
        return {}
    }
}

/** Exported for tests. */
export class SponsorHttpError extends Error {
    readonly stage: 'sponsor' | 'execute'
    readonly status: number
    readonly body: string
    /** Stable machine-readable code, when the relayer masked an upstream error. */
    readonly code?: string
    /** The relayer's own message. Safe to show — it never carries upstream text. */
    readonly detail?: string
    /** Ties this failure to one relayer log line. */
    readonly traceId?: string
    constructor(stage: 'sponsor' | 'execute', status: number, body: string) {
        super(`Sponsor ${stage} failed (${status})`)
        this.name = 'SponsorHttpError'
        this.stage = stage
        this.status = status
        this.body = body
        const parsed = parseErrorBody(body)
        this.code = parsed.code
        this.detail = parsed.error
        this.traceId = parsed.traceId
    }
}

/** Carry the traceId into the UI so a user report points at the log line. */
function withTrace(message: string, traceId?: string): string {
    return traceId ? `${message} (traceId: ${traceId})` : message
}

/** Exported for tests. */
export function sponsorFailureMessage(err: unknown): string {
    if (isNetworkError(err)) {
        return 'Network error reaching the sponsor service — please check your connection and try again.'
    }
    if (err instanceof SponsorHttpError) {
        if (err.status === 429) return 'Too many requests — please wait a moment and try again.'
        if (err.code === 'account_already_active') {
            return withTrace('This account is already active, so it cannot be reactivated.', err.traceId)
        }
        if (err.code === 'account_quarantined') {
            return withTrace('This account is still locked, so it cannot be reactivated yet.', err.traceId)
        }
        if (err.code === 'max_delegate_keys') {
            return withTrace(MAX_DELEGATE_KEYS_CONNECT_MESSAGE, err.traceId)
        }
        if (err.code === 'sponsor_misconfigured') {
            return withTrace('The sponsor service is misconfigured, so this transaction could not be sponsored. Please report this.', err.traceId)
        }
        if (err.status === 502) return withTrace('The transaction was rejected by the sponsor (it may be invalid or already applied). Please refresh and try again.', err.traceId)
        if (err.status >= 500 || err.status === 503) return 'Sponsor service is temporarily unavailable — please try again in a moment.'
        if (err.code === 'sponsor_rejected') {
            return withTrace('The sponsor service rejected this transaction. Please report this.', err.traceId)
        }
        // No code means the relayer rejected the request itself, and its
        // message names the reason — an unsupported transaction shape, a
        // malformed field. Showing it is the whole point: the generic fallback
        // below is what made an un-sponsorable transaction indistinguishable
        // from a transient sponsor failure.
        if (err.detail) return err.detail
        return 'Sponsor request was rejected. Please try again.'
    }
    return err instanceof Error ? err.message : 'Transaction sponsorship failed. Please try again.'
}

function packageIdFromConfig(body: unknown): string {
    if (typeof body !== 'object' || body === null || !('packageId' in body)) return ''
    const id = (body as { packageId: unknown }).packageId
    return typeof id === 'string' ? id.trim() : ''
}

/** Null when the baked-in package id matches GET /config. */
export function relayerPackageMismatch(localPackageId: string, body: unknown): string | null {
    const remote = packageIdFromConfig(body)
    if (!remote) return 'Relayer /config did not include a packageId.'
    if (localPackageId.trim().toLowerCase() !== remote.toLowerCase()) {
        return `This dashboard is built for package ${localPackageId}, but the relayer is on ${remote}. Set VITE_MEMWAL_PACKAGE_ID to the relayer package id and rebuild.`
    }
    return null
}

/** Throws before a transaction kind is built when the relayer package id differs. */
export async function assertRelayerPackageId(serverUrl: string, localPackageId: string): Promise<void> {
    const base = serverUrl.replace(/\/$/, '')
    let response: Response
    try {
        response = await fetch(`${base}/config`)
    } catch {
        throw new Error('Could not reach the relayer /config before building a transaction.')
    }
    if (!response.ok) {
        throw new Error(`Relayer /config returned ${response.status} before a transaction was built.`)
    }
    let body: unknown
    try {
        body = await response.json()
    } catch {
        throw new Error('Relayer /config did not return JSON before a transaction was built.')
    }
    const mismatch = relayerPackageMismatch(localPackageId, body)
    if (mismatch) throw new Error(mismatch)
}

export function useSponsoredTransaction() {
    const currentAccount = useCurrentAccount()
    const suiClient = useSuiClient()
    const { mutateAsync: signTransaction } = useSignTransaction()
    const { mutateAsync: signPersonalMessage } = useSignPersonalMessage()

    const mutateAsync = async ({ transaction }: { transaction: Transaction }): Promise<{ digest: string }> => {
        const sender = currentAccount?.address
        if (!sender) throw new Error('No wallet connected')

        // The relayer only sponsors its own package. A stale baked-in id
        // otherwise fails later as "Transaction kind is not permitted".
        await assertRelayerPackageId(config.memwalServerUrl, config.memwalPackageId)

        // TransactionKind bytes never change across retries — build once.
        const kindBytes = await transaction.build({
            client: suiClient,
            onlyTransactionKind: true,
        })
        const kindBase64 = uint8ArrayToBase64(kindBytes)

        let lastError: unknown
        for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                const authorization = await createSponsorAuthorization(
                    sender,
                    kindBytes,
                    (message) => signPersonalMessage({ message }),
                )
                // 1. Sponsor via server (proxied to sidecar → Enoki)
                const sponsorRes = await fetch(`${config.memwalServerUrl}/sponsor`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        transactionBlockKindBytes: kindBase64,
                        sender,
                        ...authorization,
                    }),
                })
                if (!sponsorRes.ok) {
                    throw new SponsorHttpError('sponsor', sponsorRes.status, await sponsorRes.text())
                }
                const sponsored = await sponsorRes.json()
                // sponsored = { bytes: base64, digest: string }

                // 2. Sign sponsored bytes with user wallet
                //    (silent for zkLogin; wallet prompt for extension wallets)
                const sponsoredTx = Transaction.from(sponsored.bytes)
                const { signature } = await signTransaction({ transaction: sponsoredTx })

                // 3. Execute via server (proxied to sidecar → Enoki)
                const execRes = await fetch(`${config.memwalServerUrl}/sponsor/execute`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        digest: sponsored.digest,
                        sender,
                        signature,
                    }),
                })
                if (!execRes.ok) {
                    throw new SponsorHttpError('execute', execRes.status, await execRes.text())
                }

                const result = await execRes.json()
                console.log(`[sponsored-tx] success, digest=${result.digest}`)
                return { digest: result.digest }
            } catch (err) {
                lastError = err
                const retryable = err instanceof SponsorHttpError
                    ? isRetryableStatus(err.status)
                    : isNetworkError(err)
                if (!retryable || attempt === MAX_ATTEMPTS) break
                console.warn(`[sponsored-tx] attempt ${attempt}/${MAX_ATTEMPTS} failed, retrying:`, err)
                await sleep(BASE_DELAY_MS * 2 ** (attempt - 1))
            }
        }

        // Sponsorship failed after retries. Do NOT self-pay — every user is
        // meant to be gaslessly sponsored — so surface the real cause instead
        // of masking it as "No valid gas coins".
        console.error('[sponsored-tx] sponsorship failed after retries:', lastError)
        throw new Error(sponsorFailureMessage(lastError))
    }

    return { mutateAsync }
}

// Helper: Uint8Array → base64
function uint8ArrayToBase64(bytes: Uint8Array): string {
    let binary = ''
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i])
    }
    return btoa(binary)
}
