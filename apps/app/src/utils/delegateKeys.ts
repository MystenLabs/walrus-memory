import { fetchObjectJson } from './suiClientCompat'

export const MAX_DELEGATE_KEYS = 20

export const MAX_DELEGATE_KEYS_CONNECT_MESSAGE =
    'This Walrus Memory account already has the maximum number of delegate keys (20). Go to /dashboard and revoke an unused key, then try again.'

type AccountDelegateKeysShape = { delegate_keys?: { public_key?: unknown }[] }

/**
 * Read the on-chain delegate key count for a MemWalAccount. Returns `null`
 * when the object cannot be fetched so transient RPC errors fall through to
 * transaction sponsorship instead of blocking sign-in with a false limit message.
 */
export async function fetchDelegateKeyCount(
    suiClient: unknown,
    accountId: string,
): Promise<number | null> {
    try {
        const json = (await fetchObjectJson(suiClient, accountId)) as AccountDelegateKeysShape | null
        if (!json || !Array.isArray(json.delegate_keys)) return null
        return json.delegate_keys.length
    } catch {
        return null
    }
}

/**
 * Matches the 20-delegate-key cap across preflight errors, classified
 * `/sponsor` 409 responses (`max_delegate_keys`), and direct MoveAbort
 * messages (`abort code: 2` in `add_delegate_key`).
 */
export function isMaxDelegateKeysError(err: unknown): boolean {
    if (
        err &&
        typeof err === 'object' &&
        'code' in err &&
        (err as { code?: unknown }).code === 'max_delegate_keys'
    ) {
        return true
    }
    const message = err instanceof Error ? err.message : String(err)
    if (message.includes('maximum number of delegate keys (20)')) return true
    if (message.toLowerCase().includes(`already has ${MAX_DELEGATE_KEYS} delegate keys`)) return true
    return message.includes('abort code: 2') && message.includes('add_delegate_key')
}
