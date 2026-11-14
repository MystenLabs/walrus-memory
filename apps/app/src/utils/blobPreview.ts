import { normalizeSuiAddress } from '@mysten/sui/utils'
import { Transaction } from '@mysten/sui/transactions'
import { EncryptedObject, SealClient, SessionKey } from '@mysten/seal'
import { config, type SealServerConfigEntry } from '../config'
import { getWalrusClient } from './walrusBlobs'
import type { SignPersonalMessage } from './securityDeleteAuth'
import type { DeletionScope } from './securityDeleteApi'

type SuiClientLike = Parameters<typeof getWalrusClient>[0]
const DEFAULT_SERVERS: Record<'testnet' | 'mainnet', SealServerConfigEntry[]> = {
    testnet: [
        { objectId: '0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75', weight: 1 },
        { objectId: '0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8', weight: 1 },
    ],
    mainnet: [
        { objectId: '0x145540d931f182fef76467dd8074c9839aea126852d90d18e1556fcbbd1208b6', weight: 1 },
        { objectId: '0xe0eb52eba9261b96e895bbb4deca10dcd64fbc626a1133017adcd5131353fd10', weight: 1 },
    ],
}

// Mysten's official testnet committee aggregator used by post-migration
// testnet relayers. Selected only when a ciphertext header references this
// committee object id and no explicit server override is configured.
const DEFAULT_COMMITTEE_SERVERS: Record<'testnet' | 'mainnet', SealServerConfigEntry[]> = {
    testnet: [
        {
            objectId: '0xb012378c9f3799fb5b1a7083da74a4069e3c3f1c93de0b27212a5799ce1e1e98',
            weight: 1,
            aggregatorUrl: 'https://seal-aggregator-testnet.mystenlabs.com',
        },
    ],
    mainnet: [],
}

const toConfiguredEntries = (
    jsonConfigs: readonly SealServerConfigEntry[] | undefined,
    csvIds: readonly string[],
): SealServerConfigEntry[] => {
    if (jsonConfigs && jsonConfigs.length > 0) {
        return jsonConfigs.map(entry => ({ ...entry, objectId: normalizeSuiAddress(entry.objectId) }))
    }
    return csvIds.map(objectId => ({ objectId: normalizeSuiAddress(objectId), weight: 1 }))
}

const resolvePreviewPolicy = (scope: DeletionScope = 'legacy') => (
    scope === 'current'
        ? {
            packageId: config.memwalPackageId,
            policyPackageId: config.memwalSealPolicyPackageId || config.memwalPackageId,
            registryId: config.memwalRegistryId,
            configuredServers: toConfiguredEntries(config.sealServerConfigs, config.sealKeyServers),
        }
        : {
            packageId: config.legacyMemwalPackageId,
            policyPackageId: config.legacyMemwalPackageId,
            registryId: undefined,
            configuredServers: toConfiguredEntries(config.legacySealServerConfigs, config.legacySealKeyServers),
        }
)

function selectServerConfigs(
    configured: readonly SealServerConfigEntry[],
    network: 'testnet' | 'mainnet',
    services: readonly (readonly [string, number])[] | undefined,
): SealServerConfigEntry[] {
    const fallback = configured.length > 0 ? [...configured] : DEFAULT_SERVERS[network]
    if (!Array.isArray(services) || services.length === 0) {
        return fallback
    }
    const counts = new Map<string, number>()
    for (const [serviceId] of services) {
        const normalized = normalizeSuiAddress(serviceId)
        counts.set(normalized, (counts.get(normalized) ?? 0) + 1)
    }
    const candidates = configured.length > 0
        ? configured
        : [...DEFAULT_SERVERS[network], ...DEFAULT_COMMITTEE_SERVERS[network]]
    const matched = candidates
        .map(entry => ({ ...entry, objectId: normalizeSuiAddress(entry.objectId) }))
        .filter(entry => counts.has(entry.objectId))
        .map(entry => ({ ...entry, weight: counts.get(entry.objectId)! }))
    return matched.length > 0 ? matched : fallback
}

const sessions = new Map<string, Promise<SessionKey>>()
const activeReads = new Set<AbortController>()
let previewGeneration = 0
const sessionKeyFor = (address: string, accountObjectId: string, packageId: string) =>
    `${normalizeSuiAddress(address)}:${normalizeSuiAddress(accountObjectId)}:${config.suiNetwork}:${packageId}`

async function createSession(
    suiClient: SuiClientLike,
    address: string,
    packageId: string,
    signPersonalMessage: SignPersonalMessage,
): Promise<SessionKey> {
    const normalizedAddress = normalizeSuiAddress(address)
    const signer = {
        toSuiAddress: () => normalizedAddress,
        getPublicKey: () => ({ toSuiAddress: () => normalizedAddress }),
        sign: async (data: Uint8Array) => signPersonalMessage(data),
        signPersonalMessage,
    }
    const session = await SessionKey.create({
        address: normalizedAddress,
        // Match the package under which the blob was Seal-encrypted:
        // pre-migration (`legacy`) uses legacyMemwalPackageId, while
        // post-migration (`current`) uses memwalPackageId.
        packageId,
        ttlMin: 5,
        // SessionKey only consumes getPublicKey/toSuiAddress and
        // signPersonalMessage for this certificate flow. A connected wallet
        // does not expose the keypair-only Signer methods.
        signer: signer as never,
        suiClient: suiClient as never,
    })
    return session
}

async function getSession(opts: {
    suiClient: SuiClientLike
    address: string
    accountObjectId: string
    packageId: string
    signPersonalMessage: SignPersonalMessage
}): Promise<SessionKey> {
    const key = sessionKeyFor(opts.address, opts.accountObjectId, opts.packageId)
    const existing = sessions.get(key)
    if (existing) {
        const session = await existing
        if (!session.isExpired()) return session
        sessions.delete(key)
    }
    const promise = createSession(opts.suiClient, opts.address, opts.packageId, opts.signPersonalMessage)
    sessions.set(key, promise)
    try { return await promise } catch (error) {
        if (sessions.get(key) === promise) sessions.delete(key)
        throw error
    }
}

/**
 * Fetches raw (still Seal-encrypted) blob bytes. Defaults to
 * `WalrusClient.readBlob()`'s direct storage-node quorum read — correct
 * against real testnet/mainnet, where nodes advertise public hostnames.
 *
 * `config.walrusAggregatorUrl` swaps in a plain aggregator GET instead: the
 * SDK's quorum read resolves node URLs from on-chain committee data and
 * always dials them over `https://` with no override hook, but a local
 * devstack cluster's on-chain-advertised node address is a Docker-internal
 * hostname the browser can't reach at all, and devstack's router-exposed
 * alias for the node only answers plain HTTP — so the direct-node path is
 * unreachable there regardless of which package ids it's pointed at. An
 * aggregator serves the same decoded blob bytes over a browser-reachable
 * URL, but — unlike `readBlob()`, which reconstructs the blob from
 * verified slivers and only trusts bytes whose recomputed id matches the
 * request — a plain aggregator GET has no such guarantee: it could return
 * bytes for a different blob (misconfiguration, cache poisoning, a
 * malicious aggregator) and those bytes would still be a validly formed,
 * validly authorized Seal object for the same user, so Seal's AEAD tag
 * would not catch the substitution. We close that gap the same way
 * `readBlob()` does: recompute the blob id from the fetched bytes locally
 * (`computeBlobMetadata`, the same WASM encoder `readBlob()` uses to
 * verify reconstructed slivers) and reject a mismatch before it ever
 * reaches Seal.
 */
async function fetchBlobBytes(opts: { suiClient: SuiClientLike; blobId: string; signal: AbortSignal }): Promise<Uint8Array> {
    const client = getWalrusClient(opts.suiClient)
    if (config.walrusAggregatorUrl) {
        const aggregatorUrl = config.walrusAggregatorUrl.replace(/\/$/, '')
        const response = await fetch(`${aggregatorUrl}/v1/blobs/${opts.blobId}`, { signal: opts.signal })
        if (!response.ok) throw new Error(`Walrus aggregator returned ${response.status} for blob ${opts.blobId}`)
        const bytes = new Uint8Array(await response.arrayBuffer())
        const { blobId: computedBlobId } = await client.computeBlobMetadata({ bytes })
        if (computedBlobId !== opts.blobId) {
            throw new Error(`Walrus aggregator returned bytes for a different blob (expected ${opts.blobId}, got ${computedBlobId})`)
        }
        return bytes
    }
    return client.readBlob({ blobId: opts.blobId, signal: opts.signal })
}

export async function fetchAndDecryptBlob(opts: {
    suiClient: SuiClientLike
    blobId: string
    address: string
    accountObjectId: string
    signPersonalMessage: SignPersonalMessage
    scope?: DeletionScope
}): Promise<string> {
    const { packageId, policyPackageId, registryId, configuredServers } = resolvePreviewPolicy(opts.scope)
    const generation = previewGeneration
    const controller = new AbortController()
    activeReads.add(controller)
    try {
        const [data, sessionKey] = await Promise.all([
            fetchBlobBytes({ suiClient: opts.suiClient, blobId: opts.blobId, signal: controller.signal }),
            getSession({ ...opts, packageId }),
        ])
        if (generation !== previewGeneration) throw new DOMException('Preview cancelled', 'AbortError')
        const parsed = EncryptedObject.parse(data)
        const idBytes = Array.from(Uint8Array.from(parsed.id.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16))))
        const transaction = new Transaction()
        const approveArgs = registryId
            ? [transaction.pure('vector<u8>', idBytes), transaction.object(registryId), transaction.object(opts.accountObjectId)]
            : [transaction.pure('vector<u8>', idBytes), transaction.object(opts.accountObjectId)]
        transaction.moveCall({
            target: `${policyPackageId}::account::seal_approve`,
            arguments: approveArgs,
        })
        const txBytes = await transaction.build({ client: opts.suiClient as never, onlyTransactionKind: true })
        const serverConfigs = selectServerConfigs(configuredServers, config.suiNetwork, parsed.services)
        const client = new SealClient({
            suiClient: opts.suiClient as never,
            serverConfigs,
            verifyKeyServers: true,
        })
        const plaintext = await client.decrypt({ data, sessionKey, txBytes })
        if (generation !== previewGeneration) throw new DOMException('Preview cancelled', 'AbortError')
        return new TextDecoder().decode(plaintext)
    } finally {
        activeReads.delete(controller)
    }
}

export function clearSealSession(): void {
    previewGeneration++
    sessions.clear()
    activeReads.forEach(controller => controller.abort())
    activeReads.clear()
}
