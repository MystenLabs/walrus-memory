import { beforeEach, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
    create: vi.fn(), readBlob: vi.fn(), decrypt: vi.fn(), build: vi.fn(),
    computeBlobMetadata: vi.fn(), moveCall: vi.fn(), sealClientOptions: vi.fn(),
    parseEncryptedObject: vi.fn<() => { id: string; services?: [string, number][] }>(() => ({ id: '00'.repeat(32) })),
}))
const config = vi.hoisted(() => ({
    suiNetwork: 'testnet' as const,
    memwalPackageId: '0x1',
    memwalSealPolicyPackageId: '0x1',
    memwalRegistryId: '0xreg',
    legacyMemwalPackageId: '0x1',
    sealServerConfigs: [] as { objectId: string; weight: number; aggregatorUrl?: string }[],
    legacySealServerConfigs: [] as { objectId: string; weight: number; aggregatorUrl?: string }[],
    sealKeyServers: [] as string[],
    legacySealKeyServers: [] as string[],
    walrusAggregatorUrl: '',
}))
vi.mock('../config', () => ({ config }))
vi.mock('./walrusBlobs', () => ({ getWalrusClient: () => ({ readBlob: mocks.readBlob, computeBlobMetadata: mocks.computeBlobMetadata }) }))
vi.mock('@mysten/sui/transactions', () => ({ Transaction: class {
    pure = vi.fn((_type: string, value: unknown) => ({ kind: 'pure', value }))
    object = vi.fn((id: string) => ({ kind: 'object', id }))
    moveCall = mocks.moveCall
    build = mocks.build
} }))
vi.mock('@mysten/seal', () => ({
    EncryptedObject: { parse: mocks.parseEncryptedObject },
    SessionKey: { create: mocks.create },
    SealClient: class {
        constructor(options: unknown) { mocks.sealClientOptions(options) }
        decrypt = mocks.decrypt
    },
}))

import { clearSealSession, fetchAndDecryptBlob } from './blobPreview'

const newSession = () => ({
    isExpired: () => false,
})

beforeEach(() => {
    clearSealSession(); vi.clearAllMocks()
    config.walrusAggregatorUrl = ''
    mocks.parseEncryptedObject.mockReturnValue({ id: '00'.repeat(32) })
    mocks.create.mockImplementation(async ({ signer }: { signer: { signPersonalMessage: (message: Uint8Array) => Promise<unknown> } }) => {
        await signer.signPersonalMessage(new TextEncoder().encode('seal message'))
        return newSession()
    })
    mocks.readBlob.mockResolvedValue(new Uint8Array([1]))
    mocks.build.mockResolvedValue(new Uint8Array([2]))
    mocks.decrypt.mockResolvedValue(new TextEncoder().encode('hello'))
    mocks.computeBlobMetadata.mockImplementation(async () => ({ blobId: 'a' }))
    vi.stubGlobal('fetch', vi.fn(async () => new Response(new Uint8Array([9]))))
})

it('caches one identity-scoped Seal session', async () => {
    const sign = vi.fn(async () => ({ signature: 'sig' }))
    const opts = { suiClient: {} as never, address: '0x1', accountObjectId: '0x2', signPersonalMessage: sign }
    await fetchAndDecryptBlob({ ...opts, blobId: 'a' })
    await fetchAndDecryptBlob({ ...opts, blobId: 'b' })
    expect(sign).toHaveBeenCalledTimes(1)
    expect(mocks.decrypt).toHaveBeenCalledTimes(2)
})

it('shares concurrent session creation', async () => {
    let release!: (value: ReturnType<typeof newSession>) => void
    mocks.create.mockImplementation(({ signer }: { signer: { signPersonalMessage: (message: Uint8Array) => Promise<unknown> } }) => {
        void signer.signPersonalMessage(new TextEncoder().encode('seal message'))
        return new Promise(resolve => { release = resolve })
    })
    const sign = vi.fn(async () => ({ signature: 'sig' }))
    const opts = { suiClient: {} as never, address: '0x1', accountObjectId: '0x2', signPersonalMessage: sign }
    const first = fetchAndDecryptBlob({ ...opts, blobId: 'a' })
    const second = fetchAndDecryptBlob({ ...opts, blobId: 'b' })
    await vi.waitFor(() => expect(mocks.create).toHaveBeenCalledTimes(1))
    release(newSession())
    await Promise.all([first, second])
    expect(sign).toHaveBeenCalledTimes(1)
})

it('never reuses a session across account objects and clear forces renewal', async () => {
    const sign = vi.fn(async () => ({ signature: 'sig' }))
    const base = { suiClient: {} as never, address: '0x1', signPersonalMessage: sign, blobId: 'a' }
    await fetchAndDecryptBlob({ ...base, accountObjectId: '0x2' })
    await fetchAndDecryptBlob({ ...base, accountObjectId: '0x3' })
    clearSealSession()
    await fetchAndDecryptBlob({ ...base, accountObjectId: '0x2' })
    expect(sign).toHaveBeenCalledTimes(3)
})

it('cancels stale preview work before plaintext decryption after identity cleanup', async () => {
    let release!: (value: Uint8Array) => void
    mocks.readBlob.mockReturnValue(new Promise(resolve => { release = resolve }))
    const pending = fetchAndDecryptBlob({
        suiClient: {} as never,
        address: '0x1',
        accountObjectId: '0x2',
        blobId: 'a',
        signPersonalMessage: vi.fn(async () => ({ signature: 'sig' })),
    })
    await vi.waitFor(() => expect(mocks.readBlob).toHaveBeenCalledOnce())
    clearSealSession()
    release(new Uint8Array([1]))
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' })
    expect(mocks.decrypt).not.toHaveBeenCalled()
})

it('accepts aggregator bytes whose recomputed blob id matches the request', async () => {
    config.walrusAggregatorUrl = 'https://aggregator.example'
    mocks.computeBlobMetadata.mockResolvedValue({ blobId: 'requested-blob' })
    const opts = {
        suiClient: {} as never, address: '0x1', accountObjectId: '0x2', blobId: 'requested-blob',
        signPersonalMessage: vi.fn(async () => ({ signature: 'sig' })),
    }
    await expect(fetchAndDecryptBlob(opts)).resolves.toBe('hello')
    expect(fetch).toHaveBeenCalledWith('https://aggregator.example/v1/blobs/requested-blob', expect.anything())
})

it('rejects aggregator bytes for a substituted blob (id mismatch)', async () => {
    config.walrusAggregatorUrl = 'https://aggregator.example'
    // Aggregator returns bytes for a *different*, validly-formed blob than
    // the one requested -- the recomputed id must not match.
    mocks.computeBlobMetadata.mockResolvedValue({ blobId: 'substituted-blob' })
    const opts = {
        suiClient: {} as never, address: '0x1', accountObjectId: '0x2', blobId: 'requested-blob',
        signPersonalMessage: vi.fn(async () => ({ signature: 'sig' })),
    }
    await expect(fetchAndDecryptBlob(opts)).rejects.toThrow(/different blob/)
    expect(mocks.decrypt).not.toHaveBeenCalled()
})

it('strips a trailing slash from the configured aggregator URL', async () => {
    config.walrusAggregatorUrl = 'https://aggregator.example/'
    mocks.computeBlobMetadata.mockResolvedValue({ blobId: 'requested-blob' })
    const opts = {
        suiClient: {} as never, address: '0x1', accountObjectId: '0x2', blobId: 'requested-blob',
        signPersonalMessage: vi.fn(async () => ({ signature: 'sig' })),
    }
    await fetchAndDecryptBlob(opts)
    expect(fetch).toHaveBeenCalledWith('https://aggregator.example/v1/blobs/requested-blob', expect.anything())
})

it('binds the Seal session to the LEGACY package id at cutover', async () => {
    config.legacyMemwalPackageId = '0xold'
    try {
        const opts = {
            suiClient: {} as never, address: '0x1', accountObjectId: '0x2', blobId: 'a',
            signPersonalMessage: vi.fn(async () => ({ signature: 'sig' })),
        }
        await fetchAndDecryptBlob(opts)
        expect(mocks.create).toHaveBeenCalledWith(expect.objectContaining({ packageId: '0xold' }))
    } finally {
        config.legacyMemwalPackageId = '0x1'
    }
})

it('binds post-migration preview sessions to memwalPackageId without colliding with legacy cache', async () => {
    config.legacyMemwalPackageId = '0xold'
    config.memwalPackageId = '0xcurrent'
    config.memwalSealPolicyPackageId = '0xcurrent'
    try {
        const sign = vi.fn(async () => ({ signature: 'sig' }))
        const base = {
            suiClient: {} as never,
            address: '0x1',
            accountObjectId: '0x2',
            blobId: 'a',
            signPersonalMessage: sign,
        }
        await fetchAndDecryptBlob({ ...base, scope: 'legacy' })
        await fetchAndDecryptBlob({ ...base, scope: 'current' })
        expect(mocks.create).toHaveBeenNthCalledWith(1, expect.objectContaining({ packageId: '0xold' }))
        expect(mocks.create).toHaveBeenNthCalledWith(2, expect.objectContaining({ packageId: '0xcurrent' }))
        expect(mocks.moveCall).toHaveBeenNthCalledWith(1, {
            target: '0xold::account::seal_approve',
            arguments: [
                expect.objectContaining({ kind: 'pure' }),
                { kind: 'object', id: '0x2' },
            ],
        })
        expect(mocks.moveCall).toHaveBeenNthCalledWith(2, {
            target: '0xcurrent::account::seal_approve',
            arguments: [
                expect.objectContaining({ kind: 'pure' }),
                { kind: 'object', id: '0xreg' },
                { kind: 'object', id: '0x2' },
            ],
        })
        expect(sign).toHaveBeenCalledTimes(2)
    } finally {
        config.legacyMemwalPackageId = '0x1'
        config.memwalPackageId = '0x1'
        config.memwalSealPolicyPackageId = '0x1'
    }
})

it('selects the Mysten testnet committee aggregator when the ciphertext header references it', async () => {
    mocks.parseEncryptedObject.mockReturnValue({
        id: '00'.repeat(32),
        services: [['0xb012378c9f3799fb5b1a7083da74a4069e3c3f1c93de0b27212a5799ce1e1e98', 1]],
    })
    await fetchAndDecryptBlob({
        suiClient: {} as never,
        address: '0x1',
        accountObjectId: '0x2',
        blobId: 'a',
        scope: 'current',
        signPersonalMessage: vi.fn(async () => ({ signature: 'sig' })),
    })
    expect(mocks.sealClientOptions).toHaveBeenCalledWith(expect.objectContaining({
        serverConfigs: [{
            objectId: '0xb012378c9f3799fb5b1a7083da74a4069e3c3f1c93de0b27212a5799ce1e1e98',
            weight: 1,
            aggregatorUrl: 'https://seal-aggregator-testnet.mystenlabs.com',
        }],
    }))
})
