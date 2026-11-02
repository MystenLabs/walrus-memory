import type { SealClient } from "@mysten/seal";

type KeyServers = Awaited<ReturnType<SealClient["getKeyServers"]>>;
type CreateSealClient = (options: { verifyKeyServers: boolean }) => SealClient;

function cloneKeyServers(servers: KeyServers): KeyServers {
    return new Map(Array.from(servers, ([id, server]) => [
        id,
        { ...server, pk: new Uint8Array(server.pk) },
    ]));
}

/**
 * Share verified public key-server metadata, never derived keys or sessions.
 *
 * A fresh SealClient normally repeats Sui object/dynamic-field reads even when
 * PoP verification is disabled. Keep the verified metadata for the existing
 * five-minute trust window, including one loader for concurrent requests.
 * Key-server URL/public-key/version changes are picked up after that window
 * (or a restart); expired metadata is not served if verification fails.
 *
 * The configured server set must stay fixed for this factory's lifetime.
 */
export function createSealDecryptClientFactory(
    createClient: CreateSealClient,
    options: { metadataTtlMs?: number; now?: () => number } = {},
): { create: () => Promise<SealClient>; reset: () => void } {
    const metadataTtlMs = options.metadataTtlMs ?? 5 * 60 * 1000;
    const now = options.now ?? Date.now;
    let metadata: KeyServers | undefined;
    let verifiedUntilMs = 0;
    let pending: Promise<KeyServers> | undefined;

    async function verifiedMetadata(): Promise<KeyServers> {
        if (metadata && now() < verifiedUntilMs) return metadata;

        if (!pending) {
            const loading = Promise.resolve()
                .then(() => createClient({ verifyKeyServers: true }).getKeyServers())
                .then((servers) => {
                    // Do not retain mutable objects owned by the verifier.
                    const snapshot = cloneKeyServers(servers);
                    if (pending === loading) {
                        metadata = snapshot;
                        verifiedUntilMs = now() + metadataTtlMs;
                    }
                    return snapshot;
                });
            pending = loading;
        }

        const loading = pending;
        try {
            return await loading;
        } finally {
            // Rejections are not cached. A later request can retry, and an
            // older load cannot clear a replacement installed after reset.
            if (pending === loading) pending = undefined;
        }
    }

    return {
        async create() {
            const snapshot = await verifiedMetadata();
            // Derived-key caches in Seal 1.1.0 are not SessionKey scoped.
            // Preserve a fresh client for each request; only its public
            // getKeyServers() path is supplied from the verified snapshot.
            const client = createClient({ verifyKeyServers: false });
            client.getKeyServers = async () => cloneKeyServers(snapshot);
            return client;
        },
        reset() {
            metadata = undefined;
            verifiedUntilMs = 0;
            pending = undefined;
        },
    };
}
