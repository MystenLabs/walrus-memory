/**
 * Walrus Memory — Manual Client (Full Client-Side)
 *
 * User-side flow where the SDK handles everything locally:
 * - SEAL encrypt/decrypt via @mysten/seal (user's own Sui wallet)
 * - Walrus upload is done by the relayer; downloads use the HTTP aggregator
 * - Embedding via OpenAI-compatible API (user's own key)
 * - Vector registration via Walrus Memory server (Ed25519 signed)
 *
 * @example
 * ```typescript
 * import { MemWalManual } from "@mysten-incubation/memwal/manual"
 *
 * const memwal = MemWalManual.create({
 *     key: process.env.MEMWAL_DELEGATE_KEY!,      // Ed25519 delegate key
 *     suiPrivateKey: process.env.SUI_PRIVATE_KEY!, // suiprivkey1... for SEAL + Walrus
 *     embeddingApiKey: process.env.OPENAI_API_KEY!,
 *     packageId: "0x...",
 *     accountId: "0x...",
 *     registryId: "0x...",
 * })
 *
 * // Remember — all client-side: embed → SEAL encrypt → Walrus upload → register
 * await memwal.rememberManual("I'm allergic to peanuts")
 *
 * // Recall — all client-side: embed → search → download → SEAL decrypt
 * const result = await memwal.recallManual("food allergies")
 * ```
 */

import type {
    MemWalManualConfig,
    WalletSigner,
    RememberManualResult,
    RecallManualMemoryResult,
    RecallManualMemory,
    MemWalManualRecallOptions,
    RestoreResult,
    SealServerConfig,
    RelayerVersionMetadata,
} from "./types.js";
import {
    sha256hex,
    hexToBytes,
    bytesToHex,
    normalizePrivateKey,
    u64ToLeHex,
    normalizeServerUrl,
    assertNonBlankText,
    sanitizeServerError,
    clockDriftErrorFromResponse,
    assertFiniteScoringWeights,
    scoringWeightsToWire,
    fetchWithDeadline,
    DEFAULT_PREFLIGHT_TIMEOUT_MS,
    RESTORE_REQUEST_TIMEOUT_MS,
    deadlineSignal,
    requestTimeoutError,
} from "./utils.js";
import { assertCompatibleRelayer, compatibilityErrorFromStatus } from "./compatibility.js";
import { resolveLimitOrOptions } from "./recall-args.js";
import { createDefaultSuiClient } from "./sui-client.js";

// ============================================================
// Constants
// ============================================================

type ResolvedSealServerConfig = Omit<SealServerConfig, "weight"> & {
    weight: number;
};

// Default SEAL server configs per network.
// Keep testnet on the legacy independent servers so Manual mode can decrypt
// data written by the hosted testnet relayer. Committee aggregators remain
// supported through explicit sealServerConfigs.
const DEFAULT_SEAL_SERVER_CONFIGS: Record<string, ResolvedSealServerConfig[]> = {
    mainnet: [
        {
            objectId: "0x145540d931f182fef76467dd8074c9839aea126852d90d18e1556fcbbd1208b6", // Overclock (Open)
            weight: 1,
        },
        {
            objectId: "0xe0eb52eba9261b96e895bbb4deca10dcd64fbc626a1133017adcd5131353fd10", // Studio Mirai (Open)
            weight: 1,
        },
    ],
    testnet: [
        {
            objectId: "0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75",
            weight: 1,
        },
        {
            objectId: "0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8",
            weight: 1,
        },
    ],
};

function normalizeSealServerConfigs(configs: SealServerConfig[]): ResolvedSealServerConfig[] {
    return configs.map((config, index) => {
        const objectId = config.objectId?.trim();
        if (!objectId) {
            throw new Error(`MemWalManual: sealServerConfigs[${index}].objectId is required`);
        }

        const weight = config.weight ?? 1;
        if (!Number.isInteger(weight) || weight < 1) {
            throw new Error(`MemWalManual: sealServerConfigs[${index}].weight must be a positive integer`);
        }

        const aggregatorUrl = config.aggregatorUrl?.trim();
        const apiKeyName = config.apiKeyName?.trim();
        const apiKey = config.apiKey?.trim();
        if ((apiKeyName && !apiKey) || (!apiKeyName && apiKey)) {
            throw new Error(
                `MemWalManual: sealServerConfigs[${index}] must provide both apiKeyName and apiKey, or neither`
            );
        }

        return {
            objectId,
            weight,
            ...(aggregatorUrl ? { aggregatorUrl } : {}),
            ...(apiKeyName && apiKey ? { apiKeyName, apiKey } : {}),
        };
    });
}

function resolveSealServerConfigs(config: MemWalManualConfig, network: string): ResolvedSealServerConfig[] {
    if (config.sealServerConfigs !== undefined) {
        return normalizeSealServerConfigs(config.sealServerConfigs);
    }

    if (config.sealKeyServers !== undefined) {
        return normalizeSealServerConfigs(config.sealKeyServers.map((objectId) => ({ objectId })));
    }

    return normalizeSealServerConfigs(DEFAULT_SEAL_SERVER_CONFIGS[network] ?? []);
}

function sealServerConfigTotalWeight(configs: ResolvedSealServerConfig[]): number {
    return configs.reduce((sum, config) => sum + config.weight, 0);
}

/** Encode arbitrary-size bytes without passing the whole payload as function arguments. */
function bytesToBase64(bytes: Uint8Array): string {
    const chunkSize = 0x8000;
    const chunks: string[] = [];
    for (let offset = 0; offset < bytes.length; offset += chunkSize) {
        chunks.push(String.fromCharCode(...bytes.subarray(offset, offset + chunkSize)));
    }
    return btoa(chunks.join(""));
}

async function readSuccessJson<T>(res: Response): Promise<T> {
    const raw = await res.text();
    if (raw.trim() === "") {
        throw Object.assign(new Error(`MemWal: HTTP ${res.status} response had an empty body; expected JSON`), { status: res.status });
    }
    try {
        return JSON.parse(raw) as T;
    } catch (err) {
        if (err instanceof SyntaxError) {
            throw Object.assign(new Error(`MemWal: HTTP ${res.status} response was not JSON`), { status: res.status });
        }
        throw err;
    }
}

// ============================================================
// MemWalManual Client
// ============================================================

function destroyedClientError(): Error {
    return new Error(
        "Walrus Memory client was destroyed; its keys are zeroed. Create a new one.",
    );
}

const SEAL_SESSION_TTL_MIN = 5;
const SEAL_SESSION_SAFETY_MARGIN_MS = 30_000;

export class MemWalManual {
    private destroyed = false;
    private delegatePrivateKey: Uint8Array;
    private delegatePublicKey: Uint8Array | null = null;
    private serverUrl: string;
    private config: MemWalManualConfig;
    private walletSigner: WalletSigner | null;
    private namespace: string;
    private relayerVersionMetadata: RelayerVersionMetadata | null = null;
    private compatibilityPromise: Promise<RelayerVersionMetadata> | null = null;
    /** Per-round-trip budget for the compatibility preflight (WALM-598). */
    private preflightTimeoutMs: number;
    private sessionCache: { bytes: string; expiresAt: number } | null = null;
    private sessionBuildPromise: Promise<string> | null = null;

    // Lazily initialized heavy clients (typed as any to avoid peer dep compile errors)
    private _suiClient: any = null;
    private _sealClient: any = null;
    private _keypair: any = null;

    private constructor(config: MemWalManualConfig) {
        if (!config.suiPrivateKey && !config.walletSigner) {
            throw new Error("MemWalManual: provide either suiPrivateKey or walletSigner");
        }
        if (config.suiPrivateKey && config.walletSigner) {
            throw new Error("MemWalManual: provide suiPrivateKey OR walletSigner, not both");
        }
        const rawKey =
            typeof config.key === "string"
                ? hexToBytes(normalizePrivateKey(config.key))
                : config.key;
        if (!(rawKey instanceof Uint8Array) || rawKey.length !== 32) {
            const got = rawKey instanceof Uint8Array
                ? String(rawKey.length)
                : typeof rawKey;
            throw new Error(`Ed25519 seed must be exactly 32 bytes, got ${got}`);
        }
        // Copy caller-provided Uint8Array so destroy() zeroes only the
        // client's internal key buffer without mutating the caller's bytes (#973).
        this.delegatePrivateKey = typeof config.key === "string" ? rawKey : new Uint8Array(rawKey);
        // LOW-22: default to HTTPS; warn (do not throw) on plaintext HTTP
        // against non-localhost hosts.
        this.serverUrl = normalizeServerUrl(config.serverUrl ?? "https://relayer.memory.walrus.xyz");
        this.walletSigner = config.walletSigner ?? null;
        if (typeof config.accountId !== "string" || config.accountId.trim().length === 0) {
            throw new TypeError(
                `MemWalManual.create: "accountId" is required (Walrus Memory object ID, e.g. 0x...); got ${config.accountId}`,
            );
        }
        // Clone config (and any sealServerConfigs entries) and drop `key` from
        // the stored config so `destroy()` can scrub secret fields without
        // mutating the caller's input object (#977).
        const clonedConfig: MemWalManualConfig = {
            ...config,
            ...(config.sealServerConfigs
                ? { sealServerConfigs: config.sealServerConfigs.map((entry) => ({ ...entry })) }
                : {}),
        };
        delete (clonedConfig as Partial<MemWalManualConfig>).key;
        this.config = clonedConfig;
        if (config.namespace !== undefined && !config.namespace) {
            throw new Error("namespace cannot be empty");
        }
        this.namespace = config.namespace ?? "default";
        this.preflightTimeoutMs = config.preflightTimeoutMs ?? DEFAULT_PREFLIGHT_TIMEOUT_MS;
    }

    /**
     * Create a new MemWalManual client.
     *
     * Requires peer dependencies: @mysten/sui, @mysten/seal
     *
     * When `config.key` is passed as a `Uint8Array`, the bytes are copied into an
     * internal buffer so `destroy()` zeroes only the client's copy and leaves the
     * caller's `Uint8Array` unchanged.
     *
     * @param config.key - Ed25519 delegate private key (hex, `suiprivkey1...`, or 32-byte `Uint8Array`; copied on `create()`) for server auth
     * @param config.suiPrivateKey - Sui private key (bech32) for SEAL + Walrus (OR walletSigner)
     * @param config.walletSigner - Connected wallet signer from dapp-kit (OR suiPrivateKey)
     * @param config.embeddingApiKey - OpenAI/OpenRouter API key for embeddings
     * @param config.packageId - Immutable first-published package ID used by SEAL
     * @param config.sealPolicyPackageId - Current seal_approve package after an upgrade
     * @param config.registryId - AccountRegistry shared object ID (for SEAL seal_approve)
     * @param config.accountId - Walrus Memory account object ID (for SEAL seal_approve)
     */
    static create(config: MemWalManualConfig): MemWalManual {
        return new MemWalManual(config);
    }

    /**
     * Wipe the client's internal delegate key buffers, drop references to
     * `suiPrivateKey`, `embeddingApiKey`, `sealServerConfigs` API keys,
     * `walletSigner`, and cached Sui/SEAL/keypair instances, and invalidate the
     * client so subsequent or in-flight operations reject.
     *
     * Note: JavaScript `string` values (`suiPrivateKey`, `embeddingApiKey`) are
     * immutable in V8/JS runtimes and cannot be zeroed in place. `destroy()`
     * drops all references held by this client so those strings become eligible
     * for garbage collection once the caller also releases its references.
     */
    destroy(): void {
        this.destroyed = true;
        if (this.delegatePrivateKey) {
            this.delegatePrivateKey.fill(0);
        }
        if (this.delegatePublicKey) {
            this.delegatePublicKey.fill(0);
            this.delegatePublicKey = null;
        }
        const internalSecretKey = this._keypair?.keypair?.secretKey;
        if (internalSecretKey instanceof Uint8Array) {
            internalSecretKey.fill(0);
        }
        this._keypair = null;
        this._suiClient = null;
        this._sealClient = null;
        this.walletSigner = null;
        if (this.config) {
            delete (this.config as Partial<MemWalManualConfig>).key;
            delete (this.config as Partial<MemWalManualConfig>).suiPrivateKey;
            delete (this.config as Partial<MemWalManualConfig>).embeddingApiKey;
            delete (this.config as Partial<MemWalManualConfig>).walletSigner;
            delete (this.config as Partial<MemWalManualConfig>).suiClient;
            if (Array.isArray(this.config.sealServerConfigs)) {
                for (const entry of this.config.sealServerConfigs) {
                    if (entry && typeof entry === "object") {
                        delete entry.apiKey;
                        delete entry.apiKeyName;
                    }
                }
            }
        }
        this.relayerVersionMetadata = null;
        this.compatibilityPromise = null;
        this.sessionCache = null;
        this.sessionBuildPromise = null;
    }

    /**
     * Build an ephemeral SEAL SessionKey, sign its personal message, and export
     * it as a base64-encoded JSON envelope suitable for `x-seal-session`.
     * Memoised until 30s before expiration (5m TTL).
     */
    async buildSealSession(): Promise<string> {
        if (this.destroyed) throw destroyedClientError();
        // Fast path: cached session still fresh.
        if (this.sessionCache && Date.now() < this.sessionCache.expiresAt) {
            return this.sessionCache.bytes;
        }
        // Single-flight: concurrent requests share one build.
        if (this.sessionBuildPromise) return this.sessionBuildPromise;

        const buildPromise = this.buildSealSessionInner().finally(() => {
            if (this.sessionBuildPromise === buildPromise) {
                this.sessionBuildPromise = null;
            }
        });
        this.sessionBuildPromise = buildPromise;
        return buildPromise;
    }

    private async buildSealSessionInner(): Promise<string> {
        if (this.destroyed) throw destroyedClientError();
        // Same key MemWal uses. An owner wallet session prompts on every
        // refresh and is broader than the delegate this client already holds.
        // Dynamic imports: @mysten/sui and @mysten/seal are optional peers.
        // Server-mode MemWal must still load when they are not installed.
        const { Ed25519Keypair } = await import("@mysten/sui/keypairs/ed25519");
        if (this.destroyed) throw destroyedClientError();
        const keypair = Ed25519Keypair.fromSecretKey(this.delegatePrivateKey);
        const suiClient = await this.getSuiClient();
        const { SessionKey } = await import("@mysten/seal");
        if (this.destroyed) throw destroyedClientError();

        const session = await SessionKey.create({
            address: keypair.getPublicKey().toSuiAddress(),
            packageId: this.config.packageId,
            ttlMin: SEAL_SESSION_TTL_MIN,
            signer: keypair,
            suiClient,
        });
        if (this.destroyed) throw destroyedClientError();

        const personalMessage = session.getPersonalMessage();
        const signResult = await keypair.signPersonalMessage(personalMessage);
        if (this.destroyed) throw destroyedClientError();
        await session.setPersonalMessageSignature(signResult.signature);
        if (this.destroyed) throw destroyedClientError();

        const exported = session.export();
        const jsonStr = JSON.stringify({
            address: exported.address,
            packageId: exported.packageId,
            mvrName: exported.mvrName,
            creationTimeMs: exported.creationTimeMs,
            ttlMin: exported.ttlMin,
            personalMessageSignature: exported.personalMessageSignature,
            sessionKey: exported.sessionKey,
        });
        const bytes =
            typeof btoa === "function"
                ? btoa(jsonStr)
                : Buffer.from(jsonStr, "utf8").toString("base64");

        if (this.destroyed) throw destroyedClientError();
        this.sessionCache = {
            bytes,
            expiresAt:
                Date.now() +
                SEAL_SESSION_TTL_MIN * 60_000 -
                SEAL_SESSION_SAFETY_MARGIN_MS,
        };
        return bytes;
    }

    /**
     * Fetch and validate the relayer compatibility contract.
     */
    async compatibility(): Promise<RelayerVersionMetadata> {
        if (this.destroyed) throw destroyedClientError();
        return this.ensureCompatibleRelayer();
    }

    /** Whether this client uses a connected wallet signer (vs raw keypair) */
    get isWalletMode(): boolean {
        return this.walletSigner !== null;
    }

    // ============================================================
    // Lazy Client Initialization
    // All @mysten/* imports are dynamic to avoid requiring peer deps at
    // compile time. Users who only use the server-mode MemWal class
    // don't need these packages installed.
    // ============================================================

    private async getSuiClient() {
        if (this.destroyed) throw destroyedClientError();
        if (!this._suiClient) {
            // Prefer externally-provided client (e.g. from dapp-kit's useSuiClient()),
            // otherwise gRPC against the public fullnode for suiNetwork.
            const client =
                this.config.suiClient ?? await createDefaultSuiClient(this.config.suiNetwork);
            if (this.destroyed) throw destroyedClientError();
            this._suiClient = client;
        }
        return this._suiClient;
    }

    private async getKeypair() {
        if (this.destroyed) throw destroyedClientError();
        if (this.walletSigner) {
            throw new Error("getKeypair() not available in wallet signer mode");
        }
        if (!this._keypair) {
            const { decodeSuiPrivateKey } = await import("@mysten/sui/cryptography");
            const { Ed25519Keypair } = await import("@mysten/sui/keypairs/ed25519");
            if (this.destroyed) throw destroyedClientError();
            const { secretKey } = decodeSuiPrivateKey(this.config.suiPrivateKey!);
            const keypair = Ed25519Keypair.fromSecretKey(secretKey);
            secretKey.fill(0);
            if (this.destroyed) {
                const kpSecret = (keypair as any)?.keypair?.secretKey;
                if (kpSecret instanceof Uint8Array) kpSecret.fill(0);
                throw destroyedClientError();
            }
            this._keypair = keypair;
        }
        return this._keypair;
    }

    /** Get the transaction signer address from the wallet or configured keypair. */
    private async getSignerAddress(): Promise<string> {
        if (this.destroyed) throw destroyedClientError();
        if (this.walletSigner) {
            return this.walletSigner.address;
        }
        const keypair = await this.getKeypair();
        return keypair.getPublicKey().toSuiAddress();
    }

    private async getSealClient() {
        if (this.destroyed) throw destroyedClientError();
        if (!this._sealClient) {
            // @ts-ignore — optional peer dependency
            const { SealClient } = await import("@mysten/seal");
            if (this.destroyed) throw destroyedClientError();
            const suiClient = await this.getSuiClient();
            if (this.destroyed) throw destroyedClientError();
            const network = this.config.suiNetwork ?? "mainnet";
            const serverConfigs = resolveSealServerConfigs(this.config, network);
            if (serverConfigs.length === 0) {
                throw new Error(
                    `MemWalManual: no SEAL key servers configured for network "${network}". ` +
                        "Please provide sealServerConfigs or sealKeyServers in config."
                );
            }
            this._sealClient = new SealClient({
                suiClient,
                serverConfigs,
                verifyKeyServers: true,
            });
        }
        return this._sealClient;
    }

    /** MED-10: SEAL threshold — defaults to 2, capped to configured server weight. */
    private get sealThreshold(): number {
        if (this.config.sealThreshold !== undefined) {
            return this.config.sealThreshold;
        }
        const network = this.config.suiNetwork ?? "mainnet";
        const totalWeight = sealServerConfigTotalWeight(resolveSealServerConfigs(this.config, network));
        return totalWeight > 0 ? Math.min(2, totalWeight) : 2;
    }

    // ============================================================
    // Core Manual API
    // ============================================================

    /**
     * Remember (hybrid flow):
     * 1. Embed text (OpenAI/OpenRouter)
     * 2. SEAL encrypt locally (no wallet signature needed)
     * 3. Send {encrypted_data, vector} to server — server handles Walrus upload relay
     */
    async rememberManual(text: string, namespace?: string): Promise<RememberManualResult> {
        if (this.destroyed) throw destroyedClientError();
        assertNonBlankText(text);

        const ns = namespace ?? this.namespace;

        // Step 1 & 2: Embed + SEAL encrypt concurrently. Namespace produces a
        // distinct SEAL identity, but delegates remain authorized account-wide.
        const [vector, encrypted] = await Promise.all([
            this.embed(text),
            this.sealEncrypt(new TextEncoder().encode(text), ns),
        ]);

        // Step 3: Send encrypted bytes (base64) + vector to server.
        // Server will upload to Walrus via upload-relay and return the blob_id.
        const encryptedBase64 = bytesToBase64(encrypted);
        return this.signedRequest<RememberManualResult>("POST", "/api/remember/manual", {
            encrypted_data: encryptedBase64,
            vector,
            namespace: ns,
        });
    }

    /**
     * Recall (manual/full client-side):
     * 1. Embed query (OpenAI)
     * 2. Search server for matching vectors
     * 3. Download blobs from Walrus
     * 4. SEAL decrypt each blob
     *
     * `recallManual(query, { limit?, namespace? })` is valid.
     * `recallManual(query, namespace)` throws `TypeError`.
     */
    async recallManual(query: string, options: MemWalManualRecallOptions): Promise<RecallManualMemoryResult>;
    async recallManual(query: string, limit?: number, namespace?: string): Promise<RecallManualMemoryResult>;
    async recallManual(
        query: string,
        limitOrOptions: number | MemWalManualRecallOptions = 10,
        namespace?: string
    ): Promise<RecallManualMemoryResult> {
        if (this.destroyed) throw destroyedClientError();
        if (!query.trim()) throw new Error("Query cannot be empty");

        const options = resolveLimitOrOptions(
            "recallManual",
            limitOrOptions,
            namespace,
        );
        const limit = options.limit !== undefined ? options.limit : 10;
        if (typeof limit !== "number" || !Number.isInteger(limit) || limit <= 0) {
            throw new TypeError(
                `limit must be a positive integer, got ${limit}`,
            );
        }
        assertFiniteScoringWeights(options.scoringWeights);
        const ns = options.namespace ?? this.namespace;

        // Step 1: Embed query
        const vector = await this.embed(query);

        // Step 2: Search server
        const searchResult = await this.signedRequest<{
            results: { blob_id: string; distance: number }[];
            total: number;
        }>("POST", "/api/recall/manual", {
            vector,
            limit,
            namespace: ns,
            scoring_weights: scoringWeightsToWire(options.scoringWeights),
        });

        if (searchResult.results.length === 0) {
            return { results: [], total: 0 };
        }

        // Step 3: Download all encrypted blobs from Walrus concurrently
        const downloadTasks = searchResult.results.map(async (hit) => {
            try {
                const data = await this.walrusDownload(hit.blob_id);
                return { blob_id: hit.blob_id, data, distance: hit.distance };
            } catch (err) {
                console.error(`[MemWalManual] Walrus download failed for ${hit.blob_id}:`, err);
                return null;
            }
        });
        const downloadedBlobs = (await Promise.all(downloadTasks)).filter(
            (d): d is { blob_id: string; data: Uint8Array; distance: number } => d !== null
        );

        if (downloadedBlobs.length === 0) {
            return { results: [], total: 0 };
        }

        // Step 4: Create ONE SEAL SessionKey (one wallet popup), then decrypt all blobs
        let sealClient: any;
        let suiClient: any;
        let SessionKey: any;
        let EncryptedObject: any;
        let Transaction: any;
        let normalizeSuiAddress: (address: string) => string;
        let sessionKey: any;
        try {
            sealClient = await this.getSealClient();
            suiClient = await this.getSuiClient();
            // @ts-ignore — optional peer dependency
            ({ SessionKey, EncryptedObject } = await import("@mysten/seal"));
            ({ Transaction } = await import("@mysten/sui/transactions"));
            ({ normalizeSuiAddress } = await import("@mysten/sui/utils"));
        } catch (err) {
            console.error("[MemWalManual] Failed to initialize SEAL/SUI clients:", err);
            return { results: [], total: 0 };
        }

        const immutablePackageId = normalizeSuiAddress(this.config.packageId);
        const parsedBlobs: ({ parsed: any } & (typeof downloadedBlobs)[number])[] = [];
        for (const blob of downloadedBlobs) {
            let parsed: any;
            try {
                parsed = EncryptedObject.parse(blob.data);
            } catch (err) {
                console.error(`[MemWalManual] SEAL decrypt failed for ${blob.blob_id}:`, err);
                continue;
            }
            if (normalizeSuiAddress(parsed.packageId) !== immutablePackageId) {
                console.error(
                    `[MemWalManual] Skipping ciphertext ${blob.blob_id}: packageId does not match ` +
                        "the configured immutable packageId"
                );
                continue;
            }
            parsedBlobs.push({ ...blob, parsed });
        }
        if (parsedBlobs.length === 0) {
            return { results: [], total: 0 };
        }

        const callerAddress = await this.getSignerAddress();

        // Create signer (wallet adapter or keypair)
        const signer = await this.createSigner(callerAddress);

        // Create session key ONCE (triggers one wallet popup)
        // HIGH-7 / LOW-13: Reduced from 30 to 5 minutes to limit the exposure
        // window if a session token is compromised.
        try {
            sessionKey = await SessionKey.create({
                address: callerAddress,
                packageId: this.config.packageId,
                ttlMin: 5,
                signer,
                suiClient,
            });
        } catch (err) {
            console.error("[MemWalManual] SessionKey.create failed:", err);
            return { results: [], total: 0 };
        }

        // Decrypt each blob sequentially using the shared session key
        const results: RecallManualMemory[] = [];
        for (const blob of parsedBlobs) {
            try {
                const fullId = blob.parsed.id;

                // Build seal_approve PTB. hexToBytes rejects empty, odd-length,
                // and non-hex ids instead of coercing NaN to 0.
                const idBytes = Array.from(hexToBytes(fullId));
                const tx = new Transaction();
                tx.moveCall({
                    target: `${this.config.sealPolicyPackageId ?? this.config.packageId}::account::seal_approve`,
                    arguments: [
                        tx.pure.vector("u8", idBytes),
                        tx.object(this.config.registryId),
                        tx.object(this.config.accountId),
                    ],
                });
                const txBytes = await tx.build({
                    client: suiClient,
                    onlyTransactionKind: true,
                });

                // Fetch decryption keys using shared session key
                await sealClient.fetchKeys({
                    ids: [fullId],
                    txBytes,
                    sessionKey,
                    threshold: this.sealThreshold,
                });

                // Decrypt locally
                const plaintext = await sealClient.decrypt({
                    data: blob.data,
                    sessionKey,
                    txBytes,
                });
                const text = new TextDecoder().decode(plaintext);
                results.push({ blob_id: blob.blob_id, text, distance: blob.distance });
            } catch (err) {
                console.error(`[MemWalManual] SEAL decrypt failed for ${blob.blob_id}:`, err);
            }
        }

        return { results, total: results.length };
    }

    // ============================================================
    // Internal: Signer Factory
    // ============================================================

    /** Create a signer adapter — either from wallet or keypair */
    private async createSigner(callerAddress: string): Promise<any> {
        if (this.walletSigner) {
            const ws = this.walletSigner;
            return {
                toSuiAddress: () => callerAddress,
                getPublicKey: () => ({ toSuiAddress: () => callerAddress }),
                sign: async (data: Uint8Array) => {
                    const result = await ws.signPersonalMessage({ message: data });
                    return { signature: result.signature };
                },
                signPersonalMessage: async (data: Uint8Array) => {
                    const result = await ws.signPersonalMessage({ message: data });
                    return { signature: result.signature };
                },
            };
        }
        return this.getKeypair();
    }

    // ============================================================
    // Internal: Embedding
    // ============================================================

    private async embed(text: string): Promise<number[]> {
        if (this.destroyed) throw destroyedClientError();
        if (!this.config.embeddingApiKey) {
            throw new Error(
                "MemWalManual: embeddingApiKey is required. " + "Provide your OpenAI or OpenRouter API key in config."
            );
        }

        const apiBase = (this.config.embeddingApiBase ?? "https://api.openai.com/v1").replace(/\/$/, "");
        const isOpenRouter = apiBase.includes("openrouter.ai");
        const defaultModel = isOpenRouter ? "openai/text-embedding-3-small" : "text-embedding-3-small";
        const model = this.config.embeddingModel ?? defaultModel;

        const resp = await fetch(`${apiBase}/embeddings`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${this.config.embeddingApiKey}`,
            },
            body: JSON.stringify({ model, input: text }),
        });

        if (!resp.ok) {
            const errText = await resp.text();
            throw new Error(`Embedding API error (${resp.status}): ${errText}`);
        }

        const data = await readSuccessJson<{ data: { embedding: number[] }[] }>(resp);
        if (!data.data?.[0]?.embedding) {
            throw new Error("Embedding API returned no data");
        }
        return data.data[0].embedding;
    }

    // ============================================================
    // Internal: SEAL Encrypt
    // ============================================================

    /**
     * SEAL-encrypt a payload.
     *
     * Namespace scoping: the `id` passed to SEAL includes the namespace, so
     * namespaces receive distinct keys. `seal_approve` authorizes delegates at
     * account scope, however, so this does not isolate delegates from each
     * other's namespaces.
     *
     * ENG-1725 fix: The on-chain `seal_approve` matches the tail of the id
     * against `bcs::to_bytes(account.owner)` for every caller — owner and
     * delegate alike. The id MUST therefore carry the owner's 32 raw address
     * bytes at that position (in hex form on the SEAL side, raw on the Move
     * side). The previous LOW-24 layout — `hex(accountId) || hex(namespace)`
     * — used the MemWalAccount object id (not the owner address) and put the
     * namespace last, so the match always failed and owners could no longer
     * recall their own manually-remembered data.
     *
     * Rotation: SEAL hands out one reusable secret key per identity, so an id
     * fixed at `owner` would let any delegate that ever fetched the key keep
     * decrypting new memories forever — removal on chain would not touch the
     * copy in their hands. Tailing the id with the account's
     * `access_counter_version` means a revocation bumps the counter, which
     * changes the identity, which yields a key they cannot fetch.
     *
     * Layout:
     *   id = hex(utf8(namespace)) || hex(ownerAddress[2:]) || hex(u64le(counter))
     *
     * - namespace is the prefix, so different namespaces use different SEAL
     *   keys. It is an organization boundary, not an authorization boundary:
     *   every account delegate may request every namespace key.
     * - owner address (32 bytes) then counter (8 bytes) are the tail →
     *   `seal_approve` parses the counter off the end and rebuilds the
     *   expected `owner ‖ counter` suffix to compare.
     *
     * NOTE: Ciphertext written between the original LOW-24 fix and the
     * ENG-1725 fix (id = accountHex + nsHex) is unrecoverable by the owner
     * caller. There is no production data in that window per the team.
     */
    private async sealEncrypt(plaintext: Uint8Array, namespace: string): Promise<Uint8Array> {
        if (this.destroyed) throw destroyedClientError();
        const sealClient = await this.getSealClient();

        // Build a namespace-scoped SEAL id tailing with the owner's address
        // bytes then the rotation counter, so the on-chain `seal_approve`
        // suffix check passes. Hex-encoded throughout so the id is a stable
        // ASCII hex string.
        const { ownerHex, counter } = await this.fetchSealIdentity();
        if (this.destroyed) throw destroyedClientError();
        const nsHex = bytesToHex(new TextEncoder().encode(namespace));
        const scopedId = `${nsHex}${ownerHex}${u64ToLeHex(counter)}`;

        const result = await sealClient.encrypt({
            threshold: this.sealThreshold,
            packageId: this.config.packageId,
            id: scopedId,
            data: plaintext,
        });

        return new Uint8Array(result.encryptedObject);
    }

    /**
     * Read the account owner and SEAL rotation counter fresh from chain.
     *
     * Deliberately not cached, and it must stay that way: the counter's only
     * job is to stop a just-removed delegate from reading what comes next, and
     * a cached value would encrypt the next memory under the identity that
     * delegate already holds a key for. One read per encrypt is the price of
     * the property. Recall does not need this — `EncryptedObject.parse` gives
     * back the id the blob was written under.
     */
    private async fetchSealIdentity(): Promise<{
        ownerHex: string;
        counter: bigint;
    }> {
        const suiClient = await this.getSuiClient();
        // getSuiClient() can hand back either client generation, and they
        // disagree on both the request and the response: the v2 gRPC/JSON-RPC
        // clients take { objectId, include } and answer { object: { json } },
        // while the legacy client takes { id, options } and answers
        // { data: { content: { fields } } }. Send both key sets — each client
        // ignores the one it does not know — and read whichever came back.
        const res: any = await suiClient.getObject({
            objectId: this.config.accountId,
            id: this.config.accountId,
            include: { json: true },
            options: { showContent: true },
        });
        const fields = res?.object?.json ?? res?.data?.content?.fields;
        const objectType = res?.object?.type ?? res?.data?.type ?? res?.data?.content?.type;
        const typeParts = typeof objectType === "string" ? objectType.split("::") : [];
        const typePackageHex = typeParts[0]?.replace(/^0x/i, "") ?? "";
        const configuredPackageHex = this.config.packageId.replace(/^0x/i, "");
        const packageMatches =
            /^[0-9a-fA-F]{1,64}$/.test(typePackageHex) &&
            /^[0-9a-fA-F]{1,64}$/.test(configuredPackageHex) &&
            typePackageHex.padStart(64, "0").toLowerCase() === configuredPackageHex.padStart(64, "0").toLowerCase();
        if (!packageMatches || typeParts[1] !== "account" || typeParts[2] !== "MemWalAccount") {
            throw new Error(
                `MemWalManual: object ${this.config.accountId} is not a ` +
                    `${this.config.packageId}::account::MemWalAccount.`
            );
        }
        if (fields?.active !== true) {
            throw new Error(`MemWalManual: account ${this.config.accountId} is not active; refusing to encrypt.`);
        }
        const owner = fields?.owner;
        if (typeof owner !== "string") {
            throw new Error(
                `MemWalManual: account ${this.config.accountId} has no owner field. ` +
                    "packageId/accountId may point at different contracts."
            );
        }
        const ownerHex = owner.replace(/^0x/i, "");
        if (!/^[0-9a-fA-F]{1,64}$/.test(ownerHex)) {
            throw new Error(`MemWalManual: account ${this.config.accountId} has an invalid owner field.`);
        }

        const rawCounter = fields?.access_counter_version;
        if (rawCounter === undefined || rawCounter === null) {
            throw new Error(
                `MemWalManual: account ${this.config.accountId} has no access_counter_version field. ` +
                    "This account predates SEAL identity rotation, or packageId/accountId point at different contracts."
            );
        }
        return {
            ownerHex: ownerHex.padStart(64, "0").toLowerCase(),
            counter: BigInt(rawCounter),
        };
    }

    // ============================================================
    // Internal: Walrus download
    // ============================================================


    private async walrusDownload(blobId: string): Promise<Uint8Array> {
        // Direct HTTP fetch to the Walrus aggregator. Upload goes through the relayer.
        const network = this.config.suiNetwork ?? "mainnet";
        const defaultAggregator =
            network === "testnet"
                ? "https://aggregator.walrus-testnet.walrus.space"
                : "https://aggregator.walrus-mainnet.walrus.space";
        const aggregatorUrl = this.config.walrusAggregatorUrl ?? defaultAggregator;
        const resp = await fetch(`${aggregatorUrl}/v1/blobs/${blobId}`);
        if (!resp.ok) {
            throw new Error(`Walrus download failed (${resp.status}): ${await resp.text()}`);
        }
        const buffer = await resp.arrayBuffer();
        return new Uint8Array(buffer);
    }

    // ============================================================
    // Internal: Signed HTTP Requests (same pattern as MemWal class)
    // ============================================================

    private async getDelegatePublicKey(): Promise<Uint8Array> {
        if (this.destroyed) throw destroyedClientError();
        if (!this.delegatePublicKey) {
            const ed = await import("@noble/ed25519");
            if (this.destroyed) throw destroyedClientError();
            const derived = await ed.getPublicKeyAsync(this.delegatePrivateKey);
            if (this.destroyed) throw destroyedClientError();
            this.delegatePublicKey = derived;
        }
        return this.delegatePublicKey.slice();
    }

    private async ensureCompatibleRelayer(): Promise<RelayerVersionMetadata> {
        if (this.relayerVersionMetadata) return this.relayerVersionMetadata;
        if (this.compatibilityPromise) return this.compatibilityPromise;

        this.compatibilityPromise = this.fetchCompatibilityMetadata().finally(() => {
            this.compatibilityPromise = null;
        });
        return this.compatibilityPromise;
    }

    private async fetchCompatibilityMetadata(): Promise<RelayerVersionMetadata> {
        // Bounded like the relayer-mode client's preflight: these run inside
        // whatever signed request triggered them.
        const versionRes = await fetchWithDeadline(
            `${this.serverUrl}/version`,
            { method: "GET" },
            this.preflightTimeoutMs,
            "preflight GET /version",
        );
        let body: Partial<RelayerVersionMetadata>;

        if (versionRes.ok) {
            body = await readSuccessJson<Partial<RelayerVersionMetadata>>(versionRes);
        } else if (versionRes.status === 404 || versionRes.status === 405) {
            const healthRes = await fetchWithDeadline(
                `${this.serverUrl}/health`,
                { method: "GET" },
                this.preflightTimeoutMs,
                "preflight GET /health",
            );
            if (!healthRes.ok) {
                throw new Error(
                    `Walrus Memory compatibility check failed: GET /version returned ` +
                        `${versionRes.status}, and GET /health returned ${healthRes.status}`
                );
            }
            body = await readSuccessJson<Partial<RelayerVersionMetadata>>(healthRes);
        } else {
            throw new Error(`Walrus Memory compatibility check failed: GET /version returned ${versionRes.status}`);
        }

        assertCompatibleRelayer(body, this.serverUrl);
        this.relayerVersionMetadata = body;
        return body;
    }

    /**
     * Make a signed request to the server.
     *
     * Signature format (LOW-1 + MED-1 + LOW-23):
     *   "{timestamp}.{method}.{path_and_query}.{body_sha256}.{nonce}.{account_id}"
     *
     * Headers sent: x-public-key, x-signature, x-timestamp, x-nonce, x-account-id.
     */
    private async signedRequest<T>(
        method: string,
        path: string,
        body: object,
        options: { timeoutMs?: number; signal?: AbortSignal; includeSealSession?: boolean } = {},
    ): Promise<T> {
        if (this.destroyed) throw destroyedClientError();
        await this.ensureCompatibleRelayer();
        if (this.destroyed) throw destroyedClientError();
        const ed = await import("@noble/ed25519");

        const timestamp = Math.floor(Date.now() / 1000).toString();
        const bodyStr = JSON.stringify(body);
        const bodySha256 = await sha256hex(bodyStr);

        // MED-1: per-request nonce for replay protection.
        const nonce = crypto.randomUUID();

        // LOW-23: include x-account-id in the canonical signed message so an
        // intermediary cannot rebind a signed request to a different account.
        const message = `${timestamp}.${method}.${path}.${bodySha256}.${nonce}.${this.config.accountId}`;
        const msgBytes = new TextEncoder().encode(message);

        if (this.destroyed) throw destroyedClientError();
        const signature = await ed.signAsync(msgBytes, this.delegatePrivateKey);
        if (this.destroyed) throw destroyedClientError();
        const publicKey = await this.getDelegatePublicKey();
        if (this.destroyed) throw destroyedClientError();

        const headers: Record<string, string> = {
            "Content-Type": "application/json",
            "x-public-key": bytesToHex(publicKey),
            "x-signature": bytesToHex(signature),
            "x-timestamp": timestamp,
            "x-nonce": nonce,
            "x-account-id": this.config.accountId,
        };

        if (options.includeSealSession) {
            headers["x-seal-session"] = await this.buildSealSession();
            if (this.destroyed) throw destroyedClientError();
        }

        const url = `${this.serverUrl}${path}`;
        const deadline = options.timeoutMs ? deadlineSignal(options.timeoutMs, options.signal) : undefined;
        try {
            const res = await fetch(url, {
                method,
                headers,
                body: bodyStr,
                signal: deadline?.signal ?? options.signal,
            });

            if (!res.ok) {
                const raw = await res.text();
                const compatibilityError = compatibilityErrorFromStatus(res.status, raw);
                if (compatibilityError) throw compatibilityError;

                const clockDriftError = clockDriftErrorFromResponse(res);
                if (clockDriftError) throw clockDriftError;

                const { message: sanitized, serverCode } = sanitizeServerError(
                    res.status,
                    raw,
                    res.headers.get("x-auth-error"),
                );
                const err = new Error(sanitized) as Error & {
                    status?: number;
                    serverCode?: string;
                    retryAfterSeconds?: number;
                    cause?: string;
                };
                err.status = res.status;
                if (serverCode) err.serverCode = serverCode;
                const retryAfter = Number(res.headers.get("retry-after"));
                if (Number.isFinite(retryAfter) && retryAfter > 0) {
                    err.retryAfterSeconds = retryAfter;
                }
                err.cause = raw;
                throw err;
            }

            return await readSuccessJson<T>(res);
        } catch (err) {
            const status = err && typeof err === "object" && "status" in err ? err.status : undefined;
            if (deadline?.timedOut() && typeof status !== "number") {
                throw requestTimeoutError(method, url, options.timeoutMs!);
            }
            throw err;
        } finally {
            deadline?.dispose();
        }
    }

    // ============================================================
    // Restore
    // ============================================================

    /**
     * Restore a namespace. The server downloads the blobs, decrypts them with
     * the delegate key, and re-indexes them.
     *
     * Sends `x-seal-session` built from the delegate key, not the owner
     * wallet. That session lets the relayer decrypt for this restore only,
     * for the usual short TTL.
     *
     * @param namespace - Namespace to restore
     * @returns RestoreResult with count of restored entries
     */
    async restore(namespace: string, limit: number = 10): Promise<RestoreResult> {
        if (this.destroyed) throw destroyedClientError();
        if (typeof limit !== "number" || !Number.isInteger(limit) || limit <= 0) {
            throw new TypeError(
                `limit must be a positive integer, got ${limit}`,
            );
        }
        const result = await this.signedRequest<RestoreResult>(
            "POST",
            "/api/restore",
            {
                namespace,
                limit,
            },
            {
                includeSealSession: true,
                timeoutMs: RESTORE_REQUEST_TIMEOUT_MS,
            },
        );
        // Relayers older than WALM-319 omit `truncated` entirely — treat
        // "not present" as "not known to be truncated" rather than drop
        // the field or require every relayer version to send it.
        // Relayers older than COMG-719 omit `failed`; default to 0.
        return {
            ...result,
            truncated: result.truncated ?? false,
            failed: result.failed ?? 0,
        };
    }
}
