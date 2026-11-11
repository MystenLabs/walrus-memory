/**
 * Shared Sui / SEAL / Walrus clients.
 *
 * Initialized once at boot — eliminates ~1-2s Node.js cold-start per call,
 * which is the whole reason the sidecar exists. The Walrus client is the
 * one exception: it caches on-chain package metadata, so it is recreated
 * (`refreshWalrusClient`) whenever that metadata goes stale.
 */

import { MetadataEncoder } from "./metadata-encoder.js";
import { SuiGrpcClient } from "@mysten/sui/grpc";
import { SuiGraphQLClient } from "@mysten/sui/graphql";
import { normalizeStructTag } from "@mysten/sui/utils";
import { SealClient } from "@mysten/seal";
import { createSealSessionPool, readSealAuthorizationVersions } from "./seal-session-pool.js";
import { WalrusClient, type WalrusClientConfig } from "@mysten/walrus";
import {
    SEAL_KEY_SERVER_TIMEOUT_MS,
    SEAL_COMMITTEE_IDENTITY,
    SEAL_POLICY_PACKAGE_ID,
    SEAL_SERVER_CONFIGS,
    SUI_GRAPHQL_URL,
    SUI_GRPC_URL,
    SUI_NETWORK,
    SUI_TYPE,
    UPLOAD_RELAY_TIP_CACHE_TTL_MS,
    UPLOAD_RELAY_TIP_TIMEOUT_MS,
    WALRUS_CLIENT_MAX_AGE_MS,
    WALRUS_DIRECT_UPLOAD,
    WALRUS_STORAGE_NODE_TIMEOUT_MS,
    WALRUS_PACKAGE_ID,
    WALRUS_STAKING_POOL_ID,
    WALRUS_SYSTEM_OBJECT_ID,
    WALRUS_UPLOAD_RELAY_URL,
} from "./config.js";
import { shortAddress } from "./util.js";
import { createSealDecryptClientFactory } from "./seal-metadata.js";

// Shared gRPC core client for Walrus, SEAL, Enoki, and blob queries.
export const suiClient = new SuiGrpcClient({ network: SUI_NETWORK, baseUrl: SUI_GRPC_URL });
// Separate archival read path for immutable creation provenance. The regular
// gRPC fullnode remains the low-latency path for current objects and writes.
// Apply a transport timeout globally because the SDK's high-level
// getTransaction() helper does not accept an AbortSignal.
const ARCHIVAL_GRAPHQL_TIMEOUT_MS = 15_000;
const archivalFetch: typeof fetch = (input, init) => {
    const timeout = AbortSignal.timeout(ARCHIVAL_GRAPHQL_TIMEOUT_MS);
    const signal = init?.signal ? AbortSignal.any([init.signal, timeout]) : timeout;
    return fetch(input, { ...init, signal });
};
export const suiGraphqlClient = new SuiGraphQLClient({
    network: SUI_NETWORK,
    url: SUI_GRAPHQL_URL,
    fetch: archivalFetch,
});

export function createSealClient(options?: { verifyKeyServers?: boolean }): SealClient {
    return new SealClient({
        suiClient: suiClient as any,
        serverConfigs: SEAL_SERVER_CONFIGS,
        verifyKeyServers: options?.verifyKeyServers ?? true,
        timeout: SEAL_KEY_SERVER_TIMEOUT_MS,
    });
}

// Reuse verified public metadata as well as PoP trust. Fresh SDK clients would
// otherwise repeat the Sui object/dynamic-field reads on every decrypt.
const decryptSealClients = createSealDecryptClientFactory(createSealClient);

// The pool's live state fence invalidates derived keys on any account or
// registry change. Public metadata keeps its independent five-minute cache.
const decryptSessions = createSealSessionPool(
    () => decryptSealClients.create(),
    scope => readSealAuthorizationVersions(suiClient, scope[3], scope[4]),
);
let sessionBypasses = 0;

export function resetSealKeyServerTrustForTests(): void {
    decryptSessions.reset();
    decryptSealClients.reset();
}

export function sealSessionCacheMetrics(): string {
    const stats = decryptSessions.stats();
    return [
        "# TYPE memwal_seal_session_cache_total counter",
        ...Object.entries(stats).filter(([key]) => key !== "entries").map(([key, value]) =>
            `memwal_seal_session_cache_total{result="${key}"} ${value}`),
        `memwal_seal_session_cache_total{result="bypass"} ${sessionBypasses}`,
        "# TYPE memwal_seal_session_cache_entries gauge",
        `memwal_seal_session_cache_entries ${stats.entries}`,
        "",
    ].join("\n");
}

export async function createDecryptSealClient(context?: {
    sessionHeader?: string;
    session: { export(): { creationTimeMs: number; ttlMin: number } };
    packageId: string;
    policyPackageId: string;
    accountId: string;
    registryId?: string;
    ids: string[];
}): Promise<SealClient> {
    // Legacy delegate keys and the legacy ABI deliberately stay request-local.
    if (!context?.sessionHeader || !context.registryId || process.env.SEAL_SESSION_CACHE_ENABLED === "false") {
        sessionBypasses++;
        return decryptSealClients.create();
    }
    const exported = context.session.export();
    // The pool caps each retained client at five minutes, without rejecting
    // a still-valid longer SDK session when that cache lease expires.
    const expiresAt = exported.creationTimeMs + exported.ttlMin * 60_000 - 10_000;
    return decryptSessions.get({
        header: context.sessionHeader,
        expiresAt,
        scope: [SUI_NETWORK, context.packageId, context.policyPackageId || SEAL_POLICY_PACKAGE_ID,
            context.accountId, context.registryId, JSON.stringify(SEAL_COMMITTEE_IDENTITY),
            await decryptSealClients.fingerprint()],
        ids: context.ids,
    });
}

// Encryption shares public metadata only; derived-key reuse is confined to the pool.
export const sealEncryptClient = createSealClient();

const metadataEncoder = new MetadataEncoder();

function createWalrusClient(): WalrusClient {
    // WalrusClient only resolves package/staking ids itself for
    // "mainnet"/"testnet" — anything else (e.g. a devstack localnet) needs
    // them supplied directly via packageConfig.
    const useRelay =
        !WALRUS_DIRECT_UPLOAD && !!WALRUS_UPLOAD_RELAY_URL && WALRUS_UPLOAD_RELAY_URL !== "none";
    const baseConfig = {
        suiClient: suiClient as any,
        // Applies to both branches: the relay still reads slivers back from
        // storage nodes, and the direct branch has nothing else to set it.
        storageNodeClientOptions: { timeout: WALRUS_STORAGE_NODE_TIMEOUT_MS },
        ...(useRelay
            ? {
                  uploadRelay: {
                      host: WALRUS_UPLOAD_RELAY_URL,
                      sendTip: { max: 10_000_000 },
                      timeout: Number(process.env.WALRUS_RELAY_TIMEOUT_MS) || 120_000,
                  },
              }
            : {}),
    };
    const config: WalrusClientConfig = WALRUS_SYSTEM_OBJECT_ID && WALRUS_STAKING_POOL_ID
        ? {
            ...baseConfig,
            packageConfig: {
                systemObjectId: WALRUS_SYSTEM_OBJECT_ID,
                stakingPoolId: WALRUS_STAKING_POOL_ID,
            },
        }
        : { ...baseConfig, network: SUI_NETWORK as "mainnet" | "testnet" };
    const client = new WalrusClient(config);
    if (useRelay) {
        client.computeBlobMetadata = async (input) => metadataEncoder.compute({
            ...input,
            numShards: input.numShards ?? (await client.systemState()).committee.n_shards,
        });
    }
    return client;
}

let walrusClient = createWalrusClient();
let walrusClientCreatedAtMs = Date.now();

export function getWalrusClient(): WalrusClient {
    return walrusClient;
}

export function walrusClientAgeMs(): number {
    return Date.now() - walrusClientCreatedAtMs;
}

export function refreshWalrusClient(reason: string): void {
    try {
        walrusClient.reset();
    } catch (err: any) {
        console.warn(`[walrus/client] reset failed before refresh reason=${reason}: ${err?.message || err}`);
    }
    walrusClient = createWalrusClient();
    walrusClientCreatedAtMs = Date.now();
    clearUploadRelayTipCache();
    console.warn(`[walrus/client] refreshed reason=${reason}`);
}

export function refreshWalrusClientIfStale(maxAgeMs = WALRUS_CLIENT_MAX_AGE_MS): void {
    const ageMs = walrusClientAgeMs();
    if (ageMs >= maxAgeMs) {
        refreshWalrusClient(`max_age_${ageMs}ms`);
    }
}

/**
 * Fetch the Walrus on-chain System object's version (u64 -> decimal string).
 * Reads go through the version-unchecked `inner` accessor so even the
 * stale cached client returns the value it last cached. After
 * refreshWalrusClient(), the recreated client refetches fresh metadata so
 * the returned value reflects the new on-chain version.
 *
 * Safe in the error path: any failure (RPC down, API drift) returns null
 * rather than throwing — we never want diagnostic logging to mask the
 * original error.
 */
export async function fetchWalrusSystemVersion(): Promise<string | null> {
    try {
        const sys = await walrusClient.systemObject();
        const version = (sys as any)?.version;
        if (version === undefined || version === null) return null;
        return String(version);
    } catch {
        return null;
    }
}

// ============================================================
// Upload-relay tip address cache
// ============================================================

type UploadRelayTipConfigResponse = {
    send_tip?: {
        address?: string;
    };
};

let uploadRelayTipAddressCache: string | null | undefined = undefined;
let uploadRelayTipAddressCacheLoadedAtMs = 0;

export function clearUploadRelayTipCache(): void {
    uploadRelayTipAddressCache = undefined;
    uploadRelayTipAddressCacheLoadedAtMs = 0;
}

export function uploadRelayTipCacheSnapshot(): {
    status: "uninitialized" | "none" | "present";
    ageMs: number | null;
} {
    return {
        status:
            uploadRelayTipAddressCache === undefined
                ? "uninitialized"
                : uploadRelayTipAddressCache === null
                    ? "none"
                    : "present",
        ageMs: uploadRelayTipAddressCache === undefined
            ? null
            : Date.now() - uploadRelayTipAddressCacheLoadedAtMs,
    };
}

export async function getUploadRelayTipAddress(): Promise<string | null> {
    if (WALRUS_DIRECT_UPLOAD || !WALRUS_UPLOAD_RELAY_URL || WALRUS_UPLOAD_RELAY_URL === "none") {
        return null;
    }

    if (
        uploadRelayTipAddressCache !== undefined &&
        Date.now() - uploadRelayTipAddressCacheLoadedAtMs < UPLOAD_RELAY_TIP_CACHE_TTL_MS
    ) {
        return uploadRelayTipAddressCache;
    }

    try {
        const resp = await fetch(`${WALRUS_UPLOAD_RELAY_URL}/v1/tip-config`, {
            signal: AbortSignal.timeout(UPLOAD_RELAY_TIP_TIMEOUT_MS),
        });
        if (!resp.ok) {
            // Carry the HTTP status as a structured field so the strict
            // durable-path classifier treats relay outages as shared-infra
            // (budget-free) rather than burning the row's retry budget.
            const error = new Error(`tip-config request failed (${resp.status})`);
            (error as Error & { status?: number }).status = resp.status;
            throw error;
        }

        const json = await resp.json() as UploadRelayTipConfigResponse;
        const address = json.send_tip?.address;
        if (typeof address === "string" && address.startsWith("0x")) {
            uploadRelayTipAddressCache = address;
            uploadRelayTipAddressCacheLoadedAtMs = Date.now();
            return address;
        }

        uploadRelayTipAddressCache = null;
        uploadRelayTipAddressCacheLoadedAtMs = Date.now();
        return null;
    } catch (err: any) {
        console.warn(`[upload-relay] could not load tip-config: ${err.message || err}`);
        // Fail before transaction submission: omitting a required relay tip can
        // turn a recoverable dependency outage into a permanently ambiguous job.
        throw err;
    }
}

export async function getSuiBalanceMist(owner: string): Promise<string | null> {
    try {
        const res: any = await (suiClient as any).getBalance({ owner, coinType: SUI_TYPE });
        const total = res?.balance?.balance ?? res?.balance?.coinBalance;
        return total != null ? String(total) : null;
    } catch (err: any) {
        console.warn(`[wallet] balance lookup failed for ${shortAddress(owner)}: ${err?.message || err}`);
        return null;
    }
}

export type WalletBalanceSnapshot = {
    walletSuiBalanceMist: string;
    walletSuiAddressBalanceMist: string;
    walletSuiCoinBalanceMist: string;
    walletSuiAddressFundedCount: number;
    walletWalBalanceFrost: string;
    walletWalAddressBalanceFrost: string;
    walletWalCoinBalanceFrost: string;
    walletWalAddressFundedCount: number;
    perWallet: Array<{
        address: string;
        walletIndex: number;
        suiMist: string;
        suiAddressBalanceMist: string;
        walFrost: string;
        walAddressBalanceFrost: string;
    }>;
};

const BALANCE_RPC_TIMEOUT_MS = 1_500;
let walCoinTypePromise: Promise<string> | undefined;
let walletBalanceSnapshotPromise: Promise<WalletBalanceSnapshot> | undefined;

function getWalCoinType(): Promise<string> {
    walCoinTypePromise ??= suiClient.movePackageService.getFunction(
        {
            packageId: WALRUS_PACKAGE_ID,
            moduleName: "staking",
            name: "stake_with_pool",
        },
        { timeout: BALANCE_RPC_TIMEOUT_MS },
    ).then(({ response }) => {
        const typeName =
            response.function?.parameters[1]?.body?.typeParameterInstantiation[0]?.typeName;
        if (!typeName) {
            throw new Error("canonical WAL coin type not found");
        }
        return normalizeStructTag(typeName);
    }).catch((error) => {
        walCoinTypePromise = undefined;
        throw error;
    });
    return walCoinTypePromise;
}

async function listAllBalances(owner: string) {
    const balances = [];
    let pageToken: Uint8Array | undefined;
    do {
        const { response } = await suiClient.stateService.listBalances(
            { owner, pageSize: 1_000, pageToken },
            { timeout: BALANCE_RPC_TIMEOUT_MS },
        );
        balances.push(...response.balances);
        pageToken = response.nextPageToken?.length ? response.nextPageToken : undefined;
    } while (pageToken);
    return balances;
}

async function loadWalletBalanceSnapshot(owners: string[]): Promise<WalletBalanceSnapshot> {
    const [walType, balancesByOwner] = await Promise.all([
        getWalCoinType(),
        Promise.all(owners.map(listAllBalances)),
    ]);
    let suiBalanceMist = 0n;
    let suiAddressBalanceMist = 0n;
    let suiCoinBalanceMist = 0n;
    let walBalanceFrost = 0n;
    let walAddressBalanceFrost = 0n;
    let walCoinBalanceFrost = 0n;
    let suiAddressFundedCount = 0;
    let walAddressFundedCount = 0;
    const suiType = normalizeStructTag(SUI_TYPE);
    const perWallet: WalletBalanceSnapshot["perWallet"] = [];
    balancesByOwner.forEach((balances, index) => {
        let ownerSuiAddressBalance = 0n;
        let ownerWalAddressBalance = 0n;
        let ownerSuiTotal = 0n;
        let ownerWalTotal = 0n;
        for (const balance of balances) {
            if (!balance.coinType) {
                throw new Error("Sui gRPC balance entry has no coin type");
            }
            const coinType = normalizeStructTag(balance.coinType);
            const total = balance.balance ?? 0n;
            const address = balance.addressBalance ?? 0n;
            const coins = balance.coinBalance ?? total - address;
            if (coinType === suiType) {
                suiBalanceMist += total;
                suiAddressBalanceMist += address;
                suiCoinBalanceMist += coins;
                ownerSuiAddressBalance += address;
                ownerSuiTotal += total;
            } else if (coinType === walType) {
                walBalanceFrost += total;
                walAddressBalanceFrost += address;
                walCoinBalanceFrost += coins;
                ownerWalAddressBalance += address;
                ownerWalTotal += total;
            }
        }
        if (ownerSuiAddressBalance > 0n) suiAddressFundedCount += 1;
        if (ownerWalAddressBalance > 0n) walAddressFundedCount += 1;
        perWallet.push({
            address: owners[index],
            walletIndex: index,
            suiMist: ownerSuiTotal.toString(),
            suiAddressBalanceMist: ownerSuiAddressBalance.toString(),
            walFrost: ownerWalTotal.toString(),
            walAddressBalanceFrost: ownerWalAddressBalance.toString(),
        });
    });
    return {
        walletSuiBalanceMist: suiBalanceMist.toString(),
        walletSuiAddressBalanceMist: suiAddressBalanceMist.toString(),
        walletSuiCoinBalanceMist: suiCoinBalanceMist.toString(),
        walletSuiAddressFundedCount: suiAddressFundedCount,
        walletWalBalanceFrost: walBalanceFrost.toString(),
        walletWalAddressBalanceFrost: walAddressBalanceFrost.toString(),
        walletWalCoinBalanceFrost: walCoinBalanceFrost.toString(),
        walletWalAddressFundedCount: walAddressFundedCount,
        perWallet,
    };
}

export function getWalletBalanceSnapshot(owners: string[]): Promise<WalletBalanceSnapshot> {
    walletBalanceSnapshotPromise ??= loadWalletBalanceSnapshot(owners).finally(() => {
        walletBalanceSnapshotPromise = undefined;
    });
    return walletBalanceSnapshotPromise;
}
