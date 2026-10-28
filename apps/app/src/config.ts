/**
 * App-wide configuration from environment variables
 */
import { requiredMemwalIds } from './requiredMemwalIds'

const DEFAULT_ANALYTICS_ALLOWED_HOSTS = 'walrus.xyz,www.walrus.xyz'

function parseCsv(value: string | undefined, fallback = '') {
    return (value || fallback)
        .split(',')
        .map(s => s.trim())
        .filter(Boolean)
}

const { memwalPackageId, memwalRegistryId } = requiredMemwalIds({
    VITE_MEMWAL_PACKAGE_ID: import.meta.env.VITE_MEMWAL_PACKAGE_ID as string | undefined,
    VITE_MEMWAL_REGISTRY_ID: import.meta.env.VITE_MEMWAL_REGISTRY_ID as string | undefined,
})
const sealKeyServers = parseCsv(import.meta.env.VITE_SEAL_KEY_SERVERS as string)
const legacySealKeyServers = parseCsv(import.meta.env.VITE_LEGACY_SEAL_KEY_SERVERS as string)
const localE2eJsonRpc = import.meta.env.DEV &&
    (import.meta.env.VITE_SUI_LOCAL_E2E_JSON_RPC as string || '') === 'true'

export const config = {
    enokiApiKey: import.meta.env.VITE_ENOKI_API_KEY as string || '',
    googleClientId: import.meta.env.VITE_GOOGLE_CLIENT_ID as string || '',
    memwalPackageId,
    memwalRegistryId,
    // Legacy-deployment ids for the security-delete surface. The exposed
    // blobs were Seal-encrypted under the PRE-cutover package, and Seal
    // decryption is package-bound (identity namespace + seal_approve policy
    // + the Account object's type all live in that package) — after cutover
    // ships a new package, the preview must keep talking to the old one,
    // exactly like the server keeps LEGACY_DB_URL next to DATABASE_URL.
    // Unset falls back to the current ids, so pre-cutover deployments need
    // no configuration change.
    legacyMemwalPackageId: import.meta.env.VITE_LEGACY_MEMWAL_PACKAGE_ID as string || memwalPackageId,
    legacyMemwalRegistryId: import.meta.env.VITE_LEGACY_MEMWAL_REGISTRY_ID as string || memwalRegistryId,
    // Target of the pre-migration cleanup notice's guide link.
    securityGuideUrl: import.meta.env.VITE_SECURITY_GUIDE_URL as string ||
        'https://docs.wal.app/walrus-memory/guides/delete-old-memories',
    // Date the v1 → v1_new security migration completed. Shown in the
    // pre-migration delete card.
    migrationCompletedDate: import.meta.env.VITE_MIGRATION_COMPLETED_DATE as string ||
        'July 30, 2026',
    memwalServerUrl: import.meta.env.VITE_MEMWAL_SERVER_URL as string || 'http://localhost:8000',
    suiNetwork: (import.meta.env.VITE_SUI_NETWORK as string || 'testnet') as 'testnet' | 'mainnet',
    // The local browser suite gets a distinct dapp-kit/wallet chain identity;
    // protocol package defaults still intentionally use suiNetwork above.
    suiClientNetwork: localE2eJsonRpc ? 'localnet' as const :
        (import.meta.env.VITE_SUI_NETWORK as 'testnet' | 'mainnet' || 'testnet'),
    // JSON-RPC endpoint override for the app's shared Sui client. For a real
    // network it applies only to the active network; the local browser suite
    // also uses it for its explicit localnet escape hatch.
    suiRpcUrl: import.meta.env.VITE_SUI_RPC_URL as string || '',
    localE2eJsonRpc,
    // gRPC endpoint used by the security-delete subsystem's dedicated client.
    suiGrpcUrl: import.meta.env.VITE_SUI_GRPC_URL as string || '',
    sealKeyServers,
    // Same cutover rationale as legacyMemwalPackageId: legacy blobs were
    // encrypted against the pre-cutover key-server committee. Unset falls
    // back to the current set.
    legacySealKeyServers: legacySealKeyServers.length > 0 ? legacySealKeyServers : sealKeyServers,
    // Walrus aggregator read fallback for the security-delete preview.
    // WalrusClient.readBlob() resolves storage-node URLs from on-chain
    // committee data and always dials them over `https://`
    // (@mysten/walrus's WalrusClient hardcodes the scheme) — against a
    // local devstack cluster, that on-chain-advertised address is a
    // Docker-internal hostname unreachable from the browser, and even
    // devstack's router-exposed alias for the node only answers plain
    // HTTP. There is no WalrusClient config hook to remap this. Empty (the
    // default) preserves today's behavior exactly (direct node quorum
    // reads); set to an aggregator base URL to fetch the decoded blob
    // bytes via a plain HTTP GET instead. See utils/blobPreview.ts.
    walrusAggregatorUrl: import.meta.env.VITE_WALRUS_AGGREGATOR_URL as string || '',
    // Walrus package config override, mirroring the sidecar's
    // WALRUS_SYSTEM_OBJECT_ID/WALRUS_STAKING_POOL_ID (see
    // services/server/scripts/sidecar/clients.ts createWalrusClient).
    // WalrusClient only resolves package/staking ids itself for
    // "mainnet"/"testnet" — a devstack localnet needs them supplied
    // directly, or every WalrusClient call that touches on-chain package
    // state (including blobPreview.ts's aggregator-bytes blob id check)
    // resolves the wrong (real testnet) system object and fails. Empty
    // (the default) keeps using `suiNetwork`'s built-in config.
    walrusSystemObjectId: import.meta.env.VITE_WALRUS_SYSTEM_OBJECT_ID as string || '',
    walrusStakingPoolId: import.meta.env.VITE_WALRUS_STAKING_POOL_ID as string || '',
    sidecarUrl: import.meta.env.VITE_SIDECAR_URL as string || 'http://localhost:9000',
    docsUrl: import.meta.env.VITE_DOCS_URL as string ||
        'https://docs.wal.app/walrus-memory/',
    termsOfServiceUrl: import.meta.env.VITE_TERMS_OF_SERVICE_URL as string ||
        'https://docs.wal.app/docs/legal/walrus_general_tos',
    privacyPolicyUrl: import.meta.env.VITE_PRIVACY_POLICY_URL as string ||
        'https://docs.wal.app/docs/legal/privacy',
    // "Back to Console" target (WALM-675). Never read from a URL query param,
    // since that's the trust model WALM-288 broke. A set VITE_CONSOLE_URL
    // wins; otherwise this is the Memory tab for the active network.
    // WM only appends from=wm, and Console's return flow runs on that tab.
    consoleUrl: import.meta.env.VITE_CONSOLE_URL as string ||
        ((import.meta.env.VITE_SUI_NETWORK as string || 'testnet') === 'mainnet'
            ? 'https://console.walrus.xyz/buckets?tab=memory'
            : 'https://testnet.console.walrus.xyz/buckets?tab=memory'),
    gtmContainerId: import.meta.env.VITE_GTM_CONTAINER_ID as string || '',
    gaMeasurementId: import.meta.env.VITE_GA_MEASUREMENT_ID as string || '',
    posthogProjectApiKey: (
        (import.meta.env.VITE_POSTHOG_PROJECT_API_KEY as string | undefined) ||
        (import.meta.env.VITE_POSTHOG_KEY as string | undefined) ||
        ''
    ),
    posthogHost: import.meta.env.VITE_POSTHOG_HOST as string || 'https://t.walrus.xyz',
    posthogUiHost: import.meta.env.VITE_POSTHOG_UI_HOST as string || 'https://us.posthog.com',
    // Client SDK key. Blank disables Statsig. This is not a server secret.
    statsigClientKey: import.meta.env.VITE_STATSIG_CLIENT_KEY as string || '',
    analyticsAllowedHosts: parseCsv(
        import.meta.env.VITE_ANALYTICS_ALLOWED_HOSTS as string | undefined,
        DEFAULT_ANALYTICS_ALLOWED_HOSTS,
    ),
    // Dashboard Walrus Console button and "View your memories" card.
    // Off unless explicitly enabled.
    walrusConsoleEnabled: (import.meta.env.VITE_WALRUS_CONSOLE_ENABLED as string || '') === 'true',
    // Permanent V1 memory deletion UI. Off by default so nothing
    // is user-visible until the feature is tested and rollout is agreed.
    // Must be enabled together with the relayer's ENABLE_MEMORY_DELETION.
    enableMemoryDeletion: (import.meta.env.VITE_ENABLE_MEMORY_DELETION as string || '') === 'true',
    securityDeleteEnabled: (import.meta.env.VITE_SECURITY_DELETE_ENABLED as string || '') === 'true',
    demoUrls: (import.meta.env.VITE_DEMO_URLS as string || '')
        .split(',').map(s => s.trim()).filter(Boolean)
        .map(entry => {
            const [label, url] = entry.split('|').map(s => s.trim())
            return url ? { label, url } : { label: label, url: label }
        }),
} as const
