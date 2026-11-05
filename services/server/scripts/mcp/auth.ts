/**
 * =============================================================================
 * MCP AUTH — Delegate-key Bearer resolution
 * =============================================================================
 * Walrus Memory MCP authenticates each session with a delegate key (Ed25519 private)
 * passed via the `Authorization: Bearer <hex>` header. The Walrus Memory account id
 * comes from a second header (`X-MemWal-Account-Id`) so the same delegate key
 * can be registered against multiple accounts.
 *
 * No OAuth flow — Walrus Memory's on-chain delegate-key model IS the auth. The
 * relayer already verifies the delegate key is registered against the account
 * on its first signed request, so we don't repeat that check here.
 *
 * Session key (stable across reconnects):
 *     delegate:${account_id}:${delegate_pubkey_hex}
 * =============================================================================
 */
import { MemWal } from "@mysten-incubation/memwal";
import { verifyInternalOrigin } from "./internal-auth.js";
import { normalizeMcpNamespace } from "./tools/util.js";

export interface MemWalSession {
    accountId: string;
    delegateKeyHex: string;
    delegatePubKeyHex: string;
    namespace?: string;
    memwal: MemWal;
    /** Relayer base URL the SDK dials. Loopback unless the deployment
     *  overrides it, so it is NOT a network identity — see
     *  `publicRelayerUrl`. MemWal keeps its own copy private, so we carry
     *  one alongside. */
    relayerUrl: string;
    /** The relayer's public origin, when the deployment states one.
     *  `memwal_health` reports it so a client pointed at the wrong network
     *  sees that, rather than discovering it via missing memories. Unset
     *  when the sidecar only knows the loopback address it dials. */
    publicRelayerUrl?: string;
    authMethod: "delegate-key";
    oauthScope?: string;
    /** Stable coding-agent id (`claude-code`, `codex`, `other`, …). */
    agentClient?: string;
    /** Raw MCP `clientInfo.name` after sanitizing. */
    clientName?: string;
    clientVersion?: string;
}

export interface AuthResolution {
    session: MemWalSession;
    sessionKey: string;
}

export class McpAuthError extends Error {
    readonly status: number;
    constructor(message: string, status = 401) {
        super(message);
        this.name = "McpAuthError";
        this.status = status;
    }
}

const HEX64_RE = /^(0x)?[0-9a-fA-F]{64}$/;

/**
 * Canonical form of a scope string for use in the session key: deduplicated,
 * sorted, single-space separated. Order and repetition carry no meaning, so
 * `"memwal:write memwal:read"` and `"memwal:read memwal:read memwal:write"`
 * must not open two distinct sessions. Absent scope collapses to `""`.
 */
export function normalizeScope(scope: string | undefined): string {
    return [...new Set(scope?.split(/\s+/).filter(Boolean) ?? [])].sort().join(" ");
}

/**
 * Derive the Ed25519 public-key hex from a private-key hex (32-byte seed).
 * Lazy import so we don't pull crypto into module init.
 */
async function publicKeyHex(privateKeyHex: string): Promise<string> {
    const { getPublicKeyAsync } = await import("@noble/ed25519");
    const seedHex = privateKeyHex.startsWith("0x")
        ? privateKeyHex.slice(2)
        : privateKeyHex;
    const seed = hexToBytes(seedHex);
    const pub = await getPublicKeyAsync(seed);
    return bytesToHex(pub);
}

function hexToBytes(hex: string): Uint8Array {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}

function bytesToHex(b: Uint8Array): string {
    return Array.from(b)
        .map((x) => x.toString(16).padStart(2, "0"))
        .join("");
}

/**
 * Resolve auth from incoming HTTP headers.
 *
 * Required headers:
 *     X-MemWal-Internal-Sidecar-Token: <SIDECAR_AUTH_TOKEN>
 *     Authorization: Bearer <ed25519-private-key-hex>     (64 hex chars)
 *     X-MemWal-Account-Id: 0x<sui-object-id>             (66 chars)
 * Optional:
 *     X-MemWal-Namespace: <namespace>                    (default per-tool)
 *     X-MemWal-Internal-Oauth-Scope: <space-separated>   (relayer-issued)
 *
 * The internal token is checked first: `x-memwal-internal-*` headers state
 * decisions the relayer already made, so only the relayer may set them. An
 * absent scope grants no tools — see tools/index.ts.
 *
 * Throws McpAuthError on missing / malformed credentials.
 */
export async function resolveAuth(
    headers: Headers,
    serverUrl: string,
    publicRelayerUrl?: string
): Promise<AuthResolution> {
    // Runs before anything else reads the request: `x-memwal-internal-*`
    // headers carry decisions the relayer already made, so a caller that
    // cannot prove it is the relayer must not be able to state them.
    if (!verifyInternalOrigin(headers)) {
        throw new McpAuthError(
            "Request did not originate from the MemWal relayer",
            401
        );
    }

    const authHeader = headers.get("authorization");
    if (!authHeader || !authHeader.toLowerCase().startsWith("bearer ")) {
        throw new McpAuthError(
            "Missing Authorization: Bearer <delegate-key-hex> header"
        );
    }
    const rawKey = authHeader.slice("bearer ".length).trim();
    if (!HEX64_RE.test(rawKey)) {
        throw new McpAuthError(
            "Bearer token must be a 64-char hex Ed25519 private key (32-byte seed)"
        );
    }
    const delegateKeyHex = rawKey.startsWith("0x") ? rawKey.slice(2) : rawKey;

    const accountId = headers.get("x-memwal-account-id");
    if (!accountId || !/^0x[0-9a-fA-F]{64}$/.test(accountId)) {
        throw new McpAuthError(
            "Missing or malformed X-MemWal-Account-Id header (0x-prefixed 64-hex Sui object id)"
        );
    }

    const rawNamespace = headers.get("x-memwal-namespace") ?? undefined;
    let namespace: string | undefined;
    if (rawNamespace !== undefined) {
        try {
            namespace = normalizeMcpNamespace(rawNamespace);
        } catch (err) {
            throw new McpAuthError((err as Error).message);
        }
    }
    const oauthScope = headers.get("x-memwal-internal-oauth-scope") ?? undefined;
    const delegatePubKeyHex = await publicKeyHex(delegateKeyHex);

    const memwal = MemWal.create({
        key: delegateKeyHex,
        accountId,
        serverUrl,
        namespace,
    });

    const session: MemWalSession = {
        accountId,
        delegateKeyHex,
        delegatePubKeyHex,
        namespace,
        memwal,
        relayerUrl: serverUrl,
        publicRelayerUrl,
        authMethod: "delegate-key",
        oauthScope,
    };

    // Session key stable across reconnects from same {account, delegate,
    // scope}. We don't include namespace because the same client can call
    // multiple namespaces in one session via per-tool overrides.
    //
    // The scope IS included: `registerTools` binds the tool set at session-open
    // time, so a session opened with write scope keeps its write tools for its
    // whole life. Without the scope in the key, a later read-only (or
    // scope-less) request would pass the session-binding check and drive that
    // write-capable transport — which would leave the fail-closed guarantee
    // holding only until initialization. Delegate keys are reused across grants
    // for the same account (`find_reusable_oauth_delegate`), so {account,
    // delegate} alone does not distinguish two grants of differing scope.
    const sessionKey = `delegate:${accountId}:${delegatePubKeyHex}:${normalizeScope(oauthScope)}`;

    return { session, sessionKey };
}
