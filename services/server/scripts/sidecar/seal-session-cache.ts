import { createHash } from "crypto";
import type { SealClient } from "@mysten/seal";

/**
 * Identity of a decrypt credential whose derived-key cache may be reused.
 *
 * `fingerprint` is a SHA-256 of the credential bytes, never the credential
 * itself. `expiresAt` is the absolute wall-clock deadline for reuse; the
 * cache clamps it to its own maximum TTL.
 */
export interface SealSessionCacheKey {
    fingerprint: string;
    expiresAt: number;
}

interface CachedSessionClient {
    client: Promise<SealClient>;
    expiresAt: number;
    lastUsed: number;
}

export interface SealSessionClientCacheOptions {
    /** Maximum number of credentials retained. Default 256. */
    maxEntries?: number;
    /** Never retain keys longer than this, even if the credential claims a longer TTL. Default 5 min. */
    maxTtlMs?: number;
    /** Injectable clock for tests. */
    now?: () => number;
}

/**
 * Legacy `x-delegate-key` calls have no client-side session expiry. Bound
 * their reuse to one minute — long enough for a burst of recalls, short enough
 * that a key revoked on-chain stops decrypting promptly. The production
 * `x-seal-session` path uses the session's own (five-minute) deadline instead.
 */
export const SEAL_LEGACY_KEY_CACHE_TTL_MS = 60 * 1000;

/**
 * Derive the cache key for an exported `x-seal-session` header.
 *
 * The SDK reuses the exact exported bytes for the whole SessionKey lifetime,
 * so hashing the header gives one cache entry per client session. A session
 * that omits `creationTimeMs` / `ttlMin` is not cacheable: without a deadline
 * we cannot bound how long a derived key would stay resident.
 */
export function sessionCacheKeyFromExportedSession(
    header: string,
    exported: { creationTimeMs?: unknown; ttlMin?: unknown },
): SealSessionCacheKey | undefined {
    const creationTimeMs = Number(exported.creationTimeMs);
    const ttlMin = Number(exported.ttlMin);
    if (!Number.isFinite(creationTimeMs) || !Number.isFinite(ttlMin) || ttlMin <= 0) {
        return undefined;
    }
    return {
        fingerprint: createHash("sha256").update(header).digest("hex"),
        expiresAt: creationTimeMs + ttlMin * 60_000,
    };
}

/**
 * Derive the cache key for the deprecated `x-delegate-key` path.
 *
 * The delegate key is itself a long-lived decryption credential (it can mint
 * SessionKeys), so caching the derived keys it authorizes for five minutes
 * adds no capability the caller did not already have. The fingerprint still
 * isolates different delegate keys from each other.
 */
export function delegateKeyCacheKey(privateKey: string, now: number = Date.now()): SealSessionCacheKey {
    return {
        fingerprint: createHash("sha256").update(`delegate:${privateKey}`).digest("hex"),
        expiresAt: now + SEAL_LEGACY_KEY_CACHE_TTL_MS,
    };
}

/**
 * Bounded, credential-scoped cache of SealClients.
 *
 * `SealClient` keeps derived keys in an internal map keyed by
 * `(package id, encrypted-object id, key-server id)`. A cached derived key is
 * enough to decrypt its object without another key-server round-trip, which
 * is the dominant cost of a recall (roughly one second per 25-object batch in
 * production). The SDK's key map is deliberately NOT scoped to the
 * SessionKey that fetched a key, so a process-wide client would let one
 * authenticated caller reuse a key another caller obtained. This cache never
 * shares an entry between fingerprints: a credential only reuses keys it
 * fetched itself.
 *
 * Entries expire at the credential's own deadline (clamped to `maxTtlMs`) and
 * the map is LRU-bounded, so a stream of unique credentials cannot grow
 * memory without bound. @mysten/seal 1.1.0's `SealClient` does not expose its
 * key map, so eviction here is the only way to bound it.
 */
export function createSealSessionClientCache(
    createClient: () => Promise<SealClient>,
    options: SealSessionClientCacheOptions = {},
): { get(key: SealSessionCacheKey): Promise<SealClient>; reset(): void; size(): number } {
    const maxEntries = options.maxEntries ?? 256;
    const maxTtlMs = options.maxTtlMs ?? 5 * 60 * 1000;
    const now = options.now ?? Date.now;
    const entries = new Map<string, CachedSessionClient>();

    function evictExpired(nowMs: number): void {
        for (const [fingerprint, entry] of entries) {
            if (entry.expiresAt <= nowMs) entries.delete(fingerprint);
        }
    }

    function evictLeastRecentlyUsed(): void {
        while (entries.size > maxEntries) {
            let oldestFingerprint: string | undefined;
            let oldestUsed = Infinity;
            for (const [fingerprint, entry] of entries) {
                if (entry.lastUsed < oldestUsed) {
                    oldestUsed = entry.lastUsed;
                    oldestFingerprint = fingerprint;
                }
            }
            if (oldestFingerprint === undefined) return;
            entries.delete(oldestFingerprint);
        }
    }

    return {
        async get(key) {
            const nowMs = now();
            evictExpired(nowMs);
            const existing = entries.get(key.fingerprint);
            if (existing && existing.expiresAt > nowMs) {
                existing.lastUsed = nowMs;
                return existing.client;
            }
            if (existing) entries.delete(key.fingerprint);

            const expiresAt = Math.min(key.expiresAt, nowMs + maxTtlMs);
            const entry: CachedSessionClient = {
                // Promise.resolve().then(...) turns a synchronous throw in
                // createClient into a rejection the caller can observe.
                client: Promise.resolve().then(createClient),
                expiresAt,
                lastUsed: nowMs,
            };

            // A credential already at its deadline still gets a client (so the
            // SDK/route can report the real expiry), but is not retained.
            if (expiresAt > nowMs) {
                // Insert before returning so concurrent requests for the same
                // credential share one client and one key-server fetch.
                entries.set(key.fingerprint, entry);
                // A failed creation must not poison the entry: the next request
                // should retry rather than reuse a rejected promise.
                entry.client.catch(() => {
                    if (entries.get(key.fingerprint) === entry) {
                        entries.delete(key.fingerprint);
                    }
                });
                evictLeastRecentlyUsed();
            }

            return entry.client;
        },
        reset() {
            entries.clear();
        },
        size() {
            return entries.size;
        },
    };
}
