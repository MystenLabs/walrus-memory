import { createHash } from "node:crypto";
import { normalizeSuiAddress } from "@mysten/sui/utils";
import type { SealClient } from "@mysten/seal";

export interface SessionClientInput {
    /** Exact opaque header; hashed, never retained or logged. Legacy keys must not use this pool. */
    header: string;
    expiresAt: number;
    /** Includes network, immutable/executable packages, account, registry and committee. */
    scope: string[];
    ids: string[];
}

interface Entry {
    expiresAt: number;
    credentialExpiresAt: number;
    idleUntil: number;
    ids: Set<string>;
    approvedThresholds: Map<string, number>;
    client: Promise<SealClient>;
}

const liveGuards = new WeakMap<SealClient, () => void>();
const approvedKeyMaps = new WeakMap<SealClient, Map<string, number>>();

export function assertSealSessionClientLive(client: SealClient): void {
    liveGuards.get(client)?.();
}

export function hasSealSessionApprovedKeys(
    client: SealClient,
    ids: readonly string[],
    threshold: number,
): boolean {
    const guard = liveGuards.get(client);
    const approved = approvedKeyMaps.get(client);
    if (!guard || !approved || ids.length === 0) return false;
    guard();
    return ids.every((id) => (approved.get(id) ?? 0) >= threshold);
}

/**
 * Cache derived keys only for an exact session AND current authorization state.
 * readState is deliberately invoked on EVERY lookup, including hits. It must
 * fail closed and return current versions/digests of every mutable object read
 * by account::seal_approve (account + registry). A changed object forces a new
 * client and therefore another key-server policy evaluation. There is no stale
 * authorization fallback, and no caching of deprecated delegate-key headers.
 */
export function createSealSessionPool(
    createClient: () => Promise<SealClient>,
    readState: (scope: string[]) => Promise<string>,
    options: { now?: () => number; maxEntries?: number; maxIds?: number; idleMs?: number } = {},
) {
    const now = options.now ?? Date.now;
    const maxEntries = options.maxEntries ?? 256;
    const maxIds = options.maxIds ?? 128;
    const idleMs = options.idleMs ?? 60_000;
    if (!Number.isInteger(maxEntries) || maxEntries < 1 || !Number.isInteger(maxIds) || maxIds < 1 || idleMs <= 0) {
        throw new Error("Invalid SEAL session pool bounds");
    }
    const entries = new Map<string, Entry>();
    const counters = { hit: 0, miss: 0, expiry: 0, lru: 0, capacity: 0, keyJoin: 0, failure: 0 };

    function sweep() {
        const time = now();
        for (const [key, entry] of entries) {
            if (entry.expiresAt <= time || entry.idleUntil <= time) {
                entries.delete(key);
                counters.expiry++;
            }
        }
    }

    // Evict resident key maps even if traffic stops; guards still enforce the
    // exact expiry synchronously. The unref'd timer never keeps a process alive.
    const cleanup = setInterval(sweep, Math.min(idleMs, 10_000));
    cleanup.unref();

    return {
        async get(input: SessionClientInput): Promise<SealClient> {
            if (!input.header || !Number.isFinite(input.expiresAt) || input.expiresAt <= now()) {
                throw new Error("SEAL session expired");
            }
            // Do not reuse a cached client if either live read fails. No raw
            // credential or object JSON is stored in the scope fingerprint.
            const state = await readState(input.scope);
            if (input.expiresAt <= now()) throw new Error("SEAL session expired");
            sweep();
            const key = createHash("sha256").update(JSON.stringify([input.header, input.scope, state])).digest("hex");
            const ids = new Set(input.ids);
            if (ids.size > maxIds) throw new Error("SEAL request exceeds session key budget");
            let entry = entries.get(key);
            if (entry && new Set([...entry.ids, ...ids]).size > maxIds) {
                entries.delete(key);
                counters.capacity++;
                entry = undefined;
            }
            if (entry) {
                counters.hit++;
                ids.forEach(id => entry!.ids.add(id));
                entry.idleUntil = Math.min(entry.expiresAt, now() + idleMs);
                entries.delete(key); entries.set(key, entry); // O(1) LRU touch.
            } else {
                counters.miss++;
                const expiresAt = Math.min(input.expiresAt, now() + 300_000);
                entry = {
                    expiresAt,
                    credentialExpiresAt: input.expiresAt,
                    idleUntil: Math.min(expiresAt, now() + idleMs),
                    ids,
                    approvedThresholds: new Map(),
                    client: undefined!,
                };
                const current = entry;
                const assertLive = () => {
                    if (now() >= current.credentialExpiresAt) throw new Error("SEAL session expired");
                };
                entry.client = Promise.resolve().then(createClient).then(client => {
                    assertLive();
                    liveGuards.set(client, assertLive);
                    approvedKeyMaps.set(client, current.approvedThresholds);
                    // Wrap the SDK method too: client.decrypt() internally
                    // calls fetchKeys(), so cold chunks share the actual key
                    // fetch, not just construction of a shared client.
                    const originalFetch = client.fetchKeys.bind(client);
                    const pending = new Map<string, Promise<void>>();
                    client.fetchKeys = async args => {
                        assertLive();
                        if (args.ids.some(id => !current.ids.has(id))) throw new Error("Unreserved SEAL identity");
                        const fetchKey = JSON.stringify([[...new Set(args.ids)].sort(), args.threshold]);
                        let work = pending.get(fetchKey);
                        if (work) counters.keyJoin++;
                        else {
                            work = Promise.resolve().then(() => originalFetch(args));
                            pending.set(fetchKey, work);
                        }
                        try {
                            await work;
                            assertLive();
                            for (const id of args.ids) {
                                const prev = current.approvedThresholds.get(id) ?? 0;
                                if (args.threshold > prev) current.approvedThresholds.set(id, args.threshold);
                            }
                        } catch (err) {
                            counters.failure++;
                            if (entries.get(key) === current) entries.delete(key);
                            throw err;
                        } finally {
                            if (pending.get(fetchKey) === work) pending.delete(fetchKey);
                        }
                    };
                    if (typeof client.getDerivedKeys === "function") {
                        const originalGetDerivedKeys = client.getDerivedKeys.bind(client);
                        client.getDerivedKeys = async args => {
                            assertLive();
                            if (!current.ids.has(args.id)) throw new Error("Unreserved SEAL identity");
                            const derived = await originalGetDerivedKeys(args);
                            assertLive();
                            return derived;
                        };
                    }
                    const originalDecrypt = client.decrypt.bind(client);
                    client.decrypt = async args => {
                        assertLive();
                        const value = await originalDecrypt(args);
                        assertLive();
                        return value;
                    };
                    return client;
                }).catch(err => {
                    if (entries.get(key) === current) entries.delete(key);
                    throw err;
                });
                entries.set(key, entry);
                while (entries.size > maxEntries) {
                    entries.delete(entries.keys().next().value!);
                    counters.lru++;
                }
            }
            return entry.client;
        },
        reset() { entries.clear(); },
        stats() { sweep(); return { ...counters, entries: entries.size }; },
    };
}

interface InFlightAuthRead {
    token: symbol;
    promise: Promise<string>;
}

const MAX_SHARED_VERSION_CACHE = 1024;
const sharedInitialVersions = new Map<string, string>();
const inFlightAuthReads = new WeakMap<object, Map<string, InFlightAuthRead>>();

function canonicalObjectKey(objectId: string): string {
    return /^0x[0-9a-fA-F]{1,64}$/.test(objectId) ? normalizeSuiAddress(objectId) : objectId;
}

function recordInitialSharedVersion(objectId: string, owner: unknown): void {
    const sharedVersion = (owner as { Shared?: { initialSharedVersion?: unknown } } | null | undefined)
        ?.Shared?.initialSharedVersion;
    const text = sharedVersion !== undefined && sharedVersion !== null ? String(sharedVersion) : "";
    if (!/^\d+$/.test(text)) return;
    const key = canonicalObjectKey(objectId);
    if (sharedInitialVersions.has(key)) {
        sharedInitialVersions.delete(key);
    } else if (sharedInitialVersions.size >= MAX_SHARED_VERSION_CACHE) {
        sharedInitialVersions.delete(sharedInitialVersions.keys().next().value!);
    }
    sharedInitialVersions.set(key, text);
}

export function getCachedInitialSharedVersion(objectId: string): string | undefined {
    return sharedInitialVersions.get(canonicalObjectKey(objectId));
}

export function clearCachedInitialSharedVersionsForTests(): void {
    sharedInitialVersions.clear();
}

function withReadTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeoutPromise = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`SEAL authorization state read timed out after ${timeoutMs}ms`)), timeoutMs);
        timer.unref?.();
    });
    return Promise.race([promise, timeoutPromise]).finally(() => {
        if (timer !== undefined) clearTimeout(timer);
    });
}

type AuthObjectShape = {
    version?: unknown;
    digest?: unknown;
    owner?: unknown;
} | null | undefined;

export type SealAuthorizationVersionReader = {
    getObject: (input: { objectId: string; signal?: AbortSignal }) => Promise<{
        object?: AuthObjectShape;
    }>;
    getObjects?: (input: { objectIds: string[] }) => Promise<{
        objects: Array<AuthObjectShape | Error>;
    }>;
};

function validateAuthObject(objectId: string, object: AuthObjectShape): [string, string, string] {
    if (!object || object instanceof Error || !/^\d+$/.test(String(object.version)) || typeof object.digest !== "string" || !object.digest) {
        throw new Error("Cannot verify current SEAL authorization state");
    }
    recordInitialSharedVersion(objectId, object.owner);
    return [objectId, String(object.version), String(object.digest)];
}

/**
 * Read only stable version/digest metadata; never trust caller-supplied versions.
 * Uses `getObjects` (`BatchGetObjects`) when available to collapse two unary gRPC
 * calls into one, and coalesces strictly concurrent in-flight reads for the same
 * `(accountId, registryId)` with zero post-settlement retention.
 */
export async function readSealAuthorizationVersions(
    client: SealAuthorizationVersionReader,
    accountId: string,
    registryId: string,
): Promise<string> {
    let perClient = inFlightAuthReads.get(client);
    if (!perClient) {
        perClient = new Map();
        inFlightReadsSet(client, perClient);
    }
    const flightKey = `${accountId}\0${registryId}`;
    const existing = perClient.get(flightKey);
    if (existing) return await existing.promise;

    const token = Symbol("seal-auth-read");
    const promise = (async () => {
        if (typeof client.getObjects === "function") {
            const batch = await withReadTimeout(
                client.getObjects({ objectIds: [accountId, registryId] }),
                5_000,
            );
            if (!Array.isArray(batch?.objects) || batch.objects.length !== 2) {
                throw new Error("Cannot verify current SEAL authorization state");
            }
            const entries = [
                validateAuthObject(accountId, batch.objects[0] as AuthObjectShape),
                validateAuthObject(registryId, batch.objects[1] as AuthObjectShape),
            ];
            return JSON.stringify(entries);
        }

        const objects = await Promise.all([accountId, registryId].map(async objectId => {
            const result = await client.getObject({ objectId, signal: AbortSignal.timeout(5_000) });
            return validateAuthObject(objectId, result?.object);
        }));
        return JSON.stringify(objects);
    })();

    perClient.set(flightKey, { token, promise });
    try {
        return await promise;
    } finally {
        if (perClient.get(flightKey)?.token === token) {
            perClient.delete(flightKey);
        }
    }
}

function inFlightReadsSet(client: object, map: Map<string, InFlightAuthRead>): void {
    inFlightAuthReads.set(client, map);
}
