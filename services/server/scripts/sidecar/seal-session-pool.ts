import { createHash } from "node:crypto";
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
    client: Promise<SealClient>;
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
                entry = { expiresAt, credentialExpiresAt: input.expiresAt,
                    idleUntil: Math.min(expiresAt, now() + idleMs), ids, client: undefined! };
                const current = entry;
                const assertLive = () => {
                    if (now() >= current.credentialExpiresAt) throw new Error("SEAL session expired");
                };
                entry.client = Promise.resolve().then(createClient).then(client => {
                    assertLive();
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
                        try { await work; assertLive(); }
                        catch (err) {
                            counters.failure++;
                            if (entries.get(key) === current) entries.delete(key);
                            throw err;
                        } finally {
                            if (pending.get(fetchKey) === work) pending.delete(fetchKey);
                        }
                    };
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

/** Read only stable version/digest metadata; never trust caller-supplied versions. */
export async function readSealAuthorizationVersions(
    client: { getObject: (input: { objectId: string; signal?: AbortSignal }) => Promise<{
        object?: { version?: unknown; digest?: unknown } | null;
    }> },
    accountId: string,
    registryId: string,
): Promise<string> {
    const objects = await Promise.all([accountId, registryId].map(async objectId => {
        const result = await client.getObject({ objectId, signal: AbortSignal.timeout(5_000) });
        const object = result?.object;
        if (!object || !/^\d+$/.test(String(object.version)) || typeof object.digest !== "string" || !object.digest) {
            throw new Error("Cannot verify current SEAL authorization state");
        }
        return [objectId, String(object.version), String(object.digest)];
    }));
    return JSON.stringify(objects);
}
