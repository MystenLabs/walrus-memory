import { availableParallelism } from "node:os";
import { Worker } from "node:worker_threads";
import { fromHex } from "@mysten/bcs";
import type { SealClient, SessionKey } from "@mysten/seal";
import { SEAL_SERVER_CONFIGS, SEAL_THRESHOLD } from "./config.js";
import {
    decryptBonehFranklinItem,
    decryptBonehFranklinSlice,
    type DecryptBonehFranklinSliceOutput,
    type DecryptSliceItem,
} from "./seal-decrypt-crypto.mjs";
import { hasSealSessionApprovedKeys } from "./seal-session-pool.js";
import { formattedError } from "./util.js";

const DEFAULT_MAX_WORKERS = 4;
const EMPTY_TX_BYTES = new Uint8Array(0);

export function configuredDecryptWorkerCount(): number {
    const raw = process.env.SEAL_DECRYPT_WORKERS?.trim();
    if (raw !== undefined && raw !== "") {
        const parsed = Number.parseInt(raw, 10);
        if (Number.isInteger(parsed) && parsed >= 0) {
            return Math.min(parsed, 16);
        }
    }
    return Math.min(Math.max(1, availableParallelism()), DEFAULT_MAX_WORKERS);
}

const SERVER_WEIGHTS_ENTRIES: Array<[string, number]> = SEAL_SERVER_CONFIGS.map((s) => [s.objectId, s.weight]);
const SERVER_WEIGHTS_MAP = new Map<string, number>(SERVER_WEIGHTS_ENTRIES);
const TOTAL_SERVER_WEIGHT = SEAL_SERVER_CONFIGS.reduce((sum, s) => sum + s.weight, 0);

interface PendingTask {
    payload: {
        items: DecryptSliceItem[];
        derivedKeysById: Array<[string, Array<[string, Uint8Array]>]>;
        serverWeightsEntries: Array<[string, number]>;
        totalServerWeight: number;
    };
    resolve: (value: DecryptBonehFranklinSliceOutput) => void;
    reject: (reason: unknown) => void;
}

interface PoolWorker {
    worker: Worker;
    busy: boolean;
    currentTaskId: number | null;
}

let nextTaskId = 1;
const workers: PoolWorker[] = [];
const inFlightTasks = new Map<number, PendingTask>();
const taskQueue: Array<{ id: number; task: PendingTask }> = [];

function spawnPoolWorker(): PoolWorker {
    const workerUrl = new URL("./seal-decrypt-worker.mjs", import.meta.url);
    const worker = new Worker(workerUrl);
    worker.unref();
    const slot: PoolWorker = { worker, busy: false, currentTaskId: null };

    worker.on("message", (msg: { id: number; ok: boolean; output?: DecryptBonehFranklinSliceOutput; error?: string }) => {
        const pending = inFlightTasks.get(msg.id);
        inFlightTasks.delete(msg.id);
        slot.busy = false;
        slot.currentTaskId = null;
        dispatchNext();
        if (!slot.busy) {
            worker.unref();
        }
        if (!pending) return;
        if (msg.ok && msg.output) {
            pending.resolve(msg.output);
        } else {
            pending.reject(new Error(msg.error || "seal decrypt worker failed"));
        }
    });

    worker.on("error", (err) => {
        const idx = workers.indexOf(slot);
        if (idx >= 0) workers.splice(idx, 1);
        if (slot.currentTaskId !== null) {
            const pending = inFlightTasks.get(slot.currentTaskId);
            inFlightTasks.delete(slot.currentTaskId);
            slot.currentTaskId = null;
            pending?.reject(err);
        }
        dispatchNext();
    });

    worker.on("exit", (code) => {
        const idx = workers.indexOf(slot);
        if (idx >= 0) workers.splice(idx, 1);
        if (slot.currentTaskId !== null) {
            const pending = inFlightTasks.get(slot.currentTaskId);
            inFlightTasks.delete(slot.currentTaskId);
            slot.currentTaskId = null;
            pending?.reject(new Error(`seal decrypt worker exited unexpectedly (code=${code})`));
        }
        dispatchNext();
    });

    workers.push(slot);
    return slot;
}

function dispatchNext(): void {
    const maxWorkers = configuredDecryptWorkerCount();
    while (taskQueue.length > 0) {
        let idle = workers.find((w) => !w.busy);
        if (!idle && workers.length < maxWorkers) {
            idle = spawnPoolWorker();
        }
        if (!idle) break;

        const next = taskQueue.shift()!;
        idle.busy = true;
        idle.currentTaskId = next.id;
        idle.worker.ref();
        inFlightTasks.set(next.id, next.task);
        idle.worker.postMessage({ id: next.id, payload: next.task.payload });
    }
}

function runSliceOnWorker(payload: PendingTask["payload"]): Promise<DecryptBonehFranklinSliceOutput> {
    return new Promise((resolve, reject) => {
        const id = nextTaskId++;
        taskQueue.push({
            id,
            task: { payload, resolve, reject },
        });
        dispatchNext();
    });
}

export async function stopSealDecryptPool(): Promise<void> {
    const active = workers.splice(0, workers.length);
    while (taskQueue.length > 0) {
        const queued = taskQueue.shift()!;
        queued.task.reject(new Error("seal decrypt worker pool stopped"));
    }
    await Promise.allSettled(active.map((slot) => slot.worker.terminate()));
}

function cloneKeyEntries(
    rawById: Map<string, Array<[string, Uint8Array]>>,
): Array<[string, Array<[string, Uint8Array]>]> {
    return Array.from(rawById, ([id, entries]) => [
        id,
        entries.map(([objectId, bytes]) => [objectId, new Uint8Array(bytes)]),
    ]);
}

function wipeKeyMap(rawById: Map<string, Array<[string, Uint8Array]>>): void {
    for (const entries of rawById.values()) {
        for (const [, bytes] of entries) {
            bytes.fill(0);
        }
    }
    rawById.clear();
}

async function extractDerivedKeyBytesById(
    sealClient: SealClient,
    ids: string[],
    sessionKey: SessionKey,
    getTxBytes: () => Promise<Uint8Array>,
    threshold: number,
): Promise<Map<string, Array<[string, Uint8Array]>>> {
    const out = new Map<string, Array<[string, Uint8Array]>>();
    let cachedTxBytes: Uint8Array | undefined;
    for (const id of ids) {
        const txBytes = hasSealSessionApprovedKeys(sealClient, [id], threshold)
            ? EMPTY_TX_BYTES
            : (cachedTxBytes ??= await getTxBytes());
        const derivedMap = await sealClient.getDerivedKeys({
            id,
            txBytes,
            sessionKey,
            threshold,
        });
        const entries: Array<[string, Uint8Array]> = [];
        for (const [objectId, derivedKey] of derivedMap.entries()) {
            entries.push([objectId, fromHex(derivedKey.toString())]);
        }
        out.set(id, entries);
    }
    return out;
}

/**
 * Decrypt a single item using threshold-sliced Boneh-Franklin crypto with
 * automatic fallback to `sealClient.decrypt()` on unsupported modes.
 */
export async function decryptSingleSealItem(params: {
    sealClient: SealClient;
    encryptedData: Uint8Array;
    parsedObject: any;
    fullId: string;
    sessionKey: SessionKey;
    getTxBytes: () => Promise<Uint8Array>;
    assertLive?: () => void;
}): Promise<Uint8Array> {
    const { sealClient, encryptedData, parsedObject, fullId, sessionKey, getTxBytes, assertLive } = params;
    assertLive?.();
    const itemId = String(parsedObject?.id ?? fullId);
    const rawThreshold = Number(parsedObject?.threshold) || SEAL_THRESHOLD;
    const singleThreshold =
        TOTAL_SERVER_WEIGHT > 0 && rawThreshold > TOTAL_SERVER_WEIGHT
            ? SEAL_THRESHOLD
            : Math.max(SEAL_THRESHOLD, rawThreshold);
    const rawById = await extractDerivedKeyBytesById(
        sealClient,
        [itemId],
        sessionKey,
        getTxBytes,
        singleThreshold,
    );
    try {
        const entries = rawById.get(itemId) ?? [];
        const plain = decryptBonehFranklinItem({
            encryptedData,
            parsedObject,
            derivedKeysByObjectId: new Map(entries),
            serverWeights: SERVER_WEIGHTS_MAP,
            totalServerWeight: TOTAL_SERVER_WEIGHT,
        });
        assertLive?.();
        return plain;
    } catch {
        const txBytes = await getTxBytes();
        const fallback = await sealClient.decrypt({
            data: encryptedData,
            sessionKey,
            txBytes,
        });
        assertLive?.();
        return fallback;
    } finally {
        wipeKeyMap(rawById);
    }
}

/**
 * Decrypt up to 25 SEAL-encrypted items in parallel across stateless worker threads.
 * Preserves exact per-item error isolation and session-expiry guards.
 */
export async function decryptBatchSealItems(params: {
    sealClient: SealClient;
    parsedItems: DecryptSliceItem[];
    uniqueIds: string[];
    sessionKey: SessionKey;
    getTxBytes: () => Promise<Uint8Array>;
    assertLive?: () => void;
}): Promise<{
    results: Array<{ index: number; decryptedData: string }>;
    errors: Array<{ index: number; code: string; error: string }>;
}> {
    const { sealClient, parsedItems, uniqueIds, sessionKey, getTxBytes, assertLive } = params;
    if (parsedItems.length === 0) {
        return { results: [], errors: [] };
    }

    assertLive?.();
    const validThresholds = parsedItems
        .map((it) => Number(it.parsedObject?.threshold) || 0)
        .filter((t) => t >= 1 && (TOTAL_SERVER_WEIGHT <= 0 || t <= TOTAL_SERVER_WEIGHT));
    const batchThreshold = Math.max(SEAL_THRESHOLD, ...validThresholds);
    const rawById = await extractDerivedKeyBytesById(
        sealClient,
        uniqueIds,
        sessionKey,
        getTxBytes,
        batchThreshold,
    );

    try {
        const workerCount = configuredDecryptWorkerCount();
        let sliceOutputs: DecryptBonehFranklinSliceOutput[];

        if (workerCount <= 1 || parsedItems.length === 1) {
            sliceOutputs = [
                decryptBonehFranklinSlice({
                    items: parsedItems,
                    derivedKeysById: cloneKeyEntries(rawById),
                    serverWeightsEntries: SERVER_WEIGHTS_ENTRIES,
                    totalServerWeight: TOTAL_SERVER_WEIGHT,
                }),
            ];
        } else {
            const slicesCount = Math.min(workerCount, parsedItems.length);
            const sliceSize = Math.ceil(parsedItems.length / slicesCount);
            const promises: Array<Promise<DecryptBonehFranklinSliceOutput>> = [];
            for (let offset = 0; offset < parsedItems.length; offset += sliceSize) {
                const sliceItems = parsedItems.slice(offset, offset + sliceSize);
                promises.push(
                    runSliceOnWorker({
                        items: sliceItems,
                        derivedKeysById: cloneKeyEntries(rawById),
                        serverWeightsEntries: SERVER_WEIGHTS_ENTRIES,
                        totalServerWeight: TOTAL_SERVER_WEIGHT,
                    }),
                );
            }
            sliceOutputs = await Promise.all(promises);
        }

        assertLive?.();

        const results: Array<{ index: number; decryptedData: string }> = [];
        const errors: Array<{ index: number; code: string; error: string }> = [];
        const fallbackSet = new Set<number>();

        for (const out of sliceOutputs) {
            results.push(...out.results);
            errors.push(...out.errors);
            for (const idx of out.fallbackIndices) fallbackSet.add(idx);
        }

        if (fallbackSet.size > 0) {
            const txBytes = await getTxBytes();
            for (const item of parsedItems) {
                if (!fallbackSet.has(item.index)) continue;
                try {
                    const decrypted = await sealClient.decrypt({
                        data: item.encryptedData,
                        sessionKey,
                        txBytes,
                    });
                    assertLive?.();
                    results.push({
                        index: item.index,
                        decryptedData: Buffer.from(decrypted).toString("base64"),
                    });
                } catch (err) {
                    errors.push({
                        index: item.index,
                        code: "DECRYPT_FAILED",
                        error: `decrypt failed: ${formattedError(err)}`,
                    });
                }
            }
        }

        results.sort((a, b) => a.index - b.index);
        errors.sort((a, b) => a.index - b.index);
        return { results, errors };
    } finally {
        wipeKeyMap(rawById);
    }
}
