/**
 * Stateless CPU worker thread for Boneh-Franklin BLS12-381 batch decryption.
 * Holds zero session state or cached keys between messages; key buffers are
 * wiped inside `decryptBonehFranklinSlice`'s `finally` block on every task.
 */
import { parentPort } from "node:worker_threads";
import { decryptBonehFranklinSlice } from "./seal-decrypt-crypto.mjs";

if (!parentPort) {
    throw new Error("seal-decrypt-worker must run as a worker_threads Worker");
}

parentPort.on("message", (task) => {
    const { id, payload } = task;
    try {
        const output = decryptBonehFranklinSlice(payload);
        parentPort.postMessage({ id, ok: true, output });
    } catch (err) {
        parentPort.postMessage({
            id,
            ok: false,
            error: err instanceof Error ? err.message : String(err),
        });
    }
});
