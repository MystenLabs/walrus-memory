import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { parentPort, workerData } from 'node:worker_threads';

// The worker only imports the pure encoder. It cannot make an RPC or HTTP call.
globalThis.fetch = async () => { throw new Error('Metadata worker network access is disabled'); };
assert.ok(parentPort, 'Metadata worker requires a coordinator');
for (const file of workerData.files) {
  const digest = createHash('sha256').update(await readFile(file.path)).digest('hex');
  assert.equal(digest, file.sha256, 'Metadata implementation changed after fingerprinting');
}
const { getWasmBindings } = await import(workerData.wasmModuleUrl);
const bindings = await getWasmBindings();
parentPort.postMessage({ type: 'ready' });
parentPort.on('message', ({ id, bytes, numShards }) => {
  const started = performance.now();
  const cpu = typeof process.threadCpuUsage === 'function' ? process.threadCpuUsage() : null;
  try {
    const value = bindings.computeMetadata(numShards, new Uint8Array(bytes), 'RS2');
    const used = cpu ? process.threadCpuUsage(cpu) : null;
    parentPort.postMessage({ type: 'result', id, result: {
      blobId: value.blobId, rootHash: new Uint8Array(value.rootHash),
      unencodedLength: String(value.unencodedLength), encodingType: value.encodingType,
    }, wallMs: performance.now() - started,
    cpuMs: used ? (used.user + used.system) / 1000 : null });
  } catch {
    // Do not serialize ciphertext or arbitrary encoder internals into the log.
    parentPort.postMessage({ type: 'error', id, error: 'Pure metadata computation failed' });
  }
});
