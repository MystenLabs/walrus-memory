import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { mkdtemp, mkdir, readFile, writeFile, copyFile, symlink, rm, stat, readdir } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

globalThis.fetch = async () => { throw new Error('Offline metadata tests prohibit network'); };
const dependencyRoot = process.env.MEMWAL_RENEWAL_TEST_DEPENDENCIES ??
  fileURLToPath(new URL('../../../.grok/renewal-testnet/cache/dependencies/node_modules', import.meta.url));
const temporary = await mkdtemp(path.join(os.tmpdir(),'memwal-metadata-cache-'));
const runtime = path.join(temporary,'runtime');
await mkdir(runtime);
await writeFile(path.join(runtime,'package.json'),'{"type":"module"}\n');
await symlink(dependencyRoot,path.join(runtime,'node_modules'),'dir');
for (const name of ['metadata-cache.ts','metadata-worker.mjs'])
  await copyFile(new URL('../runtime/'+name,import.meta.url),path.join(runtime,name));
const { createMetadataComputer, deriveMetadataBlobId } = await import(pathToFileURL(path.join(runtime,'metadata-cache.ts')));
const { getWasmBindings } = await import(pathToFileURL(path.join(dependencyRoot,'@mysten/walrus/dist/wasm.mjs')));
const bindings = await getWasmBindings();
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const canonical = value => {
  if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
  if(value!==null&&typeof value==='object')return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
  return JSON.stringify(value);
};
const vector = (text,numShards=1000) => {
  const bytes=new TextEncoder().encode(text), expected=bindings.computeMetadata(numShards,bytes);
  return {bytes,expectedBlobId:expected.blobId,expectedSha256:digest(bytes),numShards,
    sourceProvenance:'offline-test:original-owner:0'};
};
const first=vector('Existing ciphertext fixture A, unchanged bytes.'),
  second=vector('Existing ciphertext fixture B, unchanged bytes.'),
  smallerShards=vector('Existing ciphertext fixture A, unchanged bytes.',10);
const directory=path.join(temporary,'cache'),events=[];
const instances=[];
let assertions=0;
try {
  const computer=await createMetadataComputer({cacheDir:directory,threads:4,
    onMetric:(event,detail)=>events.push({event,detail})});instances.push(computer);

  // Independent actual SDK output plus simultaneous callers: only one job.
  const [a,b]=await Promise.all([computer.compute(first),computer.compute(first)]);
  assert.equal(a.blobId,first.expectedBlobId);assert.equal(b.blobId,first.expectedBlobId);
  assert.equal(deriveMetadataBlobId(a.rootHash,first.bytes.length),first.expectedBlobId);
  assert.equal(computer.stats.computed,1);assert.equal(computer.stats.inflightDeduplicated,1);
  assert.equal(computer.stats.poolSubmitted,1);assert.equal(a.rootBindingVerified,true);
  assert.equal(a.cacheHit,false);assert.equal(a.sourceProvenance,first.sourceProvenance);assertions++;

  const hit=await computer.compute(first);
  assert.equal(hit.cacheHit,true);assert.equal(computer.stats.poolSubmitted,1);
  hit.rootHash.fill(0);
  assert.equal(deriveMetadataBlobId((await computer.compute(first)).rootHash,first.bytes.length),first.expectedBlobId);
  assert.equal((await stat(path.join(directory,'.integrity-key'))).mode&0o077,0);assertions++;

  // Byte mismatch fails before a worker or a cache hit can hide it.
  const submitted=computer.stats.poolSubmitted;
  const altered={...first,bytes:new Uint8Array(first.bytes)};altered.bytes[0]^=1;
  await assert.rejects(computer.compute(altered),/ciphertext hash differs/);
  assert.equal(computer.stats.poolSubmitted,submitted);assertions++;

  // Accidental entry tampering is detected and the root is recomputed.
  const filename=path.join(directory,a.cacheKey+'.json');
  let entry=JSON.parse(await readFile(filename,'utf8'));
  entry.payload.metadata.rootHash=Buffer.alloc(32).toString('base64');
  await writeFile(filename,JSON.stringify(entry));
  const recovered=await computer.compute(first);
  assert.equal(recovered.cacheHit,false);assert.equal(computer.stats.invalid,1);
  assert.equal(deriveMetadataBlobId(recovered.rootHash,first.bytes.length),first.expectedBlobId);assertions++;

  // Even a correctly signed wrong root cannot pass the independent blob-ID proof.
  entry=JSON.parse(await readFile(filename,'utf8'));
  entry.payload.metadata.rootHash=Buffer.alloc(32,7).toString('base64');
  const cacheKey=await readFile(path.join(directory,'.integrity-key'));
  entry.hmac=createHmac('sha256',cacheKey).update(canonical(entry.payload)).digest('hex');
  await writeFile(filename,JSON.stringify(entry));
  const rootRecovered=await computer.compute(first);
  assert.equal(rootRecovered.cacheHit,false);assert.equal(computer.stats.invalid,2);
  assert.equal(rootRecovered.blobId,first.expectedBlobId);assertions++;

  // Shard/codec parameters form the key, and changed shards need their new ID.
  await assert.rejects(computer.compute({...first,numShards:10}),/Blob ID must match/);
  const different=await computer.compute(smallerShards);
  assert.notEqual(different.cacheKey,a.cacheKey);assert.equal(different.cacheHit,false);
  assert.notEqual(different.blobId,a.blobId);
  const wrongId='A'.repeat(43);
  await assert.rejects(computer.compute({...second,expectedBlobId:wrongId}),/Blob ID must match/);assertions++;

  // Close drains pending work and rejects future calls; no workers survive close.
  const pending=computer.compute(second),closing=computer.close();
  assert.equal((await pending).blobId,second.expectedBlobId);await closing;
  await assert.rejects(computer.compute(first),/closed/);assertions++;

  // A later process/instance gets qualified hits without booting a pool.
  const again=await createMetadataComputer({cacheDir:directory,threads:4});instances.push(again);
  const persistent=await again.compute(first);
  assert.equal(persistent.cacheHit,true);assert.equal(again.stats.poolSubmitted,0);
  assert.equal(again.fingerprint,computer.fingerprint);
  assert.equal(again.implementation.sdkVersion,'1.1.7');
  assert.equal(again.implementation.wasmVersion,'0.2.2');
  assert.equal(again.implementation.hashesVersion,'2.4.0');await again.close();assertions++;

  for (const kind of ['symlink','truncated']) {
    const bad=path.join(temporary,'bad-'+kind);await mkdir(bad);
    if(kind==='symlink')await symlink(path.join(directory,'.integrity-key'),path.join(bad,'.integrity-key'));
    else await writeFile(path.join(bad,'.integrity-key'),new Uint8Array(3),{mode:0o600});
    await assert.rejects(createMetadataComputer({cacheDir:bad,threads:4}));
  }
  assertions++;
  assert.ok(events.some(e=>e.event==='metadata_cache_hit'));
  assert.ok(events.some(e=>e.event==='metadata_cache_invalid'));
  assert.ok(events.some(e=>e.event==='metadata_pool_ready'));
  const files=(await readdir(directory)).filter(n=>n.endsWith('.json'));
  assert.ok(files.every(n=>!n.includes('nonce')&&!n.includes('certificate')));
  console.log(JSON.stringify({all_passed:true,groups:assertions,networkCalls:0,chainTransactions:0,
    cacheHits:computer.stats.hits,cacheInvalid:computer.stats.invalid,
    workerJobs:computer.stats.poolCompleted,threadCpuMeasuredJobs:computer.stats.workerCpuMeasuredJobs,
    fingerprint:computer.fingerprint}));
} finally {
  await Promise.allSettled(instances.map(instance=>instance.close()));
  await rm(temporary,{recursive:true,force:true});
}
