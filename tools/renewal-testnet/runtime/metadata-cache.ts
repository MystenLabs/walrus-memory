import assert from 'node:assert/strict';
import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { constants } from 'node:fs';
import { mkdir, open, readFile, readdir, realpath, rename, lstat, unlink, link } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Worker } from 'node:worker_threads';
import { blake2b } from '@noble/hashes/blake2.js';

const VERSION = 1;
const sha = (bytes: Uint8Array | string) => createHash('sha256').update(bytes).digest('hex');
const canonical = (value: any): string => {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value !== null && typeof value === 'object') return '{' + Object.keys(value).sort()
    .map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  return JSON.stringify(value);
};
const same = (a: unknown, b: unknown) => canonical(a) === canonical(b);

type Input = { bytes: Uint8Array; expectedBlobId: string; expectedSha256: string;
  numShards: number; sourceProvenance?: string };
type Metadata = { blobId: string; rootHash: Uint8Array; unencodedLength: bigint; encodingType: 'RS2' };
type Binding = { schemaVersion: number; fingerprint: string; sha256: string; byteLength: number;
  expectedBlobId: string; numShards: number; encodingType: 'RS2'; sourceProvenance: string | null };
type Job = { id: number; bytes: Uint8Array; numShards: number;
  resolve: (value: any) => void; reject: (error: Error) => void; timer?: ReturnType<typeof setTimeout> };
type Slot = { worker: Worker; ready: boolean; current?: Job };
type Options = { cacheDir: string; threads?: number;
  onMetric?: (event: string, detail: Record<string, unknown>) => void };

// Same derivation enforced by Walrus blob::new: BCS(u8 RS2=1, u64 size,
// u256 rootHash), followed by Blake2b-256. The root bytes are already u256 LE.
export function deriveMetadataBlobId(rootHash: Uint8Array, byteLength: number): string {
  assert.equal(rootHash.length, 32, 'Expected 32-byte metadata root');
  assert.ok(Number.isSafeInteger(byteLength) && byteLength >= 0);
  const data = Buffer.alloc(41);
  data[0] = 1; data.writeBigUInt64LE(BigInt(byteLength), 1);
  data.set(rootHash, 9);
  return Buffer.from(blake2b(data, { dkLen: 32 })).toString('base64url');
}

async function packageRoot(entry: string) {
  let directory = path.dirname(await realpath(entry));
  while (directory !== path.dirname(directory)) {
    try { await readFile(path.join(directory, 'package.json')); return directory; }
    catch (error: any) { if (error.code !== 'ENOENT') throw error; }
    directory = path.dirname(directory);
  }
  throw new Error('Cannot locate metadata implementation package');
}
async function collectFiles(directory: string, prefix: string): Promise<Array<{name:string;path:string;sha256:string}>> {
  const output: Array<{name:string;path:string;sha256:string}> = [];
  for (const entry of (await readdir(directory, { withFileTypes: true })).sort((a,b)=>a.name.localeCompare(b.name))) {
    const filename = path.join(directory, entry.name), name = prefix + '/' + entry.name;
    if (entry.isDirectory()) output.push(...await collectFiles(filename, name));
    else if (entry.isFile() && (/\.(mjs|js|wasm)$/.test(entry.name) || entry.name === 'package.json'))
      output.push({name,path:filename,sha256:sha(await readFile(filename))});
  }
  return output;
}
async function implementation() {
  const require = createRequire(import.meta.url);
  const sdkRoot = await packageRoot(require.resolve('@mysten/walrus'));
  const wasmRoot = await packageRoot(require.resolve('@mysten/walrus-wasm'));
  const hashesRoot = await packageRoot(require.resolve('@noble/hashes/blake2.js'));
  const sdkVersion = JSON.parse(await readFile(path.join(sdkRoot,'package.json'),'utf8')).version;
  const wasmVersion = JSON.parse(await readFile(path.join(wasmRoot,'package.json'),'utf8')).version;
  const hashesVersion = JSON.parse(await readFile(path.join(hashesRoot,'package.json'),'utf8')).version;
  assert.equal(sdkVersion,'1.1.7','Metadata computer requires the pinned Walrus SDK');
  assert.equal(wasmVersion,'0.2.2','Metadata computer requires the pinned WASM implementation');
  assert.equal(hashesVersion,'2.4.0','Metadata computer requires the pinned Blake2 implementation');
  const workerPath = fileURLToPath(new URL('./metadata-worker.mjs', import.meta.url));
  const files = [
    ...await collectFiles(path.join(sdkRoot,'dist'), 'walrus/dist'),
    ...await collectFiles(path.join(wasmRoot,'nodejs'), 'walrus-wasm/nodejs'),
    ...await collectFiles(hashesRoot, 'noble-hashes'),
    ...await Promise.all([
      ['walrus/package.json',path.join(sdkRoot,'package.json')],
      ['walrus-wasm/package.json',path.join(wasmRoot,'package.json')],
      ['walrus-wasm/index.mjs',path.join(wasmRoot,'index.mjs')],
      ['metadata-worker.mjs',workerPath],
      ['metadata-cache.ts',fileURLToPath(import.meta.url)],
    ].map(async ([name, filename]) => ({name,path:filename,sha256:sha(await readFile(filename))}))),
  ].sort((a,b)=>a.name.localeCompare(b.name));
  const publicBinding = {schemaVersion:VERSION,sdkVersion,wasmVersion,hashesVersion,
    encodingType:'RS2',files:files.map(({name,sha256})=>({name,sha256}))};
  return {fingerprint:sha(canonical(publicBinding)),publicBinding,files,workerPath,
    wasmModuleUrl:pathToFileURL(path.join(sdkRoot,'dist/wasm.mjs')).href};
}
async function readRegular(filename: string, privateFile = false): Promise<Buffer> {
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await handle.stat();
    assert.ok(stat.isFile(), 'Metadata cache path must be a regular file');
    if (privateFile) assert.equal(stat.mode & 0o077, 0, 'Cache integrity key must be private');
    return await handle.readFile();
  } finally { await handle.close(); }
}
async function atomicWrite(filename: string, contents: string) {
  const temporary = filename + '.' + randomUUID() + '.tmp';
  try {
    const handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    try { await handle.writeFile(contents); await handle.sync(); } finally { await handle.close(); }
    await rename(temporary, filename);
  } finally { await unlink(temporary).catch((error:any)=>{if(error.code!=='ENOENT')throw error;}); }
}
async function integrityKey(directory: string) {
  const filename = path.join(directory,'.integrity-key');
  const temporary=filename+'.'+randomUUID()+'.tmp';
  try {
    const handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    try { await handle.writeFile(randomBytes(32)); await handle.sync(); } finally { await handle.close(); }
    // link publishes a fully written key exclusively; another initializer never
    // observes a partially written key or replaces the existing signing key.
    await link(temporary,filename);
  } catch (error:any) { if(error.code!=='EEXIST')throw error; }
  finally {await unlink(temporary).catch((error:any)=>{if(error.code!=='ENOENT')throw error;});}
  const key = await readRegular(filename, true);
  assert.equal(key.length,32,'Invalid metadata cache integrity key');
  return key;
}

export async function createMetadataComputer(options: Options) {
  assert.ok(path.isAbsolute(options.cacheDir), 'Metadata cache directory must be absolute');
  const threads = options.threads ?? 4;
  assert.ok(Number.isInteger(threads) && threads >= 1 && threads <= 4);
  await mkdir(options.cacheDir,{recursive:true,mode:0o700});
  assert.ok((await lstat(options.cacheDir)).isDirectory(), 'Metadata cache directory cannot be a symlink');
  const key = await integrityKey(options.cacheDir), codec = await implementation();
  await atomicWrite(path.join(options.cacheDir,'implementation-'+codec.fingerprint+'.json'),
    JSON.stringify({...codec.publicBinding,fingerprint:codec.fingerprint},null,2)+'\n');
  const stats = {calls:0,hits:0,misses:0,invalid:0,computed:0,inflightDeduplicated:0,
    poolSubmitted:0,poolCompleted:0,workerCpuMs:0,workerCpuMeasuredJobs:0,
    workerWallMs:0,poolBootMs:0,cacheReadMs:0,cacheWriteMs:0,hashMs:0,errors:0,threads};
  const emit = (event:string,detail:Record<string,unknown>) => options.onMetric?.(event,detail);
  const signature = (payload:any) => createHmac('sha256',key).update(canonical(payload)).digest('hex');
  const inflight = new Map<string,Promise<any>>(), slots:Slot[]=[], queue:Job[]=[];
  let initialization:Promise<void>|undefined, failure:Error|undefined, closing=false, closed=false, sequence=0;
  const fail = (error:Error) => {
    if(failure)return; failure=error; stats.errors++;
    for(const job of queue.splice(0)){if(job.timer)clearTimeout(job.timer);job.reject(error);}
    for(const slot of slots){
      if(slot.current?.timer)clearTimeout(slot.current.timer);
      slot.current?.reject(error);slot.current=undefined;void slot.worker.terminate();
    }
  };
  const pump = () => {
    if(failure||closed)return;
    for(const slot of slots){
      if(!slot.ready||slot.current||!queue.length)continue;
      const job=queue.shift()!;slot.current=job;
      job.timer=setTimeout(()=>fail(new Error('Metadata computation exceeded its deadline')),60_000);
      job.timer.unref();
      slot.worker.postMessage({id:job.id,bytes:job.bytes,numShards:job.numShards});
    }
  };
  const start = () => initialization ??= (async()=>{
    const tick=performance.now();
    try {
      await Promise.all(Array.from({length:threads},()=>new Promise<void>((resolve,reject)=>{
        const worker=new Worker(pathToFileURL(codec.workerPath),{workerData:{
          wasmModuleUrl:codec.wasmModuleUrl,files:codec.files}});
        const slot:Slot={worker,ready:false};slots.push(slot);
        const startupTimer=setTimeout(()=>{const error=new Error('Metadata worker startup exceeded its deadline');reject(error);fail(error);},30_000);
        startupTimer.unref();
        worker.on('error',()=>{clearTimeout(startupTimer);const error=new Error('Metadata worker failed');reject(error);fail(error);});
        worker.on('exit',code=>{if(!closed&&(code!==0||slot.current)){
          clearTimeout(startupTimer);
          const error=new Error('Metadata worker exited unexpectedly');reject(error);fail(error);}});
        worker.on('message',message=>{
          if(message.type==='ready'){clearTimeout(startupTimer);slot.ready=true;resolve();pump();return;}
          const job=slot.current;
          if(!job||message.id!==job.id){fail(new Error('Unexpected metadata worker response'));return;}
          slot.current=undefined;
          if(job.timer)clearTimeout(job.timer);
          if(message.type==='error'){job.reject(new Error('Pure metadata computation failed'));stats.errors++;}
          else if(message.type==='result'){
            stats.poolCompleted++;stats.workerWallMs+=message.wallMs;
            if(message.cpuMs!==null){stats.workerCpuMs+=message.cpuMs;stats.workerCpuMeasuredJobs++;}
            job.resolve(message.result);
          } else {job.reject(new Error('Invalid metadata worker response'));fail(new Error('Invalid metadata worker response'));}
          pump();
        });
      })));
      stats.poolBootMs+=performance.now()-tick;
      emit('metadata_pool_ready',{threads,fingerprint:codec.fingerprint,poolBootMs:stats.poolBootMs});
    } catch { const error=failure??new Error('Cannot start metadata worker pool');fail(error);throw error; }
  })();
  const computeWorker = async(bytes:Uint8Array,numShards:number)=>{
    await start();if(failure)throw failure;
    stats.poolSubmitted++;
    return new Promise<any>((resolve,reject)=>{queue.push({id:++sequence,bytes,numShards,resolve,reject});pump();});
  };
  const validateMetadata = (raw:any,binding:Binding):Metadata => {
    assert.equal(raw.blobId,binding.expectedBlobId,'Computed/cached Blob ID must match the existing source');
    assert.equal(raw.encodingType,'RS2','Metadata codec must be RS2');
    assert.equal(String(raw.unencodedLength),String(binding.byteLength),'Metadata byte length must match downloaded bytes');
    const root=typeof raw.rootHash==='string'?Buffer.from(raw.rootHash,'base64'):new Uint8Array(raw.rootHash);
    assert.equal(root.length,32,'Invalid metadata root');
    if(typeof raw.rootHash==='string')assert.equal(Buffer.from(root).toString('base64'),raw.rootHash,'Noncanonical metadata root');
    assert.equal(deriveMetadataBlobId(root,binding.byteLength),binding.expectedBlobId,'Metadata root must derive the existing source Blob ID');
    return {blobId:raw.blobId,rootHash:new Uint8Array(root),unencodedLength:BigInt(raw.unencodedLength),encodingType:'RS2'};
  };
  const computeOne = async(bytes:Uint8Array,binding:Binding,cacheKey:string)=>{
    const filename=path.join(options.cacheDir,cacheKey+'.json');
    let metadata:Metadata|undefined,cacheHit=false,tick=performance.now();
    try {
      const entry=JSON.parse((await readRegular(filename)).toString('utf8'));
      assert.ok(entry&&entry.payload&&typeof entry.hmac==='string'&&/^[a-f0-9]{64}$/.test(entry.hmac));
      const expected=Buffer.from(signature(entry.payload),'hex'),actual=Buffer.from(entry.hmac,'hex');
      assert.ok(timingSafeEqual(actual,expected),'Metadata cache integrity verification failed');
      assert.ok(same(entry.payload.binding,binding),'Metadata cache bindings differ');
      metadata=validateMetadata(entry.payload.metadata,binding);cacheHit=true;stats.hits++;
    } catch(error:any) {
      if(error.code!=='ENOENT'){
        stats.invalid++;emit('metadata_cache_invalid',{cacheKey,fingerprint:codec.fingerprint});
      }
    } finally {stats.cacheReadMs+=performance.now()-tick;}
    if(!metadata){
      stats.misses++;emit('metadata_cache_miss',{cacheKey,fingerprint:codec.fingerprint,numShards:binding.numShards});
      metadata=validateMetadata(await computeWorker(bytes,binding.numShards),binding);
      stats.computed++;
      const payload={binding,metadata:{...metadata,rootHash:Buffer.from(metadata.rootHash).toString('base64'),
        unencodedLength:String(metadata.unencodedLength)},createdAt:new Date().toISOString()};
      tick=performance.now();
      await atomicWrite(filename,JSON.stringify({payload,hmac:signature(payload)})+'\n');
      stats.cacheWriteMs+=performance.now()-tick;
      emit('metadata_computed',{cacheKey,fingerprint:codec.fingerprint,numShards:binding.numShards});
    } else emit('metadata_cache_hit',{cacheKey,fingerprint:codec.fingerprint,numShards:binding.numShards});
    return {...metadata,cacheKey,fingerprint:codec.fingerprint,numShards:binding.numShards,sha256:binding.sha256,
      byteLength:binding.byteLength,sourceProvenance:binding.sourceProvenance,cacheHit,cacheVersion:VERSION,
      rootDerivedBlobId:deriveMetadataBlobId(metadata.rootHash,binding.byteLength),rootBindingVerified:true};
  };
  const compute = async(input:Input)=>{
    assert.ok(!closing&&!closed,'Metadata computer is closed');if(failure)throw failure;
    assert.ok(input.bytes instanceof Uint8Array,'Metadata input must be bytes');
    assert.ok(/^[a-f0-9]{64}$/.test(input.expectedSha256),'Expected canonical SHA-256');
    assert.ok(/^[A-Za-z0-9_-]{43}$/.test(input.expectedBlobId),'Expected canonical Blob ID');
    assert.ok(Number.isInteger(input.numShards)&&input.numShards>0&&input.numShards<=65535,'Invalid current shard count');
    assert.ok(input.sourceProvenance===undefined||typeof input.sourceProvenance==='string');
    const tick=performance.now(),bytes=new Uint8Array(input.bytes),digest=sha(bytes);
    stats.hashMs+=performance.now()-tick;
    assert.equal(digest,input.expectedSha256,'Downloaded ciphertext hash differs before metadata computation');
    stats.calls++;
    const binding:Binding={schemaVersion:VERSION,fingerprint:codec.fingerprint,sha256:digest,byteLength:bytes.length,
      expectedBlobId:input.expectedBlobId,numShards:input.numShards,encodingType:'RS2',sourceProvenance:input.sourceProvenance??null};
    const cacheKey=sha(canonical(binding));
    let pending=inflight.get(cacheKey);
    if(pending)stats.inflightDeduplicated++;
    else {
      pending=computeOne(bytes,binding,cacheKey);inflight.set(cacheKey,pending);
      void pending.then(()=>inflight.delete(cacheKey),()=>inflight.delete(cacheKey));
    }
    const value=await pending;
    return {...value,rootHash:new Uint8Array(value.rootHash)};
  };
  const close = async()=>{
    if(closed)return;closing=true;
    await Promise.allSettled([...inflight.values()]);
    if(initialization)await initialization.catch(()=>{});
    closed=true;
    await Promise.allSettled(slots.map(slot=>slot.worker.terminate()));
  };
  emit('metadata_computer_ready',{threads,fingerprint:codec.fingerprint,sdkVersion:codec.publicBinding.sdkVersion,
    wasmVersion:codec.publicBinding.wasmVersion,cacheVersion:VERSION});
  return {compute,close,stats,fingerprint:codec.fingerprint,implementation:codec.publicBinding};
}
