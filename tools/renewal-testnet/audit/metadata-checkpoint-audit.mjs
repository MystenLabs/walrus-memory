#!/usr/bin/env node
// Independent, read-only post-hoc audit. Never reads config.json, owner/cache
// integrity keys, signs, submits, or calls an RPC. --journal replays its public
// SQL/log sidecar; downloaded ciphertext remains an explicit local input.
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir,readdir} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';

globalThis.fetch=async()=>{throw new Error('Metadata checkpoint audit forbids every network request');};
const argv=process.argv.slice(2);
const option=(name,fallback)=>argv.includes(name)?argv[argv.indexOf(name)+1]:fallback;
const here=path.dirname(fileURLToPath(import.meta.url));
const deps=path.resolve(option('--deps',path.join(process.cwd(),'.grok/renewal-testnet/cache/source-856fb017/node_modules')));
const require=createRequire(path.join(deps,'../package.json'));
const load=name=>import(pathToFileURL(require.resolve(name)).href);
const [{Transaction},{bcs},{normalizeStructTag},{blake2b}]=await Promise.all([
  load('@mysten/sui/transactions'),load('@mysten/sui/bcs'),load('@mysten/sui/utils'),load('@noble/hashes/blake2.js')]);
const sha=value=>createHash('sha256').update(value).digest('hex');
const canonical=value=>Array.isArray(value)?'['+value.map(canonical).join(',')+']':
  value!==null&&typeof value==='object'?'{'+Object.keys(value).sort().map(key=>JSON.stringify(key)+':'+canonical(value[key])).join(',')+'}':JSON.stringify(value);
const parse=async filename=>JSON.parse(await readFile(filename,'utf8'));
const pretty=value=>JSON.stringify(value,(_key,v)=>typeof v==='bigint'?v.toString():v,2)+'\n';
const canonical64=(value,length,label)=>{
  assert.equal(typeof value,'string',label);const bytes=Buffer.from(value,'base64');
  assert.equal(bytes.toString('base64'),value,`${label} canonical base64`);
  if(length!==undefined)assert.equal(bytes.length,length,`${label} byte length`);return bytes;
};
function deriveBlobId(root,size){
  assert.equal(root.length,32);assert.ok(Number.isSafeInteger(size)&&size>0);
  const encoded=Buffer.alloc(41);encoded[0]=1;encoded.writeBigUInt64LE(BigInt(size),1);root.copy(encoded,9);
  return Buffer.from(blake2b(encoded,{dkLen:32})).toString('base64url');
}
function rootAuth(bytes,nonce){
  assert.equal(nonce.length,32);const size=Buffer.alloc(8);size.writeBigUInt64LE(BigInt(bytes.length));
  return Buffer.concat([createHash('sha256').update(bytes).digest(),createHash('sha256').update(nonce).digest(),size]);
}
function pure(data,arg){
  assert.ok(Number.isInteger(arg?.Input),'Expected direct pure input');
  return canonical64(data.inputs[arg.Input]?.Pure?.bytes,undefined,'BCS pure input');
}
function unsigned(bytes,length){assert.equal(bytes.length,length);return BigInt('0x'+Buffer.from(bytes).reverse().toString('hex'));}
const call=(command,module,name)=>command.MoveCall?.module===module&&command.MoveCall.function===name;
const one=(rows,predicate,label)=>{const matches=rows.filter(predicate);assert.equal(matches.length,1,label);return matches[0];};
const certificateBcs=bcs.struct('AuditRelayCertificate',{signers:bcs.vector(bcs.u16()),serializedMessage:bcs.byteVector(),signature:bcs.byteVector()});
async function packageRoot(specifier,name){
  let directory=path.dirname(require.resolve(specifier));
  while(directory!==path.dirname(directory)){
    try{const pkg=await parse(path.join(directory,'package.json'));if(pkg.name===name)return {directory,pkg};}catch(error){if(error.code!=='ENOENT')throw error;}
    directory=path.dirname(directory);
  }
  throw new Error(`Missing pinned package ${name}`);
}
async function verifyImplementation(implementation,fingerprint,runtimeDir){
  assert.equal(implementation.schemaVersion,1);assert.equal(implementation.sdkVersion,'1.1.7');
  assert.equal(implementation.wasmVersion,'0.2.2');assert.equal(implementation.hashesVersion,'2.4.0');assert.equal(implementation.encodingType,'RS2');
  assert.equal(sha(canonical(implementation)),fingerprint,'Independent public implementation fingerprint');
  const [sdk,wasm,hashes]=await Promise.all([packageRoot('@mysten/walrus','@mysten/walrus'),
    packageRoot('@mysten/walrus-wasm','@mysten/walrus-wasm'),packageRoot('@noble/hashes/blake2.js','@noble/hashes')]);
  assert.equal(sdk.pkg.version,implementation.sdkVersion);assert.equal(wasm.pkg.version,implementation.wasmVersion);assert.equal(hashes.pkg.version,implementation.hashesVersion);
  const names=new Set();let checked=0;
  for(const file of implementation.files){
    assert.equal(typeof file.name,'string');assert.ok(!file.name.split('/').includes('..'));assert.ok(!names.has(file.name));names.add(file.name);
    assert.match(file.sha256,/^[a-f0-9]{64}$/);let filename;
    if(file.name.startsWith('walrus/dist/'))filename=path.join(sdk.directory,file.name.slice(7));
    else if(file.name.startsWith('walrus-wasm/nodejs/'))filename=path.join(wasm.directory,file.name.slice(12));
    else if(file.name.startsWith('noble-hashes/'))filename=path.join(hashes.directory,file.name.slice(13));
    else if(file.name==='walrus/package.json')filename=path.join(sdk.directory,'package.json');
    else if(['walrus-wasm/package.json','walrus-wasm/index.mjs'].includes(file.name))filename=path.join(wasm.directory,file.name.slice(12));
    else if(['metadata-worker.mjs','metadata-cache.ts'].includes(file.name))filename=path.join(runtimeDir,file.name);
    else throw new Error(`Unexpected implementation input ${file.name}`);
    assert.equal(sha(await readFile(filename)),file.sha256,`Pinned implementation bytes: ${file.name}`);checked++;
  }
  for(const name of ['metadata-worker.mjs','metadata-cache.ts','walrus/package.json','walrus-wasm/package.json','walrus-wasm/index.mjs'])assert.ok(names.has(name),`Fingerprint missing ${name}`);
  assert.ok(checked>20,'Fingerprint must cover actual SDK/WASM/hash implementation files');return checked;
}
const sqlFor=runId=>`BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='30s';
SELECT jsonb_build_object('schemaVersion',1,'runId','${runId}','snapshotAt',clock_timestamp(),
 'memories',(SELECT coalesce(jsonb_agg(jsonb_build_object('run_id',run_id,'memory_id',memory_id,'stage',stage,
  'owner',owner,'namespace',namespace,'account_id',account_id,'vector_entry_id',vector_entry_id,
  'origin_run_id',origin_run_id,'origin_memory_id',origin_memory_id,'provenance_run_id',provenance_run_id,
  'ciphertext_sha256',ciphertext_sha256,'ciphertext_bytes',ciphertext_bytes,'source_blob_id',source_blob_id,
  'source_object_id',source_object_id,'current_object_id',current_object_id,'source_end_epoch',source_end_epoch,
  'current_end_epoch',current_end_epoch,'source_metadata',source_metadata) ORDER BY memory_id),'[]'::jsonb)
  FROM exercise_renewal_memories WHERE run_id='${runId}'),
 'journal',(SELECT coalesce(jsonb_agg(jsonb_build_object('id',id,'memory_id',memory_id,'phase',phase,'state',state,
  'created_at',created_at,'payload',payload) ORDER BY id),'[]'::jsonb) FROM exercise_renewal_journal WHERE run_id='${runId}'),
 'priorNonces',(SELECT coalesce(jsonb_agg(jsonb_build_object('run_id',j.run_id,'memory_id',j.memory_id,'journal_id',j.id,
  'blob_id',m.source_blob_id,'nonce',j.payload->>'nonce') ORDER BY j.id),'[]'::jsonb)
  FROM exercise_renewal_journal j JOIN exercise_renewal_memories m USING(run_id,memory_id)
  WHERE j.run_id<>'${runId}' AND j.phase IN('seed.flow','renew.flow') AND j.state='encoded' AND j.payload->>'nonce' IS NOT NULL
  AND m.source_blob_id IN(SELECT source_blob_id FROM exercise_renewal_memories WHERE run_id='${runId}')));
COMMIT;`;

async function readEvents(runDir){
  const logs=path.join(runDir,'logs'),events=[],files=[];
  for(const name of (await readdir(logs)).filter(name=>/^migrate\.attempt-\d+\.log$/.test(name)).sort()){
    const filename=path.join(logs,name),contents=await readFile(filename,'utf8');files.push({name,sha256:sha(contents)});
    for(const [index,line]of contents.split('\n').entries()){
      if(!line.startsWith('{'))continue;let event;try{event=JSON.parse(line);}catch{continue;}
      if(event.event==='transport'&&event.kind==='relay_post'||event.event?.startsWith('metadata_')||event.event==='complete'&&event.command==='migrate')
        events.push({file:name,line:index+1,event});
    }
  }
  assert.ok(files.length,'Saved migration logs required');return {events,files};
}
function bindCheckpoint(memory,plan,encoded,bytes,fingerprint){
  assert.equal(encoded.execution,'explicit-public-sdk-v1','Refuse non-explicit or legacy flow');
  assert.equal(encoded.step,'encoded');assert.equal(encoded.blobId,memory.source_blob_id);
  assert.equal(encoded.ciphertextSha256,sha(bytes));assert.equal(encoded.ciphertextSha256,memory.ciphertext_sha256);
  for(const length of [encoded.byteLength,encoded.unencodedSize])assert.equal(length,bytes.length);
  assert.equal(BigInt(encoded.unencodedLength),BigInt(bytes.length));assert.equal(memory.ciphertext_bytes,bytes.length);
  assert.equal(encoded.encodingType,'RS2');assert.equal(encoded.cacheVersion,1);assert.equal(encoded.rootBindingVerified,true);
  assert.equal(encoded.codecFingerprint,fingerprint);assert.ok(Number.isInteger(encoded.numShards)&&encoded.numShards>0&&encoded.numShards<=65535);
  assert.equal(encoded.numShards,plan.numShards);
  const sourceProvenance=JSON.stringify({originRunId:memory.origin_run_id??memory.provenance_run_id??memory.run_id,
    originMemoryId:memory.origin_memory_id??memory.memory_id,vectorEntryId:memory.vector_entry_id??`${memory.run_id}:${memory.memory_id}`,
    owner:memory.owner,namespace:memory.namespace});
  assert.equal(encoded.sourceProvenance,sourceProvenance,'Cache source provenance');
  const binding={schemaVersion:1,fingerprint,sha256:sha(bytes),byteLength:bytes.length,expectedBlobId:memory.source_blob_id,
    numShards:plan.numShards,encodingType:'RS2',sourceProvenance};
  assert.equal(encoded.cacheKey,sha(canonical(binding)),'Independent cache key');assert.equal(typeof encoded.cacheHit,'boolean');
  const nonce=canonical64(encoded.nonce,32,'Fresh upload nonce'),root=canonical64(encoded.rootHash,32,'Metadata root');
  assert.equal(deriveBlobId(root,bytes.length),memory.source_blob_id,'Independent root/size → known source blob ID');
  assert.equal(encoded.rootDerivedBlobId,memory.source_blob_id);return {nonce,root};
}
function verifyRegister(data,encoded,bytes,nonce,root,plan){
  const register=one(data.commands,c=>call(c,'system','register_blob'),'Exactly one register_blob').MoveCall;
  const reserve=one(data.commands,c=>call(c,'system','reserve_space'),'Exactly one reserve_space').MoveCall;
  assert.equal(pure(data,register.arguments[2]).toString('base64url'),encoded.blobId,'BCS blob ID LE bytes');
  assert.deepEqual(pure(data,register.arguments[3]),root,'BCS metadata root');
  assert.equal(unsigned(pure(data,register.arguments[4]),8),BigInt(bytes.length));
  assert.equal(unsigned(pure(data,register.arguments[5]),1),1n,'BCS RS2 discriminant');
  assert.equal(unsigned(pure(data,register.arguments[6]),1),1n,'BCS deletable');
  assert.equal(unsigned(pure(data,reserve.arguments[2]),4),BigInt(plan.requestedEpochs));
  const auth=rootAuth(bytes,nonce),matches=data.inputs.flatMap((input,index)=>input.Pure&&Buffer.from(input.Pure.bytes,'base64').equals(auth)?[index]:[]);
  assert.equal(matches.length,1,'Exactly one raw72 auth input = SHA(bytes)||SHA(nonce)||u64LE(size)');return matches[0];
}
function createdObject(receipt,blobType){
  assert.equal(receipt.effects?.status?.success,true);
  const created=one(receipt.effects.changedObjects??[],change=>change.idOperation==='Created'&&change.outputState==='ObjectWrite'&&
    typeof receipt.objectTypes?.[change.objectId]==='string'&&normalizeStructTag(receipt.objectTypes[change.objectId])===blobType,'One new Blob in finalized effects');
  return created.objectId;
}
function verifyUploadEvent(event,encoded,registered,bytes,relay,requireSuccess=true){
  if(requireSuccess)assert.equal(event.status,200,'Successful actual relay POST');assert.equal(event.method,'POST');
  assert.equal(event.sha256,sha(bytes));assert.equal(event.bytes,bytes.length);
  const url=new URL(event.url),base=new URL(relay);assert.equal(url.origin,base.origin);assert.equal(url.pathname,base.pathname.replace(/\/$/,'')+'/v1/blob-upload-relay');
  assert.deepEqual([...url.searchParams.keys()].sort(),['blob_id','deletable_blob_object','encoding_type','nonce','tx_id']);
  assert.equal(url.searchParams.get('blob_id'),encoded.blobId);assert.equal(url.searchParams.get('tx_id'),registered.txDigest);
  assert.equal(url.searchParams.get('deletable_blob_object'),registered.blobObjectId);assert.equal(url.searchParams.get('encoding_type'),'RS2');
  assert.equal(url.searchParams.get('nonce'),canonical64(encoded.nonce,32,'nonce').toString('base64url'));
}
async function main(){
  if(argv.includes('--self-test'))return selfTest();
  const runDir=path.resolve(option('--run-dir','')),expected=Number(option('--expected-count','0')),out=option('--out',null);
  assert.ok(option('--run-dir',null)&&out,'Usage: --run-dir DIR --container NAME --expected-count N --out FILE [--journal PUBLIC_SIDECAR] [--deps NODE_MODULES]');
  assert.ok(Number.isSafeInteger(expected)&&expected>=1&&expected<=1000);
  const config=await parse(path.join(runDir,'config.public.json')),manifestBytes=await readFile(path.join(runDir,'manifest.json')),
    manifest=JSON.parse(manifestBytes),costBytes=await readFile(path.join(runDir,'cost.json')),cost=JSON.parse(costBytes);
  assert.match(config.runId,/^[A-Za-z0-9_-]+$/);assert.equal(config.network,'testnet');assert.equal(config.mode,'migration-only');assert.equal(config.renewMode,'fused');
  assert.equal(config.count,expected);assert.equal(manifest.length,expected);assert.equal(cost.runId,config.runId);assert.equal(cost.all_passed,true);
  assert.equal(cost.localBcsTransactions,2*expected);assert.equal(cost.rpcCalls,0);assert.equal(cost.pending.length,0);
  assert.equal(cost.totals.seed.transactions,0);assert.equal(cost.totals.setup.transactions,0);
  const journalInput=option('--journal',null);let snapshot,logProof;
  if(journalInput){const saved=await parse(journalInput);snapshot=saved.snapshot;logProof=saved.logProof;
    assert.equal(saved.manifestSha256,sha(manifestBytes));assert.equal(saved.costSha256,sha(costBytes));}
  else{
    const container=option('--container',config.container);assert.match(container??'',/^[A-Za-z0-9_.-]+$/);
    snapshot=JSON.parse(execFileSync('docker',['exec','-i',container,'psql','-XAtq','-v','ON_ERROR_STOP=1','-U','renewal','-d','renewal_e2e'],
      {input:sqlFor(config.runId),encoding:'utf8',maxBuffer:128*1024*1024,timeout:60000}));
    logProof=await readEvents(runDir);
  }
  const exportPath=path.resolve(out).replace(/\.json$/,'')+'.journal.json';await mkdir(path.dirname(exportPath),{recursive:true});
  const exported={schemaVersion:1,runId:config.runId,method:'Repeatable-read READ ONLY public SQL snapshot plus saved migration log events',
    exportSql:sqlFor(config.runId),manifestSha256:sha(manifestBytes),costSha256:sha(costBytes),snapshot,logProof};
  await writeFile(exportPath,pretty(exported));
  assert.equal(snapshot.schemaVersion,1);assert.equal(snapshot.runId,config.runId);assert.equal(snapshot.memories.length,expected);
  const completes=logProof.events.filter(row=>row.event.event==='complete').map(row=>row.event);
  assert.ok(completes.length,'Successful migration completion record');
  const complete=completes.at(-1),fingerprint=complete.metadataCache?.fingerprint,implementation=complete.metadataCache?.implementation;
  assert.equal(complete.metadataCache.enabled,true);assert.equal(complete.metadataCache.threads,config.metadataThreads??4);assert.ok(implementation);
  assert.match(fingerprint,/^[a-f0-9]{64}$/);
  const implementationFiles=await verifyImplementation(implementation,fingerprint,path.resolve(option('--runtime-dir',path.join(here,'../runtime'))));
  const currentNonces=new Set(),allDigests=new Set(),items=[],manifestMap=new Map(manifest.map(row=>[row.memory_id,row]));
  const costMap=new Map(cost.transactions.map(row=>[`${row.memoryId}/${row.phase}`,row]));
  const priorNonces=new Set();for(const row of snapshot.priorNonces){
    const bytes=Buffer.from(row.nonce,'base64');assert.equal(bytes.length,32,'Prior public nonce length');priorNonces.add(bytes.toString('hex'));
  }
  const posts=logProof.events.filter(row=>row.event.event==='transport'&&row.event.kind==='relay_post');
  const blobType=normalizeStructTag(`${config.walrusPackageId}::blob::Blob`);
  assert.equal(new Set(snapshot.journal.map(row=>row.id)).size,snapshot.journal.length,'Unique SQL journal IDs');
  assert.ok(snapshot.journal.every(row=>Number.isSafeInteger(row.id)&&Number.isInteger(row.memory_id)&&row.memory_id>=0&&row.memory_id<expected),'Every public checkpoint belongs to this cohort');
  assert.equal(snapshot.journal.filter(row=>row.state==='prepared').length,2*expected);
  assert.equal(snapshot.journal.filter(row=>row.state==='finalized'&&row.payload.digest).length,2*expected);
  for(let id=0;id<expected;id++){
    const memory=one(snapshot.memories,row=>row.memory_id===id,'Dense memory IDs'),row=manifestMap.get(id);assert.ok(row);assert.equal(memory.stage,'migrated');
    for(const key of ['run_id','owner','namespace','vector_entry_id','origin_run_id','origin_memory_id','provenance_run_id','source_blob_id','source_object_id','current_object_id','source_end_epoch','current_end_epoch','ciphertext_sha256','ciphertext_bytes','source_metadata'])
      assert.deepEqual(memory[key],row[key],`Public manifest/SQL ${id}/${key}`);
    const records=snapshot.journal.filter(row=>row.memory_id===id),record=(phase,state)=>one(records,row=>row.phase===phase&&row.state===state,`${id}/${phase}/${state}`);
    assert.ok(records.every(row=>['renew.lease_plan','renew.flow','renew.register','renew.certify_transfer','db_commit'].includes(row.phase)),'Unexpected seed/setup/transaction phase');
    const planned=record('renew.lease_plan','planned'),encodedRow=record('renew.flow','encoded'),registeredRow=record('renew.flow','registered'),uploadedRow=record('renew.flow','uploaded'),certifiedRow=record('renew.flow','certified');
    const plan=planned.payload,encoded=encodedRow.payload,registered=registeredRow.payload,uploaded=uploadedRow.payload,certified=certifiedRow.payload;
    assert.equal(plan.inputObjectId,memory.source_object_id);assert.equal(plan.inputEndEpoch,memory.source_end_epoch);
    assert.equal(plan.targetEndEpoch,Math.max(plan.inputEndEpoch+1,plan.currentEpoch+config.renewalEpochs));assert.equal(plan.targetEndEpoch,plan.currentEpoch+plan.requestedEpochs);
    assert.ok(plan.requestedEpochs>=1&&plan.requestedEpochs<=53);assert.ok(memory.current_end_epoch>=plan.targetEndEpoch);
    const bytes=await readFile(path.join(runDir,'data','downloads',`${id}.bin`));
    const {nonce,root}=bindCheckpoint(memory,plan,encoded,bytes,fingerprint),nonceHex=nonce.toString('hex');
    assert.ok(!currentNonces.has(nonceHex),'Every registration gets a distinct fresh nonce');assert.ok(!priorNonces.has(nonceHex),'Never reuse a prior cycle nonce');currentNonces.add(nonceHex);
    const cacheEvent=one(logProof.events,event=>event.event.cacheKey===encoded.cacheKey&&event.event.event===(encoded.cacheHit?'metadata_cache_hit':'metadata_computed'),`${id} actual cache outcome`);
    assert.equal(cacheEvent.event.fingerprint,fingerprint);assert.equal(cacheEvent.event.numShards,plan.numShards);
    const built={};
    for(const phase of ['renew.register','renew.certify_transfer']){
      const prepared=record(phase,'prepared'),finalized=record(phase,'finalized');
      assert.ok(prepared.id<finalized.id);assert.equal(prepared.payload.digest,finalized.payload.digest);assert.equal(finalized.payload.effects?.status?.success,true);
      const dataBytes=canonical64(prepared.payload.bytes,undefined,'Prepared transaction');assert.ok(dataBytes.length>0);
      const tx=Transaction.from(dataBytes);assert.equal(await tx.getDigest(),finalized.payload.digest,'Independent BCS digest');
      assert.ok(!allDigests.has(finalized.payload.digest),'Unique finalized transaction digest');allDigests.add(finalized.payload.digest);
      const costRow=costMap.get(`${id}/${phase}`);assert.ok(costRow);assert.equal(costRow.digest,finalized.payload.digest);assert.equal(costRow.source,'local-prepared-bcs');
      built[phase]={data:tx.getData(),prepared,finalized};
    }
    const registration=built['renew.register'],certification=built['renew.certify_transfer'];
    const authInput=verifyRegister(registration.data,encoded,bytes,nonce,root,plan),newObject=createdObject(registration.finalized.payload,blobType);
    assert.notEqual(newObject,memory.source_object_id);assert.equal(newObject,memory.current_object_id);
    assert.equal(registered.blobObjectId,newObject);assert.equal(registered.txDigest,registration.finalized.payload.digest);
    assert.equal(registered.blobId,encoded.blobId);assert.equal(registered.nonce,encoded.nonce);
    for(const key of ['blobId','blobObjectId','txDigest','nonce'])assert.equal(uploaded[key],registered[key]);
    assert.equal(certified.blobId,encoded.blobId);assert.equal(certified.blobObjectId,newObject);assert.equal(certified.certifyDigest,certification.finalized.payload.digest);
    const certBytes=canonical64(uploaded.certificate,undefined,'Uploaded certificate'),certificate=certificateBcs.parse(certBytes);
    assert.deepEqual(Buffer.from(certificateBcs.serialize(certificate).toBytes()),certBytes);assert.ok(certificate.signers.length&&certificate.serializedMessage.length&&certificate.signature.length);
    const certify=one(certification.data.commands,c=>call(c,'system','certify_blob'),'One certify command').MoveCall;
    assert.deepEqual(bcs.byteVector().parse(pure(certification.data,certify.arguments[2])),certificate.signature);
    assert.deepEqual(bcs.byteVector().parse(pure(certification.data,certify.arguments[4])),certificate.serializedMessage);
    const ordered=[planned,encodedRow,registration.prepared,registration.finalized,registeredRow,uploadedRow,certification.prepared,certification.finalized,certifiedRow,record('db_commit','finalized')];
    for(let i=1;i<ordered.length;i++)assert.ok(ordered[i-1].id<ordered[i].id,`${id} immutable checkpoint/transaction order`);
    assert.ok(Date.parse(encodedRow.created_at)<=Date.parse(registration.prepared.created_at),'Nonce checkpoint timestamp precedes prepared transaction');
    const matchingPosts=posts.filter(row=>{try{return new URL(row.event.url).searchParams.get('tx_id')===registered.txDigest;}catch{return false;}});
    assert.ok(matchingPosts.length,'Actual recorded raw-body relay POST');
    const successes=matchingPosts.filter(row=>row.event.status===200);assert.ok(successes.length,'Actual successful relay response');
    for(const post of matchingPosts)verifyUploadEvent(post.event,encoded,registered,bytes,config.relayUrl,false);
    for(const post of successes)verifyUploadEvent(post.event,encoded,registered,bytes,config.relayUrl);
    items.push({memoryId:id,blobId:encoded.blobId,newObjectId:newObject,rootHashSha256:sha(root),nonceSha256:sha(nonce),
      cacheKey:encoded.cacheKey,cacheHit:encoded.cacheHit,numShards:encoded.numShards,authInput,registerDigest:registered.txDigest,
      certifyDigest:certified.certifyDigest,relayPosts:matchingPosts.length,successfulRelayPosts:successes.length,checkpointOrder:ordered.map(row=>row.id)});
  }
  assert.equal(allDigests.size,2*expected);assert.equal(costMap.size,2*expected);
  assert.equal(snapshot.journal.filter(row=>row.phase==='db_commit'&&row.state==='finalized').length,expected);
  const matchedDigests=new Set(items.map(row=>row.registerDigest));
  assert.ok(posts.every(row=>matchedDigests.has(new URL(row.event.url).searchParams.get('tx_id'))),'No unmatched relay POST');
  const summary={all_passed:true,runId:config.runId,auditedAt:new Date().toISOString(),expectedCount:expected,
    method:'Independent downloaded bytes + root commitment/cache binding + prepared BCS digest/register/auth + finalized effects + actual relay transport + SQL checkpoint ordering',
    noNetwork:true,noKeys:true,localBcsTransactions:allDigests.size,uniqueFreshNonces:currentNonces.size,priorNonceRows:snapshot.priorNonces.length,
    implementationFingerprint:fingerprint,implementationFilesVerified:implementationFiles,cacheHits:items.filter(row=>row.cacheHit).length,cacheMisses:items.filter(row=>!row.cacheHit).length,
    relayPosts:posts.length,successfulRelayPosts:posts.filter(row=>row.event.status===200).length,commits:expected,
    manifestSha256:sha(manifestBytes),costSha256:sha(costBytes),journalExport:exportPath,journalExportSha256:sha(await readFile(exportPath)),
    sourceSha256:sha(await readFile(fileURLToPath(import.meta.url))),logFiles:logProof.files,
    limitations:['Does not read cache HMAC keys or certify cache file HMACs; verifies content/root/source/fingerprint commitments independently.',
      'Fresh nonce randomness is established by reviewed runtime source; audit proves length, uniqueness and absence from prior same-content cycle checkpoints.',
      'Saved transport proves the observed POST body binding; successful chain certification and separate fresh-object audit supply storage verification.',
      'Original cost auditor remains responsible for strict command allowlists, monetary tracing, fused fence/owner transfer and gas totals.'],items};
  await writeFile(path.resolve(out),pretty(summary));console.log(JSON.stringify({all_passed:true,runId:config.runId,items:expected,localBcsTransactions:allDigests.size,uniqueFreshNonces:currentNonces.size,out:path.resolve(out)}));
}
async function selfTest(){
  const bytes=Buffer.from('independent metadata checkpoint audit'),nonce=Buffer.alloc(32,17),root=Buffer.alloc(32,23),blobId=deriveBlobId(root,bytes.length),fingerprint='a'.repeat(64);
  const memory={run_id:'fixture',memory_id:0,owner:'owner',namespace:'namespace',ciphertext_sha256:sha(bytes),ciphertext_bytes:bytes.length,source_blob_id:blobId};
  const provenance=JSON.stringify({originRunId:'fixture',originMemoryId:0,vectorEntryId:'fixture:0',owner:'owner',namespace:'namespace'});
  const binding={schemaVersion:1,fingerprint,sha256:sha(bytes),byteLength:bytes.length,expectedBlobId:blobId,numShards:100,encodingType:'RS2',sourceProvenance:provenance};
  const encoded={step:'encoded',execution:'explicit-public-sdk-v1',blobId,ciphertextSha256:sha(bytes),byteLength:bytes.length,unencodedSize:bytes.length,
    unencodedLength:String(bytes.length),encodingType:'RS2',cacheVersion:1,rootBindingVerified:true,codecFingerprint:fingerprint,numShards:100,sourceProvenance:provenance,
    cacheKey:sha(canonical(binding)),cacheHit:false,nonce:nonce.toString('base64'),rootHash:root.toString('base64'),rootDerivedBlobId:blobId};
  const plan={numShards:100,requestedEpochs:5};bindCheckpoint(memory,plan,encoded,bytes,fingerprint);
  for(const change of [{nonce:'invalid'},{rootHash:Buffer.alloc(32).toString('base64')},{cacheKey:'bad'},{sourceProvenance:'wrong'},{codecFingerprint:'bad'},{numShards:99},{execution:'legacy'},{ciphertextSha256:'bad'}])
    assert.throws(()=>bindCheckpoint(memory,plan,{...encoded,...change},bytes,fingerprint));
  const input=value=>({Pure:{bytes:Buffer.from(value).toString('base64')}}),u=(n,length)=>{const value=Buffer.alloc(length);if(length===8)value.writeBigUInt64LE(BigInt(n));else value.writeUIntLE(n,0,length);return value;};
  const data={inputs:[input(Buffer.from(blobId,'base64url')),input(root),input(u(bytes.length,8)),input([1]),input(u(5,4)),input(rootAuth(bytes,nonce))],commands:[
    {MoveCall:{module:'system',function:'reserve_space',arguments:[{}, {},{Input:4}]}},
    {MoveCall:{module:'system',function:'register_blob',arguments:[{},{},{Input:0},{Input:1},{Input:2},{Input:3},{Input:3}]}}]};
  assert.equal(verifyRegister(data,encoded,bytes,nonce,root,plan),5);
  const bad=structuredClone(data);bad.inputs[5]=input(Buffer.alloc(72));assert.throws(()=>verifyRegister(bad,encoded,bytes,nonce,root,plan));
  const relay='https://upload-relay.testnet.walrus.space',registered={txDigest:'digest',blobObjectId:'object'},url=new URL(relay+'/v1/blob-upload-relay');
  for(const [key,value]of Object.entries({blob_id:blobId,nonce:nonce.toString('base64url'),tx_id:'digest',deletable_blob_object:'object',encoding_type:'RS2'}))url.searchParams.set(key,value);
  const event={url:url.href,status:200,method:'POST',sha256:sha(bytes),bytes:bytes.length};verifyUploadEvent(event,encoded,registered,bytes,relay);
  for(const change of [{bytes:0},{sha256:'wrong'},{status:500},{url:url.href+'&extra=bad'}])assert.throws(()=>verifyUploadEvent({...event,...change},encoded,registered,bytes,relay));
  const cert={signers:[1,3],serializedMessage:new Uint8Array([4,5]),signature:new Uint8Array([6,7])};assert.deepEqual(certificateBcs.parse(certificateBcs.serialize(cert).toBytes()),cert);
  console.log(JSON.stringify({all_passed:true,selfTest:true,groups:5,negativeCases:13,noNetwork:true,noKeys:true}));
}
try{await main();}catch(error){console.error(JSON.stringify({all_passed:false,error:String(error?.message??error).slice(0,1500)}));process.exitCode=1;}
