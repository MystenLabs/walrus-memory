// Offline adapter tests execute the actual TypeScript functions extracted from
// run.ts. Network, CLI signing and chain submission are replaced by strict mocks;
// cryptographic metadata/cache tests live separately in test-metadata-cache.mjs.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

let forbiddenNetworkCalls=0;
globalThis.fetch=async()=>{forbiddenNetworkCalls++;throw new Error('Offline adapter test prohibits network');};
const dependencyRoot=process.env.MEMWAL_RENEWAL_TEST_DEPENDENCIES??
  fileURLToPath(new URL('../../../.grok/renewal-testnet/cache/dependencies/node_modules',import.meta.url));
const require=createRequire(path.join(dependencyRoot,'../package.json'));
const ts=require('typescript');
const load=async name=>import(pathToFileURL(require.resolve(name)));
const {Transaction}=await load('@mysten/sui/transactions');
const {bcs}=await load('@mysten/sui/bcs');
const {fromBase64,normalizeStructTag}=await load('@mysten/sui/utils');
const {blake2b}=await load('@noble/hashes/blake2.js');
const filename=fileURLToPath(new URL('../runtime/run.ts',import.meta.url));
const source=await readFile(filename,'utf8');
const metadataSource=await readFile(new URL('../runtime/metadata-cache.ts',import.meta.url),'utf8');
const digest=value=>createHash('sha256').update(value).digest('hex');
const clone=value=>structuredClone(value);
function compiled(code,dependencies){
  const js=ts.transpileModule(code,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}}).outputText;
  return new Function(...Object.keys(dependencies),js)(...Object.values(dependencies));
}
const deriveCode=metadataSource.slice(metadataSource.indexOf('export function deriveMetadataBlobId'),metadataSource.indexOf('\nasync function packageRoot'))
  .replace('export function','function');
const deriveMetadataBlobId=compiled(deriveCode+'\nreturn deriveMetadataBlobId;',{assert,blake2b});
const adapterCode=source.slice(source.indexOf('const RelayCertificate='),source.indexOf('async function appendFusedTail'))+
  source.slice(source.indexOf('async function uploadExplicitFused'),source.indexOf('async function uploadOne'))+
  '\nreturn {uploadExplicitFused,createdBlobId,RelayCertificate};';
const root=new Uint8Array(32).fill(17),bytes=new TextEncoder().encode('Synthetic unchanged ciphertext: offline adapter fixture.');
const blobId=deriveMetadataBlobId(root,bytes.length);
const publicAddress=n=>'0x'+n.toString(16).padStart(64,'0');
const row={run_id:'child',memory_id:0,origin_run_id:'canonical-full',origin_memory_id:7,
  vector_entry_id:'canonical-full:7',owner:publicAddress(2),namespace:'synthetic/existing',
  ciphertext_sha256:digest(bytes),source_blob_id:blobId,source_object_id:publicAddress(3),source_end_epoch:588};
const plan={currentEpoch:584,numShards:1000,requestedEpochs:5,targetEndEpoch:589};
const metadata={memwal_owner:row.owner,memwal_namespace:row.namespace,exercise_run:'canonical-full',exercise_memory:'7'};
function harness(options={}){
  const state={journal:[],receipts:new Map(),events:[],calls:{compute:0,register:0,relay:0,certify:0,submit:0,tail:0,system:0},
    relayInputs:[],registerInputs:[],failJournal:options.failJournal,failRelay:options.failRelay??0,
    currentShards:options.currentShards??1000};
  const config={runId:'child',walrusPackageId:publicAddress(8)};
  const writer={toSuiAddress:()=>publicAddress(1)};
  const record=(kind,detail)=>state.events.push({kind,...detail});
  const journal=async(id,phase,status,payload)=>{
    record('journal',{phase,state:status});
    if(state.failJournal===status){state.failJournal=null;throw new Error('synthetic journal crash '+status);}
    state.journal.push({id,phase,state:status,payload:clone(payload)});
  };
  const sql=async(strings,...values)=>{
    const text=strings.join('?');
    assert.match(text,/SELECT/,'Offline database mock permits SELECT only');
    if(text.includes("phase='renew.flow'"))return clone(state.journal.filter(x=>x.id===values[1]&&x.phase==='renew.flow'));
    assert.ok(text.includes("state='finalized'"));
    const receipt=state.receipts.get(`${values[1]}:${values[2]}`);
    return receipt?[{payload:clone(receipt)}]:[];
  };
  const receipt=(phase,id)=>({digest:phase==='renew.register'?'fresh-register-digest':'fresh-certify-digest',
    effects:{status:{success:true},changedObjects:phase==='renew.register'?[{objectId:publicAddress(100+id),idOperation:'Created',outputState:'ObjectWrite'}]:[]},
    objectTypes:phase==='renew.register'?{[publicAddress(100+id)]:`${config.walrusPackageId}::blob::Blob`}:{}});
  const submit=async(id,phase,tx)=>{
    state.calls.submit++;record('submit',{phase});
    assert.ok(tx instanceof Transaction);assert.ok(['renew.register','renew.certify_transfer'].includes(phase));
    assert.ok(!state.receipts.has(`${id}:${phase}`),'Never repeat a finalized paid phase');
    const transaction=receipt(phase,id);state.receipts.set(`${id}:${phase}`,clone(transaction));
    return {digest:transaction.digest,transaction};
  };
  const system=async()=>{state.calls.system++;return {committee:{n_shards:state.currentShards}};};
  const walrus={systemState:system,
    sendUploadRelayTip(input){record('tip',{});assert.deepEqual(input.blobDigest,new Uint8Array(Buffer.from(row.ciphertext_sha256,'hex')));
      assert.equal(input.nonce.length,32);return tx=>tx.pure.u64(1);},
    registerBlob(input){state.calls.register++;state.registerInputs.push(clone(input));record('register_builder',{});
      assert.equal(input.epochs,5);assert.equal(input.deletable,true);assert.deepEqual(input.attributes,metadata);
      return tx=>tx.moveCall({target:'0x2::test::new_blob',arguments:[]});},
    async writeBlobToUploadRelay(input){state.calls.relay++;state.relayInputs.push(clone(input));record('relay',{});
      assert.deepEqual(input.blob,bytes);assert.equal(input.blobId,blobId);assert.equal(input.txDigest,'fresh-register-digest');
      if(state.failRelay-->0)throw new Error('synthetic transient relay failure');
      return {blobId,certificate:{signers:[1],serializedMessage:[2,3],signature:[4,5]}};},
    certifyBlobTransaction(input){state.calls.certify++;record('certify_builder',{});
      assert.equal(typeof input.certificate,'string');assert.deepEqual(adapter.RelayCertificate.parse(fromBase64(input.certificate)),
        {signers:[1],serializedMessage:new Uint8Array([2,3]),signature:new Uint8Array([4,5])});
      const tx=new Transaction();tx.moveCall({target:'0x2::test::certify_blob',arguments:[]});return tx;}
  };
  class WalrusClient{systemState=system;}
  const computer={fingerprint:'pinned-offline-codec-fingerprint',
    async compute(input){state.calls.compute++;record('compute',{});assert.deepEqual(input.bytes,bytes);assert.equal(input.expectedBlobId,blobId);
      return {blobId,rootHash:new Uint8Array(root),unencodedLength:BigInt(bytes.length),encodingType:'RS2',sha256:digest(bytes),
        byteLength:bytes.length,numShards:1000,cacheKey:'bound-cache-key',cacheVersion:1,fingerprint:computer.fingerprint,
        cacheHit:options.cacheHit??false,rootDerivedBlobId:blobId,rootBindingVerified:true};}};
  const appendFusedTail=async(tx,id,r,objectId,b,m,p)=>{state.calls.tail++;record('fused_tail',{});
    assert.deepEqual(b,bytes);assert.deepEqual(m,metadata);assert.equal(p.targetEndEpoch,589);
    tx.moveCall({target:'0x2::test::seal_fence',arguments:[]});tx.transferObjects([tx.object(objectId)],r.owner);};
  const adapter=compiled(adapterCode,{assert,bcs,config,sql,normalizeStructTag,Transaction,WalrusClient,walrus,sui:{},
    writer,submit,journal,json:JSON.stringify,vectorId:r=>r.vector_entry_id,now:()=>performance.now(),phaseTimes:{},
    timed:async(_name,fn)=>fn(),getMetadataComputer:async()=>computer,metric:()=>{},sha:digest,randomBytes,fromBase64,
    deriveMetadataBlobId,appendFusedTail});
  state.run=()=>adapter.uploadExplicitFused(0,bytes,metadata,row,plan);state.adapter=adapter;
  return state;
}
const results=[];
async function test(name,fn){await fn();results.push({name,pass:true});}
await test('fresh two-transaction flow persists all checkpoints before dependent work',async()=>{
  const h=harness();const output=await h.run();assert.equal(output.blobId,blobId);assert.equal(output.objectId,publicAddress(100));
  assert.deepEqual(h.calls,{compute:1,register:1,relay:1,certify:1,submit:2,tail:1,system:1});
  const position=(kind,state,phase)=>h.events.findIndex(e=>e.kind===kind&&(!state||e.state===state)&&(!phase||e.phase===phase));
  assert.ok(position('journal','encoded')<position('submit',null,'renew.register'));
  assert.ok(position('journal','registered')<position('relay'));
  assert.ok(position('journal','uploaded')<position('certify_builder'));
  assert.deepEqual(h.journal.map(e=>e.state),['encoded','registered','uploaded','certified']);
  const before=clone(h.calls);await h.run();assert.deepEqual(h.calls,before,'Completed receipt recovery performs no paid/relay/compute work');
});
await test('independent cycles keep same bytes/root/blob but create a fresh nonce',async()=>{
  const a=harness(),b=harness({cacheHit:true});await a.run();await b.run();
  const ae=a.journal[0].payload,be=b.journal[0].payload;
  assert.equal(ae.blobId,be.blobId);assert.equal(ae.rootHash,be.rootHash);assert.equal(ae.sourceProvenance,be.sourceProvenance);
  assert.notEqual(ae.nonce,be.nonce);assert.equal(be.cacheHit,true);assert.equal(b.calls.relay,1);assert.equal(b.calls.register,1);
});
await test('crash after finalized registration recovers created object without remint',async()=>{
  const h=harness({failJournal:'registered'});await assert.rejects(h.run(),/synthetic journal crash registered/);
  const nonce=h.journal[0].payload.nonce;await h.run();
  assert.equal(h.calls.register,1);assert.equal(h.calls.submit,2);assert.equal(h.calls.compute,1);
  assert.equal(h.journal.find(e=>e.state==='registered').payload.nonce,nonce);
});
await test('relay retry reuses exact registration digest/object/nonce and bytes',async()=>{
  const h=harness({failRelay:1});await assert.rejects(h.run(),/synthetic transient relay failure/);await h.run();
  assert.equal(h.calls.register,1);assert.equal(h.calls.submit,2);assert.equal(h.calls.relay,2);
  assert.deepEqual(h.relayInputs[0],h.relayInputs[1]);
});
await test('crash after finalized certify/transfer recovers without repeat certificate or relay',async()=>{
  const h=harness({failJournal:'certified'});await assert.rejects(h.run(),/synthetic journal crash certified/);
  const before=clone(h.calls);await h.run();assert.deepEqual(h.calls,before);assert.equal(h.journal.at(-1).state,'certified');
});
await test('corrupted encoded root fails independent binding before any relay or paid work',async()=>{
  const h=harness({failJournal:'registered'});await assert.rejects(h.run());
  h.journal[0].payload.rootHash=Buffer.alloc(32,99).toString('base64');const before=clone(h.calls);
  await assert.rejects(h.run(),/independently derive/);assert.deepEqual(h.calls,before);
});
await test('noncanonical saved nonce and changed codec fail closed',async()=>{
  for(const mutate of [e=>e.nonce=e.nonce.replace(/=+$/,''),e=>e.codecFingerprint='changed-codec']){
    const h=harness({failJournal:'registered'});await assert.rejects(h.run());mutate(h.journal[0].payload);
    const before=clone(h.calls);await assert.rejects(h.run());assert.deepEqual(h.calls,before);
  }
});
await test('shard change after registration stops before relay and never remints',async()=>{
  const h=harness({failJournal:'registered'});await assert.rejects(h.run());
  // Reuse persisted journal/receipts but return a different fresh system snapshot.
  h.currentShards=1001;const before=clone(h.calls);
  await assert.rejects(h.run(),/Shard parameters changed after registration/);
  assert.equal(h.calls.register,before.register);assert.equal(h.calls.submit,before.submit);
  assert.equal(h.calls.relay,before.relay);assert.equal(h.calls.system,before.system+1);
});
await test('created object recovery rejects ambiguous/unsuccessful effects',async()=>{
  const h=harness();await h.run();const r=clone(h.receipts.get('0:renew.register'));
  r.effects.changedObjects.push({...r.effects.changedObjects[0],objectId:publicAddress(101)});
  r.objectTypes[publicAddress(101)]=r.objectTypes[publicAddress(100)];
  assert.throws(()=>h.adapter.createdBlobId(r),/exactly one/);r.effects.status.success=false;
  assert.throws(()=>h.adapter.createdBlobId(r),/successful finalized/);
});
await test('unresolved prepared submit stops before build, funds, signing or execution',async()=>{
  const submitCode=source.slice(source.indexOf('async function submit('),source.indexOf('async function auditSchema'));
  const actual=compiled(submitCode+'\nreturn submit;',{assert,writer:{},boundedChain:async fn=>fn(),timed:async(_n,fn)=>fn(),
    sql:async()=>[{payload:{digest:'unresolved-public-digest'}}],config:{runId:'child'}});
  const tx=new Proxy({},{get(){throw new Error('Must not build or mutate transaction');}});
  await assert.rejects(actual(0,'renew.register',tx),/Unreconciled prepared transaction/);
});
await test('relay JSON timing wrapper preserves single-read Response semantics',async()=>{
  const response=new Response(JSON.stringify({certificate:'public-test-only'}));let measured=0;
  const originalJson=response.json.bind(response);response.json=async()=>{try{return await originalJson();}finally{measured++;}};
  assert.deepEqual(await response.json(),{certificate:'public-test-only'});assert.equal(measured,1);
});
assert.equal(forbiddenNetworkCalls,0);
const summary={schemaVersion:1,pass:true,groups:results.length,results,
  scope:'Actual adapter/receipt/submit functions with real SDK Transaction and BCS; strict mocked chain/relay/DB. Actual metadata crypto/pool validated separately. No signing, wallet keys, network or chain writes.',
  runtimeSha256:digest(source),networkCalls:0,chainWrites:0,cliSigningCalls:0};
const output=process.env.MEMWAL_RENEWAL_ADAPTER_EVIDENCE;
if(output){await mkdir(path.dirname(output),{recursive:true});await writeFile(output,JSON.stringify(summary,null,2)+'\n');}
console.log(JSON.stringify(summary));
