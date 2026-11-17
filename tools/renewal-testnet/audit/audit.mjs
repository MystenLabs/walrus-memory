#!/usr/bin/env node
// Read-only, independent of run.ts/product completion validators. No wallet APIs.
import assert from 'node:assert/strict';
import {readFile, writeFile, mkdir} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {createRequire} from 'node:module';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';

const argv=process.argv.slice(2);
const flag=(name,fallback)=>argv.includes(name)?argv[argv.indexOf(name)+1]:fallback;
const deps=flag('--deps',null);
const require=deps?createRequire(path.join(path.resolve(deps),'../package.json')):createRequire(import.meta.url);
const load=specifier=>import(pathToFileURL(require.resolve(specifier)).href);
const [{SuiGrpcClient},{bcs},{deriveDynamicFieldID,normalizeStructTag,normalizeSuiAddress,fromBase58},
  {WalrusClient,blobIdFromInt,blobIdToInt}]=await Promise.all([
  load('@mysten/sui/grpc'),load('@mysten/sui/bcs'),load('@mysten/sui/utils'),load('@mysten/walrus')]);

const Storage=bcs.struct('AuditStorage',{id:bcs.Address,start_epoch:bcs.u32(),end_epoch:bcs.u32(),storage_size:bcs.u64()});
const Blob=bcs.struct('AuditBlob',{id:bcs.Address,registered_epoch:bcs.u32(),blob_id:bcs.u256(),
  size:bcs.u64(),encoding_type:bcs.u8(),certified_epoch:bcs.option(bcs.u32()),storage:Storage,deletable:bcs.bool()});
// Move VecMap preserves insertion order; bcs.map sorts during serialization.
const Metadata=bcs.struct('AuditMetadata',{metadata:bcs.struct('AuditVecMap',{
  contents:bcs.vector(bcs.struct('AuditEntry',{key:bcs.string(),value:bcs.string()}))})});
const Field=bcs.struct('AuditMetadataField',{id:bcs.Address,name:bcs.vector(bcs.u8()),value:Metadata});
const nameBytes=bcs.vector(bcs.u8()).serialize([...Buffer.from('metadata')]).toBytes();
const metadataId=id=>deriveDynamicFieldID(id,{vector:{u8:null}},nameBytes);
const sha=value=>createHash('sha256').update(value).digest('hex');
const json=value=>JSON.stringify(value,(_key,v)=>v instanceof Uint8Array?{base64:Buffer.from(v).toString('base64')}:typeof v==='bigint'?v.toString():v,2);
const address=value=>normalizeSuiAddress(value);
const owner=(object,kind)=>object?.owner?.[kind];
const briefError=error=>String(error?.message??error).split('\n')[0].slice(0,600);

function validateManifest(rows,expected,runId,expectedOwners,config={}){
  assert.ok(Array.isArray(rows)); assert.equal(rows.length,expected,'Manifest cohort count');
  const sources=new Set(),currents=new Set(),blobs=new Set();
  rows.forEach((row,index)=>{
    assert.equal(row.memory_id,index,'Manifest must contain ordered contiguous memory IDs');
    assert.equal(row.run_id,runId); assert.equal(row.stage,'migrated');
    assert.equal(address(row.owner),row.owner); assert.equal(typeof row.namespace,'string');
    assert.match(row.ciphertext_sha256,/^[a-f0-9]{64}$/); assert.ok(Number.isSafeInteger(row.ciphertext_bytes)&&row.ciphertext_bytes>0);
    for(const key of ['source_object_id','current_object_id'])assert.equal(address(row[key]),row[key]);
    assert.notEqual(row.source_object_id,row.current_object_id);
    assert.ok(Number.isSafeInteger(row.source_end_epoch)&&Number.isSafeInteger(row.current_end_epoch));
    assert.ok(row.current_end_epoch>row.source_end_epoch);
    assert.equal(row.source_metadata.memwal_owner,row.owner);
    assert.equal(row.source_metadata.memwal_namespace,row.namespace);
    if(config.mode==='migration-only'){
      assert.equal(row.parent_run_id,config.parentSourceRunId);
      assert.equal(row.parent_memory_id,index+Number(config.sourceOffset??0));
      assert.equal(row.origin_run_id,row.parent_run_id);assert.equal(row.origin_memory_id,row.parent_memory_id);
      assert.equal(row.vector_entry_id,`${row.origin_run_id}:${row.origin_memory_id}`);
      assert.equal(row.source_metadata.exercise_run,row.provenance_run_id??row.origin_run_id);
      assert.equal(row.source_metadata.exercise_memory,String(row.origin_memory_id));
      assert.equal(typeof row.source_provenance,'object');assert.ok(row.source_provenance);
    }else{
      assert.equal(row.source_metadata.exercise_run,runId);
      assert.equal(row.source_metadata.exercise_memory,String(row.memory_id));
    }
    sources.add(row.source_object_id);currents.add(row.current_object_id);blobs.add(row.source_blob_id);
  });
  assert.equal(sources.size,expected);assert.equal(currents.size,expected);assert.equal(blobs.size,expected);
  assert.equal([...sources].filter(id=>currents.has(id)).length,0,'Source/current sets must be disjoint');
  if(expectedOwners!==undefined)assert.equal(new Set(rows.map(row=>row.owner)).size,expectedOwners,'Fixture owner count');
}

function auditPair(row,objects,config,currentEpoch){
  const expectedBlobType=normalizeStructTag(`${config.walrusPackageId}::blob::Blob`);
  const expectedFieldType=normalizeStructTag(`0x2::dynamic_field::Field<vector<u8>,${config.walrusPackageId}::metadata::Metadata>`);
  const parsed=[];
  for(const [phase,id,endEpoch]of [['source',row.source_object_id,row.source_end_epoch],['current',row.current_object_id,row.current_end_epoch]]){
    const object=objects.get(id);assert.ok(object,`${phase} Blob missing`);
    assert.equal(object.objectId,id);assert.equal(normalizeStructTag(object.type),expectedBlobType);
    assert.equal(address(owner(object,'AddressOwner')),row.owner,`${phase} owner`);
    assert.ok(object.content instanceof Uint8Array,`${phase} Blob BCS missing`);
    const blob=Blob.parse(object.content);
    assert.deepEqual(Blob.serialize(blob).toBytes(),object.content,`${phase} exact Blob BCS layout`);
    assert.equal(address(blob.id),id);assert.equal(blobIdFromInt(blob.blob_id),row.source_blob_id);
    assert.equal(BigInt(blob.size),BigInt(row.ciphertext_bytes));assert.equal(blob.deletable,true);
    assert.ok(Number.isSafeInteger(blob.certified_epoch),`${phase} must be certified`);
    assert.ok(blob.registered_epoch<=blob.certified_epoch&&blob.certified_epoch<=currentEpoch);
    assert.equal(blob.storage.end_epoch,endEpoch,`${phase} chain/DB end epoch`);
    assert.ok(blob.storage.start_epoch<=blob.storage.end_epoch);
    assert.ok(BigInt(blob.storage.storage_size)>0n);
    const fieldId=metadataId(id),fieldObject=objects.get(fieldId);
    assert.ok(fieldObject,`${phase} metadata missing`);assert.equal(fieldObject.objectId,fieldId);
    assert.equal(normalizeStructTag(fieldObject.type),expectedFieldType);
    assert.equal(address(owner(fieldObject,'ObjectOwner')),id,`${phase} metadata parent`);
    const field=Field.parse(fieldObject.content);
    assert.deepEqual(Field.serialize(field).toBytes(),fieldObject.content,`${phase} exact metadata BCS layout`);
    assert.equal(address(field.id),fieldId);assert.deepEqual(field.name,[...Buffer.from('metadata')]);
    const entries=field.value.metadata.contents.map(({key,value})=>[key,value]);
    assert.equal(new Set(entries.map(([key])=>key)).size,entries.length,`${phase} metadata keys unique`);
    const metadata=Object.fromEntries(entries);
    assert.deepEqual(metadata,row.source_metadata,`${phase} exact metadata`);
    parsed.push({phase,objectId:id,version:object.version,digest:object.digest,
      previousTransaction:object.previousTransaction,blobId:blobIdFromInt(blob.blob_id),owner:row.owner,
      bytes:String(blob.size),registeredEpoch:blob.registered_epoch,certifiedEpoch:blob.certified_epoch,
      endEpoch:blob.storage.end_epoch,metadataId:fieldId,metadataVersion:fieldObject.version,
      metadataDigest:fieldObject.digest,metadata,blobBcsSha256:sha(object.content),metadataBcsSha256:sha(fieldObject.content)});
  }
  assert.ok(parsed[1].endEpoch>parsed[0].endEpoch);assert.ok(parsed[1].endEpoch>currentEpoch,'Current lease must be live');
  return {memoryId:row.memory_id,passed:true,sameOwnerContentCoexist:true,
    liveLeaseOverlap:parsed[0].endEpoch>currentEpoch,source:parsed[0],current:parsed[1]};
}

const exportSql=`BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='30s';
SELECT coalesce(jsonb_agg(jsonb_build_object(
 'run_id',run_id,'memory_id',memory_id,'owner',owner,'namespace',namespace,
 'ciphertext_sha256',ciphertext_sha256,'ciphertext_bytes',ciphertext_bytes,
 'source_metadata',source_metadata,'source_blob_id',source_blob_id,
 'source_object_id',source_object_id,'current_object_id',current_object_id,
 'source_end_epoch',source_end_epoch,'current_end_epoch',current_end_epoch,'stage',stage
) ORDER BY memory_id),'[]'::jsonb)
FROM exercise_renewal_memories WHERE run_id=:'run_id';
ROLLBACK;`;

async function selfTest(){
  const id=n=>`0x${n.toString(16).padStart(64,'0')}`;
  const config={walrusPackageId:id(9)},runId='audit-self-test';
  const metadata={memwal_owner:id(1),memwal_namespace:'fixture',exercise_run:runId,exercise_memory:'0'};
  const row={run_id:runId,memory_id:0,owner:id(1),namespace:'fixture',ciphertext_sha256:'a'.repeat(64),
    ciphertext_bytes:4153,source_metadata:metadata,source_blob_id:blobIdFromInt(123n),
    source_object_id:id(2),current_object_id:id(3),source_end_epoch:21,current_end_epoch:23,stage:'migrated'};
  validateManifest([row],1,runId);
  const existing={...row,run_id:'renewal-child',parent_run_id:runId,parent_memory_id:66,
    origin_run_id:runId,origin_memory_id:66,vector_entry_id:`${runId}:66`,provenance_run_id:runId,
    source_provenance:{source_object_id:id(2)},source_metadata:{...metadata,exercise_memory:'66'}};
  const existingConfig={mode:'migration-only',parentSourceRunId:runId,sourceOffset:66};
  validateManifest([existing],1,'renewal-child',1,existingConfig);
  assert.throws(()=>validateManifest([{...existing,source_metadata:{...existing.source_metadata,exercise_run:'renewal-child'}}],1,'renewal-child',1,existingConfig));
  const objects=new Map();
  for(const [objectId,end_epoch]of [[id(2),21],[id(3),23]]){
    const content=Blob.serialize({id:objectId,registered_epoch:20,blob_id:blobIdToInt(row.source_blob_id),
      size:4153,encoding_type:1,certified_epoch:20,storage:{id:id(4),start_epoch:20,end_epoch,storage_size:5000},deletable:true}).toBytes();
    objects.set(objectId,{objectId,type:`${id(9)}::blob::Blob`,owner:{AddressOwner:id(1)},content});
    const fieldId=metadataId(objectId);
    objects.set(fieldId,{objectId:fieldId,type:`0x2::dynamic_field::Field<vector<u8>,${id(9)}::metadata::Metadata>`,
      owner:{ObjectOwner:objectId},content:Field.serialize({id:fieldId,name:[...Buffer.from('metadata')],
        value:{metadata:{contents:Object.entries(metadata).map(([key,value])=>({key,value}))}}}).toBytes()});
  }
  assert.equal(auditPair(row,objects,config,20).passed,true);
  const mutated=new Map(objects);const current=objects.get(id(3));
  const uncertified=Blob.parse(current.content);uncertified.certified_epoch=null;
  mutated.set(id(3),{...current,content:Blob.serialize(uncertified).toBytes()});
  assert.throws(()=>auditPair(row,mutated,config,20),/certified/);
  assert.throws(()=>auditPair({...row,current_end_epoch:22},objects,config,20),/end epoch/);
  assert.throws(()=>auditPair(row,objects,config,23),/live/);
  const wrongOwner=new Map(objects);wrongOwner.set(id(3),{...current,owner:{AddressOwner:id(8)}});
  assert.throws(()=>auditPair(row,wrongOwner,config,20),/owner/);
  const missingField=new Map(objects);missingField.delete(metadataId(id(3)));
  assert.throws(()=>auditPair(row,missingField,config,20),/metadata missing/);
  console.log(json({selfTest:'PASS',positivePairs:1,rejectedCases:6,existingOffsetProvenance:'PASS',networkRequests:0}));
}

async function main(){
  if(argv.includes('--self-test'))return selfTest();
  const configPath=flag('--config',null);assert.ok(configPath,'--config PUBLIC_CONFIG.json is required');
  const config=JSON.parse(await readFile(configPath,'utf8'));
  const expected=Number(flag('--expected-count','1000'));
  const expectedOwners=Number(flag('--expected-owners',String(Math.min(expected,2))));
  assert.ok(Number.isInteger(expected)&&expected>0&&expected<=1000);assert.equal(config.network,'testnet');
  assert.ok(Number.isInteger(expectedOwners)&&expectedOwners>0&&expectedOwners<=expected);
  assert.match(config.runId,/^renewal-[a-zA-Z0-9-]+$/);
  const endpoint=new URL(config.suiGrpcUrl);
  assert.equal(endpoint.protocol,'https:');assert.match(endpoint.hostname,/^(fullnode|mysten-rpc)\.testnet\.sui\.io$/);
  assert.equal(address(config.walrusPackageId),config.walrusPackageId);
  const dbUrl=new URL(config.databaseUrl);
  assert.ok(['127.0.0.1','localhost'].includes(dbUrl.hostname),'Only the isolated local database is allowed');
  assert.equal(dbUrl.pathname,'/renewal_e2e');
  const plan={readOnly:true,runId:config.runId,expectedMemories:expected,blobObjects:expected*2,
    metadataObjects:expected*2,batchSize:50,batches:Math.ceil(expected*4/50),batchConcurrency:2,
    endpoint:endpoint.origin,ownerKeyFileRead:false,chainWrites:false};
  if(!argv.includes('--execute')){
    if(argv.includes('--manifest'))validateManifest(JSON.parse(await readFile(flag('--manifest',null),'utf8')),expected,config.runId,expectedOwners,config);
    console.log(json({...plan,executed:false,manifestValidated:argv.includes('--manifest')}));return;
  }
  const out=path.resolve(flag('--out',path.join(path.dirname(fileURLToPath(import.meta.url)),'output',config.runId)));
  await mkdir(out,{recursive:true});
  let manifest;
  if(argv.includes('--manifest'))manifest=JSON.parse(await readFile(flag('--manifest',null),'utf8'));
  else{
    const container=flag('--container',config.container);
    assert.equal(typeof container,'string','--container or config.container is required');
    assert.match(container,/^memwal-renewal[a-zA-Z0-9_.-]*$/);
    const publicSql=config.mode==='migration-only'?exportSql.replace("'run_id',run_id,", "'run_id',run_id,'vector_entry_id',vector_entry_id,'parent_run_id',parent_run_id,'parent_memory_id',parent_memory_id,'origin_run_id',origin_run_id,'origin_memory_id',origin_memory_id,'provenance_run_id',provenance_run_id,'source_provenance',source_provenance,"):exportSql;
    manifest=JSON.parse(execFileSync('docker',['exec','-i',container,'psql','-q','-X','-A','-t','-U','renewal','-d','renewal_e2e',
      '-v','ON_ERROR_STOP=1','-v',`run_id=${config.runId}`],{input:publicSql,encoding:'utf8',maxBuffer:16*1024*1024,timeout:45000}));
  }
  validateManifest(manifest,expected,config.runId,expectedOwners,config);
  await writeFile(path.join(out,'manifest.json'),json(manifest));
  const started=new Date().toISOString(),nativeFetch=globalThis.fetch;
  const requests=[];
  globalThis.fetch=async(input,init)=>{
    const url=new URL(typeof input==='string'?input:input instanceof URL?input.href:input.url);
    // gRPC reads use HTTP POST. Explicit RPC allowlist excludes execution/simulation/signing.
    assert.equal(url.origin,endpoint.origin,'Audit may contact only the verified Sui testnet RPC');
    assert.match(url.pathname,/^\/sui\.rpc\.v2\.(LedgerService|StateService)\/(BatchGetObjects|GetObjects|GetObject|GetServiceInfo|GetEpoch)$/);
    const tick=performance.now();
    const signal=init?.signal?AbortSignal.any([init.signal,AbortSignal.timeout(45000)]):AbortSignal.timeout(45000);
    try{const response=await nativeFetch(input,{...init,signal});requests.push({path:url.pathname,status:response.status,ms:performance.now()-tick});return response;}
    catch(error){requests.push({path:url.pathname,error:String(error.message),ms:performance.now()-tick});throw error;}
  };
  const fresh=()=>new SuiGrpcClient({network:'testnet',baseUrl:config.suiGrpcUrl});
  const sui=fresh();
  const chain=await sui.core.getChainIdentifier();
  assert.equal(Buffer.from(fromBase58(chain.chainIdentifier)).subarray(0,4).toString('hex'),'4c78adac');
  const epochBefore=Number((await new WalrusClient({network:'testnet',suiClient:sui}).stakingState()).epoch);
  assert.ok(Number.isSafeInteger(epochBefore));
  const ids=manifest.flatMap(row=>[row.source_object_id,row.current_object_id,metadataId(row.source_object_id),metadataId(row.current_object_id)]);
  assert.equal(new Set(ids).size,expected*4);
  const batches=[];for(let i=0;i<ids.length;i+=50)batches.push(ids.slice(i,i+50));
  const objects=new Map(),batchErrors=[];let cursor=0;
  await Promise.all(Array.from({length:2},async()=>{
    while(cursor<batches.length){
      const batchIndex=cursor++,batch=batches[batchIndex];
      try{
        let result;
        for(let attempt=0;attempt<3;attempt++){
          try{result=await sui.core.getObjects({objectIds:batch,include:{content:true,previousTransaction:true}});break;}
          catch(error){if(attempt===2)throw error;await new Promise(resolve=>setTimeout(resolve,500*(attempt+1)));}
        }
        assert.equal(result.objects.length,batch.length);
        result.objects.forEach((object,index)=>{
          if(object instanceof Error)throw new Error(`${batch[index]}: ${object.message}`);
          assert.equal(object.objectId,batch[index]);assert.ok(!objects.has(object.objectId));objects.set(object.objectId,object);
        });
      }catch(error){batchErrors.push({batchIndex,error:briefError(error)});}
    }
  }));
  const epochAfter=Number((await new WalrusClient({network:'testnet',suiClient:fresh()}).stakingState()).epoch);
  assert.ok(Number.isSafeInteger(epochAfter));
  const pairs=manifest.map(row=>{try{return auditPair(row,objects,config,epochAfter);}catch(error){return{memoryId:row.memory_id,passed:false,error:briefError(error)};}});
  const passed=pairs.filter(pair=>pair.passed);
  const summary={...plan,executed:true,started,completed:new Date().toISOString(),chainIdentifier:chain.chainIdentifier,
    walrusEpochBefore:epochBefore,walrusEpochAfter:epochAfter,fetchedObjects:objects.size,batchErrors,
    passedMemories:passed.length,failedMemories:pairs.filter(pair=>!pair.passed),
    coexistingSourceCurrentSameOwnerContent:passed.filter(pair=>pair.sameOwnerContentCoexist).length,
    stillLiveLeaseOverlap:passed.filter(pair=>pair.liveLeaseOverlap).length,
    networkRequests:requests.length,passed:passed.length===expected&&objects.size===expected*4&&batchErrors.length===0,
    limitation:'Protocol/database audit; does not exercise Rust HTTP ingress/auth/queues. Same ciphertext retains its content-addressed blob ID.'};
  await Promise.all([writeFile(path.join(out,'objects.json'),json([...objects.values()])),
    writeFile(path.join(out,'pairs.json'),json(pairs)),writeFile(path.join(out,'requests.json'),json(requests)),
    writeFile(path.join(out,'summary.json'),json(summary))]);
  console.log(json(summary));if(!summary.passed)process.exitCode=1;
}
try{await main();}catch(error){console.error(json({audit:'FAILED',message:briefError(error),chainWrites:false}));process.exitCode=1;}
