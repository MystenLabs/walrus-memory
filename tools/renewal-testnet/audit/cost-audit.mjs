import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import path from 'node:path';
import {pathToFileURL} from 'node:url';

// This auditor never signs, submits, updates SQL, reads owner keys, or uses wallet deltas.
const argv=process.argv.slice(2);
const option=(name,fallback)=>argv.includes(name)?argv[argv.indexOf(name)+1]:fallback;
const deps=option('--deps',argv.includes('--self-test')?(process.env.MEMWAL_RENEWAL_TEST_DEPENDENCIES??null):null);
const require=deps?createRequire(path.join(path.resolve(deps),'../package.json')):createRequire(import.meta.url);
const load=specifier=>import(pathToFileURL(require.resolve(specifier)).href);
const [{default:postgres},{Transaction,coinWithBalance},{SuiGrpcClient},{normalizeSuiAddress,normalizeStructTag},{bcs},{Ed25519PublicKey}]=await Promise.all([
  load('postgres'),load('@mysten/sui/transactions'),load('@mysten/sui/grpc'),load('@mysten/sui/utils'),load('@mysten/sui/bcs'),load('@mysten/sui/keypairs/ed25519')]);
const selfTest=argv.includes('--self-test');
// Public RFC8032 fixture only; this synthetic writer is never used for a live run.
const SYNTHETIC_WRITER_PUBLIC_BYTES=Buffer.from('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a','hex');
const SYNTHETIC_WRITER_PUBLIC_KEY=Buffer.concat([Buffer.from([0]),SYNTHETIC_WRITER_PUBLIC_BYTES]).toString('base64');
const SYNTHETIC_WRITER_ADDRESS=new Ed25519PublicKey(SYNTHETIC_WRITER_PUBLIC_BYTES).toSuiAddress();
function configuredWriter(configuration){
  assert.equal(typeof configuration.fundingPublicKey,'string','Cost audit requires the configured funding public key');
  const bytes=Buffer.from(configuration.fundingPublicKey,'base64');
  assert.ok(bytes.length===33&&bytes[0]===0&&bytes.toString('base64')===configuration.fundingPublicKey,
    'Funding public key must be canonical flagged Ed25519 base64');
  const derived=new Ed25519PublicKey(bytes.subarray(1)).toSuiAddress();
  assert.equal(typeof configuration.fundingAddress,'string','Cost audit requires the configured funding address');
  assert.equal(normalizeSuiAddress(configuration.fundingAddress),derived,'Configured funding address must match its public key');
  return derived;
}
const config=selfTest?{network:'testnet',runId:'renewal-self-test',databaseUrl:'postgresql://renewal@127.0.0.1/renewal_e2e',
  suiGrpcUrl:'https://mysten-rpc.testnet.sui.io',policyPackageId:normalizeSuiAddress('0xa'),registryId:normalizeSuiAddress('0x2'),
  fundingPublicKey:SYNTHETIC_WRITER_PUBLIC_KEY,fundingAddress:SYNTHETIC_WRITER_ADDRESS}:
  JSON.parse(await readFile(option('--config',undefined),'utf8'));
const runId=option('--run-id',config.runId);
const allowRpcMissing=argv.includes('--allow-rpc-missing');
const requireComplete=argv.includes('--require-complete');
const expectedSeed=option('--expect-seed',undefined);
const expectedRenew=option('--expect-renew',undefined);
const expectedSetup=option('--expect-setup',undefined);
const migrationOnly=config.mode==='migration-only';
const renewMode=option('--renew-mode',config.renewMode??'unfused');
assert.ok(['fused','unfused'].includes(renewMode));
assert.ok(migrationOnly||renewMode==='unfused','Full mode keeps the original three-transaction flow');
const db=new URL(config.databaseUrl);
const endpoint=new URL(config.suiGrpcUrl);
assert.equal(config.network,'testnet');assert.equal(endpoint.protocol,'https:');
assert.match(endpoint.hostname,/^(fullnode|mysten-rpc)\.testnet\.sui\.io$/);
assert.ok(['127.0.0.1','localhost'].includes(db.hostname)); assert.equal(db.pathname,'/renewal_e2e');
const FRAMEWORK=normalizeSuiAddress('0x2');
const SUI=normalizeStructTag('0x2::sui::SUI');
const WAL=normalizeStructTag('0x8270feb7375eee355e64fdb69c50abb6b5f9393a722883c1cf45f8e26048810a::wal::WAL');
const writer=configuredWriter(config);
const sql=selfTest||argv.includes('--journal')?null:postgres(config.databaseUrl,{max:1,onnotice:()=>{}});
let rpcCalls=0;
const nativeFetch=globalThis.fetch;
globalThis.fetch=async(input,init)=>{
  assert.ok(allowRpcMissing,'Cost audit network fallback is disabled; all prepared BCS must be local');
  const url=new URL(typeof input==='string'?input:input instanceof URL?input.href:input.url);
  assert.equal(url.origin,endpoint.origin);assert.equal(url.pathname,'/sui.rpc.v2.LedgerService/GetTransaction');
  return nativeFetch(input,{...init,signal:AbortSignal.timeout(45000)});
};
const rpc=new SuiGrpcClient({network:'testnet',baseUrl:config.suiGrpcUrl});
const raw=(v)=>BigInt(v);
const ref=(a)=>a?.Input!==undefined?`input:${a.Input}`:a?.Result!==undefined?`result:${a.Result}`:
  a?.NestedResult?`nested:${a.NestedResult.join(':')}`:null;
const pure=(d,a)=>{
  assert.ok(Number.isInteger(a?.Input),'Expected direct pure input');
  const bytes=d.inputs[a.Input]?.Pure?.bytes; assert.equal(typeof bytes,'string','Expected resolved pure input');
  return Buffer.from(bytes,'base64');
};
function uint(d,a,length){const b=pure(d,a);assert.equal(b.length,length);return BigInt(`0x${Buffer.from(b).reverse().toString('hex')}`);}
const isCall=(c,module,fn)=>c?.MoveCall?.module===module&&c.MoveCall.function===fn;
const isFrameworkCall=(c,fn)=>isCall(c,'coin',fn)&&normalizeSuiAddress(c.MoveCall.package)===FRAMEWORK;
function withdrawal(d,index){
  const w=d.inputs[index]?.FundsWithdrawal; assert.ok(w,'Expected FundsWithdrawal input');
  assert.equal(w.withdrawFrom?.$kind,'Sender'); assert.equal(w.reservation?.$kind,'MaxAmountU64');
  return {index,type:normalizeStructTag(w.typeArg.Balance),amount:raw(w.reservation.MaxAmountU64)};
}
function splitPayment(d,arg){
  assert.ok(Array.isArray(arg?.NestedResult),'Payment must be a SplitCoins result');
  const [commandIndex,position]=arg.NestedResult; const split=d.commands[commandIndex]?.SplitCoins;
  assert.ok(split,'Payment source is not SplitCoins');
  const redeemIndex=split.coin?.Result; assert.ok(Number.isInteger(redeemIndex));
  const redeem=d.commands[redeemIndex]; assert.ok(isFrameworkCall(redeem,'redeem_funds'));
  assert.equal(redeem.MoveCall.arguments.length,1);
  const input=redeem.MoveCall.arguments[0].Input; assert.ok(Number.isInteger(input));
  const w=withdrawal(d,input); assert.equal(normalizeStructTag(redeem.MoveCall.typeArguments[0]),w.type);
  const amount=uint(d,split.amounts[position],8);
  return {...w,amount,withdrawalAmount:w.amount,commandIndex,position,redeemIndex,split};
}
function destroyedAfter(d,arg,after,type){
  const indices=d.commands.flatMap((c,i)=>isFrameworkCall(c,'destroy_zero')&&
    normalizeStructTag(c.MoveCall.typeArguments[0])===type&&ref(c.MoveCall.arguments[0])===ref(arg)?[i]:[]);
  assert.equal(indices.length,1,'Payment coin must have exactly one destroy_zero proof'); assert.ok(indices[0]>after);
}
function returnedRemainder(d,payment){
  const calls=d.commands.filter(c=>isFrameworkCall(c,'send_funds')&&
    normalizeStructTag(c.MoveCall.typeArguments[0])===payment.type&&
    ref(c.MoveCall.arguments[0])===`result:${payment.redeemIndex}`);
  assert.equal(calls.length,1,'Expected SDK return of the zero remainder');
  const recipient=`0x${pure(d,calls[0].MoveCall.arguments[1]).toString('hex')}`;
  assert.equal(recipient,d.sender,'SDK remainder must return to sender');
}
function registeredCost(d,events,memory){
  assert.deepEqual(d.gasData.payment,[],'Registration must pay gas from address balance');
  assert.equal(d.sender,writer); assert.equal(d.gasData.owner,writer);
  assert.equal(d.inputs.filter(i=>i.Object?.ImmOrOwnedObject).length,0,'Registration must not lock owned coins');
  const reserves=d.commands.flatMap((c,i)=>isCall(c,'system','reserve_space')?[i]:[]);
  const registers=d.commands.flatMap((c,i)=>isCall(c,'system','register_blob')?[i]:[]);
  assert.equal(reserves.length,1);assert.equal(registers.length,1);
  const reserveIndex=reserves[0],registerIndex=registers[0];
  const reserve=d.commands[reserveIndex].MoveCall,register=d.commands[registerIndex].MoveCall;
  assert.equal(reserve.package,register.package); assert.ok(reserveIndex<registerIndex);
  assert.equal(ref(register.arguments[1]),`result:${reserveIndex}`);
  const storage=splitPayment(d,reserve.arguments[3]),write=splitPayment(d,register.arguments[7]);
  assert.equal(storage.type,WAL);assert.equal(write.type,WAL);
  assert.equal(storage.index,write.index);assert.equal(storage.commandIndex,write.commandIndex);
  assert.notEqual(storage.position,write.position); assert.equal(storage.split.amounts.length,2);
  const walTotal=storage.amount+write.amount;
  assert.equal(storage.withdrawalAmount,walTotal,'Count storage/write once, not again as a withdrawal');
  destroyedAfter(d,reserve.arguments[3],reserveIndex,WAL);destroyedAfter(d,register.arguments[7],registerIndex,WAL);
  returnedRemainder(d,storage);
  const withdrawals=d.inputs.flatMap((input,i)=>input.FundsWithdrawal?[withdrawal(d,i)]:[]);
  assert.equal(withdrawals.filter(w=>w.type===WAL).length,1);
  const suis=withdrawals.filter(w=>w.type===SUI);assert.equal(suis.length,1);
  assert.equal(withdrawals.length,2,'Unexpected extra withdrawal token or payment');
  const transfers=d.commands.flatMap((c,i)=>c.TransferObjects?[{i,...c.TransferObjects}]:[]);
  const tipTransfers=transfers.filter(t=>t.objects.some(o=>o.NestedResult&&d.commands[o.NestedResult[0]]?.SplitCoins));
  assert.equal(tipTransfers.length,1);assert.equal(tipTransfers[0].objects.length,1);
  const tip=splitPayment(d,tipTransfers[0].objects[0]);assert.equal(tip.type,SUI);
  assert.equal(tip.index,suis[0].index);assert.equal(tip.split.amounts.length,1);assert.equal(tip.amount,tip.withdrawalAmount);
  returnedRemainder(d,tip);
  const relayAddress=`0x${pure(d,tipTransfers[0].address).toString('hex')}`;assert.notEqual(relayAddress,writer);
  const blobTransfers=transfers.filter(t=>t!==tipTransfers[0]);assert.equal(blobTransfers.length,1);
  assert.deepEqual(blobTransfers[0].objects.map(ref),[`result:${registerIndex}`]);
  assert.equal(`0x${pure(d,blobTransfers[0].address).toString('hex')}`,writer);
  const allowed=new Set(['system:reserve_space','system:register_blob','metadata:new','blob:add_metadata','blob:insert_or_update_metadata_pair']);
  for(const c of d.commands){
    assert.ok(c.MoveCall||c.SplitCoins||c.TransferObjects,'Unexpected registration command');
    if(!c.MoveCall)continue;
    const m=c.MoveCall;
    if(normalizeSuiAddress(m.package)===FRAMEWORK){assert.equal(m.module,'coin');assert.ok(['redeem_funds','destroy_zero','send_funds'].includes(m.function));}
    else{assert.equal(m.package,reserve.package);assert.ok(allowed.has(`${m.module}:${m.function}`));}
  }
  if(memory){
    const attrs=d.commands.filter(c=>isCall(c,'blob','insert_or_update_metadata_pair')).map(c=>{
      assert.equal(ref(c.MoveCall.arguments[0]),`result:${registerIndex}`,'Copied metadata must attach to this new Blob');
      return [bcs.string().parse(pure(d,c.MoveCall.arguments[1])),bcs.string().parse(pure(d,c.MoveCall.arguments[2]))];
    });
    assert.equal(new Set(attrs.map(([key])=>key)).size,attrs.length);
    assert.deepEqual(Object.fromEntries(attrs),memory.source_metadata,'Registration must preserve exact original metadata');
  }
  const epochCount=uint(d,reserve.arguments[2],4),size=uint(d,register.arguments[4],8),blobId=uint(d,register.arguments[2],32);
  const registeredEvents=(events??[]).filter(e=>e.eventType?.endsWith('::events::BlobRegistered'));
  assert.equal(registeredEvents.length,1);const event=registeredEvents[0].json;
  assert.equal(raw(event.size),size);assert.equal(raw(event.blob_id),blobId);
  assert.equal(raw(event.end_epoch)-raw(event.epoch),epochCount);
  return {walStorageRaw:storage.amount,walWriteRaw:write.amount,walTotalRaw:walTotal,suiRelayTipRaw:tip.amount,
    relayAddress,walrusRuntimePackage:reserve.package,epochs:epochCount,sizeBytes:size};
}
function zeroPayments(d,phase){
  assert.equal(d.sender,writer);assert.deepEqual(d.gasData.payment,[]);
  assert.equal(d.inputs.filter(i=>i.FundsWithdrawal).length,0,'Unexpected monetary withdrawal outside registration');
  assert.equal(d.commands.filter(c=>c.SplitCoins||c.MergeCoins||c.Upgrade||c.Publish).length,0);
  if(phase.endsWith('.certify')){
    assert.equal(d.commands.length,1);assert.ok(isCall(d.commands[0],'system','certify_blob'));
  }else{
    assert.ok(phase.endsWith('.metadata_transfer'));
    assert.equal(d.commands.filter(c=>isCall(c,'account','seal_encrypt_fence')).length,1);
    for(const c of d.commands){
      if(c.TransferObjects)continue;
      assert.ok(isCall(c,'account','seal_encrypt_fence')||isCall(c,'blob','insert_or_update_metadata_pair'));
    }
    assert.equal(d.commands.filter(c=>c.TransferObjects).length,1);
  }
  return {walStorageRaw:0n,walWriteRaw:0n,walTotalRaw:0n,suiRelayTipRaw:0n};
}
function objectInput(d,arg){
  assert.ok(Number.isInteger(arg?.Input),'Expected resolved object input');
  const object=d.inputs[arg.Input]?.Object;
  return object?.ImmOrOwnedObject?.objectId??object?.SharedObject?.objectId??object?.Receiving?.objectId;
}
function fusedCost(d,memory,runtimePackage){
  assert.ok(memory,'Fused receipt requires its cycle mapping');
  assert.equal(d.sender,writer);assert.equal(d.gasData.owner,writer);assert.deepEqual(d.gasData.payment,[]);
  assert.equal(d.inputs.filter(i=>i.FundsWithdrawal).length,0,'No WAL/other withdrawals outside registration');
  assert.equal(d.commands.length,3,'Fused finalization has exactly certify, fence and transfer');
  const [certify,fence,transfer]=d.commands;
  assert.ok(isCall(certify,'system','certify_blob'));assert.equal(normalizeSuiAddress(certify.MoveCall.package),normalizeSuiAddress(runtimePackage));
  assert.ok(isCall(fence,'account','seal_encrypt_fence'));assert.equal(normalizeSuiAddress(fence.MoveCall.package),normalizeSuiAddress(config.policyPackageId));
  assert.equal(certify.MoveCall.arguments.length,5);assert.equal(fence.MoveCall.arguments.length,3);
  assert.equal(objectInput(d,certify.MoveCall.arguments[1]),memory.current_object_id);
  assert.equal(objectInput(d,fence.MoveCall.arguments[1]),normalizeSuiAddress(config.registryId));
  assert.equal(objectInput(d,fence.MoveCall.arguments[2]),normalizeSuiAddress(memory.account_id));
  assert.ok(transfer.TransferObjects);assert.equal(transfer.TransferObjects.objects.length,1);
  assert.equal(ref(transfer.TransferObjects.objects[0]),ref(certify.MoveCall.arguments[1]),'Certify and transfer must refer to the same new Blob');
  assert.equal(normalizeSuiAddress(`0x${pure(d,transfer.TransferObjects.address).toString('hex')}`),memory.owner);
  assert.deepEqual(d.inputs.flatMap(i=>i.Object?.ImmOrOwnedObject?[i.Object.ImmOrOwnedObject.objectId]:[]),[memory.current_object_id],'Only the new Blob may be an owned input');
  return noPayments();
}
const noPayments=()=>({walStorageRaw:0n,walWriteRaw:0n,walTotalRaw:0n,suiRelayTipRaw:0n,suiFixtureFundingPrincipalRaw:0n});
function setupCost(d,row,owners){
  assert.equal(d.gasData.owner,d.sender);
  assert.equal(d.inputs.filter(i=>i.Object?.ImmOrOwnedObject).length,0,'Setup must not select owned coins');
  if(row.phase==='create_account'){
    assert.ok([-1,-2].includes(row.memory_id));assert.ok(owners.has(d.sender),'Account creator must be a fixture owner');
    assert.equal(d.inputs.filter(i=>i.FundsWithdrawal).length,0);assert.equal(d.commands.length,1);
    const call=d.commands[0]?.MoveCall;assert.ok(isCall(d.commands[0],'account','create_account'));
    assert.equal(normalizeSuiAddress(call.package),normalizeSuiAddress(config.policyPackageId));
    return noPayments();
  }
  assert.equal(row.phase,'fund_owners');assert.equal(row.memory_id,-100);assert.equal(d.sender,writer);
  assert.deepEqual(d.gasData.payment,[],'Writer fixture funding must use address-balance gas');
  const withdrawals=d.inputs.flatMap((input,i)=>input.FundsWithdrawal?[withdrawal(d,i)]:[]);
  assert.ok(withdrawals.length>0);for(const item of withdrawals)assert.equal(item.type,SUI);
  const transfers=d.commands.filter(c=>c.TransferObjects).map(c=>c.TransferObjects);
  assert.ok(transfers.length>0&&transfers.length<=owners.size);
  let principal=0n;const recipients=new Set(),paymentSources=new Map();
  for(const transfer of transfers){
    assert.equal(transfer.objects.length,1);
    const recipient=normalizeSuiAddress(`0x${pure(d,transfer.address).toString('hex')}`);
    assert.ok(owners.has(recipient),'Fixture funding cannot send to another address');
    assert.ok(!recipients.has(recipient));recipients.add(recipient);
    const payment=splitPayment(d,transfer.objects[0]);assert.equal(payment.type,SUI);assert.ok(payment.amount>0n);
    principal+=payment.amount;paymentSources.set(payment.redeemIndex,payment);
  }
  assert.equal(withdrawals.reduce((sum,item)=>sum+item.amount,0n),principal,'Funding withdrawals equal fixture principal exactly');
  for(const payment of paymentSources.values())returnedRemainder(d,payment);
  for(const command of d.commands){
    assert.ok(command.MoveCall||command.SplitCoins||command.TransferObjects,'Unexpected funding command');
    if(command.MoveCall){
      const call=command.MoveCall;assert.equal(normalizeSuiAddress(call.package),FRAMEWORK);
      assert.equal(call.module,'coin');assert.ok(['redeem_funds','send_funds','destroy_zero'].includes(call.function));
      assert.equal(normalizeStructTag(call.typeArguments[0]),SUI);
    }
  }
  if(row.purpose?.principalMist!==undefined)assert.equal(BigInt(row.purpose.principalMist),principal);
  return {...noPayments(),suiFixtureFundingPrincipalRaw:principal,fixtureRecipients:[...recipients]};
}
const decimal=(n)=>`${n<0n?'-':''}${(n<0n?-n:n)/1000000000n}.${((n<0n?-n:n)%1000000000n).toString().padStart(9,'0')}`;
const empty=()=>({transactions:0,...noPayments(),suiNetGasRaw:0n});
const stringify=(value)=>JSON.stringify(value,(_k,v)=>typeof v==='bigint'?v.toString():v,2);
function assertStages(stages,stage,count){
  // postgres returns an Array subclass; verify row values independently of its prototype.
  assert.deepEqual(Array.from(stages),[{stage,count}]);
}
async function testSetup(){
  assert.equal(writer,SYNTHETIC_WRITER_ADDRESS);
  assert.throws(()=>configuredWriter({}),/funding public key/);
  assert.throws(()=>configuredWriter({fundingPublicKey:Buffer.alloc(33,1).toString('base64'),fundingAddress:writer}),/flagged Ed25519/);
  assert.throws(()=>configuredWriter({fundingPublicKey:SYNTHETIC_WRITER_PUBLIC_KEY,fundingAddress:normalizeSuiAddress('0xd')}),/match its public key/);
  const fixture=normalizeSuiAddress('0xb'),other=normalizeSuiAddress('0xc'),owners=new Set([fixture,other]);
  const encoded=value=>({Pure:{bytes:Buffer.from(value).toString('base64')}});
  const u64=n=>{const value=Buffer.alloc(8);value.writeBigUInt64LE(BigInt(n));return encoded(value);};
  const addr=value=>encoded(Buffer.from(value.slice(2),'hex'));
  const call=(fn,args)=>({MoveCall:{package:FRAMEWORK,module:'coin',function:fn,typeArguments:[SUI],arguments:args}});
  const d={sender:writer,gasData:{owner:writer,payment:[]},inputs:[
    {FundsWithdrawal:{withdrawFrom:{$kind:'Sender'},reservation:{$kind:'MaxAmountU64',MaxAmountU64:'100'},typeArg:{Balance:SUI}}},
    u64(40),u64(60),addr(fixture),addr(other),addr(writer)],commands:[
      call('redeem_funds',[{Input:0}]),{SplitCoins:{coin:{Result:0},amounts:[{Input:1},{Input:2}]}},
      {TransferObjects:{objects:[{NestedResult:[1,0]}],address:{Input:3}}},
      {TransferObjects:{objects:[{NestedResult:[1,1]}],address:{Input:4}}},call('send_funds',[{Result:0},{Input:5}])]};
  const row={phase:'fund_owners',memory_id:-100,purpose:{principalMist:'100'}};
  const result=setupCost(d,row,owners);assert.equal(result.suiFixtureFundingPrincipalRaw,100n);
  assert.equal(result.suiRelayTipRaw+50n,50n,'Principal must not be added to setup gas');
  const unknown=structuredClone(d);unknown.inputs[3]=addr(normalizeSuiAddress('0xd'));
  assert.throws(()=>setupCost(unknown,row,owners),/another address/);
  const excess=structuredClone(d);excess.inputs[0].FundsWithdrawal.reservation.MaxAmountU64='101';
  assert.throws(()=>setupCost(excess,row,owners),/principal exactly/);
  const coin=structuredClone(d);coin.inputs.push({Object:{ImmOrOwnedObject:{objectId:fixture}}});
  assert.throws(()=>setupCost(coin,row,owners),/owned coins/);
  const account={sender:fixture,gasData:{owner:fixture,payment:[]},inputs:[],commands:[
    {MoveCall:{package:config.policyPackageId,module:'account',function:'create_account'}}]};
  assert.equal(setupCost(account,{phase:'create_account',memory_id:-1},owners).suiFixtureFundingPrincipalRaw,0n);
  const extra=structuredClone(account);extra.commands.push(extra.commands[0]);
  assert.throws(()=>setupCost(extra,{phase:'create_account',memory_id:-1},owners));
  const transaction=new Transaction();transaction.setSender(writer);transaction.setGasOwner(writer);
  transaction.setGasPayment([]);transaction.setGasPrice(1);transaction.setGasBudget(1_000_000);
  transaction.setExpiration({ValidDuring:{minEpoch:'1',maxEpoch:'2',minTimestamp:null,maxTimestamp:null,
    chain:'69WiPg3DAQiwdxfncX6wYQ2siKwAe6L9BZthQea3JNMD',nonce:1}});
  transaction.transferObjects([coinWithBalance({balance:40n})],fixture);
  transaction.transferObjects([coinWithBalance({balance:60n})],other);
  const bytes=await transaction.build({client:{core:{getBalance:async()=>({balance:{addressBalance:'1000'}})}}});
  const decoded=Transaction.from(bytes);const bcsCost=setupCost(decoded.getData(),row,owners);
  assert.equal(bcsCost.suiFixtureFundingPrincipalRaw,100n);assert.equal(await decoded.getDigest(),await transaction.getDigest());
  class ResultArray extends Array{}
  assertStages(ResultArray.from([{stage:'migrated',count:6}]),'migrated',6);
  assert.throws(()=>assertStages(ResultArray.from([{stage:'migrated',count:5}]),'migrated',6));
  assert.throws(()=>assertStages(ResultArray.from([{stage:'seeded',count:6}]),'migrated',6));
  const id=n=>normalizeSuiAddress('0x'+n.toString(16));
  const memory={current_object_id:id(1),account_id:id(3),owner:fixture};
  const fused={sender:writer,gasData:{owner:writer,payment:[]},inputs:[
    {Object:{ImmOrOwnedObject:{objectId:id(1)}}},{Object:{SharedObject:{objectId:id(2)}}},
    {Object:{SharedObject:{objectId:id(3)}}},addr(fixture),{Object:{SharedObject:{objectId:id(5)}}},encoded([0])],
    commands:[{MoveCall:{package:id(9),module:'system',function:'certify_blob',arguments:[{Input:4},{Input:0},{Input:5},{Input:5},{Input:5}]}},
      {MoveCall:{package:config.policyPackageId,module:'account',function:'seal_encrypt_fence',arguments:[{Input:5},{Input:1},{Input:2}]}},
      {TransferObjects:{objects:[{Input:0}],address:{Input:3}}}]};
  assert.equal(fusedCost(fused,memory,id(9)).walTotalRaw,0n);
  const wrongBlob=structuredClone(fused);wrongBlob.commands[2].TransferObjects.objects=[{Input:4}];
  assert.throws(()=>fusedCost(wrongBlob,memory,id(9)),/same new Blob/);
  const wrongRecipient=structuredClone(fused);wrongRecipient.inputs[3]=addr(other);
  assert.throws(()=>fusedCost(wrongRecipient,memory,id(9)));
  const extraWithdraw=structuredClone(fused);extraWithdraw.inputs.push(d.inputs[0]);
  assert.throws(()=>fusedCost(extraWithdraw,memory,id(9)),/withdrawals/);
  const wrongOrder=structuredClone(fused);wrongOrder.commands.reverse();
  assert.throws(()=>fusedCost(wrongOrder,memory,id(9)));
  console.log(stringify({selfTest:'PASS',syntheticWriter:true,positiveCases:6,rejectedCases:13,bcsTransactions:1,networkCalls:0,
    principalExcludedFromFees:true,postgresResultArrayRegression:'PASS',strictFusedCertifyFenceTransfer:'PASS'}));
}
try{
  if(selfTest){await testSetup();}else{
  const snapshot=argv.includes('--journal')?JSON.parse(await readFile(option('--journal',undefined),'utf8')):
    await sql.begin('isolation level repeatable read, read only',async tx=>({
    rows:await tx`SELECT f.run_id,f.memory_id,f.phase,f.payload->>'digest' AS digest,
      f.payload->'gasUsed' AS gas,f.payload->'effects'->'status' AS status,f.payload->'events' AS events,
      p.payload->>'bytes' AS bytes,p.payload->'purpose' AS purpose,p.id AS prepared_id,f.id AS finalized_id
      FROM exercise_renewal_journal f LEFT JOIN exercise_renewal_journal p
      ON p.run_id=f.run_id AND p.memory_id=f.memory_id AND p.phase=f.phase AND p.state='prepared'
      AND p.payload->>'digest'=f.payload->>'digest'
      WHERE f.run_id=${runId} AND f.state='finalized' AND f.payload ? 'digest' ORDER BY f.id`,
    pending:await tx`SELECT p.memory_id,p.phase,p.payload->>'digest' AS digest FROM exercise_renewal_journal p
      WHERE p.run_id=${runId} AND p.state='prepared' AND NOT EXISTS(
        SELECT 1 FROM exercise_renewal_journal f WHERE f.run_id=p.run_id AND f.memory_id=p.memory_id
        AND f.phase=p.phase AND f.state='finalized' AND f.payload->>'digest'=p.payload->>'digest') ORDER BY p.id`,
    stages:await tx`SELECT stage,count(*)::int AS count FROM exercise_renewal_memories WHERE run_id=${runId} GROUP BY stage ORDER BY stage`,
    owners:await tx`SELECT DISTINCT owner FROM exercise_renewal_memories WHERE run_id=${runId}`,
    memories:await tx`SELECT memory_id,owner,account_id,source_blob_id,source_object_id,current_object_id,
      source_end_epoch,current_end_epoch,ciphertext_bytes,source_metadata FROM exercise_renewal_memories WHERE run_id=${runId}`,
    plans:await tx`SELECT memory_id,payload FROM exercise_renewal_journal WHERE run_id=${runId}
      AND phase='renew.lease_plan' AND state='planned' ORDER BY id`
  }));
  const owners=new Set(snapshot.owners.map(row=>normalizeSuiAddress(typeof row==='string'?row:row.owner)));
  const memories=new Map((snapshot.memories??[]).map(row=>[row.memory_id,row]));
  const plans=new Map((snapshot.plans??[]).map(row=>[row.memory_id,row.payload]));
  assert.equal(plans.size,(snapshot.plans??[]).length,'Each memory has one immutable lease plan');
  const registrationPackages=new Map();
  const totals={setup:empty(),seed:empty(),renew:empty()},byPhase={},details=[],seen=new Set(),seenPhase=new Set(),accountCreators=new Set();
  const relayAddresses=new Set(),runtimePackages=new Set();let localBytes=0,setupReceiptOnly=0;
  for(const row of snapshot.rows){
    assert.ok(row.prepared_id,'Finalized receipt has no matching prepared digest');
    assert.ok(!seen.has(row.digest),'Duplicate finalized digest');seen.add(row.digest);
    assert.ok(!seenPhase.has(`${row.memory_id}/${row.phase}`),'Multiple successful receipts for one memory/phase');seenPhase.add(`${row.memory_id}/${row.phase}`);
    assert.equal(row.status?.success,true,'Only successful finalized receipts may be counted');
    assert.ok(row.gas,'Missing actual gas receipt');
    const netGas=raw(row.gas.computationCost)+raw(row.gas.storageCost)-raw(row.gas.storageRebate);
    let cost,source='local-prepared-bcs';
    const setup=['create_account','fund_owners'].includes(row.phase);
      assert.ok(setup||/^(seed|renew)\.(register|certify|metadata_transfer)$/.test(row.phase)||
        (migrationOnly&&renewMode==='fused'&&row.phase==='renew.certify_transfer'),'Unexpected transaction phase');
      if(migrationOnly)assert.ok(row.phase.startsWith('renew.'),'Migration-only cannot pay seed/setup transactions');
      let bytes=row.bytes;
      if(!bytes){
        assert.ok(allowRpcMissing,`Missing saved bytes for ${row.digest}; explicit --allow-rpc-missing required`);
        rpcCalls++;assert.ok(rpcCalls<=8,'Legacy RPC fallback budget exceeded');
        const result=await rpc.core.getTransaction({digest:row.digest,include:{bcs:true,effects:true,balanceChanges:true}});
        assert.equal(result.Transaction?.status.success,true);assert.equal(result.Transaction.digest,row.digest);
        assert.ok(result.Transaction.bcs);bytes=Buffer.from(result.Transaction.bcs).toString('base64');source='explicit-legacy-rpc-bcs';
      }else localBytes++;
      const built=Transaction.from(bytes);assert.equal(await built.getDigest(),row.digest,'BCS bytes do not match finalized digest');
      const data=built.getData(),memory=memories.get(row.memory_id);
      cost=setup?setupCost(data,row,owners):row.phase.endsWith('.register')?registeredCost(data,row.events,memory):
        row.phase==='renew.certify_transfer'?fusedCost(data,memory,registrationPackages.get(row.memory_id)):zeroPayments(data,row.phase);
      if(row.phase==='renew.register'){
        registrationPackages.set(row.memory_id,cost.walrusRuntimePackage);
        if(migrationOnly){
          const plan=plans.get(row.memory_id);assert.ok(plan&&memory,'Existing-source registration requires its lease plan/mapping');
          assert.equal(plan.inputObjectId,memory.source_object_id);assert.equal(plan.inputEndEpoch,memory.source_end_epoch);
          assert.equal(Number(cost.epochs),plan.requestedEpochs);assert.ok(plan.requestedEpochs>=1&&plan.requestedEpochs<=53);
          assert.equal(plan.targetEndEpoch,plan.currentEpoch+plan.requestedEpochs);
          assert.equal(plan.targetEndEpoch,Math.max(plan.inputEndEpoch+1,plan.currentEpoch+config.renewalEpochs));
          assert.ok(memory.current_end_epoch>=plan.targetEndEpoch&&memory.current_end_epoch>memory.source_end_epoch);
        }
      }
      if(row.phase==='create_account'){
        assert.ok(!accountCreators.has(data.sender),'Each fixture owner must create exactly one account');accountCreators.add(data.sender);
      }
      if(cost.relayAddress)relayAddresses.add(cost.relayAddress);if(cost.walrusRuntimePackage)runtimePackages.add(cost.walrusRuntimePackage);
    const group=setup?'setup':row.phase.split('.')[0];
    const value={...noPayments(),...cost,suiNetGasRaw:netGas};
    for(const bucket of [totals[group],byPhase[row.phase]??=empty()]){
      bucket.transactions++;for(const key of ['walStorageRaw','walWriteRaw','walTotalRaw','suiRelayTipRaw','suiNetGasRaw','suiFixtureFundingPrincipalRaw'])bucket[key]+=value[key];
    }
    details.push({memoryId:row.memory_id,phase:row.phase,digest:row.digest,source,...value,
      // Nonrefundable storage is already included in storageCost; do not add it again.
      gasComponents:row.gas});
  }
  for(const [group,expected]of [['seed',expectedSeed],['renew',expectedRenew]])if(expected!==undefined){
    assert.ok(Number.isSafeInteger(Number(expected))&&Number(expected)>=0);
    const phases=group==='renew'&&renewMode==='fused'?['register','certify_transfer']:['register','certify','metadata_transfer'];
    for(const phase of phases)assert.equal(byPhase[`${group}.${phase}`]?.transactions??0,Number(expected));
    if(group==='renew'&&renewMode==='fused')for(const phase of ['certify','metadata_transfer'])assert.equal(byPhase[`renew.${phase}`]?.transactions??0,0);
  }
  if(expectedSetup!==undefined)assert.equal(totals.setup.transactions,Number(expectedSetup));
  if(requireComplete){
    assert.equal(snapshot.pending.length,0,'Unresolved/inflight prepared transactions remain');
    for(const group of ['seed','renew']){
      const n=byPhase[`${group}.register`]?.transactions??0;
      if(group==='renew'&&renewMode==='fused')assert.equal(byPhase['renew.certify_transfer']?.transactions??0,n);
      else{assert.equal(byPhase[`${group}.certify`]?.transactions??0,n);assert.equal(byPhase[`${group}.metadata_transfer`]?.transactions??0,n);}
    }
    const seeded=byPhase['seed.register']?.transactions??0,renewed=byPhase['renew.register']?.transactions??0;
    if(renewed>0&&!migrationOnly)assert.equal(renewed,seeded,'Final cost requires the entire cohort migrated');
    if(migrationOnly){assert.equal(seeded,0);assert.equal(totals.setup.transactions,0);assert.equal(plans.size,renewed);}
    assertStages(snapshot.stages,renewed>0?'migrated':'seeded',migrationOnly?renewed:seeded);
    if(expectedSetup!==undefined&&Number(expectedSetup)>0){
      assert.equal(byPhase.fund_owners?.transactions??0,1);
      assert.equal(byPhase.create_account?.transactions??0,Number(expectedSetup)-1);
      assert.equal(accountCreators.size,owners.size,'Account setup must cover every synthetic owner');
    }
  }
  for(const total of Object.values(totals)){
    total.walTotal=decimal(total.walTotalRaw);total.walStorage=decimal(total.walStorageRaw);total.walWrite=decimal(total.walWriteRaw);
    total.suiRelayTip=decimal(total.suiRelayTipRaw);total.suiNetGas=decimal(total.suiNetGasRaw);
    total.suiTotal=decimal(total.suiNetGasRaw+total.suiRelayTipRaw);
    total.suiFixtureFundingPrincipal=decimal(total.suiFixtureFundingPrincipalRaw);
  }
  const manifest=details.map(d=>`${d.memoryId}\t${d.phase}\t${d.digest}\t${d.walStorageRaw}\t${d.walWriteRaw}\t${d.suiRelayTipRaw}\t${d.suiNetGasRaw}`).join('\n');
  const output=stringify({runId,all_passed:true,mode:config.mode??'full',renewMode,auditedAt:new Date().toISOString(),method:'successful-receipt + matching prepared BCS digest; exact SplitCoins payments; setup principal excluded from fees; no wallet deltas',
    rpcCalls,localBcsTransactions:localBytes,setupReceiptOnly,totals,byPhase,relayAddresses:[...relayAddresses],runtimePackages:[...runtimePackages],
    stages:snapshot.stages,pending:snapshot.pending,manifestSha256:createHash('sha256').update(manifest).digest('hex'),
    ...(argv.includes('--details')?{transactions:details}:{})});
  if(argv.includes('--out'))await writeFile(option('--out',undefined),output+'\n');
  console.log(output);
  }
}finally{if(sql)await sql.end();}
