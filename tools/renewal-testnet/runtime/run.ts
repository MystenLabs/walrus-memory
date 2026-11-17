import assert from 'node:assert/strict';
import { createHash, randomUUID, randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile, chmod, rename, realpath } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { monitorEventLoopDelay } from 'node:perf_hooks';
import postgres from 'postgres';
import { SuiGrpcClient } from '@mysten/sui/grpc';
import { Transaction, coinWithBalance } from '@mysten/sui/transactions';
import { bcs } from '@mysten/sui/bcs';
import { Ed25519Keypair, Ed25519PublicKey } from '@mysten/sui/keypairs/ed25519';
import { decodeSuiPrivateKey } from '@mysten/sui/cryptography';
import { fromBase64, fromBase58, normalizeStructTag } from '@mysten/sui/utils';
import { WalrusClient, blobIdFromInt } from '@mysten/walrus';
import { SealClient, SessionKey, EncryptedObject } from '@mysten/seal';
import { CliSigner } from './cli-signer.js';
import { createMetadataComputer, deriveMetadataBlobId } from './metadata-cache.js';

type Owner = {name: string; address: string; privateKey: string; accountId?: string};
type Config = {network: 'testnet'; runId: string; databaseUrl: string; scratch: string;
  suiGrpcUrl: string; immutablePackageId: string; policyPackageId: string; policyVerified: boolean;
  registryId: string; walrusPackageId: string; relayUrl: string; sourceEpochs: number;
  renewalEpochs: number; fundingAlias: string; fundingPublicKey: string; fundingAddress: string;
  committeeId: string; aggregatorUrl: string; walrusAggregatorUrl?: string; ownerFile: string; count: number; payloadBytes: number;
  mode?:'full'|'migration-only';parentSourceRunId?:string;sourceOffset?:number;sourceOwnerFile?:string;sourceCipherDir?:string;renewMode?:'fused'|'unfused';
  metadataCacheDir?:string;metadataThreads?:number};
const exec = promisify(execFile);
const command = process.argv[2] ?? 'preflight';
const args = process.argv.slice(3);
const flag = (name: string, fallback: string) => args.includes(name) ? args[args.indexOf(name) + 1] : fallback;
const limit = Number(flag('--limit', '1'));
const offset = Number(flag('--offset', '0'));
const concurrency = Number(flag('--concurrency', '2'));
const chainConcurrency = Number(flag('--chain-concurrency', '1'));
const execute = args.includes('--execute');
const configPath = flag('--config', '');
assert.ok(configPath, 'Pass --config with this run’s local config');
const config: Config = JSON.parse(await readFile(configPath, 'utf8'));
assert.ok(typeof config.fundingAlias==='string'&&config.fundingAlias.trim(),'Configure an explicit Sui CLI funding alias');
assert.ok(typeof config.fundingPublicKey==='string','Configure an explicit flagged Ed25519 funding public key');
const fundingKeyBytes=Buffer.from(config.fundingPublicKey,'base64');
assert.ok(fundingKeyBytes.length===33&&fundingKeyBytes[0]===0&&fundingKeyBytes.toString('base64')===config.fundingPublicKey,
  'Funding public key must be canonical base64 containing Ed25519 flag 0 plus 32 public-key bytes');
const expectedFundingAddress=new Ed25519PublicKey(fundingKeyBytes.subarray(1)).toSuiAddress();
assert.equal(config.fundingAddress,expectedFundingAddress,'Configured funding address must match its public key');
assert.equal(config.network, 'testnet');
assert.ok(config.policyVerified, 'Executable MemWal policy package must be verified before use');
assert.ok(/testnet/.test(config.suiGrpcUrl) && /testnet/.test(config.relayUrl));
const dbUrl = new URL(config.databaseUrl);
assert.ok(['127.0.0.1', 'localhost'].includes(dbUrl.hostname));
assert.equal(dbUrl.pathname, '/renewal_e2e');
assert.ok(Number.isInteger(limit) && limit > 0 && limit <= 1000);
assert.ok(Number.isInteger(offset) && offset >= 0);
assert.ok(offset + limit <= config.count, 'Requested range exceeds synthetic cohort');
assert.ok(Number.isInteger(concurrency) && concurrency >= 1 && concurrency <= 16);
assert.ok(Number.isInteger(chainConcurrency) && chainConcurrency >= 1 && chainConcurrency <= 8);
assert.ok(config.sourceEpochs > 0 && config.renewalEpochs > config.sourceEpochs);
assert.ok(Number.isInteger(config.count)&&config.count>0&&config.count<=1000);
assert.ok(!config.mode||['full','migration-only'].includes(config.mode));
assert.ok(!config.renewMode||['fused','unfused'].includes(config.renewMode));
assert.ok(config.metadataThreads===undefined||(Number.isInteger(config.metadataThreads)&&config.metadataThreads>=(config.mode==='migration-only'&&config.renewMode!=='unfused'?1:0)&&config.metadataThreads<=4));
if(config.mode==='migration-only')assert.ok(!['seed','setup','create-accounts'].includes(command),'Migration-only reuses existing contents/accounts; no seeding or funding');
assert.ok(path.resolve(config.ownerFile).startsWith(path.resolve(config.scratch)+path.sep), 'Fixture keys must stay inside this run scratch');
if (['setup', 'create-accounts', 'seed', 'migrate'].includes(command)) assert.ok(execute, 'Explicit --execute required');

// Configure actual product helpers before their module-level clients initialize.
process.env.SUI_NETWORK = 'testnet';
process.env.SUI_GRPC_URL = config.suiGrpcUrl;
process.env.MEMWAL_SEAL_POLICY_PACKAGE_ID = config.policyPackageId;
process.env.WALRUS_PACKAGE_ID = config.walrusPackageId;
process.env.WALRUS_UPLOAD_RELAY_URL = config.relayUrl;
process.env.SEAL_SERVER_CONFIGS = JSON.stringify([{objectId: config.committeeId, weight: 1,
  aggregatorUrl: config.aggregatorUrl}]);
process.env.SEAL_THRESHOLD = '1';
process.env.ENOKI_API_KEY = '';
process.env.SERVER_SUI_PRIVATE_KEYS = '';
const nativeFetch = globalThis.fetch;
const transport: Record<string, {requests:number; bytes:number}> = {};
const transportTiming:Record<string,number[]>={};
globalThis.fetch = async (input: any, init?: any) => {
  const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
  if (/enoki|openai|openrouter|railway|neon\.tech|mainnet/i.test(url)) {
    throw new Error(`Forbidden service in testnet exercise: ${new URL(url).hostname}`);
  }
  const method = init?.method ?? (typeof input === 'object' ? input.method : undefined) ?? 'GET';
  let relayLog:Record<string,unknown>|undefined;
  if (url.startsWith(config.relayUrl) && method === 'POST') {
    const body = init?.body;
    const bytes = body instanceof Uint8Array ? body : body instanceof ArrayBuffer ? new Uint8Array(body) : null;
    const key = 'relay_post'; const tally = transport[key] ??= {requests:0,bytes:0};
    tally.requests++; tally.bytes += bytes?.byteLength ?? 0;
    relayLog = {kind:key,url,method,bytes:bytes?.byteLength ?? null,
      sha256:bytes ? createHash('sha256').update(bytes).digest('hex') : null};
  }
  const requestStarted=performance.now();
  try {
    const response = await nativeFetch(input, init);
    if(relayLog){
      const headersMs=performance.now()-requestStarted;
      (transportTiming.relay_headers_ms??=[]).push(headersMs);
      console.log(JSON.stringify({at:new Date().toISOString(),event:'transport',...relayLog,status:response.status,headersMs}));
      const originalJson=response.json.bind(response);
      response.json=async()=>{
        const bodyStarted=performance.now();
        try{return await originalJson();}
        finally{const bodyMs=performance.now()-bodyStarted;(transportTiming.relay_body_ms??=[]).push(bodyMs);
          console.log(JSON.stringify({at:new Date().toISOString(),event:'relay_response_body',url,bodyMs}));}
      };
    }
    return response;
  } catch (error) {
    if (relayLog) console.log(JSON.stringify({at:new Date().toISOString(),event:'transport',...relayLog,status:null,
      error:String(error instanceof Error ? error.message : error).slice(0,500)}));
    throw error;
  }
};
const { buildSealEncryptId, fetchSealEncryptIdentity } = await import('../../services/server/scripts/sidecar/seal-identity.js');
const { appendSealPersistenceFence, parseSealPersistenceFence } = await import('../../services/server/scripts/sidecar/blob-metadata.js');
const { enforceAddressBalanceCoinIntents } = await import('../../services/server/scripts/sidecar/address-balance.js');
const { fetchBlobMetadataEntries, assertCompletionBlobObject } = await import('../../services/server/scripts/sidecar/routes/walrus-query.js');
const { buildSealApproveTx } = await import('../../services/server/scripts/sidecar/seal-ptb.js');

const sql = postgres(config.databaseUrl, { max: Math.max(2, concurrency), idle_timeout: 20 });
const sui = new SuiGrpcClient({ network: 'testnet', baseUrl: config.suiGrpcUrl });
const walrus = new WalrusClient({ network: 'testnet', suiClient: sui,
  uploadRelay: { host: config.relayUrl, sendTip: { max: 10_000_000 }, timeout: 120_000 },
  storageNodeClientOptions: { timeout: 30_000 } });
const seal = new SealClient({ suiClient: sui as any,
  serverConfigs: [{objectId: config.committeeId, weight: 1, aggregatorUrl: config.aggregatorUrl}],
  verifyKeyServers: true, timeout: 30_000 });
const writer = new CliSigner(config.fundingAlias, config.fundingPublicKey);
let owners: Owner[]=[];
if(existsSync(config.ownerFile)){
  try{owners=JSON.parse(await readFile(config.ownerFile,'utf8'));}
  catch{throw new Error('Invalid fixture owner file; contents are private and were not logged');}
}
if(owners.length) assert.equal(owners.length,2);
let ownerKeys = owners.map(o => {
  try{const k=Ed25519Keypair.fromSecretKey(decodeSuiPrivateKey(o.privateKey).secretKey);
    assert.equal(k.toSuiAddress(),o.address);return k;}
  catch{throw new Error('Fixture owner key does not match its public address');}
});
await mkdir(path.join(config.scratch, 'ciphertext'), { recursive: true });
await mkdir(path.join(config.scratch, 'downloads'), { recursive: true });
const sha = (bytes: Uint8Array | string) => createHash('sha256').update(bytes).digest('hex');
const json = (value: unknown) => JSON.stringify(value, (_k, v) => typeof v === 'bigint' ? v.toString() : v);
const metric = (event: string, data: Record<string, unknown> = {}) => console.log(json({at: new Date().toISOString(), event, ...data}));
const cleanError = (e: unknown) => String(e instanceof Error ? e.message : e).slice(0, 1500);
const now = () => performance.now();
const phaseTimes: Record<string, number[]> = {};
async function timed<T>(phase: string, fn: () => Promise<T>): Promise<T> {
  const started = now(); try { return await fn(); }
  finally { (phaseTimes[phase] ??= []).push(now() - started); }
}
let chainSlots = chainConcurrency;
const chainWaiters:Array<()=>void> = [];
let chainActive=0, chainActivePeak=0, chainBusyMs=0;
const chainQueueWaitMs:number[]=[];
const addressReservations=new Map<string,bigint>();
let reservationQueue:Promise<unknown>=Promise.resolve();
async function reserveWriterFunds(data:any,prefix='funds'):Promise<()=>void>{
  assert.equal(data.sender,writer.toSuiAddress());assert.equal(data.gasData.owner,data.sender);assert.deepEqual(data.gasData.payment,[]);
  const suiType=normalizeStructTag('0x2::sui::SUI');
  const required=new Map<string,bigint>([[suiType,BigInt(data.gasData.budget)]]);
  for(const input of data.inputs){
    if(!input.FundsWithdrawal)continue;
    const w=input.FundsWithdrawal;
    assert.equal(w.withdrawFrom?.$kind,'Sender');assert.equal(w.reservation?.$kind,'MaxAmountU64');
    assert.equal(w.typeArg?.$kind,'Balance');const type=normalizeStructTag(w.typeArg.Balance);
    required.set(type,(required.get(type)??0n)+BigInt(w.reservation.MaxAmountU64));
  }
  const queued=now();
  const gate=reservationQueue.then(async()=>{
    (phaseTimes[`${prefix}.reservation.queue_wait`]??=[]).push(now()-queued);
    const checked=await timed(`${prefix}.reservation.balance_rpc`,()=>Promise.all([...required].map(async([type,amount])=>{
      const balance=BigInt((await sui.core.getBalance({owner:data.sender,coinType:type})).balance.addressBalance);
      const outstanding=addressReservations.get(type)??0n;
      assert.ok(balance>=outstanding+amount,`Insufficient settled ${type} address balance for aggregate in-flight gas/payments; no coin fallback`);
      return {type,amount};
    })));
    for(const{type,amount}of checked)addressReservations.set(type,(addressReservations.get(type)??0n)+amount);
  });
  reservationQueue=gate.catch(()=>{});await gate;
  return ()=>{for(const[type,amount]of required)addressReservations.set(type,(addressReservations.get(type)??0n)-amount);};
}
async function boundedChain<T>(fn: () => Promise<T>): Promise<T> {
  const queued=now();
  if (chainSlots > 0) chainSlots--;
  else await new Promise<void>(resolve => chainWaiters.push(resolve));
  chainQueueWaitMs.push(now()-queued);chainActive++;chainActivePeak=Math.max(chainActivePeak,chainActive);
  const started=now();
  try { return await fn(); }
  finally { chainBusyMs+=now()-started;chainActive--;const next = chainWaiters.shift(); if (next) next(); else chainSlots++; }
}
function transactionOf(result: any): any {
  if (result?.Transaction?.status?.success === true) return result.Transaction;
  if (result?.FailedTransaction) throw new Error(`Chain transaction failed: ${json(result.FailedTransaction.status)}`);
  throw new Error('Unknown or unsuccessful transaction response');
}
async function journal(id: number, phase: string, state: string, payload: unknown) {
  await sql`INSERT INTO exercise_renewal_journal(run_id,memory_id,phase,state,payload)
    VALUES(${config.runId},${id},${phase},${state},${sql.json(JSON.parse(json(payload)))})`;
}
async function submit(id: number, phase: string, tx: Transaction, signer: any = writer, purpose?:Record<string,unknown>) {
  return boundedChain(async () => timed(phase, async () => {
    const pending=await timed(`${phase}.pending_check`,()=>sql`SELECT payload FROM exercise_renewal_journal WHERE run_id=${config.runId}
      AND memory_id=${id} AND phase=${phase} AND state='prepared'
      AND NOT EXISTS(SELECT 1 FROM exercise_renewal_journal done WHERE done.run_id=${config.runId}
        AND done.memory_id=${id} AND done.phase=${phase} AND done.state='finalized'
        AND done.payload->>'digest'=exercise_renewal_journal.payload->>'digest') LIMIT 1`);
    if(pending.length)throw new Error(`Unreconciled prepared transaction for ${id}/${phase}; inspect saved digest before retry`);
    tx.setSenderIfNotSet(signer.toSuiAddress());
    if (signer === writer) { enforceAddressBalanceCoinIntents(tx); tx.setGasPayment([]); }
    const bytes = await timed(`${phase}.build`,()=>tx.build({client:sui}));
    const built = Transaction.from(bytes);
    const digest = await timed(`${phase}.digest`,()=>built.getDigest({client:sui}));
    const data = built.getData();
    if (signer === writer) assert.deepEqual(data.gasData.payment,[],'Writer must use address-balance gas');
    const release=signer===writer?await timed(`${phase}.reservation`,()=>reserveWriterFunds(data,phase)):()=>{};
    try{
    await timed(`${phase}.prepared_journal`,()=>journal(id, phase, 'prepared', {digest,bytes:Buffer.from(bytes).toString('base64'),
      gasPayment:data.gasData.payment,expiration:data.expiration,
      ownedObjectIds:data.inputs.flatMap(input => input.Object?.ImmOrOwnedObject ? [input.Object.ImmOrOwnedObject.objectId] : []),purpose}));
    const signature = (await timed<{signature:string}>(`${phase}.cli_sign`,()=>signer.signTransaction(bytes))).signature;
    const result = await timed(`${phase}.execute`,()=>sui.core.executeTransaction({ transaction: bytes, signatures: [signature],
      include: { effects: true, transaction: true, objectTypes: true, events: true } }));
    const transaction = transactionOf(result);
    assert.equal(transaction.digest, digest);
    const finalized = await timed(`${phase}.wait`,()=>sui.core.waitForTransaction({ digest,
      include: { effects: true, transaction: true, objectTypes: true, events: true } }));
    const final = transactionOf(finalized);
    await timed(`${phase}.final_journal`,()=>journal(id, phase, 'finalized', {digest, gasUsed: final.effects?.gasUsed,
      effects: final.effects, objectTypes: final.objectTypes, events: final.events,purpose}));
    return {digest, transaction: final};
    }finally{release();}
  }));
}
async function auditSchema() {
  await sql`CREATE TABLE IF NOT EXISTS exercise_renewal_memories (
    run_id text NOT NULL, memory_id integer NOT NULL, owner_index integer NOT NULL,
    owner text NOT NULL, account_id text NOT NULL, namespace text NOT NULL,
    plaintext_sha256 text NOT NULL, ciphertext_sha256 text NOT NULL,
    plaintext_bytes integer NOT NULL, ciphertext_bytes integer NOT NULL,
    source_blob_id text, source_object_id text, source_end_epoch integer,
    current_object_id text, current_end_epoch integer, source_metadata jsonb,
    stage text NOT NULL DEFAULT 'generated', last_error text,
    created_at timestamptz NOT NULL DEFAULT now(), migrated_at timestamptz,
    PRIMARY KEY(run_id,memory_id))`;
  await sql`CREATE TABLE IF NOT EXISTS exercise_renewal_journal (
    id bigserial PRIMARY KEY, run_id text NOT NULL, memory_id integer NOT NULL,
    phase text NOT NULL, state text NOT NULL, payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now())`;
  await sql`CREATE INDEX IF NOT EXISTS exercise_renewal_journal_lookup
    ON exercise_renewal_journal(run_id,memory_id,phase)`;
  await sql`ALTER TABLE exercise_renewal_memories
    ADD COLUMN IF NOT EXISTS vector_entry_id text,
    ADD COLUMN IF NOT EXISTS parent_run_id text,
    ADD COLUMN IF NOT EXISTS parent_memory_id integer,
    ADD COLUMN IF NOT EXISTS origin_run_id text,
    ADD COLUMN IF NOT EXISTS origin_memory_id integer,
    ADD COLUMN IF NOT EXISTS provenance_run_id text,
    ADD COLUMN IF NOT EXISTS source_provenance jsonb`;
}
function plaintextFor(id: number, owner: Owner) {
  const core = { kind: 'synthetic-renewal-exercise', runId: config.runId, memoryId: id,
    owner: owner.address, facts: [
      `Synthetic project ${id} prefers TypeScript and stores its weekly build notes.`,
      `Synthetic project ${id} schedules its review on day ${(id % 7) + 1}.`,
      `Synthetic project ${id} uses namespace renewal/${config.runId}/${id % 5}.`,
    ], content: '' };
  const base = json(core); core.content = (`Fixture ${id}: synthetic engineering context; no customer data. `)
    .repeat(Math.ceil(Math.max(0, config.payloadBytes - base.length) / 65));
  return Buffer.from(json(core));
}
function cipherPath(id: number) { return path.join(config.scratch, 'ciphertext', `${id}.bin`); }
function downloadPath(id: number) { return path.join(config.scratch, 'downloads', `${id}.bin`); }
async function currentObject(id: string) {
  const result = await sui.core.getObject({ objectId: id, include: { json: true, previousTransaction: true } });
  assert.ok(result.object); return result.object;
}
function addressOwner(object: any): string | null {
  return object?.owner?.AddressOwner ?? object?.owner?.address ?? object?.owner?.owner ??
    (object?.owner?.$kind === 'AddressOwner' ? object.owner.AddressOwner : null);
}
function objectEpoch(object: any): number {
  const value = object?.json?.storage?.fields?.end_epoch ?? object?.json?.storage?.end_epoch;
  assert.ok(value !== undefined, 'Blob end_epoch missing'); return Number(value);
}
async function attrs(id: string): Promise<Record<string,string>> {
  return Object.fromEntries((await fetchBlobMetadataEntries(id)).map(x => [x.key, x.value]));
}
async function epochSchedule() {
  // Do not reuse WalrusClient's cached staking-object loader for expiry audits.
  const reader = new WalrusClient({network:'testnet',suiClient:sui});
  const [state,system]=await Promise.all([reader.stakingState(),reader.systemState()]);
  const epoch = Number(system.committee.epoch); const durationMs = Number(state.epoch_duration);
  assert.ok(Number.isInteger(epoch) && Number.isSafeInteger(durationMs) && durationMs > 0);
  return {epoch,durationMs,observedAt:new Date()};
}
function expiryAt(endEpoch:number, schedule:Awaited<ReturnType<typeof epochSchedule>>) {
  return new Date(schedule.observedAt.getTime() + Math.max(0,endEpoch-schedule.epoch)*schedule.durationMs);
}
async function readCiphertext(blobId:string, phase:string) {
  const base = config.walrusAggregatorUrl ?? 'https://aggregator.walrus-testnet.walrus.space';
  assert.ok(/testnet/.test(base));
  const response = await fetch(`${base}/v1/blobs/${blobId}`, {signal:AbortSignal.timeout(120_000)});
  assert.equal(response.status,200,`Walrus aggregator download ${phase}`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  const tally = transport.aggregator_get ??= {requests:0,bytes:0}; tally.requests++; tally.bytes += bytes.length;
  metric('transport',{kind:'aggregator_get',phase,status:response.status,blobId,bytes:bytes.length,sha256:sha(bytes)});
  return bytes;
}
async function balances() {
  const result:Record<string,unknown> = {};
  for (const [name,coinType] of Object.entries({SUI:'0x2::sui::SUI',WAL:'0x8270feb7375eee355e64fdb69c50abb6b5f9393a722883c1cf45f8e26048810a::wal::WAL'})) {
    result[name] = (await sui.core.getBalance({owner:writer.toSuiAddress(),coinType})).balance;
  }
  return result;
}
async function persistOwners() {
  await mkdir(path.dirname(config.ownerFile),{recursive:true,mode:0o700});
  const temporary=`${config.ownerFile}.${randomUUID()}.tmp`;
  await writeFile(temporary,json(owners),{mode:0o600,flag:'wx'});await chmod(temporary,0o600);
  await rename(temporary,config.ownerFile);await chmod(config.ownerFile,0o600);
}
async function ensureOwners() {
  if(owners.length){assert.equal(owners.length,2);await chmod(config.ownerFile,0o600);return;}
  const history=await sql`SELECT 1 FROM exercise_renewal_journal WHERE run_id=${config.runId} LIMIT 1`;
  const memories=await sql`SELECT 1 FROM exercise_renewal_memories WHERE run_id=${config.runId} LIMIT 1`;
  assert.equal(history.length+memories.length,0,'Fixture keys are missing for an existing run; restore that run’s original private fixture file before resuming');
  ownerKeys=Array.from({length:2},()=>Ed25519Keypair.generate());
  owners=ownerKeys.map((key,n)=>({name:`synthetic-owner-${n}`,address:key.toSuiAddress(),privateKey:key.getSecretKey()}));
  await persistOwners();
  metric('fixture_owners_created',{owners:owners.map(({privateKey,...safe})=>safe)});
}
async function pendingTransactions() {
  return sql`SELECT p.memory_id,p.phase,p.payload FROM exercise_renewal_journal p
    WHERE p.run_id=${config.runId} AND p.state='prepared' AND NOT EXISTS(
      SELECT 1 FROM exercise_renewal_journal f WHERE f.run_id=p.run_id AND f.memory_id=p.memory_id
      AND f.phase=p.phase AND f.state='finalized' AND f.payload->>'digest'=p.payload->>'digest') ORDER BY p.id`;
}
async function assertReplayNotExpired(data:any) {
  const expiration=data.expiration;
  if(!expiration||expiration.$kind==='None')return;
  const state=(await sui.core.getCurrentSystemState()).systemState;
  const epoch=BigInt(state.epoch);
  if(expiration.ValidDuring){
    const valid=expiration.ValidDuring;
    assert.equal(valid.chain,'69WiPg3DAQiwdxfncX6wYQ2siKwAe6L9BZthQea3JNMD');
    assert.ok(epoch>=BigInt(valid.minEpoch)&&epoch<=BigInt(valid.maxEpoch),'Saved transaction is outside its valid epoch range; retained for reconciliation, never rebuilt');
    if(valid.minTimestamp!==null&&valid.minTimestamp!==undefined)assert.ok(BigInt(Date.now())>=BigInt(valid.minTimestamp));
    if(valid.maxTimestamp!==null&&valid.maxTimestamp!==undefined)assert.ok(BigInt(Date.now())<=BigInt(valid.maxTimestamp),'Saved transaction has expired');
  }else if(expiration.Epoch!==undefined)assert.ok(epoch<=BigInt(expiration.Epoch),'Saved transaction epoch has expired');
  else throw new Error('Unknown saved transaction expiration; refusing replay');
}
async function reconcilePending() {
  const pending=await pendingTransactions();
  if(pending.length)assert.equal(owners.length,2,'Pending chain work requires the original fixture owner file; never create replacement keys');
  for(const row of pending){
    assert.ok((row.phase==='fund_owners'&&row.memory_id===-100)||(row.phase==='create_account'&&[-1,-2].includes(row.memory_id))||
      (/^(seed|renew)\.(register|certify|certify_transfer|metadata_transfer)$/.test(row.phase)&&row.memory_id>=0&&row.memory_id<config.count),'Unknown saved transaction phase; refusing replay');
    const digest=String(row.payload.digest);let result:any;
    try{result=await sui.core.getTransaction({digest,include:{effects:true,transaction:true,objectTypes:true,events:true}});}
    catch(error){metric('reconcile_lookup_unavailable',{id:row.memory_id,phase:row.phase,digest,error:cleanError(error)});}
    if(result?.FailedTransaction)throw new Error(`Saved transaction failed on chain: ${digest}; preserve journal and inspect its failure`);
    if(!result?.Transaction){
      assert.ok(execute,`Unresolved saved digest ${digest}; --execute permits only an exact-byte replay`);
      assert.equal(typeof row.payload.bytes,'string','Exact saved BCS bytes are required; never rebuild an unresolved transaction');
      const bytes=fromBase64(row.payload.bytes),saved=Transaction.from(bytes),data=saved.getData();
      assert.equal(await saved.getDigest(),digest,'Saved BCS bytes/digest mismatch');
      assert.equal(data.gasData.owner,data.sender,'Unexpected sponsored replay');
      await assertReplayNotExpired(data);
      const signer=data.sender===writer.toSuiAddress()?writer:ownerKeys.find(key=>key.toSuiAddress()===data.sender);
      assert.ok(signer,'No controlled signer matches the saved transaction sender');
      if(signer===writer)assert.deepEqual(data.gasData.payment,[],'Writer replay must retain address-balance gas');
      const release=signer===writer?await reserveWriterFunds(data):()=>{};
      try{
        const signature=(await signer.signTransaction(bytes)).signature;
        metric('reconcile_exact_replay',{id:row.memory_id,phase:row.phase,digest});
        result=await sui.core.executeTransaction({transaction:bytes,signatures:[signature],include:{effects:true,transaction:true,objectTypes:true,events:true}});
        transactionOf(result);
        result=await sui.core.waitForTransaction({digest,include:{effects:true,transaction:true,objectTypes:true,events:true}});
      }finally{release();}
    }
    const transaction=transactionOf(result);assert.equal(transaction.digest,digest);
    const final=transactionOf(await sui.core.waitForTransaction({digest,include:{effects:true,transaction:true,objectTypes:true,events:true}}));
    assert.equal(final.digest,digest);
    await journal(row.memory_id,row.phase,'finalized',{digest,gasUsed:final.effects?.gasUsed,effects:final.effects,
      objectTypes:final.objectTypes,events:final.events,purpose:row.payload.purpose,reconciledAt:new Date().toISOString()});
    metric('reconciled',{id:row.memory_id,phase:row.phase,digest});
  }
  assert.equal((await pendingTransactions()).length,0,'Unresolved prepared transactions remain');
  metric('reconcile_complete',{reconciled:pending.length});
}
async function recoverAccounts() {
  for(let n=0;n<owners.length;n++){
    const receipts=await sql`SELECT payload FROM exercise_renewal_journal WHERE run_id=${config.runId}
      AND memory_id=${-1-n} AND phase='create_account' AND state='finalized' ORDER BY id`;
    assert.ok(receipts.length<=1,'Multiple account creation receipts require inspection');
    if(!owners[n].accountId&&receipts.length){
      const matches=Object.entries(receipts[0].payload.objectTypes??{}).filter(([,type])=>String(type).endsWith('::account::MemWalAccount'));
      assert.equal(matches.length,1,'Cannot uniquely recover the created fixture account');
      owners[n].accountId=matches[0][0];await persistOwners();
      metric('account_recovered',{owner:owners[n].address,accountId:owners[n].accountId,digest:receipts[0].payload.digest});
    }
    if(owners[n].accountId)await fetchSealEncryptIdentity(owners[n].accountId!,owners[n].address,config.immutablePackageId,'normal',sui as any);
  }
}
async function setup() {
  await ensureOwners();await reconcilePending();await recoverAccounts();
  const recipients:Array<{owner:string;amountMist:string}>=[];
  for(const owner of owners){
    if(owner.accountId)continue;
    const balance=BigInt((await sui.core.getBalance({owner:owner.address})).balance.balance);
    if(balance<50_000_000n)recipients.push({owner:owner.address,amountMist:String(50_000_000n-balance)});
  }
  if(recipients.length){
    const previous=await sql`SELECT payload FROM exercise_renewal_journal WHERE run_id=${config.runId}
      AND memory_id=-100 AND phase='fund_owners' AND state='finalized'`;
    assert.equal(previous.length,0,'Fixture funding already finalized but balance is insufficient; refusing duplicate principal funding');
    const tx=new Transaction();
    for(const recipient of recipients)tx.transferObjects([coinWithBalance({balance:BigInt(recipient.amountMist)})],recipient.owner);
    const principalMist=String(recipients.reduce((total,r)=>total+BigInt(r.amountMist),0n));
    const result=await submit(-100,'fund_owners',tx,writer,{principalMist,recipients});
    metric('fixture_owners_funded',{digest:result.digest,principalMist,recipients});
  }
  await createAccounts();
  metric('setup_complete',{owners:owners.map(({privateKey,...safe})=>safe)});
}
async function createAccounts() {
  assert.equal(owners.length,2,'Run setup first');await recoverAccounts();
  for (let n = 0; n < owners.length; n++) {
    if (owners[n].accountId) continue;
    const tx = new Transaction(); tx.moveCall({target: `${config.policyPackageId}::account::create_account`,
      arguments: [tx.object(config.registryId), tx.object('0x6')]});
    const result = await submit(-1 - n, 'create_account', tx, ownerKeys[n]);
    const matches = Object.entries(result.transaction.objectTypes ?? {}).filter(([,t]) => String(t).endsWith('::account::MemWalAccount'));
    assert.equal(matches.length, 1, 'Expected one new synthetic MemWalAccount');
    owners[n].accountId = matches[0][0];
    await persistOwners();
    const identity = await fetchSealEncryptIdentity(owners[n].accountId!, owners[n].address,
      config.immutablePackageId, 'normal', sui as any);
    metric('account_created', {owner: owners[n].address, accountId: owners[n].accountId, digest: result.digest,
      accessCounter: String(identity.accessCounterVersion)});
  }
}
function vectorId(row:any){return row.vector_entry_id??`${row.run_id}:${row.memory_id}`;}
async function prepareExisting(){
  assert.equal(config.mode,'migration-only');
  const parentRun=config.parentSourceRunId,sourceOffset=config.sourceOffset??0;
  assert.ok(parentRun&&parentRun!==config.runId&&Number.isInteger(sourceOffset)&&sourceOffset>=0);
  assert.ok(config.sourceOwnerFile&&config.sourceCipherDir,'Existing source owner/cipher paths are required');
  const ownerPath=path.resolve(config.sourceOwnerFile),parentDirectory=path.dirname(path.dirname(ownerPath));
  assert.equal(path.basename(ownerPath),'owners.private.json');assert.equal(path.basename(path.dirname(ownerPath)),'data');
  assert.equal(path.basename(parentDirectory),parentRun,'Source owners must belong to the selected managed run');
  const realParent=await realpath(parentDirectory),realOwners=await realpath(ownerPath),realCipher=await realpath(config.sourceCipherDir);
  assert.ok(realOwners.startsWith(realParent+path.sep)&&realCipher.startsWith(realParent+path.sep),'Source fixture paths must remain inside the selected managed run');
  let importedOwners:Owner[];
  try{importedOwners=JSON.parse(await readFile(realOwners,'utf8'));}
  catch{throw new Error('Source synthetic fixture owner file is invalid; private contents were not logged');}
  assert.equal(importedOwners.length,2);
  for(const owner of importedOwners){
    assert.ok(owner.name.startsWith('synthetic-owner-')&&owner.accountId);
    try{assert.equal(Ed25519Keypair.fromSecretKey(decodeSuiPrivateKey(owner.privateKey).secretKey).toSuiAddress(),owner.address);}
    catch{throw new Error('Source fixture key/public-address mismatch');}
  }
  const [parentCount]=await sql`SELECT count(*)::int AS total,
    count(*) FILTER(WHERE stage='migrated' AND parent_run_id IS NULL)::int AS ready
    FROM exercise_renewal_memories WHERE run_id=${parentRun}`;
  assert.ok(parentCount.total===parentCount.ready&&parentCount.ready>=sourceOffset+config.count,
    'Select a completed canonical full root with a sufficient source range; selecting a child cycle is not supported');
  const parents=await sql`SELECT * FROM exercise_renewal_memories WHERE run_id=${parentRun}
    AND memory_id>=${sourceOffset} AND memory_id<${sourceOffset+config.count} ORDER BY memory_id`;
  assert.equal(parents.length,config.count,'Source range must exist in the canonical root');
  const existing=await sql`SELECT * FROM exercise_renewal_memories WHERE run_id=${config.runId} ORDER BY memory_id`;
  assert.ok(existing.length===0||existing.length===config.count,'Partial imported catalog requires inspection');
  if(owners.length)assert.deepEqual(owners.map(o=>o.address),importedOwners.map(o=>o.address),'Child fixture owners must match the source');
  else{owners=importedOwners;ownerKeys=owners.map(o=>Ed25519Keypair.fromSecretKey(decodeSuiPrivateKey(o.privateKey).secretKey));await persistOwners();}
  for(let id=0;id<parents.length;id++){
    const p=parents[id];assert.equal(p.parent_run_id,null);assert.equal(p.stage,'migrated');
    assert.equal(owners[p.owner_index].address,p.owner);assert.equal(owners[p.owner_index].accountId,p.account_id);
    const bytes=await readFile(path.join(realCipher,`${p.memory_id}.bin`));assert.equal(sha(bytes),p.ciphertext_sha256);
    if(existsSync(cipherPath(id)))assert.equal(sha(await readFile(cipherPath(id))),p.ciphertext_sha256);
    else await writeFile(cipherPath(id),bytes);
    if(existing.length){
      const row=existing[id];assert.equal(row.memory_id,id);assert.equal(row.parent_run_id,parentRun);assert.equal(row.parent_memory_id,p.memory_id);
      assert.equal(row.vector_entry_id,vectorId(p));assert.equal(row.ciphertext_sha256,p.ciphertext_sha256);
      continue;
    }
    const [vector]=await sql`SELECT id,owner,namespace,blob_id,end_epoch FROM vector_entries WHERE id=${vectorId(p)}`;
    assert.ok(vector);assert.equal(vector.owner,p.owner);assert.equal(vector.namespace,p.namespace);
    assert.equal(vector.blob_id,p.source_blob_id);assert.equal(vector.end_epoch,p.current_end_epoch);
  }
  if(!existing.length)await sql.begin(async(tx:any)=>{
    for(let id=0;id<parents.length;id++){
      const p=parents[id];const provenance={source_blob_id:p.source_blob_id,source_object_id:p.source_object_id,source_end_epoch:p.source_end_epoch,
        source_metadata:p.source_metadata,created_at:p.created_at,owner:p.owner,namespace:p.namespace,account_id:p.account_id,
        plaintext_sha256:p.plaintext_sha256,ciphertext_sha256:p.ciphertext_sha256};
      await tx`INSERT INTO exercise_renewal_memories(run_id,memory_id,owner_index,owner,account_id,namespace,plaintext_sha256,ciphertext_sha256,
        plaintext_bytes,ciphertext_bytes,source_blob_id,source_object_id,source_end_epoch,current_object_id,current_end_epoch,source_metadata,
        stage,created_at,vector_entry_id,parent_run_id,parent_memory_id,origin_run_id,origin_memory_id,provenance_run_id,source_provenance)
        VALUES(${config.runId},${id},${p.owner_index},${p.owner},${p.account_id},${p.namespace},${p.plaintext_sha256},${p.ciphertext_sha256},
          ${p.plaintext_bytes},${p.ciphertext_bytes},${p.source_blob_id},${p.current_object_id},${p.current_end_epoch},${p.current_object_id},${p.current_end_epoch},${tx.json(p.source_metadata)},
          'seeded',${p.created_at},${vectorId(p)},${parentRun},${p.memory_id},${parentRun},${p.memory_id},${p.provenance_run_id??p.source_metadata.exercise_run??parentRun},${tx.json(provenance)})`;
    }
  });
  metric('existing_prepared',{count:config.count,parentSourceRunId:parentRun,sourceOffset,alreadyImported:!!existing.length,paidSeedTransactions:0,setupTransactions:0});
}
async function leasePlan(id:number,row:any){
  const saved=await sql`SELECT payload FROM exercise_renewal_journal WHERE run_id=${config.runId} AND memory_id=${id}
    AND phase='renew.lease_plan' AND state='planned' ORDER BY id`;
  assert.ok(saved.length<=1,'Multiple lease plans require reconciliation');
  if(saved.length){const p=saved[0].payload;assert.equal(p.inputObjectId,row.source_object_id);assert.equal(p.inputEndEpoch,row.source_end_epoch);return p;}
  assert.equal(await hasFinalized(id,'renew.register'),false,'Registered object has no immutable lease plan');
  const reader=new WalrusClient({network:'testnet',suiClient:sui});
  const system=await timed('renew.lease_plan.system_read',()=>reader.systemState());
  const currentEpoch=Number(system.committee.epoch),numShards=Number(system.committee.n_shards);
  assert.ok(Number.isInteger(numShards)&&numShards>0);
  const requestedEpochs=Math.max(config.renewalEpochs,row.source_end_epoch+1-currentEpoch);
  assert.ok(Number.isInteger(requestedEpochs)&&requestedEpochs>=1&&requestedEpochs<=53,'Required lease is outside supported1..53 epochs');
  const plan={inputObjectId:row.source_object_id,inputEndEpoch:row.source_end_epoch,currentEpoch,numShards,requestedEpochs,targetEndEpoch:currentEpoch+requestedEpochs};
  await journal(id,'renew.lease_plan','planned',plan);metric('lease_planned',{id,...plan});return plan;
}
async function prepareOne(id: number) {
  const existing = await sql`SELECT memory_id FROM exercise_renewal_memories WHERE run_id=${config.runId} AND memory_id=${id}`;
  if (existing.length) return;
  const ownerIndex = id % owners.length; const owner = owners[ownerIndex];
  assert.ok(owner.accountId, 'Create synthetic MemWalAccount first');
  const identity = await fetchSealEncryptIdentity(owner.accountId, owner.address, config.immutablePackageId, 'normal', sui as any);
  const plain = plaintextFor(id, owner);
  const ciphertext = await timed('encrypt_source', async () => (await seal.encrypt({packageId: config.immutablePackageId,
    id: buildSealEncryptId(owner.address, identity.accessCounterVersion), threshold: 1, data: plain})).encryptedObject);
  await writeFile(cipherPath(id), ciphertext);
  await sql`INSERT INTO exercise_renewal_memories(run_id,memory_id,owner_index,owner,account_id,namespace,
    plaintext_sha256,ciphertext_sha256,plaintext_bytes,ciphertext_bytes)
    VALUES(${config.runId},${id},${ownerIndex},${owner.address},${owner.accountId},${`renewal/${config.runId}/${id % 5}`},
      ${sha(plain)},${sha(ciphertext)},${plain.length},${ciphertext.length})`;
}
const fusedRenewal=config.mode==='migration-only'&&config.renewMode!=='unfused';
let metadataComputer:Awaited<ReturnType<typeof createMetadataComputer>>|undefined;
let metadataComputerPromise:Promise<Awaited<ReturnType<typeof createMetadataComputer>>>|undefined;
async function getMetadataComputer(){
  assert.ok(config.metadataCacheDir&&path.isAbsolute(config.metadataCacheDir),'Fused migration requires an absolute persistent metadataCacheDir');
  if(!metadataComputerPromise)metadataComputerPromise=timed('renew.metadata.initialize',()=>createMetadataComputer({
    cacheDir:config.metadataCacheDir!,threads:config.metadataThreads??4,onMetric:(event,detail)=>metric(event,detail)}));
  metadataComputer=await metadataComputerPromise;return metadataComputer;
}
const RelayCertificate=bcs.struct('Certificate',{
  signers:bcs.vector(bcs.u16()),serializedMessage:bcs.byteVector(),signature:bcs.byteVector()});
async function finalizedReceipt(id:number,phase:string){
  const receipts=await sql`SELECT payload FROM exercise_renewal_journal WHERE run_id=${config.runId}
    AND memory_id=${id} AND phase=${phase} AND state='finalized' ORDER BY id`;
  assert.ok(receipts.length<=1,`Multiple successful ${phase} receipts require reconciliation`);
  return receipts[0]?.payload;
}
function createdBlobId(receipt:any):string{
  assert.equal(receipt.effects?.status?.success,true,'A created Blob requires successful finalized effects');
  const expected=normalizeStructTag(`${config.walrusPackageId}::blob::Blob`);
  const matches=(receipt.effects.changedObjects??[]).filter((change:any)=>change.idOperation==='Created'
    &&change.outputState==='ObjectWrite'&&typeof receipt.objectTypes?.[change.objectId]==='string'
    &&normalizeStructTag(receipt.objectTypes[change.objectId])===expected);
  assert.equal(matches.length,1,'Finalized registration must create exactly one expected Walrus Blob');
  return matches[0].objectId;
}
async function appendFusedTail(tx:Transaction,id:number,row:any,objectId:string,bytes:Uint8Array,metadata:Record<string,string>,plan:any){
  const [object,registeredMetadata]=await timed('renew.certify_transfer.precert_reads',()=>Promise.all([
    timed('renew.certify_transfer.precert_object',()=>currentObject(objectId)),
    timed('renew.certify_transfer.precert_metadata',()=>attrs(objectId))]));
  assert.equal(addressOwner(object),writer.toSuiAddress());assert.equal(String(object.json?.size),String(bytes.length));
  assert.equal(object.json?.deletable,true);
  assert.equal(blobIdFromInt(BigInt(String(object.json?.blob_id))),row.source_blob_id);
  assert.ok(objectEpoch(object)>=plan.targetEndEpoch&&objectEpoch(object)>row.source_end_epoch);
  assert.deepEqual(registeredMetadata,metadata,'Registration metadata must already match before certification');
  const fence=parseSealPersistenceFence({sealAbi:'v1-new',accountId:row.account_id,registryId:config.registryId,
    policyPackageId:config.policyPackageId,data:Buffer.from(bytes).toString('base64')},config.immutablePackageId,
    {allowLegacySealAbi:false,policyPackageId:config.policyPackageId});
  appendSealPersistenceFence(tx,fence);tx.transferObjects([tx.object(objectId)],row.owner);
}
async function uploadExplicitFused(id:number,bytes:Uint8Array,metadata:Record<string,string>,row:any,plan:any){
  const steps=await sql`SELECT state,payload FROM exercise_renewal_journal WHERE run_id=${config.runId}
    AND memory_id=${id} AND phase='renew.flow' ORDER BY id`;
  const saved=(state:string)=>{
    const found=steps.filter(step=>step.state===state);assert.ok(found.length<=1,`Multiple ${state} checkpoints require reconciliation`);
    return found[0]?.payload;
  };
  let encoded=saved('encoded'),registered=saved('registered'),uploaded=saved('uploaded'),certified=saved('certified');
  const registration=await finalizedReceipt(id,'renew.register');
  const certification=await finalizedReceipt(id,'renew.certify_transfer');
  const sourceProvenance=json({originRunId:row.origin_run_id??row.provenance_run_id??row.run_id,
    originMemoryId:row.origin_memory_id??row.memory_id,vectorEntryId:vectorId(row),owner:row.owner,namespace:row.namespace});
  let tick=now();
  const mark=(name:string)=>{(phaseTimes[`renew.flow.${name}`]??=[]).push(now()-tick);tick=now();};
  if(!encoded){
    assert.ok(!registered&&!uploaded&&!certified&&!registration&&!certification,'Existing paid work has no encoded checkpoint; never create a new nonce');
    assert.ok(Number.isInteger(plan.numShards)&&plan.numShards>0,'Lease plan must bind a fresh system shard count');
    const computer=await getMetadataComputer();
    const result=await timed('renew.metadata.compute',()=>computer.compute({bytes,expectedBlobId:row.source_blob_id,
      expectedSha256:row.ciphertext_sha256,numShards:plan.numShards,sourceProvenance}));
    assert.equal(result.blobId,row.source_blob_id);assert.equal(BigInt(result.unencodedLength),BigInt(bytes.length));
    assert.equal(result.rootHash.length,32);assert.equal(result.encodingType,'RS2');
    assert.equal(result.sha256,row.ciphertext_sha256);assert.equal(result.numShards,plan.numShards);
    assert.equal(result.rootDerivedBlobId,result.blobId);assert.equal(result.rootBindingVerified,true);
    encoded={step:'encoded',execution:'explicit-public-sdk-v1',blobId:result.blobId,
      rootHash:Buffer.from(result.rootHash).toString('base64'),unencodedSize:bytes.length,unencodedLength:String(result.unencodedLength),
      encodingType:result.encodingType,nonce:randomBytes(32).toString('base64'),ciphertextSha256:row.ciphertext_sha256,
      byteLength:result.byteLength,numShards:result.numShards,cacheKey:result.cacheKey,cacheVersion:result.cacheVersion,
      codecFingerprint:result.fingerprint,sourceProvenance,cacheHit:result.cacheHit,
      rootDerivedBlobId:result.rootDerivedBlobId,rootBindingVerified:result.rootBindingVerified};
    mark('encoded');
    await timed('renew.metadata.checkpoint',()=>journal(id,'renew.flow','encoded',encoded));
  }else{
    assert.equal(encoded.execution,'explicit-public-sdk-v1','Resume this older SDK flow with its archived runtime');
    const computer=await getMetadataComputer();
    assert.equal(encoded.codecFingerprint,computer.fingerprint,'Saved metadata codec binding changed; refusing a new encoding/nonce');
    metric('metadata_checkpoint_reused',{id,cacheKey:encoded.cacheKey,numShards:encoded.numShards});
  }
  assert.equal(encoded.blobId,row.source_blob_id);assert.equal(encoded.ciphertextSha256,sha(bytes));
  assert.equal(encoded.unencodedSize,bytes.length);assert.equal(encoded.byteLength,bytes.length);
  assert.equal(encoded.sourceProvenance,sourceProvenance);assert.equal(encoded.rootDerivedBlobId,encoded.blobId);
  assert.equal(encoded.rootBindingVerified,true);assert.equal(encoded.numShards,plan.numShards);
  const nonce=fromBase64(encoded.nonce),rootHash=fromBase64(encoded.rootHash);
  assert.equal(nonce.length,32);assert.equal(rootHash.length,32);assert.equal(encoded.encodingType,'RS2');
  assert.equal(Buffer.from(nonce).toString('base64'),encoded.nonce,'Saved nonce must use canonical base64');
  assert.equal(Buffer.from(rootHash).toString('base64'),encoded.rootHash,'Saved root must use canonical base64');
  assert.equal(deriveMetadataBlobId(rootHash,bytes.length),encoded.blobId,'Saved root/size must independently derive the source blob ID on every resume');
  assert.equal(BigInt(encoded.unencodedLength),BigInt(bytes.length));assert.equal(encoded.cacheVersion,1);
  assert.ok(typeof encoded.cacheKey==='string'&&encoded.cacheKey.length>0);
  if(registration){
    const objectId=createdBlobId(registration);assert.notEqual(objectId,row.source_object_id);
    if(registered){assert.equal(registered.blobObjectId,objectId);assert.equal(registered.txDigest,registration.digest);}
    else{
      registered={step:'registered',blobId:encoded.blobId,blobObjectId:objectId,txDigest:registration.digest,nonce:encoded.nonce};
      await journal(id,'renew.flow','registered',registered);
    }
  }else{
    assert.ok(!registered&&!uploaded&&!certified&&!certification,'Checkpoint has no finalized registration receipt');
    if(saved('encoded')){
      const reader=new WalrusClient({network:'testnet',suiClient:sui});
      const current=await timed('renew.metadata.resume_parameter_read',()=>reader.systemState());
      assert.equal(Number(current.committee.n_shards),encoded.numShards,'Shard parameters changed; preserve the existing nonce/checkpoint and stop');
    }
    const sdkSystem=await timed('renew.metadata.sdk_parameter_check',()=>walrus.systemState());
    assert.equal(Number(sdkSystem.committee.n_shards),encoded.numShards,'SDK registration parameters differ from the verified metadata binding');
    const tx=new Transaction();
    tx.add(walrus.sendUploadRelayTip({size:bytes.length,blobDigest:new Uint8Array(Buffer.from(row.ciphertext_sha256,'hex')),nonce}));
    const blob=tx.add(walrus.registerBlob({size:bytes.length,epochs:plan.requestedEpochs,blobId:encoded.blobId,
      rootHash,deletable:true,attributes:metadata}));
    tx.transferObjects([blob],writer.toSuiAddress());
    const result=await submit(id,'renew.register',tx);
    const objectId=createdBlobId(result.transaction);assert.notEqual(objectId,row.source_object_id);
    registered={step:'registered',blobId:encoded.blobId,blobObjectId:objectId,txDigest:result.digest,nonce:encoded.nonce};
    mark('registered');await journal(id,'renew.flow','registered',registered);
  }
  assert.equal(registered.blobId,encoded.blobId);assert.equal(registered.nonce,encoded.nonce);
  if(certification){
    if(certified){assert.equal(certified.blobObjectId,registered.blobObjectId);assert.equal(certified.blobId,encoded.blobId);assert.equal(certified.certifyDigest,certification.digest);}
    else{
      certified={step:'certified',blobId:encoded.blobId,blobObjectId:registered.blobObjectId,certifyDigest:certification.digest};
      await journal(id,'renew.flow','certified',certified);
    }
    return {objectId:String(registered.blobObjectId),blobId:String(encoded.blobId)};
  }
  assert.ok(!certified,'Certified checkpoint has no matching finalized certify/transfer receipt');
  if(!uploaded){
    if(registration){
      const reader=new WalrusClient({network:'testnet',suiClient:sui});
      const current=await timed('renew.metadata.resume_parameter_read',()=>reader.systemState());
      assert.equal(Number(current.committee.n_shards),encoded.numShards,'Shard parameters changed after registration; never remint on resume');
    }
    const response=await timed('renew.relay.upload',()=>walrus.writeBlobToUploadRelay({blobId:encoded.blobId,blob:bytes,
      nonce,txDigest:registered.txDigest,blobObjectId:registered.blobObjectId,deletable:true,encodingType:'RS2'}));
    assert.equal(response.blobId,encoded.blobId);
    assert.ok(response.certificate.signers.length&&response.certificate.signature.length&&response.certificate.serializedMessage.length);
    const certificate=RelayCertificate.serialize(response.certificate).toBase64();
    uploaded={step:'uploaded',blobId:encoded.blobId,blobObjectId:registered.blobObjectId,txDigest:registered.txDigest,
      certificate,nonce:encoded.nonce};
    mark('uploaded');await journal(id,'renew.flow','uploaded',uploaded);
  }
  assert.equal(uploaded.blobId,encoded.blobId);assert.equal(uploaded.blobObjectId,registered.blobObjectId);
  assert.equal(uploaded.txDigest,registered.txDigest);assert.equal(uploaded.nonce,encoded.nonce);assert.equal(typeof uploaded.certificate,'string');
  const tx=walrus.certifyBlobTransaction({blobId:encoded.blobId,blobObjectId:registered.blobObjectId,
    certificate:uploaded.certificate,deletable:true});
  await appendFusedTail(tx,id,row,registered.blobObjectId,bytes,metadata,plan);
  const result=await submit(id,'renew.certify_transfer',tx);
  certified={step:'certified',blobId:encoded.blobId,blobObjectId:registered.blobObjectId,certifyDigest:result.digest};
  mark('certified');await journal(id,'renew.flow','certified',certified);
  return {objectId:String(registered.blobObjectId),blobId:String(encoded.blobId)};
}
async function uploadOne(id: number, phase: 'seed'|'renew', bytes: Uint8Array, metadata: Record<string,string>,row?:any,plan?:any) {
  if(phase==='renew'&&fusedRenewal)return uploadExplicitFused(id,bytes,metadata,row,plan);
  const certifyPhase=phase==='renew'&&fusedRenewal?'renew.certify_transfer':`${phase}.certify`;
  const saved = await sql`SELECT phase,state,payload FROM exercise_renewal_journal WHERE run_id=${config.runId}
    AND memory_id=${id} AND phase=${`${phase}.flow`} AND state IN ('registered','uploaded','certified') ORDER BY id DESC LIMIT 1`;
  let resume = saved[0]?.payload;
  if (!resume) {
    const previousRegister = await sql`SELECT payload FROM exercise_renewal_journal WHERE run_id=${config.runId}
      AND memory_id=${id} AND phase=${`${phase}.register`} AND state='finalized' ORDER BY id DESC LIMIT 1`;
    if (previousRegister.length) {
      const encoded = await sql`SELECT payload FROM exercise_renewal_journal WHERE run_id=${config.runId}
        AND memory_id=${id} AND phase=${`${phase}.flow`} AND state='encoded' ORDER BY id DESC LIMIT 1`;
      const matches = Object.entries(previousRegister[0].payload.objectTypes ?? {})
        .filter(([,type]) => String(type).endsWith('::blob::Blob'));
      assert.ok(encoded.length && matches.length === 1, 'Cannot safely reconstruct finalized registration; reconcile without minting');
      resume = {...encoded[0].payload, step: 'registered', blobObjectId: matches[0][0],
        txDigest: previousRegister[0].payload.digest};
      await journal(id, `${phase}.flow`, 'registered', resume);
    }
  }
  if (resume && resume.step !== 'certified') {
    const cert = await sql`SELECT payload FROM exercise_renewal_journal WHERE run_id=${config.runId}
      AND memory_id=${id} AND phase=${certifyPhase} AND state='finalized' ORDER BY id DESC LIMIT 1`;
    if (cert.length) {
      resume = {...resume, step: 'certified', certifyDigest: cert[0].payload.digest};
      await journal(id, `${phase}.flow`, 'certified', resume);
    }
  }
  if (resume?.step === 'certified') return {objectId: String(resume.blobObjectId), blobId: String(resume.blobId)};
  const flow = walrus.writeBlobFlow({blob: bytes, ...(resume ? {resume: resume as any} : {})});
  let last:any=resume;
  const flowSigner = {toSuiAddress: () => writer.toSuiAddress(),
    signAndExecuteTransaction: async ({transaction}: {transaction: Transaction}) => {
      const op = resume?.step === 'uploaded' || await hasFinalized(id, `${phase}.register`) ? 'certify' : 'register';
      if(op==='certify'&&phase==='renew'&&fusedRenewal){
        assert.ok(row&&plan&&last?.blobObjectId,'Fused certification requires persisted upload/lease checkpoints');
        const objectId=String(last.blobObjectId),object=await currentObject(objectId);
        assert.equal(addressOwner(object),writer.toSuiAddress());assert.equal(String(object.json?.size),String(bytes.length));
        assert.equal(object.json?.deletable,true);
        assert.equal(blobIdFromInt(BigInt(String(object.json?.blob_id))),String(last.blobId));
        assert.ok(objectEpoch(object)>=plan.targetEndEpoch&&objectEpoch(object)>row.source_end_epoch);
        assert.deepEqual(await attrs(objectId),metadata,'Registration metadata must already match before certification');
        const fence=parseSealPersistenceFence({sealAbi:'v1-new',accountId:row.account_id,registryId:config.registryId,
          policyPackageId:config.policyPackageId,data:Buffer.from(bytes).toString('base64')},config.immutablePackageId,
          {allowLegacySealAbi:false,policyPackageId:config.policyPackageId});
        appendSealPersistenceFence(transaction,fence);transaction.transferObjects([transaction.object(objectId)],row.owner);
      }
      const result = await submit(id,op==='certify'?certifyPhase:`${phase}.register`,transaction);
      return {$kind:'Transaction', Transaction: result.transaction};
    }};
  let tick = now();
  for await (const step of flow.run({signer: flowSigner as any,
    epochs: phase === 'seed' ? config.sourceEpochs : plan.requestedEpochs,
    owner: writer.toSuiAddress(), deletable: true, attributes: metadata})) {
    (phaseTimes[`${phase}.flow.${step.step}`] ??= []).push(now() - tick); tick = now();
    await journal(id, `${phase}.flow`, step.step, step);
    last = step;
  }
  assert.ok(last?.blobObjectId && last?.blobId);
  return {objectId: String(last.blobObjectId), blobId: String(last.blobId)};
}
async function hasFinalized(id: number, phase: string): Promise<boolean> {
  return (await sql`SELECT 1 FROM exercise_renewal_journal WHERE run_id=${config.runId}
    AND memory_id=${id} AND phase=${phase} AND state='finalized' LIMIT 1`).length > 0;
}
async function transferOne(id: number, phase: string, row: any, blobObjectId: string, bytes: Uint8Array,
  metadata: Record<string,string>) {
  const object = await currentObject(blobObjectId);
  if (addressOwner(object) === row.owner) return;
  assert.equal(addressOwner(object), writer.toSuiAddress());
  const fence = parseSealPersistenceFence({sealAbi: 'v1-new', accountId: row.account_id,
    registryId: config.registryId, policyPackageId: config.policyPackageId, data: Buffer.from(bytes).toString('base64')},
    config.immutablePackageId, {allowLegacySealAbi: false, policyPackageId: config.policyPackageId});
  const tx = new Transaction(); appendSealPersistenceFence(tx, fence);
  const blob = tx.object(blobObjectId);
  for (const [key, value] of Object.entries(metadata)) tx.moveCall({
    target: `${config.walrusPackageId}::blob::insert_or_update_metadata_pair`,
    arguments: [blob, tx.pure.string(key), tx.pure.string(value)]});
  tx.transferObjects([blob], row.owner);
  await submit(id, phase, tx);
}
async function seedOne(id: number) {
  await prepareOne(id);
  const [row] = await sql`SELECT * FROM exercise_renewal_memories WHERE run_id=${config.runId} AND memory_id=${id}`;
  if (row.stage === 'seeded' || row.stage === 'migrated') return;
  const bytes = new Uint8Array(await readFile(cipherPath(id))); assert.equal(sha(bytes), row.ciphertext_sha256);
  const metadata = {memwal_namespace: row.namespace, memwal_owner: row.owner,
    memwal_package_id: config.immutablePackageId,
    memwal_agent_id: Buffer.from(ownerKeys[row.owner_index].getPublicKey().toRawBytes()).toString('hex'),
    memwal_job_id: `${config.runId}-source-${id}`, exercise_run: config.runId, exercise_memory: String(id)};
  const blob = await uploadOne(id, 'seed', bytes, metadata);
  await transferOne(id, 'seed.metadata_transfer', row, blob.objectId, bytes, metadata);
  const object = await currentObject(blob.objectId); assert.equal(addressOwner(object), row.owner);
  assert.deepEqual(await attrs(blob.objectId), metadata);
  const schedule = await epochSchedule();
  const epoch = assertCompletionBlobObject(object,{objectId:blob.objectId,owner:row.owner,size:bytes.length,blobId:blob.blobId},schedule.epoch);
  const expires = expiryAt(epoch,schedule);
  await sql.begin(async (tx:any) => {
    {
      const embedding = Array.from({length: 1536}, (_,n) => n === id % 1536 ? 1 : 0);
      await tx`INSERT INTO vector_entries(id,owner,namespace,blob_id,embedding,blob_size_bytes,importance,
        agent_id,package_id,end_epoch,expires_at,created_at,updated_at,metadata_synced_at,expiry_synced_at)
        VALUES(${`${config.runId}:${id}`},${row.owner},${row.namespace},${blob.blobId},${JSON.stringify(embedding)},
          ${bytes.length},0.5,${metadata.memwal_agent_id},${config.immutablePackageId},${epoch},${expires},
          ${new Date(Date.UTC(2026,0,1,0,0,id))},now(),now(),now()) ON CONFLICT(id) DO NOTHING`;
      const [inserted] = await tx`SELECT owner,namespace,blob_id,embedding::text,blob_size_bytes,importance,
        agent_id,package_id,end_epoch,created_at FROM vector_entries WHERE id=${`${config.runId}:${id}`}`;
      assert.equal(inserted.owner,row.owner); assert.equal(inserted.namespace,row.namespace);
      assert.equal(inserted.blob_id,blob.blobId); assert.deepEqual(JSON.parse(inserted.embedding),embedding);
      assert.equal(Number(inserted.blob_size_bytes),bytes.length); assert.equal(Number(inserted.importance),0.5);
      assert.equal(inserted.agent_id,metadata.memwal_agent_id); assert.equal(inserted.package_id,config.immutablePackageId);
      assert.equal(inserted.end_epoch,epoch); assert.equal(new Date(inserted.created_at).getTime(),Date.UTC(2026,0,1,0,0,id));
    }
    await tx`UPDATE exercise_renewal_memories SET source_blob_id=${blob.blobId},source_object_id=${blob.objectId},
      source_end_epoch=${epoch},current_object_id=${blob.objectId},current_end_epoch=${epoch},source_metadata=${tx.json(metadata)},
      stage='seeded',last_error=NULL WHERE run_id=${config.runId} AND memory_id=${id}`;
  });
  metric('seeded', {id, blobId: blob.blobId, objectId: blob.objectId, endEpoch: epoch, bytes: bytes.length});
}
async function migrateOne(id: number) {
  const [row] = await sql`SELECT * FROM exercise_renewal_memories WHERE run_id=${config.runId} AND memory_id=${id}`;
  assert.ok(row && ['seeded','migrated'].includes(row.stage), `Source ${id} must be seeded`);
  if (row.stage === 'migrated') return;
  const vectorEntryId=vectorId(row);
  const baselineRows = await sql`SELECT id,owner,namespace,embedding::text,importance,agent_id,package_id,created_at
    FROM vector_entries WHERE id=${vectorEntryId} ORDER BY id`;
  assert.equal(baselineRows.length, 1);
  if(row.parent_run_id){
    const [head]=await sql`SELECT p.current_object_id,p.current_end_epoch,v.end_epoch AS vector_end_epoch
      FROM exercise_renewal_memories p JOIN vector_entries v ON v.id=${vectorEntryId}
      WHERE p.run_id=${row.parent_run_id} AND p.memory_id=${row.parent_memory_id}`;
    assert.ok(head);assert.equal(head.current_object_id,row.source_object_id,'Canonical head changed; do not mint from stale imported input');
    assert.equal(head.current_end_epoch,row.source_end_epoch);assert.equal(head.vector_end_epoch,row.source_end_epoch);
  }
  let sourceObject:any,metadata:Record<string,string>,bytes:Uint8Array;
  if(fusedRenewal)[sourceObject,metadata,bytes]=await Promise.all([
    timed('download_metadata',()=>currentObject(row.source_object_id)),
    timed('download_metadata_attributes',()=>attrs(row.source_object_id)),
    timed('download_ciphertext',()=>readCiphertext(row.source_blob_id,'source_download'))]);
  else{
    sourceObject=await timed('download_metadata',()=>currentObject(row.source_object_id));
    metadata=await timed('download_metadata_attributes',()=>attrs(row.source_object_id));
    bytes=await timed('download_ciphertext',()=>readCiphertext(row.source_blob_id,'source_download'));
  }
  assert.equal(addressOwner(sourceObject), row.owner);
  assert.equal(objectEpoch(sourceObject),row.source_end_epoch,'Fresh input lease must match the imported current head');
  assert.equal(blobIdFromInt(BigInt(String(sourceObject.json?.blob_id))),row.source_blob_id);
  assert.equal(String(sourceObject.json?.size),String(row.ciphertext_bytes));
  assert.equal(sourceObject.json?.deletable,true);assert.ok(sourceObject.json?.certified_epoch!==null&&sourceObject.json?.certified_epoch!==undefined);
  assert.deepEqual(metadata, row.source_metadata);
  assert.equal(sha(bytes), row.ciphertext_sha256);
  await writeFile(downloadPath(id), bytes);
  await writeFile(path.join(config.scratch,'downloads',`${id}.metadata.json`), json({object: sourceObject, metadata}));
  const plan=await leasePlan(id,row);
  const blob = await uploadOne(id, 'renew', bytes, metadata,row,plan);
  assert.equal(blob.blobId, row.source_blob_id, 'Byte-identical content should retain blob ID');
  assert.notEqual(blob.objectId, row.source_object_id, 'Renewal must create a new Blob object');
  if(!fusedRenewal)await transferOne(id, 'renew.metadata_transfer', row, blob.objectId, bytes, metadata);
  let object:any,newMetadata:Record<string,string>,schedule:Awaited<ReturnType<typeof epochSchedule>>,readback:Uint8Array;
  if(fusedRenewal)[object,newMetadata,schedule,readback]=await Promise.all([
    timed('verify_new_object',()=>currentObject(blob.objectId)),timed('verify_new_metadata',()=>attrs(blob.objectId)),
    timed('verify_epoch_schedule',()=>epochSchedule()),timed('verify_ciphertext_readback',()=>readCiphertext(blob.blobId,'renew_readback'))]);
  else{
    object=await timed('verify_new_object',()=>currentObject(blob.objectId));
    newMetadata=await timed('verify_new_metadata',()=>attrs(blob.objectId));
    schedule=await epochSchedule();
    readback=await timed('verify_ciphertext_readback',()=>readCiphertext(blob.blobId,'renew_readback'));
  }
  assert.equal(addressOwner(object), row.owner);
  assert.deepEqual(newMetadata, metadata);
  const epoch = assertCompletionBlobObject(object,{objectId:blob.objectId,owner:row.owner,size:bytes.length,blobId:blob.blobId},schedule.epoch);
  assert.ok(epoch > row.source_end_epoch, 'New lease must end later');
  assert.ok(epoch>=plan.targetEndEpoch,'Certified lease must meet its immutable target');
  const expires = expiryAt(epoch,schedule);
  assert.equal(sha(readback), row.ciphertext_sha256);
  await timed('db_commit', () => sql.begin(async (tx:any) => {
    const changed = await tx`UPDATE exercise_renewal_memories SET current_object_id=${blob.objectId},current_end_epoch=${epoch},
      stage='migrated',migrated_at=now(),last_error=NULL WHERE run_id=${config.runId} AND memory_id=${id}
      AND stage='seeded' AND source_object_id=${row.source_object_id} RETURNING memory_id`;
    assert.equal(changed.length, 1, 'CAS must update exactly one source mapping');
    if(row.parent_run_id){
      const parent=await tx`UPDATE exercise_renewal_memories SET current_object_id=${blob.objectId},current_end_epoch=${epoch}
        WHERE run_id=${row.parent_run_id} AND memory_id=${row.parent_memory_id}
        AND current_object_id=${row.source_object_id} AND current_end_epoch=${row.source_end_epoch}
        AND source_blob_id=${row.source_blob_id} AND owner=${row.owner} AND namespace=${row.namespace}
        RETURNING memory_id`;
      assert.equal(parent.length,1,'Canonical parent head CAS must match the exact imported input');
    }
    const facts = await tx`UPDATE vector_entries SET blob_id=${blob.blobId},end_epoch=${epoch},expires_at=${expires},updated_at=now(),
      expiry_synced_at=now(),metadata_synced_at=now() WHERE id=${vectorEntryId}
      AND owner=${row.owner} AND namespace=${row.namespace} AND blob_id=${row.source_blob_id}
      AND end_epoch=${row.source_end_epoch} RETURNING id`;
    assert.equal(facts.length, 1, 'Exactly one source memory must update');
    const after = await tx`SELECT id,owner,namespace,embedding::text,importance,agent_id,package_id,created_at
      FROM vector_entries WHERE id=${vectorEntryId} ORDER BY id`;
    assert.deepEqual(after, baselineRows);
    await tx`INSERT INTO exercise_renewal_journal(run_id,memory_id,phase,state,payload)
      VALUES(${config.runId},${id},'db_commit','finalized',${tx.json({oldObjectId:row.source_object_id,newObjectId:blob.objectId,
        oldBlobId:row.source_blob_id,newBlobId:blob.blobId,oldEpoch:row.source_end_epoch,newEpoch:epoch,hash:sha(bytes),memoryRows:1,
        expirySchedule:schedule,expiresAt:expires,leasePlan:plan,vectorEntryId,parentRunId:row.parent_run_id,parentMemoryId:row.parent_memory_id})})`;
  }));
  metric('migrated', {id,blobId: blob.blobId,oldObjectId: row.source_object_id,newObjectId:blob.objectId,
    oldEndEpoch:row.source_end_epoch,newEndEpoch:epoch,bytes:bytes.length,owner:row.owner});
}
async function decryptSample(id: number) {
  const [row] = await sql`SELECT * FROM exercise_renewal_memories WHERE run_id=${config.runId} AND memory_id=${id}`;
  assert.ok(row && row.stage === 'migrated');
  const key = ownerKeys[row.owner_index];
  const session = await SessionKey.create({address: row.owner, packageId: config.immutablePackageId,
    ttlMin: 10, signer: key, suiClient: sui as any});
  const bytes = await readCiphertext(row.source_blob_id,'owner_decrypt');
  const parsed = EncryptedObject.parse(bytes);
  const tx = buildSealApproveTx(config.policyPackageId, config.registryId, row.account_id, [parsed.id]);
  const txBytes = await tx.build({client: sui, onlyTransactionKind: true});
  const plaintext = await seal.decrypt({data: bytes, sessionKey: session, txBytes});
  assert.equal(sha(plaintext), row.plaintext_sha256);
  metric('owner_decrypt_verified', {id, owner: row.owner, plaintextHash: sha(plaintext)});
}
async function parallel(fn: (id: number) => Promise<void>) {
  const ids = command === 'migrate'
    ? (await sql`SELECT m.memory_id FROM exercise_renewal_memories m JOIN vector_entries v ON v.id=COALESCE(m.vector_entry_id,m.run_id||':'||m.memory_id)
        WHERE m.run_id=${config.runId} AND m.memory_id>=${offset} AND m.memory_id<${offset+limit}
        AND m.stage IN ('seeded','migrated') ORDER BY m.memory_id`).map(r=>Number(r.memory_id))
    : Array.from({length:limit},(_,n)=>offset+n);
  assert.equal(ids.length,limit,'Requested migration cohort must be discovered completely in local DB');
  let cursor = 0;
  let stopped = false;
  const outcomes = await Promise.allSettled(Array.from({length: concurrency}, async () => {
    while (!stopped && cursor < ids.length) {
      const id = ids[cursor++];
      try { await fn(id); }
      catch (error) {
        stopped = true;
        await sql`UPDATE exercise_renewal_memories SET last_error=${cleanError(error)} WHERE run_id=${config.runId} AND memory_id=${id}`;
        metric('failed', {id, command, error: cleanError(error)}); throw error;
      }
    }
  }));
  const failed = outcomes.find((r):r is PromiseRejectedResult => r.status==='rejected');
  if (failed) throw failed.reason;
}
function distribution(values:number[]){
  if(!values.length)return {count:0,mean:0,p50:0,p95:0,max:0};
  const sorted=[...values].sort((a,b)=>a-b);
  return {count:values.length,mean:values.reduce((a,b)=>a+b,0)/values.length,
    p50:sorted[Math.floor((sorted.length-1)*.5)],p95:sorted[Math.floor((sorted.length-1)*.95)],max:sorted[sorted.length-1]};
}
const eventLoop=monitorEventLoopDelay({resolution:20});
try {
  const activeEnv = (await exec('sui', ['client', 'active-env'])).stdout.trim();
  assert.equal(activeEnv, 'testnet');
  const chain=await sui.core.getChainIdentifier();
  const shortChainId=Buffer.from(fromBase58(chain.chainIdentifier)).subarray(0,4).toString('hex');
  assert.equal(shortChainId,'4c78adac','Every command must use the verified Sui testnet chain');
  assert.equal(writer.toSuiAddress(),expectedFundingAddress,'Runtime signer must match the explicitly configured operator');
  metric('testnet_guard',{command,activeEnv,shortChainId,chainIdentifier:chain.chainIdentifier});
  await auditSchema();
  const balanceBefore = await balances();
  metric('wallet_balance_before',{command,balances:balanceBefore});
  const started = now();
  const cpuStarted=process.cpuUsage();eventLoop.enable();
  if (command === 'preflight') {
    const version = await sql`SELECT version()`;
    const state = await epochSchedule();
    metric('preflight', {databaseVersion: version[0].version, writer: writer.toSuiAddress(),
      owners: owners.map(({privateKey,...safe}) => safe), walrusEpoch: state.epoch, epochDurationMs:state.durationMs,
      chainIdentifier:chain.chainIdentifier,shortChainId,count: config.count,
      noEnoki: true, noLLM: true, sourceEpochs: config.sourceEpochs, renewalEpochs: config.renewalEpochs});
  } else if (command === 'setup') await setup();
  else if(command==='prepare-existing')await prepareExisting();
  else if (command === 'reconcile') await reconcilePending();
  else if (command === 'create-accounts') {await reconcilePending();await createAccounts();}
  else if (command === 'seed') await parallel(seedOne);
  else if (command === 'migrate') await parallel(migrateOne);
  else if (command === 'verify') { for (let i=offset;i<offset+limit;i++) await decryptSample(i); }
  else throw new Error(`Unknown command ${command}`);
  const counts = await sql`SELECT stage,count(*)::int AS count FROM exercise_renewal_memories WHERE run_id=${config.runId} GROUP BY stage`;
  const balanceAfter = await balances();
  metric('wallet_balance_after',{command,balances:balanceAfter});
  eventLoop.disable();const wallMs=now()-started,cpu=process.cpuUsage(cpuStarted);
  const performanceMetrics={cpuUserMs:cpu.user/1000,cpuSystemMs:cpu.system/1000,
    cpuPercentOfOneCore:(cpu.user+cpu.system)/(wallMs*1000)*100,
    eventLoopDelayMs:{p50:eventLoop.percentile(50)/1e6,p95:eventLoop.percentile(95)/1e6,max:eventLoop.max/1e6,
      mean:Number.isFinite(eventLoop.mean)?eventLoop.mean/1e6:0},
    processLifetimeMaxRssKiB:process.resourceUsage().maxRSS,rssBytesAtEnd:process.memoryUsage().rss,
    chain:{limit:chainConcurrency,activePeak:chainActivePeak,busyMs:chainBusyMs,
      capacityUtilizationPercent:chainBusyMs/(wallMs*chainConcurrency)*100,queueWaitMs:distribution(chainQueueWaitMs)}};
  const metadataCache={enabled:fusedRenewal,initialized:!!metadataComputer,threads:fusedRenewal?(config.metadataThreads??4):0,
    ...(metadataComputer?{fingerprint:metadataComputer.fingerprint,implementation:metadataComputer.implementation,...metadataComputer.stats}:{})};
  metric('complete', {command, limit, offset, concurrency, chainConcurrency, wallMs, phaseTimes, transport, counts,
    performance:performanceMetrics,metadataCache,transportTiming:Object.fromEntries(Object.entries(transportTiming).map(([key,times])=>[key,distribution(times)]))});
} catch(error){metric('fatal',{command,error:cleanError(error)});process.exitCode=1;}
finally {
  eventLoop.disable();
  try{if(metadataComputerPromise)await(await metadataComputerPromise).close();}
  catch(error){metric('metadata_pool_close_failed',{error:cleanError(error)});process.exitCode=1;}
  finally{await sql.end();}
}
