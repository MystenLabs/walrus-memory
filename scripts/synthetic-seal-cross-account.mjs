#!/usr/bin/env node
/**
 * Production-safe negative synthetic for COMG-715.
 *
 * Asserts that an identity from MemWal account A cannot authorize account B's
 * SEAL key (and the reverse). Read-only: a gRPC `simulateTransaction` (with
 * checks disabled, the gRPC equivalent of the retired JSON-RPC devInspect) of
 * `account::seal_approve` only. Does not remember, decrypt, fetch SEAL keys,
 * or execute a transaction.
 *
 * Exit 0  — required secrets unset (skip) or deny as expected.
 * Exit 1  — SYNTHETIC_SEAL_CROSS_ACCOUNT_FAIL (page: A authorized B).
 * Exit 2  — misconfiguration or Sui gRPC failure (check is not valid).
 *
 *   node scripts/synthetic-seal-cross-account.mjs
 *   node scripts/synthetic-seal-cross-account.mjs --help
 */

import path from "node:path";
import { fileURLToPath } from "node:url";

const E_NO_ACCESS = 100;
const FAIL_TOKEN = "SYNTHETIC_SEAL_CROSS_ACCOUNT_FAIL";
const OBJECT_ID_RE = /^0x[0-9a-fA-F]{64}$/;
const HEX_32_RE = /^(0x)?[0-9a-fA-F]{64}$/;

const REQUIRED_SECRETS = [
    ["SEAL_CROSS_ACCOUNT_A_ID", ["SEAL_CROSS_ACCOUNT_A_ID", "MEMWAL_ACCOUNT_A_ID"]],
    ["SEAL_CROSS_ACCOUNT_B_ID", ["SEAL_CROSS_ACCOUNT_B_ID", "MEMWAL_ACCOUNT_B_ID"]],
    ["SEAL_CROSS_ACCOUNT_A_KEY", ["SEAL_CROSS_ACCOUNT_A_KEY", "MEMWAL_DELEGATE_KEY_A"]],
    ["SEAL_CROSS_ACCOUNT_B_KEY", ["SEAL_CROSS_ACCOUNT_B_KEY", "MEMWAL_DELEGATE_KEY_B"]],
];

function env(name) {
    const v = process.env[name];
    return typeof v === "string" && v.trim() ? v.trim() : "";
}

function firstEnv(names) {
    for (const name of names) {
        const v = env(name);
        if (v) return v;
    }
    return "";
}

function usage() {
    process.stdout.write(`Production-safe SEAL cross-account synthetic (COMG-715).

Read-only dry-run of account::seal_approve. Never writes memories or mutates chain.

Skip (exit 0) when the two account ids and two delegate keys are unset.

Required to run:
  SEAL_CROSS_ACCOUNT_A_ID / SEAL_CROSS_ACCOUNT_B_ID
  SEAL_CROSS_ACCOUNT_A_KEY / SEAL_CROSS_ACCOUNT_B_KEY
  SUI_GRPC_URL and MEMWAL_PACKAGE_ID
    (or MEMWAL_SERVER_URL / MEMWAL_RELAYER_URL — GET /config fills both)
    SUI_RPC_URL is still read as a fallback for SUI_GRPC_URL, but it must be a
    fullnode that serves gRPC (for example https://fullnode.mainnet.sui.io:443).
    JSON-RPC-only endpoints no longer work.

Also used when set:
  MEMWAL_REGISTRY_ID          AccountRegistry object id
  MEMWAL_SEAL_POLICY_PACKAGE_ID   seal_approve package (defaults to MEMWAL_PACKAGE_ID)
  SUI_NETWORK                 mainnet|testnet (inferred from the gRPC URL when omitted)

Expected: ENoAccess / deny. If A can authorize B: exit 1 ${FAIL_TOKEN}.
`);
}

function normalizeHexAddress(value) {
    const hex = String(value).replace(/^0x/i, "").toLowerCase();
    if (!/^[0-9a-f]{1,64}$/.test(hex)) {
        throw new Error(`not a Sui address: ${value}`);
    }
    return `0x${hex.padStart(64, "0")}`;
}

function u64ToLeBytes(value) {
    const n = BigInt(value);
    if (n < 0n || n > 0xffff_ffff_ffff_ffffn) {
        throw new Error(`u64 out of range: ${value}`);
    }
    const out = new Uint8Array(8);
    for (let i = 0; i < 8; i++) out[i] = Number((n >> (8n * BigInt(i))) & 0xffn);
    return out;
}

function sealKeyIdBytes(ownerHex, counter) {
    const owner = Uint8Array.from(
        normalizeHexAddress(ownerHex)
            .slice(2)
            .match(/.{2}/g)
            .map((b) => parseInt(b, 16)),
    );
    const id = new Uint8Array(40);
    id.set(owner, 0);
    id.set(u64ToLeBytes(counter), 32);
    return id;
}

function shortId(id) {
    const n = normalizeHexAddress(id);
    return `${n.slice(0, 10)}…${n.slice(-6)}`;
}

function secretPresence() {
    return REQUIRED_SECRETS.map(([label, names]) => ({
        label,
        value: firstEnv(names),
    }));
}

function shouldSkip(presence) {
    return presence.every((p) => !p.value);
}

function missingSecrets(presence) {
    return presence.filter((p) => !p.value).map((p) => p.label);
}

async function getRelayerConfig(serverUrl) {
    const url = `${serverUrl.replace(/\/$/, "")}/config`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15_000);
    try {
        const res = await fetch(url, { signal: controller.signal });
        if (!res.ok) throw new Error(`GET ${url} → ${res.status}`);
        return await res.json();
    } finally {
        clearTimeout(timer);
    }
}

function inferNetwork(url, explicit) {
    if (explicit === "mainnet" || explicit === "testnet") return explicit;
    const u = (url || "").toLowerCase();
    if (u.includes("testnet")) return "testnet";
    if (u.includes("devnet")) return "devnet";
    if (u.includes("mainnet")) return "mainnet";
    return "mainnet";
}

function keypairFromDelegateKey(Ed25519Keypair, decodeSuiPrivateKey, raw) {
    try {
        if (raw.toLowerCase().startsWith("suiprivkey")) {
            const { scheme, secretKey } = decodeSuiPrivateKey(raw);
            if (scheme !== "ED25519") {
                throw new Error(`delegate key must be Ed25519, got ${scheme}`);
            }
            return Ed25519Keypair.fromSecretKey(secretKey);
        }
        if (!HEX_32_RE.test(raw)) {
            throw new Error("not hex");
        }
        const hex = raw.startsWith("0x") || raw.startsWith("0X") ? raw.slice(2) : raw;
        return Ed25519Keypair.fromSecretKey(Uint8Array.from(Buffer.from(hex, "hex")));
    } catch {
        throw new Error("invalid delegate key (need 32-byte hex seed or suiprivkey1…)");
    }
}

function parseAccountObject(objectId, result, packageId) {
    // gRPC core getObject returns { object: { type, json } }.
    const data = result?.object ?? result?.data ?? result;
    const content = data?.content ?? {};
    const fields = data?.json ?? content?.fields ?? data?.fields;
    const objectType =
        data?.type ?? content?.type ?? result?.data?.type ?? result?.data?.content?.type;
    if (!fields || typeof objectType !== "string") {
        throw new Error(`account ${shortId(objectId)}: missing Move content`);
    }
    const typeParts = objectType.split("::");
    if (typeParts[1] !== "account" || typeParts[2] !== "MemWalAccount") {
        throw new Error(`account ${shortId(objectId)} is ${objectType}, expected MemWalAccount`);
    }
    const typePkg = normalizeHexAddress(typeParts[0]);
    const configuredPkg = normalizeHexAddress(packageId);
    // Types keep the first-published package id across upgrades; PACKAGE_ID is
    // the current policy package. Equality holds only until the first upgrade.
    if (typePkg !== configuredPkg) {
        console.log(
            `note: ${shortId(objectId)} type package ${shortId(typePkg)} ≠ MEMWAL_PACKAGE_ID ${shortId(configuredPkg)} (expected after an upgrade)`,
        );
    }
    if (fields.active !== true) {
        throw new Error(`account ${shortId(objectId)} is not active`);
    }
    if (typeof fields.owner !== "string") {
        throw new Error(`account ${shortId(objectId)} has no owner`);
    }
    const rawCounter = fields.access_counter_version;
    if (rawCounter === undefined || rawCounter === null) {
        throw new Error(`account ${shortId(objectId)} has no access_counter_version`);
    }
    const delegates = [];
    const rawKeys = fields.delegate_keys ?? [];
    for (const entry of rawKeys) {
        const d = entry?.fields ?? entry;
        if (typeof d?.sui_address === "string") {
            delegates.push(normalizeHexAddress(d.sui_address));
        }
    }
    return {
        id: normalizeHexAddress(objectId),
        owner: normalizeHexAddress(fields.owner),
        counter: BigInt(rawCounter),
        delegates,
        typePackageId: typePkg,
        objectType,
    };
}

function roleOnAccount(address, account) {
    const addr = normalizeHexAddress(address);
    if (addr === account.owner) return "owner";
    if (account.delegates.includes(addr)) return "delegate";
    return null;
}

function grpcAbortCode(failed) {
    const error = failed?.status?.error;
    const text = typeof error?.message === "string" ? error.message : JSON.stringify(error ?? failed);
    if (error?.$kind === "MoveAbort" && error.MoveAbort?.abortCode !== undefined) {
        return { outcome: "abort", code: Number(error.MoveAbort.abortCode), detail: text };
    }
    return { outcome: "failure", detail: text };
}

export function extractAbortCode(inspect) {
    // gRPC core simulateTransaction result: { $kind, Transaction | FailedTransaction }.
    if (inspect?.$kind === "Transaction" && inspect.Transaction) {
        return inspect.Transaction.status?.success === false
            ? grpcAbortCode(inspect.Transaction)
            : { outcome: "success", detail: "success" };
    }
    if (inspect?.$kind === "FailedTransaction" && inspect.FailedTransaction) {
        return grpcAbortCode(inspect.FailedTransaction);
    }

    // Legacy JSON-RPC devInspect shapes, kept so recorded outputs still parse.
    const effects = inspect?.effects ?? inspect?.transactionEffects ?? inspect;
    const status = effects?.status ?? inspect?.status;
    if (!status) return { outcome: "unknown", detail: JSON.stringify(inspect).slice(0, 500) };

    const kind = status.status ?? status;
    if (kind === "success" || status.success === true) {
        return { outcome: "success", detail: "success" };
    }

    const error = status.error ?? inspect?.error ?? effects?.error;
    const text = typeof error === "string" ? error : JSON.stringify(error ?? status);

    // JSON-RPC Display: MoveAbort(<location>, <code>) in command N.
    // Location is MoveLocation { module: ModuleId { ... }, function, ... } and
    // contains commas, so the abort code is the decimal after that location.
    const moveAbort = text.match(/MoveAbort\([\s\S]*,\s*(\d+)\)/);
    if (moveAbort) {
        return { outcome: "abort", code: Number(moveAbort[1]), detail: text };
    }
    if (error && typeof error === "object") {
        const abort = error.MoveAbort ?? error.moveAbort;
        if (Array.isArray(abort) && abort.length >= 2) {
            return { outcome: "abort", code: Number(abort[1]), detail: text };
        }
        if (abort && typeof abort === "object" && abort.abortCode !== undefined) {
            return { outcome: "abort", code: Number(abort.abortCode), detail: text };
        }
    }
    const abortCode = text.match(/abort code:\s*(\d+)/i) ?? text.match(/"abortCode"\s*:\s*"?(\d+)/);
    if (abortCode) {
        return { outcome: "abort", code: Number(abortCode[1]), detail: text };
    }
    return { outcome: "failure", detail: text };
}

function pureU8Vector(tx, bytes) {
    const arr = Array.from(bytes);
    if (tx.pure && typeof tx.pure.vector === "function") {
        return tx.pure.vector("u8", arr);
    }
    return tx.pure("vector<u8>", arr);
}

async function discoverRegistry(network, typePackageId) {
    const endpoints = {
        mainnet: "https://graphql.mainnet.sui.io/graphql",
        testnet: "https://graphql.testnet.sui.io/graphql",
    };
    const url = endpoints[network];
    if (!url) return "";
    const type = `${typePackageId}::account::AccountRegistry`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15_000);
    try {
        const res = await fetch(url, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                query: "query ($type: String!) { objects(first: 5, filter: { type: $type }) { nodes { address } } }",
                variables: { type },
            }),
            signal: controller.signal,
        });
        if (!res.ok) return "";
        const json = await res.json();
        const nodes = json?.data?.objects?.nodes;
        if (!Array.isArray(nodes) || nodes.length === 0) return "";
        if (nodes.length > 1) {
            throw new Error(
                `GraphQL found ${nodes.length} AccountRegistry objects; set MEMWAL_REGISTRY_ID`,
            );
        }
        return typeof nodes[0]?.address === "string" ? nodes[0].address : "";
    } catch (err) {
        if (err instanceof Error && err.message.includes("AccountRegistry")) throw err;
        return "";
    } finally {
        clearTimeout(timer);
    }
}

async function inspectSealApprove({
    client,
    Transaction,
    sender,
    policyPackageId,
    registryId,
    accountId,
    idBytes,
}) {
    const tx = new Transaction();
    tx.setSender(sender);
    tx.moveCall({
        target: `${policyPackageId}::account::seal_approve`,
        arguments: [
            pureU8Vector(tx, idBytes),
            tx.object(registryId),
            tx.object(accountId),
        ],
    });

    // checksEnabled: false mirrors devInspect: no gas payment or signature is
    // needed, and the node simulates with a mocked gas coin. Nothing executes.
    return client.core.simulateTransaction({ transaction: tx, checksEnabled: false });
}

function failSecurity(message) {
    const line = `${FAIL_TOKEN}: ${message}`;
    console.error(`::error::${line}`);
    console.error(line);
    console.error("Page on-call. Identity from one MemWal account authorized another account's SEAL key.");
    process.exit(1);
}

function failMisconfig(message) {
    console.error(`synthetic-seal-cross-account: misconfig: ${message}`);
    process.exit(2);
}

async function run() {
    const presence = secretPresence();
    if (shouldSkip(presence)) {
        console.log(
            "synthetic-seal-cross-account: skip (required env vars unset; safe in CI without secrets)",
        );
        return;
    }
    const missing = missingSecrets(presence);
    if (missing.length) {
        failMisconfig(`partial secrets; missing ${missing.join(", ")}`);
    }

    const accountAId = firstEnv(["SEAL_CROSS_ACCOUNT_A_ID", "MEMWAL_ACCOUNT_A_ID"]);
    const accountBId = firstEnv(["SEAL_CROSS_ACCOUNT_B_ID", "MEMWAL_ACCOUNT_B_ID"]);
    const keyA = firstEnv(["SEAL_CROSS_ACCOUNT_A_KEY", "MEMWAL_DELEGATE_KEY_A"]);
    const keyB = firstEnv(["SEAL_CROSS_ACCOUNT_B_KEY", "MEMWAL_DELEGATE_KEY_B"]);

    if (!OBJECT_ID_RE.test(accountAId) || !OBJECT_ID_RE.test(accountBId)) {
        failMisconfig("account ids must be 0x-prefixed 32-byte object ids");
    }
    if (normalizeHexAddress(accountAId) === normalizeHexAddress(accountBId)) {
        failMisconfig("account A and account B must be different objects");
    }

    let packageId = firstEnv(["MEMWAL_PACKAGE_ID", "PACKAGE_ID"]);
    // SUI_RPC_URL is a backward-compatible fallback; it must point at a
    // fullnode that serves gRPC.
    let grpcUrl = firstEnv(["SUI_GRPC_URL", "SUI_RPC_URL"]);
    let network = env("SUI_NETWORK");
    const serverUrl = firstEnv(["MEMWAL_SERVER_URL", "MEMWAL_RELAYER_URL"]);

    if ((!packageId || !grpcUrl) && serverUrl) {
        const cfg = await getRelayerConfig(serverUrl);
        packageId = packageId || cfg.packageId || "";
        grpcUrl = grpcUrl || cfg.suiGrpcUrl || cfg.suiRpcUrl || "";
        network = network || cfg.network || "";
        console.log(`loaded GET ${serverUrl.replace(/\/$/, "")}/config`);
    }
    if (!packageId) failMisconfig("MEMWAL_PACKAGE_ID unset (or GET /config)");
    if (!grpcUrl) failMisconfig("SUI_GRPC_URL unset (or SUI_RPC_URL, or GET /config)");
    network = inferNetwork(grpcUrl, network);

    let suiMod;
    try {
        const [grpc, txMod, keysMod, cryptoMod] = await Promise.all([
            import("@mysten/sui/grpc"),
            import("@mysten/sui/transactions"),
            import("@mysten/sui/keypairs/ed25519"),
            import("@mysten/sui/cryptography"),
        ]);
        suiMod = { grpc, txMod, keysMod, cryptoMod };
    } catch (err) {
        failMisconfig(
            `cannot import @mysten/sui (${err instanceof Error ? err.message : err}). From repo root: pnpm install --frozen-lockfile`,
        );
    }

    const { SuiGrpcClient } = suiMod.grpc;
    const { Transaction } = suiMod.txMod;
    const { Ed25519Keypair } = suiMod.keysMod;
    const { decodeSuiPrivateKey } = suiMod.cryptoMod;
    if (typeof SuiGrpcClient !== "function" || typeof Transaction !== "function") {
        failMisconfig("@mysten/sui gRPC client or Transaction missing");
    }

    const client = new SuiGrpcClient({ network, baseUrl: grpcUrl });
    const keypairA = keypairFromDelegateKey(Ed25519Keypair, decodeSuiPrivateKey, keyA);
    const keypairB = keypairFromDelegateKey(Ed25519Keypair, decodeSuiPrivateKey, keyB);
    const addrA = normalizeHexAddress(keypairA.getPublicKey().toSuiAddress());
    const addrB = normalizeHexAddress(keypairB.getPublicKey().toSuiAddress());
    if (addrA === addrB) {
        failMisconfig("delegate keys A and B derive the same Sui address");
    }

    const readAccount = async (id) => {
        const result = await client.core.getObject({ objectId: id, include: { json: true } });
        return parseAccountObject(id, result, packageId);
    };

    const accountA = await readAccount(accountAId);
    const accountB = await readAccount(accountBId);
    if (accountA.owner === accountB.owner) {
        failMisconfig("account A and B share an owner; pick two isolated accounts");
    }

    const roleAonA = roleOnAccount(addrA, accountA);
    const roleBonB = roleOnAccount(addrB, accountB);
    const roleAonB = roleOnAccount(addrA, accountB);
    const roleBonA = roleOnAccount(addrB, accountA);
    if (!roleAonA) {
        failMisconfig(`key A (${shortId(addrA)}) is not owner/delegate of account A`);
    }
    if (!roleBonB) {
        failMisconfig(`key B (${shortId(addrB)}) is not owner/delegate of account B`);
    }
    if (roleAonB) {
        failMisconfig(`key A is also ${roleAonB} on account B; accounts are not isolated`);
    }
    if (roleBonA) {
        failMisconfig(`key B is also ${roleBonA} on account A; accounts are not isolated`);
    }

    const policyPackageId =
        firstEnv(["MEMWAL_SEAL_POLICY_PACKAGE_ID", "SEAL_POLICY_PACKAGE_ID"]) || packageId;
    let registryId = firstEnv(["MEMWAL_REGISTRY_ID", "REGISTRY_ID"]);
    if (!registryId) {
        registryId = await discoverRegistry(network, accountA.typePackageId);
    }
    if (!registryId || !OBJECT_ID_RE.test(normalizeHexAddress(registryId))) {
        failMisconfig("MEMWAL_REGISTRY_ID unset and AccountRegistry discovery failed");
    }
    registryId = normalizeHexAddress(registryId);

    console.log(
        `synthetic-seal-cross-account: ${network} policy=${shortId(policyPackageId)} registry=${shortId(registryId)}`,
    );
    console.log(
        `  A ${shortId(accountA.id)} owner=${shortId(accountA.owner)} caller=${shortId(addrA)} (${roleAonA}) counter=${accountA.counter}`,
    );
    console.log(
        `  B ${shortId(accountB.id)} owner=${shortId(accountB.owner)} caller=${shortId(addrB)} (${roleBonB}) counter=${accountB.counter}`,
    );

    const inspect = (sender, accountId, ownerHex, counter) =>
        inspectSealApprove({
            client,
            Transaction,
            sender,
            policyPackageId,
            registryId,
            accountId,
            idBytes: sealKeyIdBytes(ownerHex, counter),
        });

    const sameAccount = [
        {
            name: "A authorizes A (sanity)",
            promise: inspect(addrA, accountA.id, accountA.owner, accountA.counter),
            expect: "success",
        },
        {
            name: "B authorizes B (sanity)",
            promise: inspect(addrB, accountB.id, accountB.owner, accountB.counter),
            expect: "success",
        },
    ];
    for (const step of sameAccount) {
        const result = extractAbortCode(await step.promise);
        if (result.outcome !== "success") {
            failMisconfig(
                `${step.name} did not succeed (${result.outcome}${result.code !== undefined ? ` ${result.code}` : ""}). Check keys, package, registry.`,
            );
        }
        console.log(`  ok  ${step.name}`);
    }

    const negatives = [
        {
            name: "A on B's account + B's SEAL id",
            from: "A",
            to: "B",
            promise: inspect(addrA, accountB.id, accountB.owner, accountB.counter),
        },
        {
            name: "A on A's account + B's SEAL id",
            from: "A",
            to: "B",
            promise: inspect(addrA, accountA.id, accountB.owner, accountB.counter),
        },
        {
            name: "B on A's account + A's SEAL id",
            from: "B",
            to: "A",
            promise: inspect(addrB, accountA.id, accountA.owner, accountA.counter),
        },
        {
            name: "B on B's account + A's SEAL id",
            from: "B",
            to: "A",
            promise: inspect(addrB, accountB.id, accountA.owner, accountA.counter),
        },
    ];

    for (const step of negatives) {
        const result = extractAbortCode(await step.promise);
        if (result.outcome === "success") {
            failSecurity(
                `identity ${step.from} authorized account ${step.to}'s SEAL key (${step.name}); expected ENoAccess`,
            );
        }
        if (result.outcome === "abort" && result.code === E_NO_ACCESS) {
            console.log(`  deny ${step.name} (ENoAccess)`);
            continue;
        }
        failMisconfig(
            `${step.name}: expected ENoAccess (100), got ${result.outcome}${result.code !== undefined ? ` ${result.code}` : ""}: ${result.detail.slice(0, 300)}`,
        );
    }

    console.log("synthetic-seal-cross-account: ok (cross-account seal_approve denied as expected)");
}

const isMain =
    Boolean(process.argv[1]) &&
    path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
    const args = process.argv.slice(2);
    if (args.includes("--help") || args.includes("-h")) {
        usage();
        process.exit(0);
    }

    run().catch((err) => {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`synthetic-seal-cross-account: ${msg}`);
        process.exit(2);
    });
}
