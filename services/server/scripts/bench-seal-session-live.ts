/**
 * Read-only live SEAL A/B. Runs each checkout's actual sidecar routes on
 * loopback. Uses real Sui reads, sessions, PTBs, key servers and crypto, but
 * synthetic ciphertexts (no Walrus uploads, transactions or fixture writes).
 * This measures the SEAL hydration stage, NOT end-to-end /api/recall.
 * Manual invocation only; never run as a unit test or on PR creation.
 */
import assert from "node:assert/strict";
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { performance } from "node:perf_hooks";
import { SealClient, SessionKey } from "@mysten/seal";
import { SuiGrpcClient } from "@mysten/sui/grpc";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { decodeSuiPrivateKey } from "@mysten/sui/cryptography";
import { normalizeSuiAddress, toHex } from "@mysten/sui/utils";
import { bcs } from "@mysten/sui/bcs";
import { getSealServerConfigsFromEnv, getSealThresholdFromEnv } from "./seal-config.js";

const argv = process.argv.slice(2);
function arg(name: string, fallback = ""): string {
    const index = argv.indexOf(name);
    return index < 0 ? fallback : argv[index + 1] ?? fallback;
}
function integer(name: string, fallback: string, max: number): number {
    const text = arg(name, fallback);
    const value = Number(text);
    if (!/^\d+$/.test(text) || value < 1 || value > max) throw new Error(`Invalid ${name}`);
    return value;
}
const timeoutMs = 90_000;
const output = resolve(arg("--output", "benchmark-results/seal-session-ab.json"));
const phases: Record<string, any[]> = { baseline: [], candidate: [] };

async function serve(root: string) {
    const { createSealApp } = await import(pathToFileURL(resolve(root, "services/server/scripts/sidecar/seal-app.ts")).href);
    const server = createSealApp().listen(0, "127.0.0.1", () => {
        const address = server.address();
        if (address && typeof address !== "string") process.stdout.write(JSON.stringify({ event: "benchmark_ready", port: address.port }) + "\n");
    });
    server.on("error", () => process.exit(1));
    process.on("SIGTERM", () => { server.closeAllConnections(); server.close(() => process.exit(0)); });
}

async function start(root: string, label: string, env: NodeJS.ProcessEnv): Promise<{ child: ChildProcess; url: string }> {
    const child = spawn(process.execPath, ["--import", "tsx", resolve(import.meta.dirname, "bench-seal-session-live.ts"), "--serve-root", root],
        { cwd: import.meta.dirname, env, stdio: ["ignore", "pipe", "pipe"] });
    child.stderr!.on("data", () => { /* SDK/config warnings may include infra details; don't publish raw logs. */ });
    return new Promise((yes, no) => {
        const timer = setTimeout(() => { child.kill(); no(new Error(`${label} sidecar startup timed out`)); }, 30_000);
        let pending = "";
        child.stdout!.on("data", bytes => {
            pending += bytes;
            const lines = pending.split("\n"); pending = lines.pop()!;
            for (const line of lines) {
                let event: any;
                try { event = JSON.parse(line); } catch { continue; }
                if (event.event === "benchmark_ready") {
                    clearTimeout(timer); yes({ child, url: `http://127.0.0.1:${event.port}` });
                }
                if (event.event === "seal_decrypt_batch") phases[label].push(event);
            }
        });
        child.once("error", error => { clearTimeout(timer); no(error); });
        child.once("exit", code => { clearTimeout(timer); if (code !== 0) no(new Error(`${label} sidecar exited (${code})`)); });
    });
}

async function jsonRequest(url: string, init?: RequestInit): Promise<any> {
    const response = await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    const body = await response.json();
    if (!response.ok) throw new Error(`HTTP ${response.status} from ${new URL(url).pathname}`);
    return body;
}

function summary(values: number[]) {
    if (!values.length) throw new Error("No benchmark samples");
    const sorted = [...values].sort((a, b) => a - b);
    return { count: values.length, p50: sorted[Math.ceil(sorted.length * .5) - 1], p95: sorted[Math.ceil(sorted.length * .95) - 1] };
}

async function main() {
    const roots = { baseline: resolve(arg("--baseline-root")), candidate: resolve(arg("--candidate-root")) };
    if (!arg("--baseline-root") || !arg("--candidate-root")) throw new Error("Both checkout roots are required");
    const commits = Object.fromEntries(Object.entries(roots).map(([arm, root]) => [arm,
        execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim()]));
    if (commits.baseline === commits.candidate) throw new Error("Baseline and candidate commits must differ");
    const accountId = process.env.BENCH_ACCOUNT_ID;
    const secret = process.env.BENCH_DELEGATE_KEY;
    if (!accountId || !secret) throw new Error("BENCH_ACCOUNT_ID and BENCH_DELEGATE_KEY required");
    const config = await jsonRequest(`${arg("--server-url", process.env.BENCH_SERVER_URL).replace(/\/$/, "")}/config`);
    assert.ok(config.network === "testnet" || config.network === "mainnet");
    assert.ok(config.suiGrpcUrl, "live benchmark requires gRPC");
    process.env.SUI_NETWORK = config.network;
    const serverConfigs = getSealServerConfigsFromEnv();
    const threshold = getSealThresholdFromEnv(serverConfigs);
    const sui = new SuiGrpcClient({ network: config.network, baseUrl: config.suiGrpcUrl });
    const keypair = secret.startsWith("suiprivkey")
        ? Ed25519Keypair.fromSecretKey(decodeSuiPrivateKey(secret).secretKey)
        : Ed25519Keypair.fromSecretKey(Buffer.from(secret.replace(/^0x/, ""), "hex"));
    const account = (await sui.getObject({ objectId: accountId, include: { json: true } })).object?.json as any;
    assert.ok(account?.owner && account?.active && account?.access_counter_version !== undefined, "Invalid benchmark account");
    const id = normalizeSuiAddress(account.owner).slice(2) + toHex(bcs.u64().serialize(account.access_counter_version).toBytes());
    const policyPackageId = process.env.MEMWAL_SEAL_POLICY_PACKAGE_ID || config.packageId;
    const encryptor = new SealClient({ suiClient: sui as any, serverConfigs, verifyKeyServers: true });
    const plaintexts = Array.from({ length: 100 }, (_, i) => Buffer.from(`Live SEAL recall benchmark fixture ${i}: ${"synthetic content ".repeat(50)}`));
    const items: string[] = [];
    for (const data of plaintexts) {
        const encrypted = await encryptor.encrypt({ packageId: config.packageId, id, threshold, data });
        items.push(Buffer.from(encrypted.encryptedObject).toString("base64"));
    }
    const token = randomUUID();
    const childEnv: NodeJS.ProcessEnv = { ...process.env, SUI_NETWORK: config.network, SUI_GRPC_URL: config.suiGrpcUrl,
        MEMWAL_PACKAGE_ID: config.packageId, MEMWAL_SEAL_POLICY_PACKAGE_ID: policyPackageId,
        SIDECAR_AUTH_TOKEN: token, SERVER_SUI_PRIVATE_KEYS: "", SERVER_SUI_PRIVATE_KEY: "" };
    // The sidecar only needs local request headers, not the CI delegate secret.
    delete childEnv.BENCH_DELEGATE_KEY;
    const children: { child: ChildProcess; url: string }[] = [];
    const report: any = { baselineCommit: commits.baseline, candidateCommit: commits.candidate,
        scope: "Actual sidecar source + live Sui/SEAL; SEAL hydration only, not end-to-end recall",
        network: config.network, packageId: config.packageId, policyPackageId,
        committee: serverConfigs.map(({ objectId, weight }) => ({ objectId, weight })), threshold,
        chunkSize: 25, completed: false, samples: [], phases, errors: [],
        notes: ["No chain mutations or Walrus writes", "Both arms share ciphertexts, session bytes and sequential 25-item chunks",
            "Public metadata is prewarmed once; normal five-minute refresh remains enabled. Cold means fresh session, not cold process",
            "Order alternates AB/BA per round; warm samples use the exact preceding cold session",
            "Results include the candidate's per-request authorization-version reads; p95 is descriptive at this sample size"] };
    const rounds = integer("--rounds", "4", 10);
    const warmRuns = integer("--warm-runs", "5", 20);
    try {
        const endpoints: Record<string, string> = {};
        for (const [label, root] of Object.entries(roots)) {
            const running = await start(root, label, childEnv); children.push(running); endpoints[label] = running.url;
        }
        async function sessionHeader(signer = keypair) {
            const session = await SessionKey.create({ address: signer.toSuiAddress(), packageId: config.packageId,
                ttlMin: 5, signer, suiClient: sui as any });
            await session.getCertificate();
            return Buffer.from(JSON.stringify({ ...session.export() })).toString("base64");
        }
        async function recall(arm: string, limit: number, header: string) {
            const started = performance.now();
            const result: Buffer[] = [];
            for (let offset = 0; offset < limit; offset += 25) {
                const requestId = randomUUID();
                const response = await jsonRequest(`${endpoints[arm]}/seal/decrypt-batch`, {
                    method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json", "x-seal-session": header, "x-request-id": requestId },
                    body: JSON.stringify({ items: items.slice(offset, Math.min(limit, offset + 25)), packageId: config.packageId,
                        policyPackageId, registryId: config.registryId, accountId, sealAbi: "v1-new" }),
                });
                assert.deepEqual(response.errors, [], `${arm} returned per-item SEAL errors`);
                assert.equal(response.results.length, Math.min(25, limit - offset));
                response.results.sort((a: any, b: any) => a.index - b.index);
                result.push(...response.results.map((item: any) => Buffer.from(item.decryptedData, "base64")));
            }
            const elapsedMs = performance.now() - started;
            assert.equal(result.length, limit);
            result.forEach((value, i) => assert.ok(value.equals(plaintexts[i]), `Incorrect plaintext/order at ${i}`));
            return { elapsedMs, digest: createHash("sha256").update(Buffer.concat(result)).digest("hex") };
        }
        const metadataSession = await sessionHeader();
        for (const arm of ["baseline", "candidate"]) await recall(arm, 1, metadataSession);
        // A fresh unauthorized identity must not reuse the approved session's
        // already-warm SDK keys. No account changes or transactions required.
        const deniedHeader = await sessionHeader(Ed25519Keypair.generate());
        for (const arm of ["baseline", "candidate"]) {
            const denied = await jsonRequest(`${endpoints[arm]}/seal/decrypt-batch`, {
                method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json", "x-seal-session": deniedHeader },
                body: JSON.stringify({ items: items.slice(0, 1), packageId: config.packageId, policyPackageId,
                    registryId: config.registryId, accountId, sealAbi: "v1-new" }),
            });
            assert.equal(denied.results.length, 0, "A different unauthorized session saw warm plaintext");
            assert.ok(denied.errors.some((e: any) => /does not have access|NoAccess|ENoAccess/i.test(e.error)),
                "Negative control did not receive an authorization denial");
        }
        report.unauthorizedSessionControl = "denied in both arms after authorized warm-up";
        for (const limit of [10, 25, 100]) {
            for (let round = 0; round < rounds; round++) {
                const header = await sessionHeader();
                const order = round % 2 ? ["candidate", "baseline"] : ["baseline", "candidate"];
                for (const arm of order) {
                    report.samples.push({ arm, limit, round, phase: "cold", ...await recall(arm, limit, header) });
                    for (let i = 0; i < warmRuns; i++) report.samples.push({ arm, limit, round, phase: "warm", ...await recall(arm, limit, header) });
                }
                console.log(`Completed live pair limit=${limit}, round=${round + 1}/${rounds}`);
            }
        }
        report.comparisons = [];
        for (const limit of [10, 25, 100]) for (const phase of ["cold", "warm"]) {
            const select = (arm: string) => report.samples.filter((x: any) => x.arm === arm && x.limit === limit && x.phase === phase);
            const a = select("baseline"), b = select("candidate");
            assert.equal(new Set([...a, ...b].map((x: any) => x.digest)).size, 1);
            const baseline = summary(a.map((x: any) => x.elapsedMs)), candidate = summary(b.map((x: any) => x.elapsedMs));
            report.comparisons.push({ limit, phase, baseline, candidate, p50ReductionPercent: 100 * (1 - candidate.p50 / baseline.p50) });
        }
        report.completed = true;
        console.log("Live SEAL A/B correctness checks passed");
    } catch (error) {
        // Never serialize sessions or raw HTTP request objects into artifacts.
        report.errors.push({ name: error instanceof Error ? error.name : "Error", message: error instanceof Error ? error.message.slice(0, 200) : "Benchmark failed" });
        throw new Error("Live SEAL A/B did not complete; inspect the sanitized result artifact");
    } finally {
        await mkdir(dirname(output), { recursive: true });
        await writeFile(output, JSON.stringify(report, null, 2) + "\n");
        for (const { child } of children) child.kill("SIGTERM");
    }
}

if (argv.includes("--help")) {
    console.log("Read-only live SEAL A/B (manual only):\n" +
        "node --import tsx bench-seal-session-live.ts --baseline-root <checkout> --candidate-root <checkout> " +
        "--server-url <relayer> --rounds 4 --warm-runs 5 --output <result.json>\n" +
        "Requires BENCH_ACCOUNT_ID / BENCH_DELEGATE_KEY; optional MEMWAL_SEAL_POLICY_PACKAGE_ID. " +
        "Measures real sidecar SEAL hydration, not end-to-end recall. No transactions or Walrus writes.");
} else if (arg("--serve-root")) await serve(arg("--serve-root"));
else await main();
