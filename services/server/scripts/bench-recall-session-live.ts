/** Read-only deployed HTTP recall: fresh-session control vs reused-session cache. */
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { performance } from "node:perf_hooks";
import { SessionKey } from "@mysten/seal";
import { decodeSuiPrivateKey } from "@mysten/sui/cryptography";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { SuiGrpcClient } from "@mysten/sui/grpc";

const argv = process.argv.slice(2);
const arg = (name: string, fallback = "") => {
    const index = argv.indexOf(name); return index < 0 ? fallback : argv[index + 1] ?? fallback;
};
async function main() {
    const server = arg("--server-url", process.env.BENCH_SERVER_URL).replace(/\/$/, "");
    const output = arg("--output", "benchmark-results/memory-api.json");
    const runs = Number(arg("--runs", "10")), limit = Number(arg("--limit", "10"));
    assert.ok(Number.isInteger(runs) && runs >= 2 && runs <= 30);
    assert.ok(Number.isInteger(limit) && limit > 0 && limit <= 100);
    const secret = process.env.BENCH_DELEGATE_KEY, accountId = process.env.BENCH_ACCOUNT_ID;
    assert.ok(secret && accountId, "Benchmark credentials required");
    const keypair = Ed25519Keypair.fromSecretKey(secret.startsWith("suiprivkey")
        ? decodeSuiPrivateKey(secret).secretKey : Buffer.from(secret.replace(/^0x/, ""), "hex"));
    const get = async (path: string) => {
        const r = await fetch(server + path, { signal: AbortSignal.timeout(20_000) });
        assert.equal(r.status, 200, `${path} failed`); return r.json();
    };
    const config = await get("/config"), health = await get("/health");
    assert.ok(config.suiGrpcUrl && health.build?.commit);
    if (arg("--expected-commit")) assert.equal(health.build.commit, arg("--expected-commit"));
    const sui = new SuiGrpcClient({ network: config.network, baseUrl: config.suiGrpcUrl });
    const session = async () => {
        const key = await SessionKey.create({ address: keypair.toSuiAddress(), packageId: config.packageId,
            ttlMin: 5, signer: keypair, suiClient: sui as any });
        await key.getCertificate();
        return Buffer.from(JSON.stringify({ ...key.export() })).toString("base64");
    };
    const body = JSON.stringify({ query: arg("--query", "benchmark memory"), namespace: arg("--namespace", "benchmark"), limit, deadline_ms: 14_000 });
    const hash = createHash("sha256").update(body).digest("hex");
    async function recall(header: string) {
        const timestamp = String(Math.floor(Date.now() / 1000)), nonce = randomUUID(), requestId = randomUUID();
        const signature = await keypair.sign(new TextEncoder().encode(`${timestamp}.POST./api/recall.${hash}.${nonce}.${accountId}`));
        const started = performance.now();
        const response = await fetch(`${server}/api/recall`, { method: "POST", body, signal: AbortSignal.timeout(20_000),
            headers: { "content-type": "application/json", "x-public-key": Buffer.from(keypair.getPublicKey().toRawBytes()).toString("hex"),
                "x-signature": Buffer.from(signature).toString("hex"), "x-timestamp": timestamp, "x-nonce": nonce,
                "x-account-id": accountId, "x-seal-session": header, "x-request-id": requestId } });
        const value = await response.json();
        const latencyMs = performance.now() - started;
        assert.equal(response.status, 200, `Recall HTTP ${response.status}, stage=${value.stage ?? "unknown"}`);
        assert.ok(value.results?.length > 0, "No benchmark memories; empty recall cannot validate hydration performance");
        assert.equal(value.dropped_count ?? 0, 0, "Dropped results invalidate the timing comparison");
        const digest = createHash("sha256").update(JSON.stringify(value.results)).digest("hex");
        return { latencyMs, resultCount: value.results.length, digest, requestId };
    }
    const samples: any[] = [];
    const report: any = { timestamp: new Date().toISOString(), scope: "Deployed HTTP /api/recall; read-only; all requests use x-seal-session",
        serverCommit: health.build.commit, runnerCommit: process.env.GITHUB_SHA ?? null, limit, runs, completed: false, samples,
        notes: ["Session construction excluded; HTTP response body read included", "Embedding/blob cache prewarmed equally",
            "Fresh-session control uses new credentials per request; reused-session arm uses identical bytes",
            "This is a same-deployment session-cache control, not a historical-deployment end-to-end A/B"] };
    try {
        let reused = await session(), reusedAt = Date.now();
        await recall(reused); // prewarm embedding/blob cache and reused-session keys.
        for (let i = 0; i < runs; i++) {
            // Keep a warmed session comfortably before its absolute expiry.
            if (Date.now() - reusedAt > 180_000) { reused = await session(); reusedAt = Date.now(); await recall(reused); }
            for (const arm of i % 2 ? ["reused-session", "fresh-session"] : ["fresh-session", "reused-session"]) {
                const header = arm === "fresh-session" ? await session() : reused;
                samples.push({ arm, pair: i, ...await recall(header) });
            }
            console.log(`Completed deployed session pair ${i + 1}/${runs}`);
        }
        assert.equal((await get("/health")).build.commit, health.build.commit, "Deployment changed during benchmark");
        assert.equal(new Set(samples.map(x => x.digest)).size, 1, "Results changed between arms; comparison invalid");
        const stats = (arm: string) => {
            const values = samples.filter(x => x.arm === arm).map(x => x.latencyMs).sort((a, b) => a - b);
            return { count: values.length, p50: values[Math.ceil(values.length / 2) - 1], p95: values[Math.ceil(values.length * .95) - 1] };
        };
        report.fresh = stats("fresh-session"); report.reused = stats("reused-session");
        report.actualResults = samples[0].resultCount;
        report.p50ReductionPercent = 100 * (1 - report.reused.p50 / report.fresh.p50);
        report.completed = true;
        report.markdownTable = `Deployed commit: ${report.serverCommit}\n\n` +
            `Requested ${limit}; actual ${report.actualResults} results. ${runs} samples/arm, alternating AB/BA.\n\n` +
            `| Session | HTTP p50 ms | HTTP p95 ms |\n|---|---:|---:|\n` +
            `| Fresh each call | ${report.fresh.p50.toFixed(0)} | ${report.fresh.p95.toFixed(0)} |\n` +
            `| Reused | ${report.reused.p50.toFixed(0)} | ${report.reused.p95.toFixed(0)} |\n\n` +
            `p50 reduction: ${report.p50ReductionPercent.toFixed(1)}%. Same-deployment control, not historical-deployment A/B.`;
    } finally {
        await mkdir(dirname(output), { recursive: true }); await writeFile(output, JSON.stringify(report, null, 2) + "\n");
    }
}

await main();
