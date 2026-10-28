#!/usr/bin/env npx tsx
/**
 * bench-recall-latency.ts
 *
 * End-to-end latency benchmark for public memory APIs.
 * Measures POST /api/remember write latency and POST /api/recall cold/warm read latency.
 *
 * Usage:
 *   npx tsx bench-recall-latency.ts \
 *     --server-url    http://localhost:8000 \
 *     --account-id    <0x...> \
 *     --delegate-key  <suiprivkey1... or 64-hex> \
 *     --remember-text "I prefer concise answers" \
 *     --query         "what do I prefer?" \
 *     --namespace     default \
 *     --limit         5 \
 *     --remember-runs 3 \
 *     --post-remember-sleep-secs 30 \
 *     --cold-runs     3 \
 *     --warm-runs     10 \
 *     --output        benchmark-results/live.json
 *
 * The script runs `--remember-runs` remember calls first, then `--cold-runs`
 * recall calls, then `--warm-runs` recall calls with the same query. Set
 * `--post-remember-sleep-secs` to wait between remember and recall phases.
 *
 * Output:
 *   • ANSI table with p50/p95/p99 per phase
 *   • JSON file with raw per-request timings at --output
 */

import { createHash, randomUUID } from "crypto";
import { decodeSuiPrivateKey } from "@mysten/sui/cryptography";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import {
  isRetryableLiveBenchFailure,
  LIVE_BENCH_MAX_ATTEMPTS,
  liveBenchRetryDelayMs,
} from "./live-bench-retry.js";

// ============================================================
// CLI
// ============================================================

const API_METHOD = "POST";
const REMEMBER_PATH = "/api/remember";
const RECALL_PATH = "/api/recall";
const TEXT_ENCODER = new TextEncoder();

interface Auth {
  delegateKey: string;
  keypair: Ed25519Keypair;
  publicKeyHex: string;
}

interface Args {
  serverUrl: string;
  accountId: string;
  auth: Auth;
  rememberBodyStr: string;
  rememberBodyHash: string;
  recallBodyStr: string;
  recallBodyHash: string;
  rememberText: string;
  query: string;
  namespace: string;
  limit: number;
  rememberRuns: number;
  postRememberSleepSecs: number;
  coldRuns: number;
  warmRuns: number;
  output: string;
  color: boolean;
}

function printHelp(): void {
  console.log(`
bench-recall-latency.ts — remember + recall latency benchmark

Usage:
  npx tsx bench-recall-latency.ts [options]

Required auth options:
  --account-id    <0x...>        x-account-id header value
  --delegate-key  <key>          suiprivkey1... or 64-hex delegate private key

Optional:
  --server-url    <url>          Server URL             [default: http://localhost:8000]
  --remember-text <text>         Remember text          [default: "benchmark memory"]
  --query         <text>         Recall query text      [default: "benchmark memory"]
  --namespace     <ns>           Namespace              [default: default]
  --limit         <n>            Top-K results          [default: 5]
  --remember-runs <n>            Remember runs          [default: 3]
  --post-remember-sleep-secs <n> Wait after remember before recall [default: 30]
  --cold-runs     <n>            Cold recall runs       [default: 3]
  --warm-runs     <n>            Warm recall runs       [default: 10]
  --output        <file>         JSON output path       [default: bench-live-results.json]
  --no-color                     Disable ANSI colors
  --help                         Show this help
`);
}

function parseArgs(): Args {
  const argv = process.argv.slice(2);
  if (argv.includes("--help") || argv.includes("-h")) {
    printHelp();
    process.exit(0);
  }

  const get = (flag: string, def?: string): string | undefined => {
    const idx = argv.indexOf(flag);
    if (idx !== -1 && idx + 1 < argv.length) return argv[idx + 1];
    return def;
  };

  const required = (flag: string, env?: string): string => {
    const v = get(flag) ?? (env ? process.env[env] : undefined);
    if (!v) {
      console.error(`error: ${flag} is required`);
      process.exit(1);
    }
    return v;
  };

  const delegateKey = normalizeDelegateKey(required("--delegate-key", "BENCH_DELEGATE_KEY"));
  const rememberText = get("--remember-text", "benchmark memory")!;
  const query = get("--query", rememberText)!;
  const namespace = get("--namespace", "default")!;
  const limit = parseInt(get("--limit", "5")!, 10);
  const rememberBodyStr = JSON.stringify({ text: rememberText, namespace });
  const recallBodyStr = JSON.stringify({ query, namespace, limit });

  return {
    serverUrl: get("--server-url", "http://localhost:8000")!,
    accountId: required("--account-id", "BENCH_ACCOUNT_ID"),
    auth: buildAuth(delegateKey),
    rememberBodyStr,
    rememberBodyHash: sha256Hex(rememberBodyStr),
    recallBodyStr,
    recallBodyHash: sha256Hex(recallBodyStr),
    rememberText,
    query,
    namespace,
    limit,
    rememberRuns: parseInt(get("--remember-runs", "3")!, 10),
    postRememberSleepSecs: parseInt(get("--post-remember-sleep-secs", "30")!, 10),
    coldRuns: parseInt(get("--cold-runs", "3")!, 10),
    warmRuns: parseInt(get("--warm-runs", "10")!, 10),
    output: get("--output", "bench-live-results.json")!,
    color: !argv.includes("--no-color"),
  };
}

// ============================================================
// Helpers
// ============================================================

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, Math.min(idx, sorted.length - 1))];
}

function ms(n: number): string {
  return `${n.toFixed(0)} ms`;
}

const C = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
  cyan: "\x1b[36m",
  magenta: "\x1b[35m",
};

function color(enabled: boolean, code: string, s: string): string {
  return enabled ? `${code}${s}${C.reset}` : s;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function buildAuth(delegateKey: string): Auth {
  const keypair = keypairFromDelegateKey(delegateKey);
  return {
    delegateKey,
    keypair,
    publicKeyHex: Buffer.from(keypair.getPublicKey().toRawBytes()).toString("hex"),
  };
}

function keypairFromDelegateKey(delegateKey: string): Ed25519Keypair {
  if (delegateKey.startsWith("suiprivkey")) {
    const { scheme, secretKey } = decodeSuiPrivateKey(delegateKey);
    if (scheme !== "ED25519") {
      throw new Error(`delegate key must be Ed25519, got ${scheme}`);
    }
    return Ed25519Keypair.fromSecretKey(secretKey);
  }

  const hex = delegateKey.startsWith("0x") ? delegateKey.slice(2) : delegateKey;
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error("delegate key must be 64-char hex or suiprivkey bech32");
  }
  return Ed25519Keypair.fromSecretKey(Uint8Array.from(Buffer.from(hex, "hex")));
}

function normalizeDelegateKey(delegateKey: string): string {
  if (delegateKey.startsWith("0x") && delegateKey.length === 66) {
    return delegateKey.slice(2);
  }
  return delegateKey;
}

function sha256Hex(data: string): string {
  return createHash("sha256").update(data).digest("hex");
}

async function buildSignedHeaders(
  args: Args,
  path: string,
  bodyHash: string,
): Promise<Record<string, string>> {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = randomUUID();
  const message = `${timestamp}.${API_METHOD}.${path}.${bodyHash}.${nonce}.${args.accountId}`;
  const signature = await args.auth.keypair.sign(TEXT_ENCODER.encode(message));

  return {
    "Content-Type": "application/json",
    "x-public-key": args.auth.publicKeyHex,
    "x-signature": Buffer.from(signature).toString("hex"),
    "x-timestamp": timestamp,
    "x-nonce": nonce,
    "x-account-id": args.accountId,
    "x-delegate-key": args.auth.delegateKey,
  };
}

function stats(samples: number[]): {
  p50: number; p95: number; p99: number; min: number; max: number; mean: number;
} {
  if (samples.length === 0) return { p50: 0, p95: 0, p99: 0, min: 0, max: 0, mean: 0 };
  const sorted = [...samples].sort((a, b) => a - b);
  const mean = sorted.reduce((a, b) => a + b, 0) / sorted.length;
  return {
    p50: percentile(sorted, 50),
    p95: percentile(sorted, 95),
    p99: percentile(sorted, 99),
    min: sorted[0],
    max: sorted[sorted.length - 1],
    mean,
  };
}

// ============================================================
// Single API calls
// ============================================================

interface ApiRunResult {
  ok: boolean;
  latencyMs: number;
  resultCount?: number;
  droppedCount?: number;
  memoryId?: string;
  blobId?: string;
  statusCode?: number;
  contentType?: string | null;
  error?: string;
}

async function rememberOnce(args: Args): Promise<ApiRunResult> {
  const start = performance.now();
  try {
    const headers = await buildSignedHeaders(args, REMEMBER_PATH, args.rememberBodyHash);

    const resp = await fetch(`${args.serverUrl}${REMEMBER_PATH}`, {
      method: API_METHOD,
      headers,
      body: args.rememberBodyStr,
    });

    const latencyMs = performance.now() - start;
    const contentType = resp.headers.get("content-type");

    if (!resp.ok) {
      const body = await resp.text().catch(() => "");
      return {
        ok: false,
        latencyMs,
        statusCode: resp.status,
        contentType,
        error: body.slice(0, 300),
      };
    }

    const json = (await resp.json().catch((err: unknown) => {
      throw Object.assign(err instanceof Error ? err : new Error(String(err)), {
        statusCode: resp.status,
        contentType,
      });
    })) as { id?: string; blob_id?: string };
    return {
      ok: true,
      latencyMs,
      statusCode: resp.status,
      contentType,
      memoryId: json.id,
      blobId: json.blob_id,
    };
  } catch (err: any) {
    const latencyMs = performance.now() - start;
    return {
      ok: false,
      latencyMs,
      statusCode: err?.statusCode,
      contentType: err?.contentType,
      error: err?.message ?? String(err),
    };
  }
}

async function recallOnce(args: Args): Promise<ApiRunResult> {
  const start = performance.now();
  try {
    const headers = await buildSignedHeaders(args, RECALL_PATH, args.recallBodyHash);

    const resp = await fetch(`${args.serverUrl}${RECALL_PATH}`, {
      method: API_METHOD,
      headers,
      body: args.recallBodyStr,
    });

    const latencyMs = performance.now() - start;
    const contentType = resp.headers.get("content-type");

    if (!resp.ok) {
      const body = await resp.text().catch(() => "");
      return {
        ok: false,
        latencyMs,
        statusCode: resp.status,
        contentType,
        error: body.slice(0, 300),
      };
    }

    const json = (await resp.json().catch((err: unknown) => {
      throw Object.assign(err instanceof Error ? err : new Error(String(err)), {
        statusCode: resp.status,
        contentType,
      });
    })) as { results?: unknown[]; total?: number; dropped_count?: number };
    return {
      ok: true,
      latencyMs,
      statusCode: resp.status,
      contentType,
      resultCount: json.total ?? json.results?.length ?? 0,
      droppedCount: json.dropped_count ?? 0,
    };
  } catch (err: any) {
    const latencyMs = performance.now() - start;
    return {
      ok: false,
      latencyMs,
      statusCode: err?.statusCode,
      contentType: err?.contentType,
      error: err?.message ?? String(err),
    };
  }
}

// ============================================================
// Run a batch of calls
// ============================================================

interface BatchResult {
  label: string;
  runs: number;
  successCount: number;
  failCount: number;
  rawMs: number[];
  errors: string[];
}

async function runBatch(
  label: string,
  runs: number,
  callOnce: () => Promise<ApiRunResult>,
  formatOk: (result: ApiRunResult) => string,
): Promise<BatchResult> {
  const rawMs: number[] = [];
  const errors: string[] = [];
  let successCount = 0;
  let failCount = 0;

  for (let i = 0; i < runs; i++) {
    process.stdout.write(`  [${label}] run ${i + 1}/${runs}... `);
    let result: ApiRunResult | undefined;
    for (let attempt = 1; attempt <= LIVE_BENCH_MAX_ATTEMPTS; attempt++) {
      result = await callOnce();
      if (
        result.ok ||
        !isRetryableLiveBenchFailure(result) ||
        attempt === LIVE_BENCH_MAX_ATTEMPTS
      ) {
        break;
      }
      process.stdout.write(`retry ${attempt}/${LIVE_BENCH_MAX_ATTEMPTS - 1}... `);
      await sleep(liveBenchRetryDelayMs(attempt));
    }
    if (result!.ok) {
      rawMs.push(result!.latencyMs);
      successCount++;
      console.log(`ok ${ms(result!.latencyMs)} ${formatOk(result!)}`);
    } else {
      failCount++;
      const errMsg = result!.error?.trim() || `HTTP ${result!.statusCode}`;
      errors.push(errMsg);
      console.log(`FAILED: ${errMsg.slice(0, 120)}`);
    }

    if (i < runs - 1) {
      await new Promise((r) => setTimeout(r, 100));
    }
  }

  return { label, runs, successCount, failCount, rawMs, errors };
}

// ============================================================
// Reporting
// ============================================================

function printBatchTable(batches: BatchResult[], col: boolean): void {
  const h = (s: string) => color(col, C.bold + C.cyan, s);
  const ok = (s: string) => color(col, C.green, s);

  const colW = [12, 8, 8, 8, 10, 8, 8];
  const cols = ["phase", "p50", "p95", "p99", "mean", "min", "max"];

  function row(cells: string[]): string {
    return cells.map((c, i) => c.padStart(colW[i])).join("  ");
  }

  console.log();
  console.log(h(row(cols)));
  console.log(color(col, C.dim, row(cols.map((_, i) => "─".repeat(colW[i])))));

  for (const b of batches) {
    const s = stats(b.rawMs);
    const cells = [
      b.label,
      ms(s.p50),
      ms(s.p95),
      ms(s.p99),
      ms(s.mean),
      ms(s.min),
      ms(s.max),
    ];
    console.log(ok(row(cells)));
  }
  console.log();
}

function buildMarkdown(batches: BatchResult[]): string {
  const lines = [
    "## Walrus Memory Live Benchmark",
    "",
    "| phase | endpoint | runs | p50 | p95 | p99 | mean | min | max | fail% |",
    "|-------|----------|------|-----|-----|-----|------|-----|-----|-------|",
  ];
  for (const b of batches) {
    const s = stats(b.rawMs);
    const endpoint = b.label === "remember" ? REMEMBER_PATH : RECALL_PATH;
    const failPct = ((b.failCount / b.runs) * 100).toFixed(1);
    lines.push(
      `| ${b.label} | ${endpoint} | ${b.runs} | ${ms(s.p50)} | ${ms(s.p95)} | ${ms(s.p99)} | ${ms(s.mean)} | ${ms(s.min)} | ${ms(s.max)} | ${failPct}% |`
    );
  }
  return lines.join("\n");
}

// ============================================================
// Main
// ============================================================

async function main(): Promise<void> {
  const args = parseArgs();
  const col = args.color && process.stdout.isTTY;

  console.log(color(col, C.bold, "\n⚡ memwal-live-benchmark\n"));
  console.log(`  server:        ${args.serverUrl}`);
  console.log(`  namespace:     ${args.namespace}`);
  console.log(`  limit:         ${args.limit}`);
  console.log(`  remember text: "${args.rememberText.slice(0, 60)}"`);
  console.log(`  query:         "${args.query.slice(0, 60)}"`);
  console.log(`  remember runs: ${args.rememberRuns}`);
  console.log(`  post-remember sleep: ${args.postRememberSleepSecs}s`);
  console.log(`  cold runs:     ${args.coldRuns}`);
  console.log(`  warm runs:     ${args.warmRuns}`);
  console.log();

  process.stdout.write(color(col, C.dim, "  health check... "));
  const healthResp = await fetch(`${args.serverUrl}/health`).catch((e) => { throw new Error(`health check failed: ${e.message}`); });
  if (!healthResp.ok) throw new Error(`health check failed: HTTP ${healthResp.status}`);
  console.log(color(col, C.green, "ok\n"));

  const batches: BatchResult[] = [];

  console.log(color(col, C.magenta, `  ── Remember path (${args.rememberRuns} runs) ──`));
  const rememberBatch = await runBatch(
    "remember",
    args.rememberRuns,
    () => rememberOnce(args),
    (result) => `(id=${result.memoryId ?? "unknown"}, blob=${result.blobId ?? "unknown"})`,
  );
  batches.push(rememberBatch);

  if (args.postRememberSleepSecs > 0) {
    console.log(
      color(col, C.dim, `\n  waiting ${args.postRememberSleepSecs}s before recall phases...`)
    );
    await sleep(args.postRememberSleepSecs * 1000);
  }

  console.log(color(col, C.magenta, `\n  ── Cold recall path (${args.coldRuns} runs) ──`));
  const coldBatch = await runBatch(
    "recall-cold",
    args.coldRuns,
    () => recallOnce(args),
    (result) => `(${result.resultCount} results)`,
  );
  batches.push(coldBatch);

  console.log(color(col, C.magenta, `\n  ── Warm recall path (${args.warmRuns} runs) ──`));
  const warmBatch = await runBatch(
    "recall-warm",
    args.warmRuns,
    () => recallOnce(args),
    (result) => `(${result.resultCount} results)`,
  );
  batches.push(warmBatch);

  printBatchTable(batches, col);

  const md = buildMarkdown(batches);
  console.log(md);
  console.log();

  const TARGET_RECALL_WARM_P50_MS = 500;
  const warmStats = stats(warmBatch.rawMs);
  const totalFailures = batches.reduce((sum, b) => sum + b.failCount, 0);
  if (totalFailures > 0) {
    console.log(color(col, C.red, `✘ Benchmark had ${totalFailures} failed request(s)`));
  }
  if (warmStats.p50 < TARGET_RECALL_WARM_P50_MS) {
    console.log(
      color(col, C.green, `✔ Warm recall p50 = ${ms(warmStats.p50)} — below ${TARGET_RECALL_WARM_P50_MS}ms target ✓`)
    );
  } else {
    console.log(
      color(col, C.red, `✘ Warm recall p50 = ${ms(warmStats.p50)} — still above ${TARGET_RECALL_WARM_P50_MS}ms target`)
    );
    console.log("  → Check server logs for per-phase breakdown (embed / vector_search / walrus_fetch / seal_batch_decrypt)");
  }
  console.log();

  const jsonOut = {
    timestamp: new Date().toISOString(),
    config: {
      serverUrl: args.serverUrl,
      namespace: args.namespace,
      limit: args.limit,
      rememberText: args.rememberText,
      query: args.query,
      rememberRuns: args.rememberRuns,
      postRememberSleepSecs: args.postRememberSleepSecs,
      coldRuns: args.coldRuns,
      warmRuns: args.warmRuns,
    },
    target: { recallWarmP50Ms: TARGET_RECALL_WARM_P50_MS },
    batches: batches.map((b) => {
      const s = stats(b.rawMs);
      return {
        label: b.label,
        endpoint: b.label === "remember" ? REMEMBER_PATH : RECALL_PATH,
        runs: b.runs,
        successCount: b.successCount,
        failCount: b.failCount,
        failureRate: +(b.failCount / b.runs).toFixed(4),
        p50Ms: +s.p50.toFixed(1),
        p95Ms: +s.p95.toFixed(1),
        p99Ms: +s.p99.toFixed(1),
        meanMs: +s.mean.toFixed(1),
        minMs: +s.min.toFixed(1),
        maxMs: +s.max.toFixed(1),
        rawMs: b.rawMs.map((n) => +n.toFixed(1)),
        errors: b.errors,
      };
    }),
    markdownTable: md,
  };

  const { writeFileSync } = await import("fs");
  writeFileSync(args.output, JSON.stringify(jsonOut, null, 2));
  console.log(color(col, C.dim, `  Results written to ${args.output}\n`));

  if (totalFailures > 0) {
    process.exit(1);
  }
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  console.error(`\nFatal error: ${msg}`);
  process.exit(1);
});
