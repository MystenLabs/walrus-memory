import test from "node:test";
import assert from "node:assert/strict";
import { registerCaptureHook } from "../dist/hooks/capture.js";

const IDLE_TTL_MS = 30 * 60_000;
const MAX_SCOPES = 1_000;
const event = {
  success: true,
  messages: [{
    id: "preference",
    role: "user",
    content: "I prefer TypeScript for backend services and strict type checks.",
  }],
};

function captureHarness(analyze, requestTimeoutMs = 10_000) {
  let capture;
  registerCaptureHook({
    on: (_name, fn) => { capture = fn; },
    logger: { debug() {}, info() {}, warn() {} },
  }, { analyze }, { defaultNamespace: "default", captureMaxMessages: 10, requestTimeoutMs });
  return (session) => capture(event, { sessionKey: `agent:main:${session}` });
}

test("capture scope idle expiry refreshes on use and releases old watermarks", async (t) => {
  let now = 0;
  t.mock.method(Date, "now", () => now);
  let calls = 0;
  const capture = captureHarness(async () => { calls++; return { facts: [] }; });

  await capture("recent");
  now += IDLE_TTL_MS - 1;
  await capture("recent");
  now += IDLE_TTL_MS - 1;
  await capture("recent");
  assert.equal(calls, 1, "using a scope keeps its dedup watermark fresh");

  now += IDLE_TTL_MS;
  await capture("other");
  await capture("recent");
  assert.equal(calls, 3, "an idle scope can be recreated after its state expires");
});

test("capture capacity evicts the least recently used idle scope", async () => {
  let calls = 0;
  const capture = captureHarness(async () => { calls++; return { facts: [] }; });
  for (let i = 0; i < MAX_SCOPES; i++) await capture(`scope-${i}`);
  await capture("scope-0");
  assert.equal(calls, MAX_SCOPES);

  await capture("overflow");
  await capture("scope-0");
  assert.equal(calls, MAX_SCOPES + 1, "the recently used scope stays deduplicated");
  await capture("scope-1");
  assert.equal(calls, MAX_SCOPES + 2, "the oldest idle scope was evicted");
});

test("capture skips new scopes when every cache slot has active work", async () => {
  let calls = 0;
  let resolveImmediately = false;
  const releases = [];
  const capture = captureHarness(() => {
    calls++;
    return resolveImmediately
      ? Promise.resolve({ facts: [] })
      : new Promise((resolve) => releases.push(resolve));
  });
  const active = Array.from({ length: MAX_SCOPES }, (_, i) => capture(`busy-${i}`));
  await capture("overflow");
  await capture("busy-0");
  assert.equal(calls, MAX_SCOPES, "busy guards are neither evicted nor bypassed");

  resolveImmediately = true;
  for (const release of releases) release({ facts: [] });
  await Promise.all(active);
  await capture("overflow");
  assert.equal(calls, MAX_SCOPES + 1, "settled scopes can make room for new work");
});

test("idle expiry preserves an unresolved analyze guard after its hook times out", async (t) => {
  let now = 0;
  t.mock.method(Date, "now", () => now);
  let calls = 0;
  let release;
  const capture = captureHarness(() => {
    calls++;
    return new Promise((resolve) => { release = resolve; });
  }, 10);
  await capture("slow");
  now += IDLE_TTL_MS + 1;
  await capture("slow");
  assert.equal(calls, 1, "an old but unresolved request still blocks duplicate extraction");
  release({ facts: [] });
  await Promise.resolve();
});

test("capture keeps the same scope guarded during retry backoff", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let calls = 0;
  const capture = captureHarness(async () => {
    calls++;
    if (calls === 1) throw new Error("transient failure");
    return { facts: [] };
  });
  const first = capture("retrying");
  // Let the rejected analyze settle and schedule the retry delay.
  await new Promise((resolve) => setImmediate(resolve));
  await capture("retrying");
  assert.equal(calls, 1, "a retry delay does not admit a second extraction");
  t.mock.timers.tick(2000);
  await first;
  assert.equal(calls, 2, "the original hook alone retries");
  await capture("retrying");
  assert.equal(calls, 2, "the retry result is still watermarked");
});
