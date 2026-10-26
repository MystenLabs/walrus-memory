---
title: Production Readiness for Agent Storage
description: >-
  Patterns for running Walrus Memory in a production agent: idempotent writes, retries with exponential backoff, confirming write durability, bounding cost with batching and budgets, key custody best practices, and graceful degradation when memory is unavailable.
keywords:
  - production readiness
  - idempotent writes
  - retries
  - cost management
  - Walrus Memory
  - MemWal
goal:
  description: "Harden a Walrus Memory integration for production: add idempotent writes, configure retry and timeout logic, cap costs, secure key custody, and add graceful degradation when the relayer is unreachable."
  requires:
    - has_frontmatter:
        - title
        - description
        - keywords
      label: Has required frontmatter fields
    - min_words: 300
      label: Needs more content depth
    - has_questions: true
      label: Needs questions for AI search visibility
    - has_answer: true
      label: Needs answer summary for AI citation
questions:
  - How do I make Walrus Memory writes idempotent?
  - How do I handle retries and failures in a production MemWal agent?
  - How do I control costs when using Walrus Memory in production?
answer: >-
  Use stable idempotency keys for retried operations, persist accepted job IDs, and check completion outside the chat turn. Retry transient submission failures with backoff, honor rate limits, bound storage use, keep delegate keys in a secret manager, and continue serving when memory is unavailable.
---

The SDK gives you the storage primitives. Running them in a long-lived agent, where there is no human to retry a failed write or notice a runaway bill, takes a few patterns on top. This guide collects the ones that matter most.

The examples target the relayer-backed TypeScript client in SDK 0.1.9. See the [API reference](/sdk/api-reference) for method signatures and the [SDK changelog](/sdk/changelog) for version-specific behavior.

## Make writes idempotent

The SDK sends an idempotency key that lets the relayer return an existing job instead of creating another paid write. Automatic keys depend on the installed SDK version:

| **Method** | **Automatic key** |
| --- | --- |
| `remember`, `rememberAsync`, `rememberAndWait` | From 0.1.8, derived from the text, resolved namespace, and a fixed 30-minute time bucket. |
| `rememberBulk`, `rememberBulkAsync`, `rememberBulkAndWait` | From 0.1.9, derived from the ordered batch's text and resolved namespaces, plus the same time bucket. |

Upgrade from 0.1.8 for bulk idempotency; its bulk methods send no key even if a caller passes an options argument.

The bucket is not a rolling 30-minute guarantee: 2 attempts a few seconds apart can cross its boundary. Changing batch order, content, or namespaces also changes the automatic key.

For a durable queue, or any retry that can cross a bucket boundary or a process restart, persist one operation key with the payload. Reuse it on every submission attempt.

```ts
import { MemWal } from "@mysten-incubation/memwal";

async function rememberOnce(
  memwal: MemWal,
  text: string,
  eventId: string,
  namespace?: string,
) {
  // eventId comes from your durable event record, not a new UUID on each retry.
  return memwal.remember(text, namespace, { idempotencyKey: `event:${eventId}` });
}
```

<Note>
An explicit key is scoped to the account owner and namespace. Reusing it for different text returns a conflict rather than overwriting a memory. Generate a new operation key for an intentional new write. The client does not retain keys you supplied: pass the same key again on every retry.
</Note>

For bulk writes, persist the batch key and preserve the items and their order across retries:

```ts
const acceptedBatch = await memwal.rememberBulk(
  [
    { text: "Deploy completed.", namespace: "operations" },
    { text: "Smoke checks passed.", namespace: "operations" },
  ],
  { idempotencyKey: "deploy:release-42:batch-1" },
);
// Persist acceptedBatch.job_ids before acknowledging the queue item.
```

## Retry with backoff, but only retryable failures

Relayer requests have deadlines in SDK 0.1.8 and later; `requestTimeoutMs` defaults to 30 seconds. Submission and polling need different retry handling:

- **No acceptance response:** a network failure or request timeout can occur after the relayer accepted the write. Retry the submission with the same explicit key and unchanged payload. Use bounded exponential backoff with jitter for transient failures, and stop when your overall retry budget expires.
- **Accepted job ID:** persist it and poll that job. A wait timeout does not cancel the write or prove it failed. Keep the job ID and resume checking it rather than submitting the text under a new key.
- **Rate limit (`429`):** respect the server's retry delay, exposed as `retryAfterSeconds` when available. Status reads also use the delegate-key request budget. Immediate repeated polling can exhaust that budget without speeding up uploads.
- **Authentication or validation failure:** fix the credentials or payload before retrying. A `401 AUTH_REJECTED` or `409` key-reuse conflict does not become valid through backoff.
- **Terminal `failed` job:** inspect the job's error before deciding how to recover. Do not resubmit a failed upload indefinitely.

`waitForRememberJob` and `waitForRememberJobs` retry transient polling failures, including rate limits, within their timeout budget. In SDK 0.1.9:

| **Helper** | **First poll** | **Backoff** | **Default budget** |
| --- | --- | --- | --- |
| `waitForRememberJob` | Immediate | Jitter around 1.5 s, growing toward 5 s; server retry delay takes precedence | 60 s |
| `waitForRememberJobs` | Immediate | Same | 120 s |

The SDK retries polling only. It does not retry submissions or reads.

## Confirm durability before acting on a memory

`remember` and `rememberBulk` return when the relayer accepts the jobs. Embedding, encryption, upload, and indexing continue in the background. Return the accepted job IDs to the application and check completion in a background worker when the chat turn does not depend on the result. Avoid holding every turn open until storage finishes.

Use `rememberAndWait` or `rememberBulkAndWait` when the caller needs completion before proceeding. Otherwise, persist the IDs returned at acceptance and resume with the wait helpers before depending on the stored data. A single-job wait timeout raises `MemWalRememberJobTimeout` with its `jobId`; a bulk wait can report individual items as `timeout`, which also require later checks.

If no bulk status read succeeds and a confirming read is rate-limited, the bulk wait can throw `MemWalRateLimited` with `jobIds` and `retryAfterSeconds`. Keep the accepted IDs and schedule another status check after the cooldown; this error does not mean the jobs were canceled.

```ts
// In a background worker, load the IDs persisted at acceptance.
const settled = await memwal.waitForRememberJobs(acceptedBatch.job_ids);

const unfinished = settled.results.filter((r) => r.status !== "done");
if (unfinished.length > 0) {
  // Keep timeout items for a later status check; inspect failed items and errors.
  console.warn("Some writes are not confirmed:", unfinished);
}
```

<Warning>
A job reaches `done` after its vector row is inserted. This confirms storage and indexing, but does not guarantee that every semantic query returns it: namespaces, relevance, filters, and result limits still apply. An empty recall result alone is not evidence that the write failed, so do not submit a duplicate just to make it appear.
</Warning>

For the full write, confirm, and recall sequence in context, see [Agent Storage Loop](/sdk/agent-storage-loop).

## Bound cost

The managed relayer sponsors writes; see [Managed relayer costs](/relayer/public-relayer#storage-costs). The managed service applies usage limits, so bound your writes even though it pays.

- **Batch writes.** `rememberBulk` accepts up to 20 items and reduces submission and transaction overhead. Buffer small memories and flush them as a batch instead of writing one at a time; the call does not promise that all items become one Walrus blob.
- **Do not store what you never recall.** Ephemeral scratch state that never feeds a future `recall` does not belong in durable storage. Keep it in process memory.
- **Cap writes per cycle.** Give the agent loop a budget, for example a maximum number of memories per run or per hour, and have it drop or summarize past the cap rather than write unbounded.

```ts
let writesThisCycle = 0;
const MAX_WRITES_PER_CYCLE = 50;

// Sequential, single-process example. Use an atomic shared quota across workers.
async function budgetedRemember(memwal: MemWal, text: string, eventId: string) {
  if (writesThisCycle >= MAX_WRITES_PER_CYCLE) return false;
  await rememberOnce(memwal, text, eventId);
  writesThisCycle++;
  return true;
}
```

## Custody the agent's keys

A headless agent holds secrets no human rotates by hand, so treat them with production discipline.

- The **delegate key** authenticates the agent to the relayer.
- For client-managed encryption, the **Sui key** signs the Seal and Walrus operations. See [holding your own keys](/sdk/usage/memwal-manual#agent-state-holding-your-own-keys).

Load keys from a secret manager, never from source or logs. Give each agent its own delegate key for individual revocation; these keys still grant access across the account's namespaces. The owner can replace a lost delegate key without transferring memory ownership. Revocation does not cover already-read data; see [Ownership and access](/fundamentals/concepts/ownership-and-access#access-control-enforcement).

For client-managed encryption, losing the Sui key can make memories unrecoverable. Back it up securely; replacing a delegate key does not replace the lost encryption credentials.

## Degrade gracefully when memory is unavailable

A memory layer that is down should slow your agent, not stop it. Check reachability at startup and guard the memory paths so the agent keeps serving when the relayer is unreachable for a cycle.

```ts
let memory: MemWal | null = null;
try {
  memory = MemWal.create({ key, accountId, serverUrl, namespace });
  await memory.health();
} catch (err) {
  console.log("Memory unavailable, continuing without it this cycle:", err);
  memory = null;
}

// Guard every read and write on memory being live.
if (memory) {
  try {
    await budgetedRemember(memory, "Deploy completed.", "release-42-completed");
  } catch {
    // Leave the durable source event unacknowledged for a later retry.
    console.warn("Memory write deferred; continue serving this turn.");
  }
}
```

This is the same defensive pattern the [Cloudflare Workers guide](/sdk/cloudflare-workers) uses to keep a Worker healthy when the memory dependency has a bad moment.

## Mind the recall result cap

`recall` returns up to `limit` results, defaulting to `10`. When more memories match than the cap, the relayer does not return the extra results, with no signal that it truncated the set. If a decision depends on seeing every match, set `limit` explicitly to a value above what you expect, and treat a result count equal to `limit` as a sign there might be more.

```ts
const result = await memwal.recall({ query: "open incidents", limit: 50 });
if (result.results.length === 50) {
  console.warn("Recall hit the limit; there may be more matches than returned.");
}
```

## Next steps

- [Agent Storage Loop](/sdk/agent-storage-loop): the write, confirm, and recall loop these patterns harden
- [MemWalManual](/sdk/usage/memwal-manual): client-managed encryption and key custody
- [Troubleshooting](/troubleshooting/overview): auth, timeout, and read-after-write symptoms
- [Public relayer](/relayer/public-relayer): managed Mainnet and Testnet endpoints
