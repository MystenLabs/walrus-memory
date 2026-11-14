---
title: "Walrus Memory"
description: >-
  The recommended default MemWal client where the relayer handles embeddings, SEAL encryption, Walrus upload, and vector indexing. Covers core methods like remember, recall, analyze, and restore.
keywords:
  - Walrus Memory
  - MemWal
  - remember
  - recall
  - analyze
  - restore
goal:
  description: Call remember(), recall(), analyze(), and restore() on the default MemWal client and understand the parameters and return values for each operation.
  requires:
    - has_frontmatter:
        - title
        - description
        - keywords
      label: Has required frontmatter fields
    - min_words: 200
      label: Needs more content depth
    - has_questions: true
      label: Needs questions for AI search visibility
    - has_answer: true
      label: Needs answer summary for AI citation
questions:
  - How do I use the default Walrus Memory client?
  - What methods does the MemWal client provide?
  - How does remember and recall work in Walrus Memory?
answer: >-
  The default MemWal client is the recommended entry point where the relayer handles embeddings, SEAL encryption, Walrus upload, and vector indexing. It provides remember() for storing memories, recall() for semantic search, analyze() for fact extraction, and restore() for rebuilding missing index entries.
---

The recommended default client. The relayer handles embeddings, SEAL encryption, Walrus upload, and vector indexing.

## How It Works

1. The SDK signs each request with your delegate key
2. The relayer verifies delegate access
3. `remember` returns an accepted job while the relayer encrypts, uploads, and indexes in the background
4. `recall` searches by Memory Space and returns decrypted matches

```ts
import { MemWal } from "@mysten-incubation/memwal";

const memwal = MemWal.create({
  key: process.env.MEMWAL_KEY ?? "<your-ed25519-private-key>",
  accountId: process.env.MEMWAL_ACCOUNT_ID ?? "<your-memwal-account-id>",
  serverUrl: process.env.MEMWAL_SERVER_URL ?? "https://relayer.memory.walrus.xyz",
  namespace: "chatbot-prod",
});
```

<Warning>
**Pass plaintext to `remember()`**: The default `MemWal` client sends `text` to the relayer so the relayer can generate a vector embedding and encrypt the payload with Seal. If you encrypt `text` on the client first and pass ciphertext to `remember()`, the relayer embeds the ciphertext bytes — the write succeeds, but semantic `recall()` will not match natural-language queries. For zero-trust client-side encryption where the relayer never sees plaintext, use [`MemWalManual`](/sdk/usage/memwal-manual) (`rememberManual` / `recallManual`) and compute embeddings on the client before encrypting.
</Warning>

## Core Methods

```ts
// Store a memory
const job = await memwal.remember("User prefers dark mode and works in TypeScript.");
await memwal.waitForRememberJob(job.job_id);

// Recall relevant memories
const result = await memwal.recall({ query: "What do we know about this user?", limit: 5 });

// Extract and store facts from longer text
const analyzed = await memwal.analyze(
  "I live in Hanoi, prefer dark mode, and usually work late at night."
);
console.log(analyzed.job_ids);

// Check relayer health
await memwal.health();
```

## Restore

Rebuild missing indexed entries for one namespace. Incremental, namespace-scoped, and meant to
repair PostgreSQL vector state from Walrus-backed memory.

```ts
const result = await memwal.restore("chatbot-prod", 10);
```

## Lower-Level Methods

Use these when you already have a vector or encrypted payload:

- `rememberManual({ encryptedData, vector, namespace? })`
- `recallManual({ vector, limit?, namespace? })`
- `embed(text)`
