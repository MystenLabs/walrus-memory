# @mysten-incubation/memwal

Walrus Memory SDK for storing encrypted AI memories on Walrus and retrieving them with semantic search.

> Walrus Memory is currently in beta and actively evolving. While fully usable today, we continue to refine the developer experience and operational guidance. We welcome feedback from early builders as we continue to improve the product.

## Node.js runtime

Use a supported, security-patched Node.js runtime: **22.23.4+ within 22.x**, **24.22.1+ within 24.x**, or **26.12.1+ within 26.x**. The package `engines` field describes API compatibility, not the minimum security patch. See the [October 2026 Node.js security release](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases).

## Documentation

For full documentation, visit [memory.walrus.xyz](https://memory.walrus.xyz).

## Install

```bash
pnpm add @mysten-incubation/memwal
```

Peer dependencies (install as needed):

```bash
pnpm add @mysten/sui @mysten/seal @mysten/walrus ai zod
```

### Version compatibility

`@mysten/seal` and `@mysten/walrus` must both resolve to versions that accept the same `@mysten/sui` major. Known-good matrix:

| Package | Version |
| --- | --- |
| `@mysten/sui` | `^2.16.2` |
| `@mysten/seal` | `^1.1.3` |
| `@mysten/walrus` | `^1.1.7` |

`@mysten/walrus@0.x` bundles `@mysten/sui@1.x` and cannot coexist with `@mysten/seal@1.x`, which requires `@mysten/sui@^2.x`. If `npm install` fails with `ERESOLVE` mentioning `@mysten/sui@^1.x`, upgrade `@mysten/walrus` to `^1.1.7`, refresh your lockfile, and run `npm why @mysten/sui` to find any remaining dependency that pins sui v1.

## Quick Start

```ts
import { MemWal } from "@mysten-incubation/memwal";

const memwal = MemWal.create({
  key: process.env.MEMWAL_PRIVATE_KEY!,
  accountId: process.env.MEMWAL_ACCOUNT_ID!,
  serverUrl: process.env.MEMWAL_SERVER_URL ?? "https://relayer.memory.walrus.xyz",
  namespace: "demo",
});

await memwal.rememberAndWait(
  "User prefers dark mode and uses TypeScript.",
  undefined,
  { timeoutMs: 30_000 },
);
const memories = await memwal.recall({
  query: "What are the user's preferences?",
  topK: 10,
  maxDistance: 0.8,
});
await memwal.restore("demo");
```

`0.8` is a starting point for the distance cutoff. Calibrate `maxDistance`
against your own memories and query phrasing: lower values reduce noise, while
higher values preserve more relevant matches.

If you are self-hosting the relayer and do not have an account ID yet, see [Self-Hosting](../../docs/relayer/self-hosting.md) for the account creation and delegate key setup flow.

## Offline tests and CI

`MemWalMock` implements the core async memory API entirely in memory. It requires no key, account, relayer, chain, or paid storage and uses deterministic token-overlap ranking.

```ts
import { MemWalMock } from "@mysten-incubation/memwal";

const memwal = MemWalMock.create({ namespace: "test-user" });
await memwal.rememberAndWait("The user prefers dark mode");

const result = await memwal.recall({ query: "display preference" });
expect(result.results[0].text).toContain("dark mode");
```

The mock supports remember/job polling, bulk remember, recall, analyze, embed, health, restore, `forget(blobId)`, and `clear(namespace?)`. For deterministic behavior, `analyze` stores its full input as one fact instead of invoking an LLM extractor. Its simple relevance score is for application tests, not production search-quality evaluation.

## Write-path validation & secret screening

`remember()`, `rememberAndWait()`, and `rememberBulk*()` validate input text client-side before signing or sending requests:
- Rejects empty/whitespace-only text and inputs exceeding `MAX_REMEMBER_TEXT_BYTES` (1 MiB)
- Screens for high-confidence credential patterns (`suiprivkey1...` Bech32 keys, PEM private keys, vendor API keys, JWTs, URL userinfo credentials, auth headers, labelled seed phrases, and labelled key material) and throws `MemWalValidationError` (`code: "secret_pattern_detected"`) by default

Use `validateRemember(text)` (or `{ dryRun: true }`) to inspect validation results offline without contacting the relayer, or pass `{ allowSecrets: true }` (alias `{ skipValidation: true }`) when storing synthetic test fixtures intentionally.

## Exports

| Entry | Description |
|---|---|
| `@mysten-incubation/memwal` | Default client (`MemWal`) and offline test client (`MemWalMock`). The production client delegates embedding, encryption, storage, retrieval, and restore to the relayer. |
| `@mysten-incubation/memwal/manual` | Manual client flow (`MemWalManual`). You handle embedding calls and local SEAL operations. The relayer still handles upload relay, registration, search, and restore. |
| `@mysten-incubation/memwal/ai` | Vercel AI SDK integration - wraps `MemWal` as middleware for use with `streamText`, `generateText`, etc. |

## How It Works

1. **Scope** - Each memory operation runs inside an `owner + namespace` boundary
2. **Store** - The relayer embeds, encrypts, uploads to Walrus, and stores vector metadata in PostgreSQL
3. **Recall** - The relayer searches by owner plus namespace, resolves matching blobs, and returns plaintext results
4. **Restore** - The relayer can incrementally rebuild missing indexed entries for one namespace

## License

Apache 2.0 — see [LICENSE](../../LICENSE)
