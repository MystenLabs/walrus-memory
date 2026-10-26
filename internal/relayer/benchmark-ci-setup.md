---
title: "Benchmark CI Setup"
description: >-
  Configuration guide for the Walrus Memory relayer benchmark CI workflows, including GitHub Environment setup, Railway relayer URLs, test accounts, and manual benchmark execution.
keywords:
  - Walrus Memory
  - MemWal
  - benchmark
  - CI
  - GitHub Actions
  - performance testing
goal:
  description: Set up the relayer benchmark GitHub Actions workflow, run it locally to baseline performance, and interpret throughput and latency results.
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
  - "How do I set up benchmark CI for the Walrus Memory relayer?"
  - "What GitHub environments and secrets are needed for MemWal benchmarks?"
  - "How do I run a manual recall latency benchmark against the relayer?"
answer: >-
  The relayer benchmark CI consists of a smoke workflow (pull requests, no secrets needed) and a live workflow (pushes to dev/staging and weekly runs). Live benchmarks run against Railway-hosted relayer endpoints using GitHub Environment secrets for delegate keys and account IDs, and results are uploaded as GitHub Actions artifacts.
---

# Benchmark CI Setup

This document records how to configure the relayer benchmark workflows.

The live benchmark intentionally runs only the public relayer `/api/recall`
path. Direct sidecar and Walrus upload benchmarks are out of scope because the
hosted GitHub runner cannot reach the internal sidecar in the current Railway
deployment.

## Workflows

- `.github/workflows/benchmark-smoke.yml`
  - Runs on pull requests and pushes that touch benchmark scripts, benchmark workflows, or this setup doc.
  - Runs `cargo check`.
  - Typechecks `bench-recall-latency.ts`.
  - Runs a `--help` smoke check for the recall benchmark CLI.
  - Does not need secrets and does not call Sui, Walrus, SEAL, or OpenAI.

- `.github/workflows/benchmark-live.yml`
  - Runs automatically on pushes to `dev` and `staging`.
  - Maps push benchmarks to `benchmark-dev` and `benchmark-staging`.
  - Runs manually via `workflow_dispatch` on a selected branch/ref and target environment.
  - Also runs weekly on Monday at 09:00 UTC against the default branch environment.
  - Uses one GitHub Environment per target: `benchmark-dev` or
    `benchmark-staging`.
  - Runs `bench-recall-latency.ts` against `POST /api/remember` and `POST /api/recall`.
  - Uses the `benchmark` namespace by default to isolate benchmark writes.
  - Uploads `benchmark-results/memory-api.json` as a GitHub Actions artifact.
  - Writes the benchmark markdown table into the Actions job summary.

## Relayer URLs

| Target | Public relayer URL | Sui network |
| --- | --- | --- |
| dev | `https://relayer.dev.memwal.ai` | `testnet` |
| staging | `https://relayer-staging.memory.walrus.xyz` | `testnet` |

## Benchmark Test Accounts

Do not commit account ids, public keys, or private keys. Store them in the
GitHub Environment for that target (`benchmark-dev` or `benchmark-staging`),
or in another secret manager.

## GitHub Environment Setup

Create these GitHub Environments:

- `benchmark-dev`
- `benchmark-staging`

For each environment, set this Variable:

| Variable | dev | staging |
| --- | --- | --- |
| `BENCH_SERVER_URL` | `https://relayer.dev.memwal.ai` | `https://relayer-staging.memory.walrus.xyz` |

For each environment, set these Secrets:

| Secret | dev/staging value |
| --- | --- |
| `BENCH_ACCOUNT_ID` | testnet account id, stored only as a secret |
| `BENCH_DELEGATE_KEY` | testnet private key, stored only as a secret |

## Manual Run

Remember and recall against staging:

```bash
cd services/server/scripts

./node_modules/.bin/tsx bench-recall-latency.ts \
  --server-url https://relayer-staging.memory.walrus.xyz \
  --account-id "$BENCH_ACCOUNT_ID" \
  --delegate-key "$BENCH_DELEGATE_KEY" \
  --namespace benchmark \
  --remember-text "benchmark memory" \
  --query "benchmark memory"
```
