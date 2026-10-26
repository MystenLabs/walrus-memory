# Walrus Memory Retrieval Quality Benchmarks

A Python harness that runs industry-standard memory benchmarks (LOCOMO, LongMemEval) against Walrus Memory and compares composite scoring presets against pure cosine similarity. Results are saved as JSON artifacts with per-query detail for inspection.

> **Scope.** This is the **AI-quality** harness — it measures *memory-retrieval quality* (given a question, does the right memory come back). It is the complement to the **latency** benchmarks under `services/server/scripts/bench-*.ts`, which measure Walrus throughput / SEAL decrypt latency / sidecar concurrency. Different concerns, different tools.
>
> It runs against the server in **`BENCHMARK_MODE=true`** (the `PlaintextEngine` path — memories stored as plaintext in Postgres, bypassing SEAL + Walrus). `analyze` in that mode ingests *synchronously* (the response carries the stored ids and `status: "done"`), matching the SDK's pre-async analyze contract this harness was written against. Running through the production path would burn Walrus testnet quota measuring something this benchmark isn't testing. `BENCHMARK_MODE` is off by default and **not for production use**.

---

## TL;DR — first run

```bash
# 1. Local infra: Postgres + Redis (the server needs BOTH to boot)
docker compose -f services/server/docker-compose.yml up -d

# 2. Server .env (services/server/.env) — benchmark section:
#      BENCHMARK_MODE=true
#      RATE_LIMIT_DISABLED=1
#      PORT=3001
#    ...plus the always-required DATABASE_URL / MEMWAL_PACKAGE_ID /
#    MEMWAL_REGISTRY_ID / a reachable SUI_RPC_URL + OPENAI_API_KEY.
#    (Copy from services/server/.env.example — benchmark section at bottom.)

# 3. Start the server — wait for the "BENCHMARK_MODE=true — using
#    PlaintextEngine" warning in the logs.
cd services/server && cargo run

# 4. Harness setup (one-time)
cd services/server/benchmarks
python3 -m venv .venv && source .venv/bin/activate
python ../../../scripts/bootstrap-python-security.py
python -m pip install --require-hashes -r requirements.lock
cp config.example.yaml config.yaml
#   edit config.yaml: delegate_key, account_id, judge.api_key (OpenRouter/OpenAI)

# 5. Download a dataset (one-time per benchmark)
python run.py download locomo

# 6. Run it (ingest + eval both presets)
python run.py full locomo --presets baseline,importance_heavy
#   comparison table prints at the end; per-preset JSON lands in results/
```

**Network is required even in benchmark mode** — SEAL + Walrus are bypassed,
but auth still verifies the delegate key against Sui RPC on every request,
and embeds/judging hit OpenAI/OpenRouter. If your connection drops mid-run,
recall starts returning 401 (Sui RPC unreachable) and the run is junk —
kill it rather than trust the numbers.

The rest of this doc is the detailed reference behind each step.

---

**Current supported benchmarks** (runtime at `concurrency: 10`, full e2e mode, two presets):

| Benchmark | Status | Typical cost | Runtime (ingest + 2 eval presets) |
|---|---|---|---|
| LOCOMO | ✅ Validated | ~$3-9 | ~60-90 min |
| LongMemEval | ✅ Validated | ~$2-4 | ~2-2.5 hr |

Runtime scales with the pre-extraction context work — each
`/api/analyze` call now does an extra embed + search + decrypt round-trip
before extraction, so ingest is slower than the earlier numbers. LME
is the longer run (10,960 turns vs LOCOMO's 5,882).

Run artifacts are written to `results/` (gitignored). Each run produces
per-preset JSON files plus a session-map JSON — see
[Interpreting results](#interpreting-results). Keep durable copies of
the runs you care about somewhere outside `results/`, since it's
gitignored and gets overwritten by run-id collisions.

---

## The two-config story

Running a benchmark involves two cooperating systems, each with its own config:

```
┌──────────────────────────┐          ┌──────────────────────────┐
│ Walrus Memory server     │  ◄────── │   Benchmark harness      │
│                          │   HTTP   │   (this directory)       │
│   config: ../.env        │          │   config: config.yaml    │
└──────────────────────────┘          └──────────────────────────┘
        must run first                      runs against it
```

**Walrus Memory server** reads from `services/server/.env`. For benchmarks this needs `BENCHMARK_MODE=true` and bumped rate limits. See `services/server/.env.example` for the benchmark section at the bottom.

**Benchmark harness** reads from `benchmarks/config.yaml`. This holds credentials for the Walrus Memory server (delegate key + account ID) and the LLM provider (API key for GPT-4o judge). See `benchmarks/config.example.yaml`.

Don't confuse the two. The benchmark harness does **not** read the server's `.env`, and the server does **not** read `config.yaml`.

---

## Prerequisites

1. **Walrus Memory server running locally with `BENCHMARK_MODE=true`.** This is critical — see [Server setup for benchmarks](#server-setup-for-benchmarks) below.
2. **Postgres + Redis.** Start via `docker compose -f services/server/docker-compose.yml up -d`.
3. **A supported patched Python 3.11+** (3.11.17, 3.12.15, 3.13.17, or 3.14.9 and newer patches in those series).
4. **A registered Walrus Memory account** with a delegate key. Get one from the Walrus Memory app or via the SDK.
5. **An OpenRouter or OpenAI API key** with GPT-4o access.

---

## Server setup for benchmarks

Benchmarks need the Walrus Memory server configured specifically. In
`services/server/.env` (the benchmark section at the bottom of
`.env.example` has these ready to uncomment):

```bash
# Required — enables the plaintext storage backend that bypasses
# SEAL encryption and Walrus upload. This makes the server safe to
# benchmark (no real blockchain interactions) but UNSAFE for
# production data.
BENCHMARK_MODE=true

# The harness defaults to http://localhost:3001 (benchmarks/config.yaml).
# The server defaults to PORT=8000, so set this to match — or change the
# `server.url` in config.yaml to point at 8000. They just have to agree.
PORT=3001

# Required — default rate limits (60/min) are too low for parallel
# benchmark workers, which would hit 429s. Simplest is to bypass the
# request-rate buckets entirely (storage quota + auth still apply;
# logs a loud warning at startup):
RATE_LIMIT_DISABLED=1

# ...or, instead of full bypass, raise the individual limits:
# RATE_LIMIT_REQUESTS_PER_MINUTE=100000
# RATE_LIMIT_REQUESTS_PER_HOUR=1000000
# RATE_LIMIT_DELEGATE_KEY_PER_MINUTE=100000
```

These are *in addition to* the always-required server config — even in
benchmark mode the server panics on startup without `DATABASE_URL`,
`MEMWAL_PACKAGE_ID`, and `MEMWAL_REGISTRY_ID`, and auth still needs a
reachable `SUI_RPC_URL` to verify the delegate key on-chain (benchmark
mode bypasses SEAL + Walrus storage, **not** auth). Copy the full
`.env.example` and fill those in; the `SERVER_SUI_PRIVATE_KEY*` /
`SIDECAR_*` / `WALRUS_*` keys are *not* needed in benchmark mode (the
`PlaintextEngine` never touches SEAL or Walrus).

Migrations apply **automatically on server startup** — they're embedded
via `include_str!` in `src/storage/db.rs` and run in order against
`DATABASE_URL`. There is no manual `sqlx migrate` step. The benchmark
plaintext column is added by `migrations/008_benchmark_plaintext.sql`
(the `importance` column the ranker reads is `009_importance_signal.sql`);
both apply on first boot against a fresh database.

Start the server:

```bash
cd services/server && cargo run
```

Look for the benchmark-mode warning in the startup logs — it confirms the
`PlaintextEngine` is active (emitted from `src/main.rs`):

```
WARN ⚠️  BENCHMARK_MODE=true — using PlaintextEngine.
WARN ⚠️  Memories will be stored UNENCRYPTED in Postgres.
WARN ⚠️  This is a benchmark-only mode. UNSAFE for production.
```

---

## Benchmark harness setup

```bash
cd services/server/benchmarks

# Create a venv with a supported patched Python 3.11+
python3 -m venv .venv
source .venv/bin/activate

# Bootstrap pip from the checksum-pinned wheel, then install the locked dependencies
python ../../../scripts/bootstrap-python-security.py
python -m pip install --require-hashes -r requirements.lock

# Configure
cp config.example.yaml config.yaml
# Edit config.yaml: delegate_key, account_id, OpenRouter API key
```

Verify your config and server connection:

```bash
python run.py report  # lists what's in results/
```

If the harness can't reach the server, you'll see `ERROR: Cannot reach server at http://localhost:3001`.

---

## Running a benchmark

One-time per benchmark — download the dataset:

```bash
python run.py download locomo
python run.py download longmemeval
```

The `full` command runs ingestion + evaluation for all specified presets:

```bash
python run.py full locomo --presets baseline,default,recency_heavy
python run.py full longmemeval --presets baseline,default,recency_heavy
```

Available presets (in `presets/`). Weights shown as
`semantic / recency / importance`:

- `baseline` — pure cosine (`1.0 / 0.0 / 0.0`). Server-default ordering; the no-op-at-default contract.
- `default` — balanced (`0.5 / 0.2 / 0.2`)
- `recency_heavy` — temporal-focused (`0.3 / 0.4 / 0.2`)
- `importance_heavy` — prioritizes high-importance memories (`0.3 / 0.2 / 0.4`)

> **Note on `frequency`.** The preset YAMLs still carry a `frequency`
> key for forward-compat, but the server's `ScoringWeights`
> (`src/types.rs`) has no `frequency` field yet — it's silently ignored
> on the wire. Access-frequency is a *deferred* ranker signal (needs a
> write-on-read schema decision). Until it lands, the `frequency` value
> in any preset has no effect.

The signals the ranker actually consumes:

- **semantic** — `1 - cosine_distance` (always available)
- **recency** — `2^(-age_days / recency_half_life_days)` from `created_at`
- **importance** — the per-fact bucket score (`vital`/`standard`/`trivial`
  → `0.9`/`0.5`/`0.2`) the extractor emits at write time, persisted on
  `vector_entries.importance`. Default-0 weight means it's
  opt-in; presets that set it non-zero activate it.

### Splitting ingestion and eval

Ingestion is expensive (~20-40 min). Evaluation is cheap (~3-10 min per preset). Split them if you want to iterate on scoring:

```bash
# Run ingestion once
python run.py ingest longmemeval --run-id my-run
# Reuse that ingestion across multiple eval passes
python run.py compare longmemeval --presets baseline,default --run-id my-run --skip-ingest
python run.py compare longmemeval --presets recency_heavy,importance_heavy --run-id my-run --skip-ingest
```

### Cleaning up

```bash
python run.py cleanup --run-id my-run
```

This soft-deletes all memories in the run's benchmark namespaces.

---

## Interpreting results

### What the harness writes to `results/`

Every run writes JSON artifacts to `results/` (the directory is created
on demand — `RESULTS_DIR` in `run.py`). After a `full`/`compare` run you
get, per preset:

```
results/
  <run-id>-<benchmark>-<preset>.json     # one per preset (baseline, importance_heavy, ...)
  <run-id>-<benchmark>-session_map.json  # session → memory-id map (shared across presets)
```

For example, the LME run produced:

```
mem57-lme-20260520T144014Z-longmemeval-baseline.json
mem57-lme-20260520T144014Z-longmemeval-importance_heavy.json
mem57-lme-20260520T144014Z-longmemeval-session_map.json
```

Each per-preset artifact contains:
- `config` — scoring weights, models, recall limit, timestamp
- `prompt_versions` — `{ extract, ask }` so deltas attribute to the prompt
- `metrics_overall` + `metrics_by_category` — the J-scores (the headline numbers)
- `query_results` — per-query detail (question, ground truth, retrieved
  memories, generated answer, judge scores) for failure-mode inspection
- `ingestion` — counts + cost

### Seeing the comparison table

The `full` and `compare` commands **print a comparison table to stdout**
at the end of the run (presets side-by-side, with published memory-system /
Supermemory reference columns from `reference_scores/`). It is not
written to a file — to regenerate it later from the saved artifacts:

```bash
python run.py report --benchmark locomo      # rebuild the table from results/
python run.py report                         # all benchmarks present in results/
```

### Prose analysis is not auto-generated

The harness does **not** write a markdown summary (no `summary.md` /
`detailed-report.md`) — only the JSON artifacts and the stdout
comparison table. Per-category analysis, comparison with published
numbers (published memory-system baselines), failure-mode breakdowns, and
root-cause notes when numbers don't match expectations are written by
hand from the JSON `query_results`. The published reference numbers the
comparison table uses are in `reference_scores/{locomo,longmemeval}.yaml`.

### J-score interpretation

The LLM judge scores 4 dimensions (1-5 each), normalized to 0-100:

| J-score | Meaning |
|---|---|
| 80+ | Strong — answer is factually correct and complete |
| 50-79 | Partial — right direction, missing details |
| <50 | Failed — wrong, empty, or hallucinated |

Variance across runs is ~±2-3 points due to judge non-determinism. Retrieval itself is deterministic given fixed weights.

---

## Troubleshooting

### 426 Upgrade Required
- The client's request signing is out of date with the server's auth scheme
  (`services/server/src/auth.rs`). `client.py::_sign_request` must send an
  `x-nonce` header (UUIDv4) and sign the 6-field canonical message
  `{timestamp}.{method}.{path_and_query}.{body_sha256}.{nonce}.{account_id}`. If you see
  426 on every request, the harness predates the current nonce / account-id
  account-id-in-message changes — update `_sign_request` to match `auth.rs` and
  `packages/sdk/src/memwal.ts`.

### 401 Unauthorized
- Delegate key not registered on-chain for the account_id — use the app or SDK to register
- Account ID mismatch — double-check `x-account-id` matches the account where the key is registered
- Auth is mode-blind: even in `BENCHMARK_MODE`, every `/api/*` request must
  pass Ed25519 verification AND resolve to a real on-chain `MemWalAccount`
  whose `delegate_keys` contains the request key — so the server still needs a
  reachable `SUI_RPC_URL`.

### 429 Too Many Requests
- Rate limits too low — add the `RATE_LIMIT_*` overrides in `services/server/.env`
- Reduce `eval_concurrency` in `config.yaml`

### Server unreachable
- Server not running — check `cargo run` output in `services/server/`
- Wrong URL in `config.yaml`

### BENCHMARK_MODE warnings missing from startup
- `.env` didn't load — check you're in `services/server/` when running `cargo run`
- Typo — it's `BENCHMARK_MODE=true`, case-sensitive

### Unsupported Python or old certificates
- Recreate the venv with a patched Python 3.11+ interpreter. Python 3.9/3.10 are no longer supported.
- Run the checksum-verified pip bootstrap and install `requirements.lock` as shown above. Updating system Python does not change existing venvs.

---

## Architecture

```
benchmarks/
  run.py                   # CLI: download / ingest / eval / compare / full / report / cleanup
  config.example.yaml      # Template — copy to config.yaml and fill in
  config.yaml              # Your credentials (gitignored)
  pyproject.toml

  core/
    types.py               # Shared dataclasses (Conversation, Query, ...)
    client.py              # Walrus Memory HTTP client with Ed25519 signing
    metrics.py             # Recall@K, MRR, nDCG, F1
    judge.py               # LLM-as-Judge with fixed prompts (don't modify between runs)
    report.py              # Markdown comparison table generator

  benchmarks/              # One adapter per benchmark
    base.py                # BenchmarkAdapter contract
    locomo.py              # ✅ validated
    longmemeval.py         # ✅ validated

  presets/                 # Scoring weight configurations
    baseline.yaml
    default.yaml
    recency_heavy.yaml
    importance_heavy.yaml

  datasets/                # Downloaded datasets (gitignored)
  results/                 # Raw run artifacts (gitignored — copy out anything
                           # you want to keep; run-id collisions overwrite)
  tests/
    test_metrics.py        # Unit tests for metric implementations
```

### Key design choice: ingest once, score many

Scoring weights are **per-request parameters** in `/api/recall`. Ingestion is done once, then any number of scoring presets can be evaluated against the same stored memories without re-ingesting. This is why `full` command runs ingestion then loops over presets.

### Adding a new benchmark

1. Download a sample of the real dataset — **never** guess schema
2. Create `benchmarks/<name>.py` subclassing `BenchmarkAdapter`
3. Implement `download()` and `load()` — `load()` must return `(list[Conversation], list[Query])` with correct category names matching your `categories` class attribute
4. Add to `benchmarks/__init__.py` `BENCHMARKS` dict
5. Add `VALIDATED = True` once you've run at least 10 queries end-to-end
6. Run `python run.py full <name> --presets baseline` on a small slice to sanity check

See `locomo.py` and `longmemeval.py` for reference implementations. Both had schema surprises vs the HuggingFace documentation — inspecting the real files first prevented wasted API calls.

---

## Running the tests

```bash
source .venv/bin/activate
PYTHONPATH=. pytest tests/ -v
```

All 20 metric tests should pass.
