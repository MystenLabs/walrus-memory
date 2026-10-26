---
title: "Run the Repo Locally"
description: >-
  Step-by-step guide to set up the Walrus Memory monorepo for local development,
  including prerequisites, SDK build, running apps, and optional backend services.
keywords:
  - Walrus Memory
  - MemWal
  - local development
  - monorepo
  - setup
  - contributing
goal:
  description: Clone the MemWal monorepo, install dependencies with pnpm, build the SDK, and start whichever app or backend service you need for local development.
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
  - "How do I set up the Walrus Memory monorepo for local development?"
  - "Why do I need to run pnpm build:sdk before starting MemWal apps?"
  - "What are the prerequisites for running MemWal locally?"
answer: >-
  Clone the repo, run pnpm install, then pnpm build:sdk to compile the SDK before starting
  any app. The apps depend on the SDK compiled output, so skipping the build causes import
  errors. Backend services like the relayer and indexer are optional for frontend development.
---

## Prerequisites

| Tool | Version | Check |
|------|---------|-------|
| **Node.js** | 22.23.4 (see `.nvmrc`) | `node -v` |
| **pnpm** | ≥ 9.12 | `pnpm -v` |
| **Rust** | latest stable (only for backend services) | `rustc --version` |

<Tip>
If you only work on TypeScript apps or docs, you don't need Rust.
</Tip>

## Step 1 — Clone and Install

```bash
git clone https://github.com/MystenLabs/MemWal.git
cd MemWal
nvm install
nvm use
pnpm install
```

If you use a different Node version manager, select the version in `.nvmrc` before installing dependencies.

If `pnpm install` fails while downloading Chrome for Puppeteer (HTTP 403 — common in CI, sandboxes, or corporate networks), skip the browser download:

```bash
PUPPETEER_SKIP_DOWNLOAD=true pnpm install
```

You only need the Chrome download when running Puppeteer-dependent tests or packages.

## Step 2 — Build the SDK First

<Warning>
The apps depend on the SDK's compiled output. If you skip this step, apps will fail to start with import errors.
</Warning>

```bash
pnpm build:sdk
```

This compiles `packages/sdk` → `packages/sdk/dist/`. The apps import from `@mysten-incubation/memwal`, which resolves to this compiled output via the workspace.

## Step 3 — Run What You Need

Run individual surfaces from the repository root:

```bash
# Docs site (Mintlify)
pnpm dev:docs

# Demo apps (pick one)
pnpm dev:app          # Playground dashboard
pnpm dev:noter        # Note-taking app
pnpm dev:chatbot      # AI chatbot
pnpm dev:researcher   # Research assistant

# SDK in watch mode (recompiles on changes)
pnpm dev:sdk
```

## Step 4 — Backend Services (Optional)

The TypeScript apps talk to a managed relayer by default. You only need to run backend services if you're working on the relayer or indexer.

### Relayer (`services/server`)

Requires:
- PostgreSQL with `pgvector` extension
- Sui RPC access
- Walrus endpoints
- Embedding provider credentials (OpenAI-compatible)

Quick start:

```bash
# Start PostgreSQL with pgvector
docker compose -f services/server/docker-compose.yml up -d postgres

# Configure environment
cp services/server/.env.example services/server/.env
# Edit .env with your credentials

# Install sidecar dependencies
cd services/server/scripts && npm ci && cd ..

# Run the relayer
cargo run
```

For the full relayer setup guide, see [Self-Hosting](/relayer/self-hosting).

### Indexer (`services/indexer`)

```bash
cd services/indexer
cargo run
```

The indexer polls Sui events and syncs account data into PostgreSQL.

## Monorepo Structure

```
MemWal/
├── packages/
│   ├── sdk/                     # @mysten-incubation/memwal — TypeScript SDK
│   └── openclaw-memory-memwal/  # @mysten-incubation/oc-memwal — OpenClaw plugin
├── apps/
│   ├── app/         # Playground dashboard
│   ├── chatbot/     # AI chatbot demo
│   ├── noter/       # Note-taking demo
│   └── researcher/  # Research assistant demo
├── services/
│   ├── server/      # Rust relayer (Axum)
│   ├── indexer/     # Rust Sui event indexer
│   └── contract/    # Move smart contract
├── docs/            # Mintlify documentation site
└── SKILL.md         # Agent-first integration guide
```

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `Cannot find module '@mysten-incubation/memwal'` | SDK not built | Run `pnpm build:sdk` first |
| `ERR_MODULE_NOT_FOUND` in apps | Stale SDK build | Run `pnpm build:sdk` again |
| `pnpm install` fails | Wrong pnpm version | Use pnpm ≥ 9.12: `corepack enable && corepack prepare pnpm@9.12.3 --activate` |
| `pnpm install` fails on Puppeteer Chrome download (403) | Network blocks Chrome download | `PUPPETEER_SKIP_DOWNLOAD=true pnpm install` |
| Docs site won't start | Missing Mintlify | Run `pnpm install` from the root |
| Relayer crashes on boot | Missing pgvector | Install the `pgvector` PostgreSQL extension |
| Sidecar timeout | Missing sidecar deps | Run `cd services/server/scripts && npm ci` |

## See Also

- [Run Docs Locally](/contributing/run-docs-locally) — just the docs site
- [Self-Hosting](/relayer/self-hosting) — full relayer deployment
- [Environment Variables](/reference/environment-variables) — relayer configuration
