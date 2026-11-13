---
title: "Walrus Memory Architecture"
description: >-
  C4 container diagram of Walrus Memory: what each component does, how data
  flows between them, and its external dependencies.
keywords:
  - Walrus Memory
  - architecture
  - C4
---

# Walrus Memory architecture

This page shows the logical components of Walrus Memory, the data flows
between them, and their trust boundaries. It is checked against the code in
this repository. Environment-specific deployment details, such as hosting,
hostnames and service inventory, are kept in internal documentation.

`c4-container.puml` is the source of truth, and `c4-container.png` is
rendered from it; see [Rendering the diagram](#rendering-the-diagram).

## Containers (C4 level 2)

![Walrus Memory containers](c4-container.png)

| Container | Code | What it does |
| --- | --- | --- |
| Relayer API | `services/server/src` (Rust, axum) | The public HTTPS API. It verifies Ed25519 signed requests and applies rate limits. It runs remember, recall, restore, analyze and ask, and queues remember jobs in Postgres with apalis. It is also the OAuth authorization server for MCP connectors, serves the owner-token read API that Walrus Console uses, sponsors transactions and runs security delete. |
| Sidecar | `services/server/scripts` (Node.js, TypeScript) | Deployed together with the relayer and reachable only from it, on localhost with a shared secret. It does Seal encryption and decryption (in a separate listener process so uploads cannot stall recall), Walrus uploads, and blob metadata and transfer transactions signed by the server wallets, with Enoki sponsorship. It also hosts the MCP server, which the relayer proxies at `/api/mcp`. |
| Indexer | `services/indexer` (Rust, `sui-indexer-alt-framework`) | Reads Sui checkpoints from the checkpoint bucket, decodes `account::AccountCreated` events of the Memory package, and writes the `accounts` read model and its watermarks to Postgres. |
| Dashboard | `apps/app` (React, Vite) | A single-page app that runs in the owner's browser. Owners sign in with a Sui wallet or Google zkLogin through Enoki, create accounts and delegate keys, browse and delete memories, and approve MCP OAuth sign-ins. The browser talks to Sui, Enoki, Seal and Walrus directly, so transactions are signed on the owner's device. |
| MCP connector | `packages/mcp` (`@mysten-incubation/memwal-mcp`) | Runs on the user's machine. It bridges an MCP client's stdio to the relayer's remote MCP endpoint and handles first-run wallet login. Claude.ai custom connectors skip it and talk to `/api/mcp` with OAuth. |
| Database | PostgreSQL with pgvector | Memory vectors (HNSW, cosine), blob and namespace metadata, the job queue, OAuth clients and sessions, owner tokens, quotas and the accounts read model. It is the only full copy of jobs, OAuth state, owner tokens and quotas: a Walrus restore brings back blobs, not these. |
| Cache | Redis | The signed-request nonce replay guard, rate-limit counters and short-lived caches. Auth fails closed when Redis is down. |

### External dependencies

| Dependency | Used by | What for |
| --- | --- | --- |
| Sui fullnode | Relayer, sidecar, dashboard | The sidecar and the dashboard use gRPC. The relayer chooses its transport from configuration at startup: gRPC when `SUI_GRPC_URL` is set, JSON-RPC otherwise. A failed gRPC request does not fall back to JSON-RPC. `/config` also publishes a JSON-RPC URL for SDK compatibility. The sidecar uses GraphQL for archive reads. |
| Sui checkpoint bucket | Indexer | Checkpoint ingestion. |
| Walrus | Sidecar (writes), relayer and dashboard (reads) | Stores the Seal-encrypted memory blobs. Writes go through an upload relay or a publisher. For recall and restore, the relayer reads the encrypted blobs from aggregators (racing several) and has the sidecar decrypt them with Seal. |
| Seal key servers | Sidecar, dashboard | Release decryption keys when the onchain policy allows it. |
| Enoki | Sidecar, dashboard | Gas sponsorship, and zkLogin for Google sign-in. |
| LLM gateway (OpenAI-compatible) | Relayer | `text-embedding-3-small` embeddings, fact extraction, consolidation, ranking and ask. |
| Operations tooling | Relayer | OTLP logs and traces and Prometheus metrics to a telemetry backend, and Slack alerts for gas pool, wallet balance, embedding provider and sidecar saturation. |
| Walrus Console | Calls the relayer | Mints owner-scoped `memories.read` tokens and lists an owner's agents. |

## Rendering the diagram

The diagram uses C4-PlantUML from the PlantUML standard library. Render it
locally with Docker rather than a public render server. From this directory:

```bash
docker run --rm -v "$PWD:/data" plantuml/plantuml -tpng /data/c4-container.puml
```

In Git Bash on Windows, prefix the command with `MSYS_NO_PATHCONV=1`.
