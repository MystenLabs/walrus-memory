---
title: Managed Relayer
description: >-
  Use the Walrus Foundation-hosted managed relayer to get started with Walrus Memory without running infrastructure. Covers available endpoints, minimal SDK configuration, and the trust and availability trade-offs of the shared deployment.
keywords:
  - Walrus Memory
  - MemWal
  - managed relayer
  - public relayer
  - hosted endpoint
  - getting started
goal:
  description: Configure the SDK to use the managed Walrus Memory relayer, understand which data it can access and what that means for trust, and decide when to switch to a self-hosted alternative.
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
  - "What is the Walrus Memory managed relayer URL?"
  - "How do I connect to the public MemWal relayer?"
  - "What are the trade-offs of using the managed Walrus Memory relayer?"
answer: >-
  The Walrus Foundation hosts managed relayer endpoints for production (mainnet) at relayer.memory.walrus.xyz and staging (testnet) at relayer.dev.memwal.ai. The managed relayer provides the fastest integration path but involves trusting the hosted instance with plaintext during encryption, sharing the deployment with other users, and accepting that the service carries no SLA guarantees.
---

A managed relayer is a simpler experience for teams that want to get started without running infrastructure. If a managed relayer endpoint is available for your environment, it gives you the fastest path to integration.

## Walrus Foundation hosted endpoints

| **Network** | **Relayer URL** |
|---|---|
| **Production** (mainnet) | `https://relayer.memory.walrus.xyz` |
| **Staging** (testnet) | `https://relayer.dev.memwal.ai` |

## Minimal Config

```ts
import { MemWal } from "@mysten-incubation/memwal";

const memwal = MemWal.create({
  key: "<your-ed25519-private-key>",
  accountId: "<your-memwal-account-id>",
  serverUrl: "https://relayer.memory.walrus.xyz",
  namespace: "demo",
});
```

## What to Know

- **Shared App ID** - all users of the managed relayer share the same Walrus Memory package ID. Your own `owner + namespace` (Memory Space) isolates your data, but the underlying deployment is shared.
- **Trust assumption** - the relayer sees plaintext during encryption and embedding. By using the managed relayer, you're trusting the Walrus Foundation-hosted instance with that data. See [Trust and Security Model](/fundamentals/architecture/data-flow-security-model) for details.
- **Availability** - the Walrus Foundation provides the managed relayer as a public good without SLA guarantees.
- **No direct browser access to the main API** - the managed relayer's main API only allows cross-origin requests from Walrus Memory's own apps. For any other origin, preflight and `GET` responses on the main API carry no `Access-Control-Allow-Origin`, so the browser blocks them — call the main relayer API from your server, or through a same-origin proxy, and keep the delegate key server-side (a self-hosted relayer can allow your origins with `ALLOWED_ORIGINS`). As an intentional exception, the emergency [security-delete endpoints](/api/security-delete) (`/api/security-deletable-blobs` and `/api/security-delete`) always send `Access-Control-Allow-Origin: *` so browser-based recovery and deletion tools can call them directly without a backend proxy.

## Storage costs

The managed relayer covers WAL storage fees and SUI gas through its server wallets and configured gas sponsor. Account holders do not pay gas or WAL for these relayed writes. Account ownership does not determine which wallet pays for an upload. The shared service applies usage limits.

With a [self-hosted relayer](/relayer/self-hosting), you fund the relayer deployment.

If you need full control over the trust boundary or your own dedicated instance, see [Self-Hosting](/relayer/self-hosting).
