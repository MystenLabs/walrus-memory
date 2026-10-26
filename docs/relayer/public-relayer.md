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
  The Walrus Foundation hosts managed relayer endpoints for production (mainnet) at relayer.memory.walrus.xyz and staging (testnet) at relayer-staging.memory.walrus.xyz. The managed relayer provides the fastest integration path but involves trusting the hosted instance with plaintext during encryption, sharing the deployment with other users, and accepting that the service carries no SLA guarantees.
---

A managed relayer is a simpler experience for teams that want to get started without running infrastructure. If a managed relayer endpoint is available for your environment, it gives you the fastest path to integration.

## Walrus Foundation hosted endpoints

| **Network** | **Relayer URL** |
|---|---|
| **Production** (mainnet) | `https://relayer.memory.walrus.xyz` |
| **Staging** (testnet) | `https://relayer-staging.memory.walrus.xyz` |

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

## Storage costs

The managed relayer covers WAL storage fees and SUI gas through its server wallets and configured gas sponsor. Account holders do not pay gas or WAL for these relayed writes. Account ownership does not determine which wallet pays for an upload. The shared service applies usage limits.

With a [self-hosted relayer](/relayer/self-hosting), you fund the relayer deployment.

If you need full control over the trust boundary or your own dedicated instance, see [Self-Hosting](/relayer/self-hosting).
