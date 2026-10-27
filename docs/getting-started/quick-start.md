---
title: Quick Start
description: >-
  Get Walrus Memory running in minutes using the TypeScript SDK, from installing the SDK and
  generating credentials to configuring the client and storing and recalling your first memory.
keywords:
  - Walrus Memory
  - MemWal
  - quick start
  - TypeScript SDK
  - installation
  - setup
goal:
  description: "Get a working end-to-end Walrus Memory integration: install the SDK, create an account at memory.walrus.xyz, call remember() to store a memory, and confirm recall() returns it."
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
  - How do I get started with Walrus Memory?
  - How do I install the MemWal TypeScript SDK?
  - How do I store and recall my first memory with MemWal?
answer: >-
  To get started with Walrus Memory, install the @mysten-incubation/memwal TypeScript SDK,
  generate an account ID and delegate key from the Walrus Memory Playground, choose a relayer
  endpoint, configure the SDK client, and call remember/recall to store and retrieve memories.
---

The fastest way to get Walrus Memory running is through the TypeScript SDK.

## Prerequisites

- [Node.js](https://nodejs.org/) v22.23.4+ (or v24.22.1+ / v26.12.1+) or [Bun](https://bun.sh/) v1+

## Quick start

<Steps>
  <Step>
    ### Install the SDK

    <Tabs>
      <Tab title="pnpm">
        ```bash
        pnpm add @mysten-incubation/memwal @mysten/sui @mysten/seal
        ```
      </Tab>
      <Tab title="npm">
        ```bash
        npm install @mysten-incubation/memwal @mysten/sui @mysten/seal
        ```
      </Tab>
      <Tab title="yarn">
        ```bash
        yarn add @mysten-incubation/memwal @mysten/sui @mysten/seal
        ```
      </Tab>
      <Tab title="bun">
        ```bash
        bun add @mysten-incubation/memwal @mysten/sui @mysten/seal
        ```
      </Tab>
    </Tabs>

    **Optional packages**

    For AI middleware with [Vercel AI SDK](https://sdk.vercel.ai/) (`@mysten-incubation/memwal/ai`):

    <Tabs>
      <Tab title="pnpm">
        ```bash
        pnpm add ai
        ```
      </Tab>
      <Tab title="npm">
        ```bash
        npm install ai
        ```
      </Tab>
      <Tab title="yarn">
        ```bash
        yarn add ai
        ```
      </Tab>
      <Tab title="bun">
        ```bash
        bun add ai
        ```
      </Tab>
    </Tabs>

    `@mysten/sui` and `@mysten/seal` are required peers: the default client imports them on `recall()` to build the Seal session, and pnpm and yarn do not install peers for you.

    For the [manual client flow](/getting-started/choose-your-path) (`@mysten-incubation/memwal/manual`), also add:

    <Tabs>
      <Tab title="pnpm">
        ```bash
        pnpm add @mysten/walrus
        ```
      </Tab>
      <Tab title="npm">
        ```bash
        npm install @mysten/walrus
        ```
      </Tab>
      <Tab title="yarn">
        ```bash
        yarn add @mysten/walrus
        ```
      </Tab>
      <Tab title="bun">
        ```bash
        bun add @mysten/walrus
        ```
      </Tab>
    </Tabs>
  </Step>

  <Step>
    ### Generate your account ID and delegate key

    Create a Walrus Memory account ID and delegate private key for your SDK client using one of the hosted endpoints below.

    <Note>
    The following endpoints are provided as a public good by Walrus Foundation.
    </Note>

    | **App** | **URL** |
    | --- | --- |
    | **Walrus Memory Playground** | [memory.walrus.xyz](https://memory.walrus.xyz) |

    For the contract-based setup flow, see [Delegate Key Management](/contract/delegate-key-management) and [Walrus Memory smart contract](/contract/overview).
  </Step>

  <Step>
    ### Choose a relayer

    Use a hosted relayer, or deploy your own [self-hosted relayer](/relayer/self-hosting) with access to a wallet funded with WAL and SUI:

    <Note>
    Following endpoints are provided as public good by Walrus Foundation.
    </Note>

    | **Network** | **Relayer URL** |
    | --- | --- |
    | **Production** (mainnet) | `https://relayer.memory.walrus.xyz` |
    | **Staging** (testnet) | `https://relayer.dev.memwal.ai` |
  </Step>

  <Step>
    ### Configure the SDK

    Set up the SDK with your delegate key, account ID, and relayer URL:

    ```ts
    import { MemWal } from "@mysten-incubation/memwal";

    const memwal = MemWal.create({
      // Load your own credentials from the environment; don't hardcode an example ID.
      key: process.env.MEMWAL_KEY ?? "<your-ed25519-private-key>",
      accountId: process.env.MEMWAL_ACCOUNT_ID ?? "<your-memwal-account-id>",
      serverUrl: "https://relayer.memory.walrus.xyz",
      namespace: "my-app",
    });
    ```

    <Warning>
    Use the `accountId` **you** generated in the previous step. Recall is scoped per **account + namespace**. Reusing an account ID copied from docs or another project puts your memories in a shared space instead of isolating them to you.
    </Warning>
  </Step>

  <Step>
    ### Verify your connection

    Run a health check to confirm everything is working:

    ```ts
    await memwal.health();
    ```
  </Step>

  <Step>
    ### Store and recall your first memory

    ```ts
    const job = await memwal.remember("User prefers dark mode and works in TypeScript.");
    await memwal.waitForRememberJob(job.job_id);

    const result = await memwal.recall({ query: "What do we know about this user?" });
    console.log(result.results);
    ```

    You're up and running.
  </Step>
</Steps>

If Walrus Memory is useful to you, [a star on the GitHub repo ⭐](https://github.com/MystenLabs/MemWal) helps others find it.
