---
title: "Choose Your Path"
description: >-
  Walrus Memory supports several integration modes depending on how much control you need.
  Compare the Default SDK, Managed Relayer, Manual Client Flow, AI Middleware, Self-Hosted
  Relayer, and MCP Clients to pick the right path for your use case.
keywords:
  - Walrus Memory
  - MemWal
  - integration modes
  - SDK
  - relayer
  - manual client
  - AI middleware
  - MCP
goal:
  description: Compare the four integration paths — default SDK, manual client, AI middleware, and MCP server — and pick the one that matches your trust model, tech stack, and control requirements.
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
  - What are the different ways to integrate Walrus Memory?
  - Should I use the managed relayer or self-host for MemWal?
  - How do I use Walrus Memory with the Vercel AI SDK?
answer: >-
  Walrus Memory offers six integration paths: the Default SDK for quick starts, Managed Relayer
  for hosted infrastructure, Manual Client Flow for full client-side control over encryption,
  AI Middleware for Vercel AI SDK integration, Self-Hosted Relayer for complete trust boundary
  control, and MCP Clients for tool-use agents like Cursor and Claude Desktop.
---

Walrus Memory supports several integration modes depending on how much control you need. Pick the one that fits your use case.

<Tip>
These paths aren't mutually exclusive. You can combine them - for example, use the **Default SDK** with the **AI Middleware**, or start with the **Managed Relayer** and move to **Self-Hosting** later. They all share the same backend and data layer.
</Tip>

## 1. Default SDK

Use `@mysten-incubation/memwal` when you want the fastest working integration.

- relayer handles embedding, retrieval, and restore
- best starting point for most teams

Go to: [SDK Overview](/sdk/overview)

## 2. Managed Relayer

Use a hosted relayer, or deploy your own [self-hosted relayer](/relayer/self-hosting) with access to a wallet funded with WAL and SUI.

<Note>
Following endpoints are provided as public good by Walrus Foundation.
</Note>

| Network | Relayer URL |
| --- | --- |
| **Production** (mainnet) | `https://relayer.memory.walrus.xyz` |
| **Staging** (testnet) | `https://relayer.dev.memwal.ai` |

Go to: [Managed Relayer](/relayer/public-relayer)

## 3. Manual Client Flow

Use `@mysten-incubation/memwal/manual` when you want full client-side control over encryption and embeddings. Recommended for Web3-native users who want to minimize trust in the relayer - it never sees your plaintext data.

- client handles embeddings and SEAL encryption locally
- relayer only sees encrypted payloads and vectors

Go to: [SDK Usage](/sdk/usage)

## 4. AI Middleware

Use `@mysten-incubation/memwal/ai` when you already use the AI SDK and want recall plus auto-save behavior.

Go to: [AI Integration](/sdk/usage/with-memwal)

## 5. Self-Host the Relayer

Use this when you need full control over the trust boundary - your infrastructure, your credentials, no third party sees your data.

Go to: [Self-Hosting](/relayer/self-hosting)

## 6. MCP Clients

Use Walrus Memory's MCP server when you want Cursor, Claude Desktop, Claude Code, Antigravity, or another MCP-aware agent to save and recall memory during tool use.

- connect directly to the hosted relayer with Streamable HTTP at `/api/mcp`
- or run the local stdio package with `npx -y @mysten-incubation/memwal-mcp`

Go to: [MCP](/mcp/overview)

If the agent already has local memory, standing context, or session history, copy those facts in first: [Import Your Existing Memory](/guides/import-existing-memory).
